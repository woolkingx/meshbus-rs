//! Build a verified `PipelineRuntime` from operator YAML config.
//!
//! Steps:
//!   1. Resolve `pipeline.rule_chain_forward` (or legacy `rule_chain_path`)
//!      relative to `base_dir`, the directory holding the operator config file.
//!   2. Parse + validate forward/resolver rule_chain + rulesets via `mb_rule`. Local ruleset
//!      paths are resolved relative to the chain file's directory.
//!   3. Open GeoIP DBs if configured; absent config falls back to empty.
//!   4. Build a minimal M3 system-mode resolver with the configured shared DNS cache.
//!   5. Build `Vec<ExitCandidate>` from configured egresses.
//!   6. Build the pick_sink HookSpec with the operator's egress SinkIds so
//!      kernel verify checks the same terminal set runtime can emit.
//!   7. Register the configured source projection plus sinks/hooks/fns/pipeline/wiring into a fresh
//!      `KernelRegistry`, then run `verify()` as the load-time gate.
//!   8. Return a `PipelineRuntime` through its verifying constructor.

use crate::config::{Config, PipelineCfg};
use anyhow::anyhow;
use mb_geoip::GeoIpDb;
use mb_geosite::GeositeDb;
use mb_rule::types::Action;
use mesh_bus_core::kernel::{
    HookId, KernelRegistry, Pipeline, PipelineId, SinkId, SinkSpec, SourceId, SourceSpec, Wiring,
    kernel_registry_verify,
};
use mesh_bus_pipeline_hooks::context::{ExitCandidate, SharedHookCtx};
use mesh_bus_pipeline_hooks::runtime::PipelineRuntime;
use mesh_bus_pipeline_hooks::{geo, pick_sink, resolve, rule, specs};
use mesh_bus_resolver::cache::DnsCache;
use mesh_bus_resolver::data_handle::{ResolverBuilder, ResolverHandle};
use mesh_bus_resolver::types::{Pool, PoolMode};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const PIPELINE_ID: &str = "forward";

fn resolve_relative(base_dir: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    }
}

fn load_chain_from_path(
    label: &str,
    rule_chain_path: &Path,
    base_dir: &Path,
) -> anyhow::Result<(Arc<mb_rule::RuleChain>, Arc<mb_rule::RuleSetRegistry>)> {
    let chain_path = resolve_relative(base_dir, rule_chain_path);
    let body = std::fs::read_to_string(&chain_path)
        .map_err(|e| anyhow!("read {label} {}: {e}", chain_path.display()))?;
    let (chain, mut rulesets) = mb_rule::parse_chain_and_rulesets_yaml(&body)
        .map_err(|e| anyhow!("parse {label} {}: {e:?}", chain_path.display()))?;
    mb_rule::validate(&chain, &rulesets)
        .map_err(|e| anyhow!("validate {label} {}: {e}", chain_path.display()))?;
    if let Some(chain_dir) = chain_path.parent() {
        for rs in &mut rulesets {
            if let mb_rule::types::RulesetSource::Local { path } = &mut rs.source {
                if path.is_relative() {
                    *path = chain_dir.join(&*path);
                }
            }
        }
    }
    let registry = mb_rule::RuleSetRegistry::load(&rulesets)
        .map_err(|e| anyhow!("load rule_sets {}: {e:?}", chain_path.display()))?;
    Ok((Arc::new(chain), Arc::new(registry)))
}

fn load_forward_chain(
    pipeline_cfg: &PipelineCfg,
    base_dir: &Path,
) -> anyhow::Result<(Arc<mb_rule::RuleChain>, Arc<mb_rule::RuleSetRegistry>)> {
    let rule_chain_path = pipeline_cfg
        .forward_rule_chain_path()
        .ok_or_else(|| anyhow!("pipeline requires rule_chain_forward or legacy rule_chain_path"))?;
    let (chain, rule_sets) = load_chain_from_path("rule_chain_forward", rule_chain_path, base_dir)?;
    validate_forward_actions(&chain)?;
    Ok((chain, rule_sets))
}

fn validate_forward_actions(chain: &mb_rule::RuleChain) -> anyhow::Result<()> {
    for rule in &chain.rules {
        validate_forward_action(&rule.action)?;
    }
    validate_forward_action(&chain.default)
}

fn validate_forward_action(action: &Action) -> anyhow::Result<()> {
    match action {
        Action::Allow
        | Action::Deny
        | Action::SetRouteGroup(_)
        | Action::SetScheduleHint(_)
        | Action::SetCostBias(_) => Ok(()),
        Action::Compose(actions) => {
            for child in actions {
                validate_forward_action(child)?;
            }
            Ok(())
        }
        Action::SetResolverPool(_) | Action::SetTransform(_) => Err(anyhow!(
            "unsupported forward rule action: action cannot be projected onto policy.rule_chain HookSpec writes"
        )),
        _ => Err(anyhow!(
            "unsupported forward rule action: action cannot be projected onto policy.rule_chain HookSpec writes"
        )),
    }
}

fn load_resolver_chain(
    pipeline_cfg: &PipelineCfg,
    base_dir: &Path,
) -> anyhow::Result<Option<(Arc<mb_rule::RuleChain>, Arc<mb_rule::RuleSetRegistry>)>> {
    let Some(rule_chain_path) = &pipeline_cfg.rule_chain_resolver else {
        return Ok(None);
    };
    load_chain_from_path("rule_chain_resolver", rule_chain_path, base_dir).map(Some)
}

fn load_geoip(pipeline_cfg: &PipelineCfg, base_dir: &Path) -> anyhow::Result<Arc<GeoIpDb>> {
    let Some(geo) = &pipeline_cfg.geoip else {
        return Ok(Arc::new(GeoIpDb::empty()));
    };
    let (Some(country), Some(asn)) = (&geo.country_path, &geo.asn_path) else {
        return Err(anyhow!(
            "pipeline geoip requires both country_path and asn_path"
        ));
    };
    let country_abs = resolve_relative(base_dir, country);
    let asn_abs = resolve_relative(base_dir, asn);
    let db = GeoIpDb::open(&country_abs, &asn_abs).map_err(|e| {
        anyhow!(
            "open geoip country={} asn={}: {e}",
            country_abs.display(),
            asn_abs.display()
        )
    })?;
    Ok(Arc::new(db))
}

fn load_geosite(pipeline_cfg: &PipelineCfg, base_dir: &Path) -> anyhow::Result<Arc<GeositeDb>> {
    let Some(geosite) = &pipeline_cfg.geosite else {
        return Ok(Arc::new(GeositeDb::empty()));
    };
    let Some(path) = &geosite.path else {
        return Err(anyhow!("pipeline geosite.path is required"));
    };
    let path = resolve_relative(base_dir, path);
    let db = GeositeDb::open(&path).map_err(|e| anyhow!("open geosite {}: {e}", path.display()))?;
    Ok(Arc::new(db))
}

fn build_dns_cache(pipeline_cfg: &PipelineCfg) -> Arc<DnsCache> {
    let Some(cache_cfg) = &pipeline_cfg.dns_cache else {
        return Arc::new(DnsCache::new());
    };
    let Some(ms) = cache_cfg.serve_stale_window_ms else {
        return Arc::new(DnsCache::new());
    };
    Arc::new(DnsCache::with_stale_window(Duration::from_millis(ms)))
}

fn build_default_resolver(
    cache: Arc<DnsCache>,
    resolver_chain: Option<(Arc<mb_rule::RuleChain>, Arc<mb_rule::RuleSetRegistry>)>,
) -> anyhow::Result<Arc<dyn ResolverHandle>> {
    let mut builder = ResolverBuilder::new()
        .with_pool(Pool {
            id: "default".into(),
            mode: PoolMode::SystemMode,
            servers: vec![],
            route_group: None,
        })
        .with_default_pool("default")
        .with_cache(cache);
    if let Some((chain, sets)) = resolver_chain {
        builder = builder.with_rule_chain(chain, sets);
    }
    let resolver = builder
        .build()
        .map_err(|e| anyhow!("resolver build: {e}"))?;
    Ok(Arc::new(resolver))
}

fn candidates_from_egresses(cfg: &Config) -> Vec<ExitCandidate> {
    cfg.egresses
        .iter()
        .map(|e| {
            let (supports_stream, supports_datagram) = e.pipeline_capability_bits();
            ExitCandidate {
                sink_id: e.id().to_string(),
                route_groups: e.groups().to_vec(),
                supports_stream,
                supports_datagram,
                rtt_ms: 0,
                success_rate: 1.0,
                jitter_ms: 0,
            }
        })
        .collect()
}

fn resolve_pipeline_source_index(
    cfg: &Config,
    pipeline_cfg: &PipelineCfg,
) -> anyhow::Result<usize> {
    let idx = match pipeline_cfg.source.ingress_index {
        Some(idx) => {
            let ingress = cfg
                .ingresses
                .get(idx)
                .ok_or_else(|| anyhow!("pipeline source ingress_index {idx} is out of range"))?;
            if ingress.pipeline_source_kind() != Some(pipeline_cfg.source.kind.as_str()) {
                return Err(anyhow!(
                    "pipeline source ingress_index {idx} does not declare pipeline source kind {}",
                    pipeline_cfg.source.kind
                ));
            }
            idx
        }
        None => {
            let matches: Vec<usize> = cfg
                .ingresses
                .iter()
                .enumerate()
                .filter_map(|(idx, ingress)| {
                    (ingress.pipeline_source_kind() == Some(pipeline_cfg.source.kind.as_str()))
                        .then_some(idx)
                })
                .collect();
            match matches.as_slice() {
                [idx] => *idx,
                [] => {
                    return Err(anyhow!(
                        "pipeline requires at least one ingress declaring pipeline source kind {}",
                        pipeline_cfg.source.kind
                    ));
                }
                _ => {
                    return Err(anyhow!(
                        "pipeline source ingress_index is required when multiple ingresses declare pipeline source kind {}",
                        pipeline_cfg.source.kind
                    ));
                }
            }
        }
    };
    Ok(idx)
}

pub fn selected_pipeline_source_index(cfg: &Config) -> anyhow::Result<Option<usize>> {
    let Some(pipeline_cfg) = &cfg.pipeline else {
        return Ok(None);
    };
    resolve_pipeline_source_index(cfg, pipeline_cfg).map(Some)
}

fn pipeline_source_from_config(
    cfg: &Config,
    pipeline_cfg: &PipelineCfg,
) -> anyhow::Result<(SourceId, SourceSpec)> {
    let idx = resolve_pipeline_source_index(cfg, pipeline_cfg)?;

    for key in &pipeline_cfg.source.initial_writes {
        let head = key.split('.').next().unwrap_or("");
        if matches!(head, "policy" | "transport") {
            return Err(anyhow!(
                "pipeline source initial_writes `{key}` targets reserved lower-layer namespace `{head}`; per docs/handbook/spec/data-ontology.schema.json#metadata_namespace_ownership only net|auth|trace|ext are operator-writable at ingress (source_initial_writes_allowed=true)"
            ));
        }
    }

    let id = SourceId::new(
        pipeline_cfg
            .source
            .id
            .clone()
            .unwrap_or_else(|| format!("ingress:{idx}")),
    );
    Ok((
        id.clone(),
        SourceSpec {
            id,
            kind: pipeline_cfg.source.kind.clone(),
            initial_writes: pipeline_cfg.source.initial_writes.clone(),
        },
    ))
}

/// Assemble a verified `PipelineRuntime` from the operator config.
///
/// `base_dir` is the directory holding the operator YAML file; relative
/// `rule_chain_forward` / legacy `rule_chain_path` and `geoip.*_path`
/// entries are resolved against it.
pub fn build_pipeline_runtime(cfg: &Config, base_dir: &Path) -> anyhow::Result<PipelineRuntime> {
    let pipeline_cfg = cfg
        .pipeline
        .as_ref()
        .ok_or_else(|| anyhow!("pipeline block missing from config"))?;

    let (rule_chain, rule_sets) = load_forward_chain(pipeline_cfg, base_dir)?;
    let geoip = load_geoip(pipeline_cfg, base_dir)?;
    let geosite = load_geosite(pipeline_cfg, base_dir)?;
    let cache = build_dns_cache(pipeline_cfg);
    let resolver_chain = load_resolver_chain(pipeline_cfg, base_dir)?;
    let resolver = build_default_resolver(cache.clone(), resolver_chain)?;
    let candidates = Arc::new(candidates_from_egresses(cfg));

    let pid = PipelineId::new(PIPELINE_ID);
    let (src, source_spec) = pipeline_source_from_config(cfg, pipeline_cfg)?;
    let mut reg = KernelRegistry::default();

    reg.sources.insert(src.clone(), source_spec);

    let sink_ids: Vec<SinkId> = cfg.egresses.iter().map(|e| SinkId::new(e.id())).collect();
    for (egress, sid) in cfg.egresses.iter().zip(&sink_ids) {
        reg.sinks.insert(
            sid.clone(),
            SinkSpec {
                id: sid.clone(),
                kind: egress.pipeline_sink_kind().into(),
            },
        );
    }

    let resolve_id = HookId::new("net.resolve_or_recover");
    let enrich_id = HookId::new("net.enrich_geo_asn");
    let rule_id = HookId::new("policy.rule_chain");
    let pick_id = HookId::new("transport.pick_sink_cake");

    reg.hooks
        .insert(resolve_id.clone(), specs::RESOLVE_HOOK.clone());
    reg.hooks
        .insert(enrich_id.clone(), specs::ENRICH_HOOK.clone());
    reg.hooks.insert(rule_id.clone(), specs::RULE_HOOK.clone());

    reg.hooks.insert(
        pick_id.clone(),
        specs::pick_sink_hook_spec(sink_ids.clone()),
    );

    reg.fns
        .insert(resolve_id.clone(), resolve::resolve_or_recover);
    reg.fns.insert(enrich_id.clone(), geo::enrich_geo_asn);
    reg.fns.insert(rule_id.clone(), rule::rule_chain);
    reg.fns.insert(pick_id.clone(), pick_sink::pick_sink_cake);

    reg.pipelines.insert(
        pid.clone(),
        Pipeline {
            id: pid.clone(),
            hooks: vec![resolve_id, enrich_id, rule_id, pick_id],
        },
    );
    reg.wirings.push(Wiring {
        source: src.clone(),
        pipeline: pid.clone(),
    });

    kernel_registry_verify(&reg).map_err(|e| anyhow!("kernel registry verify: {e:?}"))?;

    let shared = SharedHookCtx {
        resolver,
        cache,
        geoip,
        geosite,
        rule_chain,
        rule_sets,
        candidates,
        tokio: tokio::runtime::Handle::current(),
    };

    PipelineRuntime::new(shared, Arc::new(reg), src).map_err(Into::into)
}
