use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ----- Rule-side DTOs (mirrors of plane-native types; mapped by adapters) -----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleNetwork {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleSessionShape {
    Stream,
    Datagram,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleTrafficClass {
    Interactive,
    Bulk,
    Control,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleTransformKind {
    Fragment,
    Compress,
    Encrypt,
    Checksum,
    Parity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleSocks5Command {
    Connect,
    Bind,
    UdpAssociate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleScheduleHint {
    Auto,
    FanOut { fanout: FanOutParams },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FanOutParams {
    pub k: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleTransformDescriptor {
    pub kind: RuleTransformKind,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleFlowId(pub String);

// ----- RuleCtx -----

#[derive(Debug, Clone, Default)]
pub struct RuleCtx {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub network: Option<RuleNetwork>,
    pub flow_id: Option<RuleFlowId>,
    pub session_shape: Option<RuleSessionShape>,
    pub operation: Option<String>,
    pub schedule_hint: Option<RuleScheduleHint>,
    pub traffic_class: Option<RuleTrafficClass>,
    pub transform_kind: Option<RuleTransformKind>,
    pub fragment_group: Option<String>,
    pub hostname: Option<String>,
    pub socks5_command: Option<RuleSocks5Command>,
    pub consumer: Option<String>,
    pub dns_qtype: Option<String>,
    pub authenticated_user: Option<String>,
    pub dst_geo: Option<String>,
    pub asn: Option<u32>,
    pub geosite_tags: Vec<String>,
}

impl RuleCtx {
    pub fn empty() -> Self {
        Self::default()
    }
}

// ----- AST -----

#[derive(Debug, Clone)]
pub enum Predicate {
    SrcCidr(ipnet::IpNet),
    DstCidr(ipnet::IpNet),
    SrcIpEq(IpAddr),
    DstIpEq(IpAddr),
    DstPortEq(u16),
    DstPortRange(u16, u16),
    NetworkEq(RuleNetwork),
    SessionShapeEq(RuleSessionShape),
    OperationEq(String),
    Socks5CommandEq(RuleSocks5Command),
    HostnameExact(String),
    HostnameSuffix(String),
    HostnameKeyword(String),
    HostnameRegex(regex::Regex),
    FragmentGroupExact(String),
    TransformKindEq(RuleTransformKind),
    TrafficClassEq(RuleTrafficClass),
    RulesetMember(String), // resolved at evaluate-time through RuleSetRegistry
    Consumer(String),
    DnsQtype(String),
    AuthenticatedUserEq(String),
    AuthenticatedUserAny,
    DstGeoEq(String),
    AsnEq(u32),
    AsnAny(Vec<u32>),
    GeositeTag(String),
}

#[derive(Debug, Clone)]
pub enum MatchExpr {
    Term(Predicate),
    Predicate(Predicate),
    All(Vec<MatchExpr>),
    Any(Vec<MatchExpr>),
    Not(Box<MatchExpr>),
}

/// Alias for ergonomic use in rule construction (e.g. `Match::Predicate(...)`).
pub type Match = MatchExpr;

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: Option<String>,
    pub r#match: MatchExpr,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchTrace {
    pub matched: bool,
    pub rule_index: Option<usize>,
    pub rule_id: Option<String>,
    pub default_used: bool,
}

#[derive(Debug, Clone)]
pub struct RuleDecision {
    pub action: Action,
    pub trace: MatchTrace,
}

#[derive(Debug, Clone)]
pub struct RuleChain {
    pub rules: Vec<Rule>,
    pub default: Action,
}

// ----- Action -----

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    Allow,
    Deny,
    SetRouteGroup(String),
    SetResolverPool(String),
    SetScheduleHint(RuleScheduleHint),
    SetTransform(RuleTransformDescriptor),
    Compose(Vec<Action>),
    SetCostBias(i32),
}

// ----- Ruleset -----

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulesetFormat {
    DomainSuffix,
    IpCidr,
    Classical,
}

#[derive(Debug, Clone)]
pub enum RulesetSource {
    Inline { values: Vec<String> },
    Local { path: std::path::PathBuf },
}

#[derive(Debug, Clone)]
pub struct Ruleset {
    pub name: String,
    pub format: RulesetFormat,
    pub field: Option<RulesetField>, // None only for `classical`
    pub source: RulesetSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesetField {
    Hostname,
    SrcIp,
    DstIp,
}
