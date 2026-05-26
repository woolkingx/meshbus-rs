#!/usr/bin/env python3
import json
from pathlib import Path

try:
    import jsonschema
except ModuleNotFoundError as exc:
    raise SystemExit("python package 'jsonschema' is required for schema instance validation") from exc


ROOT = Path(__file__).resolve().parents[1]


def load_json(path):
    return json.loads((ROOT / path).read_text())


def assert_valid(schema, instance, label):
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(instance)
    print(f"ok valid {label}")


def assert_invalid(schema, instance, label):
    jsonschema.Draft202012Validator.check_schema(schema)
    try:
        jsonschema.Draft202012Validator(schema).validate(instance)
    except jsonschema.ValidationError:
        print(f"ok invalid {label}")
        return
    raise AssertionError(f"expected invalid instance: {label}")


def validate_loadbalance_schema():
    schema = load_json("lib/mb-loadbalance/schema.json")
    assert_valid(schema, {"source_lease_activity": {"active_flows": 1}}, "lb active source")
    assert_valid(
        schema,
        {"source_lease_activity": {"active_flows": 0, "idle_since_ms": 1000}},
        "lb true idle source",
    )
    assert_valid(
        schema,
        {
            "candidate": {"id": "mesh24", "weight": 1},
            "source_lease_rotate_config": {
                "idle_timeout_ms": 600000,
                "max_age_ms": 3600000,
                "max_age_policy": "off",
                "switch_cooldown_ms": 60000,
            },
            "source_lease_decision": {
                "candidate_id": "mesh24",
                "reason": "idle-expired",
                "generation": 2,
            },
        },
        "lb decision envelope",
    )
    assert_invalid(schema, {"source_lease_activity": {"active_flows": 0}}, "lb half-idle")
    assert_invalid(
        schema,
        {"source_lease_activity": {"active_flows": 2, "idle_since_ms": 1000}},
        "lb active with idle timestamp",
    )
    assert_invalid(schema, {"candidate": {"id": "mesh24", "weight": 0}}, "lb zero weight")


def validate_core_source_activity_schema():
    schema = load_json("crates/mesh-bus-core/src/transport/forwarding/schema.json")
    source_activity = schema["definitions"]["SourceActivity"]
    assert_valid(source_activity, {"active_flows": 1}, "core active source")
    assert_valid(
        source_activity,
        {"active_flows": 0, "idle_since_ms": 1000},
        "core true idle source",
    )
    assert_invalid(source_activity, {"active_flows": 0}, "core half-idle")
    assert_invalid(
        source_activity,
        {"active_flows": 1, "idle_since_ms": 1000},
        "core active with idle timestamp",
    )


def validate_live_evidence_schema():
    schema = load_json("tests/schema.json")
    common = {
        "gateway_ssh": "root@192.0.2.36",
        "gateway_socks5": "192.0.2.36:2080",
        "gateway_operator": "http://127.0.0.1:19081",
        "gateway_service": "mesh-bus-run2.service",
        "gateway_bin": "/opt/mesh-bus/bin/mesh-bus-run2",
        "gateway_config": "/etc/mesh-bus/run2.yaml",
        "target": "https://example.com",
        "status": "ok",
        "samples": [],
        "delta": {
            "dispatch_success": 1,
            "dispatch_failure": 0,
            "meshsec_drop_total": 0,
            "native_drop_total": 0,
            "exits": {"mesh24": {"send_count": 1, "success_count": 1, "failure_count": 0}},
        },
    }
    assert_valid(
        schema,
        {
            **common,
            "kind": "mesh_bus.live_run2_pool_validation",
            "probes": 1,
            "curl_max_time_seconds": 30,
        },
        "run2 pool evidence",
    )
    assert_valid(
        schema,
        {
            **common,
            "kind": "mesh_bus.live_run2_stream_validation",
            "managed_origin": False,
            "min_bytes": 1,
            "min_seconds": 1,
            "curl": {"http_code": "200", "size_download": "10485760", "time_total": "81.9"},
        },
        "run2 stream evidence",
    )
    assert_invalid(schema, {**common, "kind": "mesh_bus.live_run2_pool_validation"}, "pool missing probe shape")
    assert_valid(
        schema,
        {
            "kind": "mesh_bus.live_observe_hooks_profile",
            "remote_ssh": "root@192.0.2.36",
            "remote_operator": "http://127.0.0.1:19081",
            "admin_bin": "/opt/mesh-bus/bin/mesh-bus-run2",
            "service": "mesh-bus-run2.service",
            "target": "https://example.com",
            "probe": "socks5-connect",
            "iterations": 2,
            "status": "ok",
            "status_before": {
                "kind": "operator.live_status",
                "status": {"egresses": []},
                "metrics": {
                    "kind": "operator.metrics_snapshot",
                    "dispatch_success": 0,
                    "dispatch_failure": 0,
                    "meshsec_drop_total": 0,
                    "native_drop_total": 0,
                    "exits": [],
                },
            },
            "metrics_before": {
                "kind": "operator.metrics_snapshot",
                "dispatch_success": 0,
                "dispatch_failure": 0,
                "meshsec_drop_total": 0,
                "native_drop_total": 0,
                "exits": [],
            },
            "metrics_after": {
                "kind": "operator.metrics_snapshot",
                "dispatch_success": 2,
                "dispatch_failure": 0,
                "meshsec_drop_total": 0,
                "native_drop_total": 0,
                "exits": [{"exit_id": "mesh24", "send_count": 2, "success_count": 2, "failure_count": 0}],
            },
            "delta": {
                "dispatch_success": 2,
                "dispatch_failure": 0,
                "meshsec_drop_total": 0,
                "native_drop_total": 0,
                "exits": {"mesh24": {"send_count": 2, "success_count": 2, "failure_count": 0}},
            },
            "samples": [
                {
                    "iteration": 1,
                    "probe": {
                        "kind": "operator.probe_result",
                        "probe": "socks5-connect",
                        "ok": True,
                        "dispatch_success_before": 0,
                        "dispatch_success_after": 1,
                        "dispatch_failure_before": 0,
                        "dispatch_failure_after": 0,
                    },
                    "selected_exits": ["mesh24"],
                }
            ],
            "assertions": {
                "observer_projection_moved": True,
                "probe_used_operator_api": True,
                "no_dispatch_failure_delta": True,
                "no_meshsec_drop_delta": True,
                "no_native_drop_delta": True,
            },
        },
        "observe/hooks profile evidence",
    )
    syscall_metrics = {
        "kind": "operator.metrics_snapshot",
        "dispatch_success": 0,
        "dispatch_failure": 0,
        "meshsec_drop_total": 0,
        "native_drop_total": 0,
        "datagram_send_total": 0,
        "datagram_failure_total": 0,
        "exits": [],
    }
    syscall_delta = {
        "dispatch_success": 3,
        "dispatch_failure": 0,
        "meshsec_drop_total": 0,
        "native_drop_total": 0,
        "datagram_failure_total": 0,
        "exits": {"mesh24": {"send_count": 3, "success_count": 3, "failure_count": 0}},
    }
    assert_valid(
        schema,
        {
            "kind": "mesh_bus.live_observe_syscall_profile",
            "remote_ssh": "root@192.0.2.36",
            "remote_operator": "http://127.0.0.1:19081",
            "admin_bin": "/opt/mesh-bus/bin/mesh-bus-run2",
            "service": "mesh-bus-run2.service",
            "target": "https://example.com",
            "probe": "socks5-connect",
            "strace_seconds": 8,
            "active_probes": 3,
            "thresholds": {"max_mmap_per_sec": 500},
            "status": "ok",
            "status_before": {
                "kind": "operator.live_status",
                "status": {"egresses": []},
                "metrics": syscall_metrics,
            },
            "metrics_before": syscall_metrics,
            "metrics_after": {**syscall_metrics, "dispatch_success": 3},
            "delta": syscall_delta,
            "phases": [
                {
                    "label": "idle",
                    "metrics_before": syscall_metrics,
                    "metrics_after": syscall_metrics,
                    "delta": {**syscall_delta, "dispatch_success": 0, "exits": {}},
                    "selected_exits": [],
                    "probes": [],
                    "syscall": {
                        "tool": "strace -f -c",
                        "seconds": 8,
                        "calls": {"mmap": {"calls": 12}, "munmap": {"calls": 12}},
                        "rates_per_sec": {"mmap": 1.5, "munmap": 1.5},
                    },
                },
                {
                    "label": "active_probe",
                    "metrics_before": syscall_metrics,
                    "metrics_after": {**syscall_metrics, "dispatch_success": 3},
                    "delta": syscall_delta,
                    "selected_exits": ["mesh24"],
                    "probes": [
                        {
                            "kind": "operator.probe_result",
                            "probe": "socks5-connect",
                            "ok": True,
                            "dispatch_success_before": 0,
                            "dispatch_success_after": 1,
                            "dispatch_failure_before": 0,
                            "dispatch_failure_after": 0,
                        }
                    ],
                    "syscall": {
                        "tool": "strace -f -c",
                        "seconds": 8,
                        "calls": {"recvmmsg": {"calls": 120}, "mmap": {"calls": 20}, "munmap": {"calls": 20}},
                        "rates_per_sec": {"recvmmsg": 15, "mmap": 2.5, "munmap": 2.5},
                    },
                },
            ],
            "assertions": {
                "service_active": True,
                "syscall_profiles_captured": True,
                "no_mmap_churn": True,
                "no_dispatch_failure_delta": True,
                "no_drop_delta": True,
                "active_probe_moved": True,
            },
        },
        "observe/syscall profile evidence",
    )


def validate_matrix_schema_fixture():
    schema = load_json("docs/handbook/spec/data-control-matrix.schema.json")
    fixture = {
        "kind": "mesh_bus.data_control_matrix",
        "families": [
            {
                "id": "scheduler-family",
                "kind": "scheduler-family",
                "owner": "LoadBalanceScheduler",
                "schema_ref": "crates/mesh-bus-scheduler-loadbalance/schema.json",
            }
        ],
        "layers": [
            {
                "id": "lb_scheduler",
                "layer": "L4",
                "owner": "LoadBalanceScheduler",
                "pdu": "RankContext -> ScheduleDecision",
                "pci": ["source_activity"],
                "sdu_boundary": "payload stays opaque",
            }
        ],
        "flows": [
            {
                "id": "flow.source-activity",
                "kind": "control",
                "from_owner": "kernel_dispatch",
                "to_owner": "lb_scheduler",
                "input_shape": "RankContext.source_activity",
                "output_shape": "SourceLeaseDecision",
                "legal_crossing": "scheduler public RankContext",
            }
        ],
        "cells": [
            {
                "family_id": "scheduler-family",
                "layer_id": "lb_scheduler",
                "flow_id": "flow.source-activity",
                "owned_pci": ["source_activity"],
                "carried_sdu": "opaque stream/datagram payload",
                "schema_ref": "lib/mb-loadbalance/schema.json#/$defs/SourceLeaseActivity",
                "code_owner": "lb_scheduler",
                "proof_gate": "cargo test -p mesh-bus-scheduler-loadbalance",
                "invalid_state": ["active_flows=0 without idle_since_ms"],
            }
        ],
    }
    assert_valid(schema, fixture, "data/control matrix fixture")


def validate_generated_matrix_if_present():
    schema = load_json("docs/handbook/spec/data-control-matrix.schema.json")
    for path in [
        Path("artifacts/flowgraph/data-control-matrix.json"),
        Path("artifacts/flowgraph-review/data-control-matrix.json"),
        Path("artifacts/flowgraph-review-lb/data-control-matrix.json"),
    ]:
        full = ROOT / path
        if full.exists():
            assert_valid(schema, json.loads(full.read_text()), str(path))


def main():
    validate_loadbalance_schema()
    validate_core_source_activity_schema()
    validate_live_evidence_schema()
    validate_matrix_schema_fixture()
    validate_generated_matrix_if_present()


if __name__ == "__main__":
    main()
