#![allow(clippy::disallowed_methods)] // serde_json::json! macro expands to internal .unwrap(); not our call-site

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use typify::{TypeSpace, TypeSpaceSettings};

/// Schema file name → JSON title mapping for use as definition keys.
const SCHEMA_FILES: &[(&str, &str)] = &[
    ("endpoint.schema.json", "Endpoint"),
    ("exit-id.schema.json", "ExitId"),
    ("session.schema.json", "Session"),
    ("frame.schema.json", "Frame"),
    ("return-event.schema.json", "ReturnEvent"),
    ("measurement.schema.json", "Measurement"),
    ("capability.schema.json", "Capabilities"),
    ("policy.schema.json", "Policy"),
    ("bus-event.schema.json", "BusEvent"),
    ("exit-snapshot.schema.json", "ExitSnapshot"),
    ("transform.schema.json", "TransformDescriptor"),
    ("fragment.schema.json", "FragmentMetadata"),
    ("reassembly.schema.json", "ReassemblyPolicy"),
];

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set by Cargo"));
    let schemas_dir = PathBuf::from("../../schemas");

    println!("cargo:rerun-if-changed=../../schemas");

    // Load all raw schema values.
    let mut raw: HashMap<String, serde_json::Value> = HashMap::new();
    for (file, _) in SCHEMA_FILES {
        let path = schemas_dir.join(file);
        let content =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read schema {file}: {e}"));
        let value: serde_json::Value =
            serde_json::from_str(&content).unwrap_or_else(|e| panic!("parse schema {file}: {e}"));
        raw.insert(file.to_string(), value);
    }

    // Build a merged schema: all types go into `definitions`,
    // external $refs are rewritten to #/definitions/<Title>.
    let mut definitions = serde_json::Map::new();
    for (file, title) in SCHEMA_FILES {
        let mut schema = raw[*file].clone();
        rewrite_refs(&mut schema, &raw);
        definitions.insert(title.to_string(), schema);
    }

    // Synthetic root schema that just holds all definitions.
    let merged = serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "definitions": definitions
    });

    let root_schema: schemars::schema::RootSchema =
        serde_json::from_value(merged).expect("merged schema is valid RootSchema");

    let mut type_space = TypeSpace::new(TypeSpaceSettings::default().with_struct_builder(true));
    type_space
        .add_root_schema(root_schema)
        .expect("add_root_schema failed");

    let contents = prettyplease::unparse(
        &syn::parse2(type_space.to_stream()).expect("parse generated token stream"),
    );
    fs::write(out_dir.join("types.rs"), contents).expect("write types.rs");
}

/// Recursively rewrite external file $refs to #/definitions/<Title>.
fn rewrite_refs(value: &mut serde_json::Value, raw: &HashMap<String, serde_json::Value>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(ref_val) = map.get("$ref").cloned() {
                if let Some(file_ref) = ref_val.as_str() {
                    if !file_ref.starts_with('#') {
                        // Find the title for this file ref.
                        let title = raw
                            .get(file_ref)
                            .and_then(|v| v.get("title"))
                            .and_then(|t| t.as_str())
                            .unwrap_or(file_ref);
                        let new_ref = format!("#/definitions/{}", title);
                        map.insert("$ref".to_string(), serde_json::Value::String(new_ref));
                    }
                }
            }
            for v in map.values_mut() {
                rewrite_refs(v, raw);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                rewrite_refs(v, raw);
            }
        }
        _ => {}
    }
}
