//! `elastalert create-index`: creates the five writeback indices with their mappings.

use crate::es::Es;
use anyhow::Result;
use serde_json::Value;

const MAPPINGS: [(&str, &str, &str); 5] = [
    ("", "elastalert", include_str!("../mappings/elastalert.json")),
    ("_status", "elastalert_status", include_str!("../mappings/elastalert_status.json")),
    ("_silence", "silence", include_str!("../mappings/silence.json")),
    ("_error", "elastalert_error", include_str!("../mappings/elastalert_error.json")),
    ("_past", "past_elastalert", include_str!("../mappings/past_elastalert.json")),
];

/// Creates missing indices. With `recreate`, existing ones are deleted first (data loss).
pub async fn create_index(es: &Es, index: &str, recreate: bool, old_index: Option<&str>) -> Result<()> {
    let caps = es.caps().await?;
    if !caps.opensearch && caps.major < 7 {
        anyhow::bail!("unsupported Elasticsearch version {}", caps.major);
    }
    if !recreate && es.exists(index).await? {
        println!("Index {index} already exists. Skipping index creation.");
        return Ok(());
    }
    for (suffix, _, mapping) in MAPPINGS {
        let name = format!("{index}{suffix}");
        if es.exists(&name).await? {
            println!("Deleting index {name}.");
            es.delete(&name).await?;
        }
        let mappings: Value = serde_json::from_str(mapping)?;
        es.put(&name, &serde_json::json!({"mappings": mappings})).await?;
        println!("Created {name}");
    }
    if let Some(old) = old_index {
        println!("Copying all data from old index '{old}' to new index '{index}'");
        let body = serde_json::json!({"source": {"index": old}, "dest": {"index": index}});
        es.post("_reindex?wait_for_completion=true", &body).await?;
    }
    println!("Done!");
    Ok(())
}
