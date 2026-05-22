//! mb-geosite — operator-curated hostname suffix tag lookup.

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum GeositeError {
    #[error("read geosite file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid geosite entry at line {line}: {reason}")]
    InvalidLine { line: usize, reason: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Node {
    tags: Vec<String>,
    children: BTreeMap<String, Node>,
}

#[derive(Debug, Clone, Default)]
pub struct GeositeDb {
    root: Node,
}

impl GeositeDb {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn open(path: &Path) -> Result<Self, GeositeError> {
        let body = match std::fs::read_to_string(path) {
            Ok(body) => body,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::empty()),
            Err(source) => {
                return Err(GeositeError::Read {
                    path: path.display().to_string(),
                    source,
                });
            }
        };
        Self::parse(&body)
    }

    pub fn parse(body: &str) -> Result<Self, GeositeError> {
        let mut db = Self::empty();
        for (idx, raw) in body.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((tag, suffix)) = line.split_once(':') else {
                return Err(GeositeError::InvalidLine {
                    line: line_no,
                    reason: "expected tag:domain".into(),
                });
            };
            let tag = tag.trim();
            let suffix = normalize_host(suffix.trim());
            if tag.is_empty() {
                return Err(GeositeError::InvalidLine {
                    line: line_no,
                    reason: "empty tag".into(),
                });
            }
            if !is_valid_tag(tag) {
                return Err(GeositeError::InvalidLine {
                    line: line_no,
                    reason: "invalid tag".into(),
                });
            }
            if suffix.is_empty() {
                return Err(GeositeError::InvalidLine {
                    line: line_no,
                    reason: "empty domain".into(),
                });
            }
            if !is_valid_domain_suffix(&suffix) {
                return Err(GeositeError::InvalidLine {
                    line: line_no,
                    reason: "invalid domain".into(),
                });
            }
            db.insert(&suffix, tag);
        }
        Ok(db)
    }

    pub fn lookup(&self, host: &str) -> Vec<String> {
        let host = normalize_host(host);
        if host.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        self.for_each_match(&host, |tag| out.push(tag.to_string()));
        out
    }

    pub fn lookup_packed(&self, host: &str) -> Vec<u8> {
        let host = normalize_host(host);
        if host.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        self.for_each_match(&host, |tag| {
            if !out.is_empty() {
                out.push(0);
            }
            out.extend_from_slice(tag.as_bytes());
        });
        out
    }

    fn insert(&mut self, suffix: &str, tag: &str) {
        let mut node = &mut self.root;
        for label in suffix.rsplit('.') {
            node = node.children.entry(label.to_string()).or_default();
        }
        node.tags.push(tag.to_ascii_lowercase());
    }

    fn for_each_match<'a>(&'a self, host: &str, mut visit: impl FnMut(&'a str)) {
        let mut node = &self.root;
        for label in host.rsplit('.') {
            let Some(next) = node.children.get(label) else {
                return;
            };
            node = next;
            for tag in &node.tags {
                visit(tag);
            }
        }
    }
}

fn normalize_host(raw: &str) -> String {
    let mut s = raw.trim().trim_start_matches('.').to_ascii_lowercase();
    while s.ends_with('.') {
        s.pop();
    }
    s
}

fn is_valid_tag(tag: &str) -> bool {
    tag.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn is_valid_domain_suffix(suffix: &str) -> bool {
    suffix.len() <= 253
        && !suffix.contains(':')
        && suffix.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
