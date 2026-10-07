//! Files of a release as a folder tree, flattened for templates: a folder is
//! an "open" row, its contents, then a "close" row, so a template can emit
//! nested `<details>` elements without recursion (and without JavaScript).
//! Files come before folders at every level; files keep the caller's order.

use std::collections::BTreeMap;

use crate::util::human_size;

pub struct TreeRow<T> {
    /// "open" (a folder starts), "file" or "close" (the folder ends).
    pub kind: &'static str,
    /// Folder name (open rows).
    pub name: String,
    /// Folder path, e.g. "sources/extra" (open rows).
    pub path: String,
    /// Files and total size below the folder (open rows).
    pub files: usize,
    pub size: String,
    /// The file (file rows).
    pub item: Option<T>,
}

/// Builds the rows from (path, size, item). Folders are sorted by name.
pub fn build<T>(items: Vec<(String, u64, T)>) -> Vec<TreeRow<T>> {
    let entries = items
        .into_iter()
        .map(|(path, size, item)| {
            let parts = path.split('/').map(str::to_string).collect::<Vec<_>>();
            (parts, size, item)
        })
        .collect();
    let mut out = Vec::new();
    emit(entries, "", &mut out);
    out
}

type Entry<T> = (Vec<String>, u64, T);

fn emit<T>(entries: Vec<Entry<T>>, prefix: &str, out: &mut Vec<TreeRow<T>>) {
    let mut folders: BTreeMap<String, Vec<Entry<T>>> = BTreeMap::new();
    for (mut parts, size, item) in entries {
        if parts.len() <= 1 {
            out.push(TreeRow {
                kind: "file",
                name: String::new(),
                path: String::new(),
                files: 0,
                size: String::new(),
                item: Some(item),
            });
        } else {
            let dir = parts.remove(0);
            folders.entry(dir).or_default().push((parts, size, item));
        }
    }
    for (name, children) in folders {
        let path = format!("{prefix}{name}");
        let files = children.len();
        let bytes: u64 = children.iter().map(|c| c.1).sum();
        out.push(TreeRow {
            kind: "open",
            name,
            path: path.clone(),
            files,
            size: human_size(bytes),
            item: None,
        });
        emit(children, &format!("{path}/"), out);
        out.push(TreeRow {
            kind: "close",
            name: String::new(),
            path: String::new(),
            files: 0,
            size: String::new(),
            item: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_first_then_folders() {
        let rows = build(vec![
            ("sources/b.tar".to_string(), 10, "sb"),
            ("z.iso".to_string(), 1, "z"),
            ("sources/deep/c.tar".to_string(), 5, "sdc"),
            ("a.iso".to_string(), 1, "a"),
            ("sources/a.tar".to_string(), 20, "sa"),
        ]);
        let shape: Vec<String> = rows
            .iter()
            .map(|r| match r.kind {
                "file" => r.item.unwrap().to_string(),
                "open" => format!("[{} {} {}", r.path, r.files, r.size),
                _ => "]".to_string(),
            })
            .collect();
        assert_eq!(
            shape,
            [
                "z",
                "a",
                "[sources 3 35 B",
                "sb",
                "sa",
                "[sources/deep 1 5 B",
                "sdc",
                "]",
                "]"
            ]
        );
    }
}
