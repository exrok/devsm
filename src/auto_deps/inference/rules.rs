use std::path::{Path, PathBuf};

pub struct FrameworkRule {
    pub name: &'static str,
    pub triggers: &'static [&'static str],
    pub additions: fn(project_root: &Path, kept: &[PathBuf]) -> Vec<PathBuf>,
}

fn first_existing(root: &Path, candidates: &[&str]) -> Option<PathBuf> {
    for c in candidates {
        let p = root.join(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn cargo_additions(root: &Path, _kept: &[PathBuf]) -> Vec<PathBuf> {
    let mut v = Vec::new();
    let lock = root.join("Cargo.lock");
    if lock.exists() {
        v.push(lock);
    }
    let src = root.join("src");
    if src.is_dir() {
        v.push(src);
    }
    v
}

fn npm_additions(root: &Path, _kept: &[PathBuf]) -> Vec<PathBuf> {
    first_existing(root, &["package-lock.json", "pnpm-lock.yaml", "yarn.lock"])
        .into_iter()
        .collect()
}

fn python_additions(root: &Path, _kept: &[PathBuf]) -> Vec<PathBuf> {
    first_existing(root, &["poetry.lock", "uv.lock", "requirements.txt"])
        .into_iter()
        .collect()
}

pub const RULES: &[FrameworkRule] = &[
    FrameworkRule { name: "cargo", triggers: &["Cargo.toml"], additions: cargo_additions },
    FrameworkRule { name: "npm", triggers: &["package.json"], additions: npm_additions },
    FrameworkRule {
        name: "python",
        triggers: &["pyproject.toml", "setup.py"],
        additions: python_additions,
    },
];
