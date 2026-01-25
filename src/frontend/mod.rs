pub mod parser;
pub mod solc;
pub mod solc_manager;

use std::fs;
use std::path::{Path, PathBuf};

use crate::norm::{NormalizedAst, SourceFile};
use crate::util::error::Result;

#[derive(Debug, Clone, Copy)]
pub enum FrontendMode {
    Full,
    Partial,
}

#[derive(Debug, Clone)]
pub struct FrontendOutput {
    pub mode: FrontendMode,
    pub ast: NormalizedAst,
}

pub fn load_project(path: &str) -> Result<FrontendOutput> {
    match solc::load_via_solc(path) {
        Ok(ast) => Ok(FrontendOutput {
            mode: FrontendMode::Full,
            ast,
        }),
        Err(err) => {
            eprintln!("solc frontend failed: {err}");
            let ast = parser::load_via_parser(path)?;
            Ok(FrontendOutput {
                mode: FrontendMode::Partial,
                ast,
            })
        }
    }
}

pub fn load_sources(root: &str) -> Result<Vec<SourceFile>> {
    let root = Path::new(root);
    let mut files = Vec::new();
    collect_sources(root, &mut files)?;
    Ok(files)
}

pub fn resolve_root(path: &str) -> Result<PathBuf> {
    let input = Path::new(path);
    let metadata = fs::metadata(input)?;
    let root = if metadata.is_dir() {
        input
    } else {
        input.parent().unwrap_or(input)
    };

    match root.canonicalize() {
        Ok(value) => Ok(value),
        Err(_) => Ok(root.to_path_buf()),
    }
}

fn collect_sources(path: &Path, out: &mut Vec<SourceFile>) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            collect_sources(&entry.path(), out)?;
        }
        return Ok(());
    }

    if !metadata.is_file() {
        return Ok(());
    }

    if !is_solidity_file(path) {
        return Ok(());
    }

    let source = fs::read_to_string(path)?;
    let id = out.len() as u32;
    out.push(SourceFile {
        id,
        path: path.display().to_string(),
        source,
    });
    Ok(())
}

fn is_solidity_file(path: &Path) -> bool {
    matches!(path.extension().and_then(|ext| ext.to_str()), Some("sol"))
}
