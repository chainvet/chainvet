//! Compiled-artifact acquisition: run solc to obtain **deployable bytecode** and
//! the **typed ABI** for each contract. This is where the "no parameter types in
//! the pipeline" gap is closed — solc's ABI JSON carries the declared types the
//! selector and calldata encoding require, alongside the bytecode revm deploys.
//!
//! Reuses the frontend's [`SolcManager`] to locate/download a compatible solc,
//! then runs its own standard-json compile requesting `abi` + bytecode.

use std::io::Write;
use std::process::{Command, Stdio};

use chainvet_core::norm::SourceFile;
use chainvet_core::util::error::{Error, Result};
use chainvet_frontend::frontend::solc_manager::SolcManager;
use serde_json::{json, Value};

use crate::abi::AbiType;

/// One callable function with its declared parameter types.
#[derive(Debug, Clone)]
pub struct AbiFn {
    pub name: String,
    pub inputs: Vec<AbiType>,
}

/// A compiled contract ready to deploy and replay against.
#[derive(Debug, Clone)]
pub struct CompiledContract {
    pub name: String,
    pub creation_bytecode: Vec<u8>,
    /// Functions the encoder can handle (unsupported-type functions are dropped
    /// here and reported as skipped at replay time).
    pub functions: Vec<AbiFn>,
}

/// Compile `sources` and return every contract with non-empty bytecode
/// (interfaces/abstract contracts, which have none, are skipped).
pub fn compile(sources: &[SourceFile]) -> Result<Vec<CompiledContract>> {
    let manager = SolcManager::new()?;
    let solc_path = manager.prepare(sources)?;
    manager.check_solc(&solc_path)?;

    let mut source_map = serde_json::Map::new();
    for src in sources {
        source_map.insert(src.path.clone(), json!({ "content": src.source }));
    }
    let input = json!({
        "language": "Solidity",
        "sources": source_map,
        "settings": {
            "outputSelection": { "*": { "*": ["abi", "evm.bytecode.object"] } }
        }
    });
    let input_str =
        serde_json::to_string(&input).map_err(|e| Error::msg(format!("solc input: {e}")))?;

    let mut child = Command::new(&solc_path)
        .arg("--standard-json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::msg(format!("spawn solc: {e}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| Error::msg("solc stdin unavailable"))?
        .write_all(input_str.as_bytes())
        .map_err(|e| Error::msg(format!("write solc input: {e}")))?;
    let output = child
        .wait_with_output()
        .map_err(|e| Error::msg(format!("run solc: {e}")))?;

    let parsed: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| Error::msg(format!("parse solc output: {e}")))?;

    if let Some(errors) = parsed.get("errors").and_then(Value::as_array) {
        let fatal: Vec<String> = errors
            .iter()
            .filter(|e| e.get("severity").and_then(Value::as_str) == Some("error"))
            .filter_map(|e| e.get("formattedMessage").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        if !fatal.is_empty() {
            return Err(Error::msg(format!("solc errors:\n{}", fatal.join("\n"))));
        }
    }

    let mut contracts = Vec::new();
    let Some(files) = parsed.get("contracts").and_then(Value::as_object) else {
        return Ok(contracts);
    };
    for contract_map in files.values() {
        let Some(contract_map) = contract_map.as_object() else {
            continue;
        };
        for (name, value) in contract_map {
            let object = value
                .pointer("/evm/bytecode/object")
                .and_then(Value::as_str)
                .unwrap_or("");
            if object.is_empty() {
                continue; // interface / abstract — nothing to deploy
            }
            let Some(creation_bytecode) = decode_hex(object) else {
                continue;
            };
            let functions = value
                .get("abi")
                .and_then(Value::as_array)
                .map(|abi| parse_functions(abi))
                .unwrap_or_default();
            contracts.push(CompiledContract {
                name: name.clone(),
                creation_bytecode,
                functions,
            });
        }
    }
    Ok(contracts)
}

/// Extract encodable `function` entries from an ABI array. Functions with any
/// unsupported parameter type (array/tuple/fixed-bytes) are dropped.
fn parse_functions(abi: &[Value]) -> Vec<AbiFn> {
    let mut functions = Vec::new();
    for entry in abi {
        if entry.get("type").and_then(Value::as_str) != Some("function") {
            continue;
        }
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let mut inputs = Vec::new();
        let mut encodable = true;
        if let Some(params) = entry.get("inputs").and_then(Value::as_array) {
            for param in params {
                let ty = param.get("type").and_then(Value::as_str).unwrap_or_default();
                match AbiType::parse(ty) {
                    Some(t) => inputs.push(t),
                    None => {
                        encodable = false;
                        break;
                    }
                }
            }
        }
        if encodable {
            functions.push(AbiFn { name, inputs });
        }
    }
    functions
}

/// Decode a hex string (optional `0x` prefix) into bytes; `None` on bad input.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_handles_prefix_and_rejects_odd() {
        assert_eq!(decode_hex("0x60806040"), Some(vec![0x60, 0x80, 0x60, 0x40]));
        assert_eq!(decode_hex("deadBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
    }

    #[test]
    fn parse_functions_keeps_encodable_drops_unsupported() {
        let abi = json!([
            { "type": "function", "name": "ok", "inputs": [
                { "name": "a", "type": "uint256" }, { "name": "b", "type": "address" } ] },
            { "type": "function", "name": "arr", "inputs": [
                { "name": "xs", "type": "uint256[]" } ] },
            { "type": "constructor", "inputs": [] },
        ]);
        let fns = parse_functions(abi.as_array().unwrap());
        assert_eq!(fns.len(), 1, "array param fn dropped, constructor ignored");
        assert_eq!(fns[0].name, "ok");
        assert_eq!(fns[0].inputs, vec![AbiType::Uint(256), AbiType::Address]);
    }
}
