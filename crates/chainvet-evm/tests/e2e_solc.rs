//! End-to-end validation of the whole chain on a *real* compiled contract:
//! solc (via the frontend's SolcManager) → creation bytecode → revm deploy →
//! replay → coverage inspector. Unlike the unit tests, which deploy hand-rolled
//! runtime blobs, this exercises genuine solc output.
//!
//! `#[ignore]`d because it invokes solc, which SolcManager downloads on first
//! use (needs network + a writable cache). Run explicitly with:
//!   cargo test -p chainvet-evm --test e2e_solc -- --ignored --nocapture

use chainvet_core::norm::SourceFile;
use chainvet_evm::{compile, encode_call, AbiType, EvmHarness};

const VAULT: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    uint256 public total;
    mapping(address => uint256) public bal;

    function deposit(uint256 amount) external {
        require(amount > 0, "zero");   // shallow revert on amount == 0
        bal[msg.sender] += amount;     // deep path writes two storage slots
        total += amount;
    }
}
"#;

fn source() -> Vec<SourceFile> {
    vec![SourceFile {
        id: 0,
        path: "Vault.sol".to_string(),
        source: VAULT.to_string(),
    }]
}

#[test]
#[ignore = "invokes solc (network download on first run)"]
fn compiles_deploys_and_coverage_tracks_depth() {
    let contracts = compile(&source()).expect("solc compile");
    let vault = contracts
        .iter()
        .find(|c| c.name == "Vault")
        .expect("Vault contract present with bytecode");
    assert!(
        vault.functions.iter().any(|f| f.name == "deposit"),
        "deposit is in the ABI"
    );

    // A reverting deposit(0) reaches strictly fewer PCs than a succeeding
    // deposit(5): the coverage inspector sees the extra storage-writing path.
    let types = [AbiType::Uint(256)];

    let mut shallow = EvmHarness::deploy(vault.creation_bytecode.clone()).expect("deploy");
    let zero = encode_call("deposit", &types, &[chainvet_fuzzing::fuzzing::types::FuzzValue::Uint(0)])
        .expect("encode");
    let out0 = shallow.call(1, 0, zero).expect("call");
    assert!(out0.reverted, "deposit(0) reverts on the require");
    let shallow_pcs = shallow.covered_pc_count();

    let mut deep = EvmHarness::deploy(vault.creation_bytecode.clone()).expect("deploy");
    let five = encode_call("deposit", &types, &[chainvet_fuzzing::fuzzing::types::FuzzValue::Uint(5)])
        .expect("encode");
    let out5 = deep.call(1, 0, five).expect("call");
    assert!(out5.success, "deposit(5) succeeds");
    let deep_pcs = deep.covered_pc_count();

    eprintln!("shallow PCs = {shallow_pcs}, deep PCs = {deep_pcs}");
    assert!(
        deep_pcs > shallow_pcs,
        "the succeeding storage-writing path ({deep_pcs}) reaches more real-EVM PCs \
         than the early require revert ({shallow_pcs})"
    );
}
