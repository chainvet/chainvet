//! A minimal in-process EVM harness over revm: deploy a contract once, then
//! replay calls against it with persistent state (so multi-transaction fuzzer
//! sequences behave as they would on-chain). Reports per-call success/revert,
//! the signal used to confirm or refute IR-interpreter findings.

use std::collections::HashMap;

use revm::context::TxEnv;
use revm::context::result::{ExecutionResult, Output};
use revm::database::{CacheDB, EmptyDB};
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, InspectCommitEvm, MainBuilder, MainContext};

use crate::coverage::CoverageInspector;

/// Number of pool addresses funded as potential senders. Mirrors the fuzzer's
/// small address pool so a `FuzzValue::Address(i)` maps to a real funded sender.
const ADDRESS_POOL: usize = 8;

/// Per-transaction gas ceiling for replayed calls. Kept below the EIP-7825
/// per-transaction gas cap (2^24 = 16,777,216) enforced by recent hardforks.
const GAS_LIMIT: u64 = 16_000_000;

/// Outcome of replaying a single transaction on the real EVM.
#[derive(Debug, Clone)]
pub struct CallOutcome {
    /// The transaction executed to completion without reverting.
    pub success: bool,
    /// The transaction reverted (REVERT opcode or a halt).
    pub reverted: bool,
    /// Gas consumed.
    pub gas_used: u64,
    /// Return data (call output), empty on revert-with-no-reason.
    pub output: Vec<u8>,
}

/// Map an address-pool index to a deterministic 20-byte address.
pub fn pool_address(index: usize) -> Address {
    let mut bytes = [0u8; 20];
    bytes[12..].copy_from_slice(&(index as u64).to_be_bytes());
    Address::from(bytes)
}

/// Errors that abort harness construction (a call that reverts is *not* an
/// error — it is a normal, reportable outcome).
#[derive(Debug)]
pub enum HarnessError {
    /// The creation transaction reverted or halted — the contract never deployed.
    DeploymentFailed,
    /// The EVM returned an internal error (not a revert).
    EvmError(String),
}

pub struct EvmHarness {
    evm: HarnessEvm,
    contract: Address,
    /// Next nonce to use per sender address.
    nonces: HashMap<Address, u64>,
}

impl EvmHarness {
    /// Deploy `creation_bytecode` (constructor + runtime) and return a harness
    /// positioned to call the deployed contract.
    pub fn deploy(creation_bytecode: Vec<u8>) -> Result<Self, HarnessError> {
        let mut db = CacheDB::new(EmptyDB::default());
        let big_balance = U256::from(1u128 << 100);
        for i in 0..ADDRESS_POOL {
            db.insert_account_info(
                pool_address(i),
                AccountInfo {
                    balance: big_balance,
                    ..Default::default()
                },
            );
        }

        let mut evm = Context::mainnet()
            .with_db(db)
            .build_mainnet_with_inspector(CoverageInspector::new());
        let deployer = pool_address(0);

        let create_tx = TxEnv {
            caller: deployer,
            kind: TxKind::Create,
            data: Bytes::from(creation_bytecode),
            value: U256::ZERO,
            gas_limit: GAS_LIMIT,
            gas_price: 0,
            nonce: 0,
            ..Default::default()
        };

        let result = evm
            .inspect_tx_commit(create_tx)
            .map_err(|e| HarnessError::EvmError(format!("{e:?}")))?;

        let contract = match result {
            ExecutionResult::Success {
                output: Output::Create(_, Some(addr)),
                ..
            } => addr,
            _ => return Err(HarnessError::DeploymentFailed),
        };

        // Discard constructor-time PCs so reported coverage is call-only.
        evm.inspector.clear();

        let mut nonces = HashMap::new();
        nonces.insert(deployer, 1);

        Ok(Self {
            evm,
            contract,
            nonces,
        })
    }

    /// The deployed contract's address.
    pub fn contract_address(&self) -> Address {
        self.contract
    }

    /// Number of distinct EVM program counters executed since deployment
    /// (constructor PCs excluded) — the cumulative EVM-coverage measure across
    /// every call replayed so far.
    pub fn covered_pc_count(&self) -> usize {
        self.evm.inspector.unique_pc_count()
    }

    /// The set of distinct PCs executed since deployment.
    pub fn covered_pcs(&self) -> &std::collections::HashSet<usize> {
        self.evm.inspector.covered_pcs()
    }

    /// Replay one call against the deployed contract with persistent state.
    /// `sender_index` selects a funded pool address; `value` is wei sent.
    pub fn call(
        &mut self,
        sender_index: usize,
        value: u128,
        calldata: Vec<u8>,
    ) -> Result<CallOutcome, HarnessError> {
        let sender = pool_address(sender_index % ADDRESS_POOL);
        let nonce = *self.nonces.get(&sender).unwrap_or(&0);

        let tx = TxEnv {
            caller: sender,
            kind: TxKind::Call(self.contract),
            data: Bytes::from(calldata),
            value: U256::from(value),
            gas_limit: GAS_LIMIT,
            gas_price: 0,
            nonce,
            ..Default::default()
        };

        let result = self
            .evm
            .inspect_tx_commit(tx)
            .map_err(|e| HarnessError::EvmError(format!("{e:?}")))?;
        self.nonces.insert(sender, nonce + 1);

        Ok(match result {
            ExecutionResult::Success { gas, output, .. } => CallOutcome {
                success: true,
                reverted: false,
                gas_used: gas.tx_gas_used(),
                output: match output {
                    Output::Call(b) => b.to_vec(),
                    Output::Create(b, _) => b.to_vec(),
                },
            },
            ExecutionResult::Revert { gas, output, .. } => CallOutcome {
                success: false,
                reverted: true,
                gas_used: gas.tx_gas_used(),
                output: output.to_vec(),
            },
            ExecutionResult::Halt { gas, .. } => CallOutcome {
                success: false,
                reverted: true,
                gas_used: gas.tx_gas_used(),
                output: Vec::new(),
            },
        })
    }
}

// The concrete revm evm type is verbose; this alias localizes it via revm's
// own `MainnetEvm<CTX>` alias. If a revm upgrade changes the shape, only this
// line needs updating.
type Db = CacheDB<EmptyDB>;
type HarnessEvm = revm::MainnetEvm<
    revm::Context<revm::context::BlockEnv, TxEnv, revm::context::CfgEnv, Db, revm::Journal<Db>>,
    CoverageInspector,
>;
