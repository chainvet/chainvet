//! ABI encoding: turn a fuzzer transaction (function name + `FuzzValue` args)
//! into EVM calldata. The 4-byte selector is `keccak256(canonical_signature)`,
//! which requires the *declared* Solidity parameter types (`uint256` vs `uint8`
//! select differently), so an [`AbiType`] list must accompany the values.

use chainvet_fuzzing::fuzzing::types::FuzzValue;
use revm::primitives::keccak256;

/// The subset of Solidity ABI types the fuzzer can produce values for. Enough to
/// encode the corpus; extended as needed. Each maps to a canonical type string
/// used for both the selector and the value encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiType {
    Uint(u16),   // uintN, N a multiple of 8 (1..=256)
    Int(u16),    // intN
    Bool,        // bool
    Address,     // address
    Bytes,       // dynamic bytes
    StringTy,    // string
}

impl AbiType {
    /// Canonical type name as it appears in a function signature.
    pub fn canonical(&self) -> String {
        match self {
            AbiType::Uint(n) => format!("uint{n}"),
            AbiType::Int(n) => format!("int{n}"),
            AbiType::Bool => "bool".to_string(),
            AbiType::Address => "address".to_string(),
            AbiType::Bytes => "bytes".to_string(),
            AbiType::StringTy => "string".to_string(),
        }
    }

    /// True for ABI dynamic types (head is an offset, tail holds the data).
    fn is_dynamic(&self) -> bool {
        matches!(self, AbiType::Bytes | AbiType::StringTy)
    }

    /// Parse a Solidity ABI type string (as it appears in solc's ABI JSON).
    /// Returns `None` for types the encoder does not yet support (arrays,
    /// tuples, fixed bytesN) — the caller then skips that function.
    pub fn parse(ty: &str) -> Option<AbiType> {
        match ty {
            "bool" => Some(AbiType::Bool),
            "address" => Some(AbiType::Address),
            "bytes" => Some(AbiType::Bytes),
            "string" => Some(AbiType::StringTy),
            "uint" => Some(AbiType::Uint(256)),
            "int" => Some(AbiType::Int(256)),
            _ => {
                // uintN / intN with an explicit width (a multiple of 8, 8..=256).
                if let Some(n) = ty.strip_prefix("uint") {
                    let bits = n.parse::<u16>().ok()?;
                    (bits % 8 == 0 && (8..=256).contains(&bits)).then_some(AbiType::Uint(bits))
                } else if let Some(n) = ty.strip_prefix("int") {
                    let bits = n.parse::<u16>().ok()?;
                    (bits % 8 == 0 && (8..=256).contains(&bits)).then_some(AbiType::Int(bits))
                } else {
                    None
                }
            }
        }
    }
}

/// The 4-byte function selector for a canonical signature like
/// `"transfer(address,uint256)"`.
pub fn selector_from_signature(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// The 4-byte selector for `name` with parameter `types`.
pub fn selector(name: &str, types: &[AbiType]) -> [u8; 4] {
    let params = types
        .iter()
        .map(AbiType::canonical)
        .collect::<Vec<_>>()
        .join(",");
    selector_from_signature(&format!("{name}({params})"))
}

/// Encode a call: `selector ++ ABI(args)`. Returns `None` if an argument does
/// not match its declared type (arity or kind mismatch) — the caller then skips
/// this transaction rather than sending malformed calldata.
pub fn encode_call(name: &str, types: &[AbiType], args: &[FuzzValue]) -> Option<Vec<u8>> {
    if types.len() != args.len() {
        return None;
    }
    let mut out = selector(name, types).to_vec();

    // Two-part ABI encoding: fixed-size head (32 bytes per arg; for dynamic
    // types an offset), followed by the tail holding dynamic data.
    let head_len = 32 * types.len();
    let mut head: Vec<u8> = Vec::with_capacity(head_len);
    let mut tail: Vec<u8> = Vec::new();

    for (ty, arg) in types.iter().zip(args) {
        if ty.is_dynamic() {
            let offset = head_len + tail.len();
            head.extend_from_slice(&word_from_u128(offset as u128));
            let bytes = dynamic_bytes(ty, arg)?;
            tail.extend_from_slice(&encode_dynamic(&bytes));
        } else {
            head.extend_from_slice(&encode_static(ty, arg)?);
        }
    }
    out.extend_from_slice(&head);
    out.extend_from_slice(&tail);
    Some(out)
}

/// Encode a static (32-byte) argument.
fn encode_static(ty: &AbiType, arg: &FuzzValue) -> Option<[u8; 32]> {
    match (ty, arg) {
        (AbiType::Uint(_), FuzzValue::Uint(v)) => Some(word_from_u128(*v)),
        // Int values fit in i128; sign-extend to a full 32-byte word.
        (AbiType::Int(_), FuzzValue::Int(v)) => Some(word_from_i128(*v)),
        (AbiType::Bool, FuzzValue::Bool(b)) => Some(word_from_u128(*b as u128)),
        // The fuzzer models an address as an index into its address pool; map it
        // to a deterministic 20-byte address (index in the low byte).
        (AbiType::Address, FuzzValue::Address(i)) => Some(word_from_address_index(*i)),
        // Tolerate a uint value supplied for an address slot (common in seeds).
        (AbiType::Address, FuzzValue::Uint(v)) => Some(word_from_address_index(*v as usize)),
        _ => None,
    }
}

fn dynamic_bytes(ty: &AbiType, arg: &FuzzValue) -> Option<Vec<u8>> {
    match (ty, arg) {
        (AbiType::Bytes, FuzzValue::Bytes(b)) => Some(b.clone()),
        (AbiType::StringTy, FuzzValue::StringVal(s)) => Some(s.clone().into_bytes()),
        _ => None,
    }
}

/// ABI-encode a dynamic byte string: 32-byte length, then data padded to 32.
fn encode_dynamic(bytes: &[u8]) -> Vec<u8> {
    let mut out = word_from_u128(bytes.len() as u128).to_vec();
    out.extend_from_slice(bytes);
    let rem = bytes.len() % 32;
    if rem != 0 {
        out.extend(std::iter::repeat_n(0u8, 32 - rem));
    }
    out
}

/// A `u128` as a big-endian, left-zero-padded 32-byte word.
fn word_from_u128(v: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&v.to_be_bytes());
    word
}

/// An `i128` as a sign-extended big-endian 32-byte word (two's complement).
fn word_from_i128(v: i128) -> [u8; 32] {
    let fill = if v < 0 { 0xffu8 } else { 0x00u8 };
    let mut word = [fill; 32];
    word[16..].copy_from_slice(&v.to_be_bytes());
    word
}

/// Map an address-pool index to a 20-byte address, right-aligned in a word.
fn word_from_address_index(index: usize) -> [u8; 32] {
    let mut word = [0u8; 32];
    // Address occupies the low 20 bytes; put the index in the last 8.
    word[24..].copy_from_slice(&(index as u64).to_be_bytes());
    word
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_matches_known_erc20_transfer() {
        // The canonical ERC-20 transfer selector is 0xa9059cbb.
        assert_eq!(
            selector_from_signature("transfer(address,uint256)"),
            [0xa9, 0x05, 0x9c, 0xbb]
        );
        assert_eq!(
            selector("transfer", &[AbiType::Address, AbiType::Uint(256)]),
            [0xa9, 0x05, 0x9c, 0xbb]
        );
    }

    #[test]
    fn uint_width_changes_selector() {
        // f(uint8) and f(uint256) must differ — why raw FuzzValue kind is not
        // enough and the declared type is required.
        assert_ne!(
            selector("f", &[AbiType::Uint(8)]),
            selector("f", &[AbiType::Uint(256)])
        );
    }

    #[test]
    fn encode_static_uint_places_value_in_last_bytes() {
        let data = encode_call("f", &[AbiType::Uint(256)], &[FuzzValue::Uint(42)]).unwrap();
        assert_eq!(data.len(), 4 + 32);
        assert_eq!(data[4 + 31], 42, "uint value in the last byte of the word");
        assert!(data[4..4 + 31].iter().all(|&b| b == 0), "left zero-padded");
    }

    #[test]
    fn arity_mismatch_is_rejected() {
        assert!(encode_call("f", &[AbiType::Uint(256)], &[]).is_none());
        assert!(encode_call("f", &[], &[FuzzValue::Uint(1)]).is_none());
    }

    #[test]
    fn parse_maps_solc_types_and_rejects_unsupported() {
        assert_eq!(AbiType::parse("uint256"), Some(AbiType::Uint(256)));
        assert_eq!(AbiType::parse("uint8"), Some(AbiType::Uint(8)));
        assert_eq!(AbiType::parse("uint"), Some(AbiType::Uint(256)));
        assert_eq!(AbiType::parse("int128"), Some(AbiType::Int(128)));
        assert_eq!(AbiType::parse("address"), Some(AbiType::Address));
        assert_eq!(AbiType::parse("bool"), Some(AbiType::Bool));
        assert_eq!(AbiType::parse("string"), Some(AbiType::StringTy));
        // Unsupported (arrays, tuples, fixed bytes, bad widths) → None.
        assert_eq!(AbiType::parse("uint256[]"), None);
        assert_eq!(AbiType::parse("bytes32"), None);
        assert_eq!(AbiType::parse("uint7"), None);
        assert_eq!(AbiType::parse("tuple"), None);
    }

    #[test]
    fn dynamic_string_encodes_offset_length_and_data() {
        let data = encode_call(
            "f",
            &[AbiType::StringTy],
            &[FuzzValue::StringVal("hi".to_string())],
        )
        .unwrap();
        // selector + head(offset=32) + len(2) + data("hi" padded to 32)
        assert_eq!(data.len(), 4 + 32 + 32 + 32);
        assert_eq!(data[4 + 31], 32, "head is the offset to the tail");
        assert_eq!(data[4 + 32 + 31], 2, "length word = 2");
        assert_eq!(&data[4 + 64..4 + 66], b"hi");
    }
}
