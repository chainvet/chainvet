#!/usr/bin/env bash
set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 1
fi
if ! command -v rg >/dev/null 2>&1; then
  echo "error: rg (ripgrep) is required" >&2
  exit 1
fi

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <contract.sol> <ground_truth.json>" >&2
  echo "example: $0 fixtures/chatgpttestcases.sol fixtures/ground_truth/chatgpttestcases.json" >&2
  exit 1
fi

CONTRACT_PATH="$1"
GROUND_TRUTH_JSON="$2"

if [[ ! -f "$CONTRACT_PATH" ]]; then
  echo "error: contract not found: $CONTRACT_PATH" >&2
  exit 1
fi
if [[ ! -f "$GROUND_TRUTH_JSON" ]]; then
  echo "error: ground truth not found: $GROUND_TRUTH_JSON" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d /tmp/hybrid-score.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

TRUTH_FILE="$TMP_DIR/truth.txt"

jq -r '.truth[]' "$GROUND_TRUTH_JSON" | sort -u > "$TRUTH_FILE"

if [[ ! -s "$TRUTH_FILE" ]]; then
  echo "error: no truth labels in $GROUND_TRUTH_JSON" >&2
  exit 1
fi

map_kind() {
  local kind="$1"
  case "$kind" in
    tx-origin|tx-origin-auth)
      echo "tx-origin"
      ;;
    unsafe-delegatecall)
      echo "delegatecall"
      ;;
    unchecked-call|unused-return-value)
      echo "unchecked-call"
      ;;
    unprotected-selfdestruct)
      echo "selfdestruct"
      ;;
    dangerous-block-timestamp|timestamp-dependency)
      echo "timestamp"
      ;;
    shadowing)
      echo "shadowing"
      ;;
    reentrancy|reentrancy-*)
      echo "reentrancy"
      ;;
    dos-with-failed-call)
      echo "dos-with-failed-call"
      ;;
    transaction-order-dependency)
      echo "transaction-order-dependency"
      ;;
    signature-malleability)
      echo "signature-malleability"
      ;;
    unsafe-send-in-require)
      echo "unsafe-send-in-require"
      ;;
    unprotected-ether-withdrawal)
      echo "unprotected-ether-withdrawal"
      ;;
    public-mint-burn)
      echo "public-mint-burn"
      ;;
    *)
      echo "other:$kind"
      ;;
  esac
}

extract_static_kinds() {
  local out_file="$1"
  RUSTFLAGS="${RUSTFLAGS:--A dead_code -A unused}" cargo run -- --static "$CONTRACT_PATH" --json > "$TMP_DIR/static.json"
  jq -r '.findings[].kind' "$TMP_DIR/static.json" | sort -u > "$out_file"
}

extract_symbolic_kinds() {
  local out_file="$1"
  RUSTFLAGS="${RUSTFLAGS:--A dead_code -A unused}" cargo run -- --symbolic "$CONTRACT_PATH" --json > "$TMP_DIR/symbolic.json"
  jq -r '(.vulnerabilities[]?.kind)' "$TMP_DIR/symbolic.json" \
    | sort -u > "$out_file"
}

extract_fuzzing_kinds() {
  local out_file="$1"
  RUSTFLAGS="${RUSTFLAGS:--A dead_code -A unused}" cargo run -- --fuzzing "$CONTRACT_PATH" > "$TMP_DIR/fuzzing.txt"
  {
    rg -o "\[[a-z0-9-]+\] \[[a-z]+\]" "$TMP_DIR/fuzzing.txt" \
      | sed -E 's/^\[([^]]+)\].*/\1/' || true
  } | sort -u > "$out_file"
}

extract_hybrid_kinds() {
  local out_file="$1"
  RUSTFLAGS="${RUSTFLAGS:--A dead_code -A unused}" cargo run -- --hybrid "$CONTRACT_PATH" > "$TMP_DIR/hybrid.txt"

  local run_dir
  run_dir="$(sed -n 's/.*run_dir=\([^,]*\).*/\1/p' "$TMP_DIR/hybrid.txt" | tail -n1)"
  if [[ -z "$run_dir" ]]; then
    echo "error: failed to parse hybrid run_dir" >&2
    exit 1
  fi
  if [[ ! -f "$run_dir/findings.json" ]]; then
    echo "error: hybrid findings not found at $run_dir/findings.json" >&2
    exit 1
  fi

  jq -r '.[] | select((.analysis_layer // "runtime") == "runtime") | .finding_type' "$run_dir/findings.json" | sort -u > "$out_file"
}

map_kinds_file() {
  local src="$1"
  local dst="$2"
  : > "$dst"
  while IFS= read -r kind; do
    [[ -z "$kind" ]] && continue
    map_kind "$kind" >> "$dst"
  done < "$src"
  sort -u "$dst" -o "$dst"
}

score_mode() {
  local mode="$1"
  local raw_file="$2"
  local mapped_file="$TMP_DIR/${mode}.mapped.txt"
  local tp_file="$TMP_DIR/${mode}.tp.txt"
  local fp_file="$TMP_DIR/${mode}.fp.txt"
  local fn_file="$TMP_DIR/${mode}.fn.txt"

  map_kinds_file "$raw_file" "$mapped_file"

  comm -12 "$mapped_file" "$TRUTH_FILE" > "$tp_file"
  comm -23 "$mapped_file" "$TRUTH_FILE" > "$fp_file"
  comm -13 "$mapped_file" "$TRUTH_FILE" > "$fn_file"

  local pred_count truth_count tp_count fp_count fn_count
  pred_count="$(wc -l < "$mapped_file" | tr -d ' ')"
  truth_count="$(wc -l < "$TRUTH_FILE" | tr -d ' ')"
  tp_count="$(wc -l < "$tp_file" | tr -d ' ')"
  fp_count="$(wc -l < "$fp_file" | tr -d ' ')"
  fn_count="$(wc -l < "$fn_file" | tr -d ' ')"

  local precision recall f1
  precision="$(awk -v tp="$tp_count" -v pred="$pred_count" 'BEGIN{if(pred==0){printf "0.000"}else{printf "%.3f", tp/pred}}')"
  recall="$(awk -v tp="$tp_count" -v truth="$truth_count" 'BEGIN{if(truth==0){printf "0.000"}else{printf "%.3f", tp/truth}}')"
  f1="$(awk -v p="$precision" -v r="$recall" 'BEGIN{if((p+r)==0){printf "0.000"}else{printf "%.3f", (2*p*r)/(p+r)}}')"

  echo "mode=$mode"
  echo "  predicted_labels=$pred_count"
  echo "  truth_labels=$truth_count"
  echo "  tp=$tp_count fp=$fp_count fn=$fn_count"
  echo "  precision=$precision recall=$recall f1=$f1"
  echo "  tp_labels=$(paste -sd, "$tp_file" 2>/dev/null || true)"
  echo "  fp_labels=$(paste -sd, "$fp_file" 2>/dev/null || true)"
  echo "  fn_labels=$(paste -sd, "$fn_file" 2>/dev/null || true)"
}

STATIC_RAW="$TMP_DIR/static.raw.txt"
SYMBOLIC_RAW="$TMP_DIR/symbolic.raw.txt"
FUZZING_RAW="$TMP_DIR/fuzzing.raw.txt"
HYBRID_RAW="$TMP_DIR/hybrid.raw.txt"

echo "[1/4] running static..."
extract_static_kinds "$STATIC_RAW"
echo "[2/4] running symbolic..."
extract_symbolic_kinds "$SYMBOLIC_RAW"
echo "[3/4] running fuzzing..."
extract_fuzzing_kinds "$FUZZING_RAW"
echo "[4/4] running hybrid..."
extract_hybrid_kinds "$HYBRID_RAW"

echo
echo "ground_truth: $GROUND_TRUTH_JSON"
echo "contract: $CONTRACT_PATH"
echo

score_mode "static" "$STATIC_RAW"
echo
score_mode "symbolic" "$SYMBOLIC_RAW"
echo
score_mode "fuzzing" "$FUZZING_RAW"
echo
score_mode "hybrid" "$HYBRID_RAW"
