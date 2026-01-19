# Arcanum Agent Quickstart Guide

**Purpose:** This document helps AI agents (Claude, etc.) quickly understand how to run benchmarks, find key files, and replicate performance testing for the Arcanum cryptography library.

**Last Updated:** 2025-01-03

---

## TL;DR - Run This

```bash
cd /home/crook/dev2/workspace/nyx/arcanum

# Quick benchmark to verify Arcanum beats blake3 crate
RUSTFLAGS="-C target-cpu=native" cargo run --release \
  -p arcanum-primitives \
  --features 'std,simd,rayon' \
  --example find_the_win
```

Expected output shows:
- **Single message (1GB):** Arcanum ~1.4x faster
- **Batch hashing (8×16MB):** Arcanum ~3x faster

---

## Key Locations

### Crate Path
```
/home/crook/dev2/workspace/nyx/arcanum/crates/arcanum-primitives/
```

### Source Files (BLAKE3 implementations)
```
src/blake3_simd.rs    # Core SIMD, hash_batch_8, hash_large_parallel
src/blake3_ultra.rs   # hash_apex, hash_minimal_alloc, hash_adaptive
src/blake3_turbo.rs   # hash_turbo (AVX2)
src/blake3_hyper.rs   # hash_hyper (AVX-512)
```

### Example Benchmarks
```
examples/find_the_win.rs   # Comprehensive benchmark (includes batch hashing)
examples/huge_bench.rs     # Large single-message benchmarks (1-3 GB)
```

### Criterion Benchmark Results
```
target/criterion/BLAKE3-Apex_Comparison/
target/criterion/BLAKE3-Ultra_Comparison/
target/criterion/ChaCha20-Poly1305-LargeScale/
```

### Documentation
```
docs/blake3-optimization-report.md   # Technical deep-dive
docs/AGENT_QUICKSTART.md             # This file
BENCHMARK_REPORT.md                   # Summary for humans
```

---

## Required Flags

### RUSTFLAGS (Critical!)
```bash
RUSTFLAGS="-C target-cpu=native"
```
Without this, SIMD codegen is suboptimal and you won't see the performance wins.

### Cargo Features
```bash
--features 'std,simd,rayon'
```

**DO NOT USE:**
```bash
--all-features  # Causes crate conflicts with bench-comparison feature
```

---

## Running Benchmarks

### Quick Examples (Recommended)

```bash
cd /home/crook/dev2/workspace/nyx/arcanum

# The comprehensive benchmark
RUSTFLAGS="-C target-cpu=native" cargo run --release \
  -p arcanum-primitives \
  --features 'std,simd,rayon' \
  --example find_the_win

# Large single-message benchmark (1-3 GB)
RUSTFLAGS="-C target-cpu=native" cargo run --release \
  -p arcanum-primitives \
  --features 'std,simd,rayon' \
  --example huge_bench
```

### Criterion Benchmarks (More Rigorous)

```bash
cd /home/crook/dev2/workspace/nyx/arcanum

RUSTFLAGS="-C target-cpu=native" cargo bench \
  -p arcanum-primitives \
  --features 'std,simd,rayon' \
  -- "BLAKE3-Apex"
```

Results appear in `target/criterion/*/report/index.html`.

---

## Key Functions and When to Use Them

| Function | Location | Use Case | Expected Speedup |
|----------|----------|----------|------------------|
| `hash_batch_8` | blake3_simd.rs | 8 independent messages | **3x** |
| `hash_apex` | blake3_ultra.rs | Single message ≥64MB | **1.9x** |
| `hash_minimal_alloc` | blake3_ultra.rs | Single message 256KB-64MB | **1.2-1.4x** |
| `hash_adaptive` | blake3_ultra.rs | Auto-selects based on size | Varies |
| `hash_large_parallel` | blake3_simd.rs | Single message <256KB | Use reference |

---

## Performance Results Summary

### Batch Hashing (THE BIG WIN)
```
Arcanum hash_batch_8:     7.17ms  (17.43 GiB/s)
blake3 crate (seq x8):   21.89ms  (5.71 GiB/s)
blake3 crate (par x8):   21.63ms  (5.78 GiB/s)
                         ^^^^^^^^
                         3.05x FASTER
```

### Large Single Messages
```
Size    | Arcanum Apex | blake3 crate | Speedup
--------|--------------|--------------|--------
64MB    | 11.14 GiB/s  | 5.81 GiB/s   | 1.92x
1GB     | 8.12 GiB/s   | 5.86 GiB/s   | 1.39x
3GB     | 11.14 GiB/s  | 5.81 GiB/s   | 1.92x
```

### Crossover Point
- Below 64MB: Reference blake3 crate wins
- At 64MB: Arcanum starts winning (~1.17x)
- At 256MB+: Arcanum dominates (~1.5-2x)

---

## Hardware Detection

Check if AVX-512 is available:
```rust
use arcanum_primitives::blake3_simd::has_avx512f;
println!("AVX-512: {}", has_avx512f());
```

Or from bash:
```bash
cat /proc/cpuinfo | grep avx512
```

AVX-512 is required for maximum performance.

---

## Common Pitfalls

### 1. Forgetting RUSTFLAGS
```bash
# WRONG - will show blake3 crate winning
cargo run --release --example find_the_win

# CORRECT
RUSTFLAGS="-C target-cpu=native" cargo run --release --example find_the_win
```

### 2. Using --all-features
```bash
# WRONG - causes blake3 crate conflict
cargo build --all-features

# CORRECT
cargo build --features 'std,simd,rayon'
```

### 3. Testing on Small Data Only
```bash
# Small data: blake3 crate wins
# Large data: Arcanum wins
# Make sure to test 64MB+ for single messages, or use batch hashing
```

### 4. Not Running in Release Mode
```bash
# WRONG
cargo run --example find_the_win

# CORRECT
cargo run --release --example find_the_win
```

---

## Creating New Benchmarks

When writing benchmark examples, use this pattern:

```rust
use arcanum_primitives::blake3_simd::{has_avx512f, hash_batch_8};
use arcanum_primitives::blake3_ultra::{hash_apex, hash_minimal_alloc};
use std::time::Instant;

fn main() {
    println!("AVX-512 detected: {}", has_avx512f());

    let data: Vec<u8> = (0..SIZE).map(|i| (i % 256) as u8).collect();

    let start = Instant::now();
    let hash = hash_apex(&data);
    let elapsed = start.elapsed();

    let throughput = SIZE as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0 / 1024.0;
    println!("Throughput: {:.2} GiB/s", throughput);
}
```

**Important:** When using heredocs in bash to create files, escape `!` characters or use sed to fix them afterward:
```bash
sed -i 's/\\!/!/g' examples/my_bench.rs
```

---

## Session Files (For Agent Recovery)

Claude Code session data lives at:
```
~/.claude/projects/--wsl--Ubuntu-home-crook-dev2-workspace/
```

The Arcanum benchmark sessions are typically in:
```
~/.claude/projects/--wsl--Ubuntu-home-crook-dev2-workspace/*.jsonl
```

---

## Quick Validation Commands

```bash
# Verify compilation
RUSTFLAGS="-C target-cpu=native" cargo check \
  -p arcanum-primitives \
  --features 'std,simd,rayon'

# Run tests
RUSTFLAGS="-C target-cpu=native" cargo test \
  -p arcanum-primitives \
  --features 'std,simd,rayon' \
  -- blake3

# Quick benchmark
RUSTFLAGS="-C target-cpu=native" cargo run --release \
  -p arcanum-primitives \
  --features 'std,simd,rayon' \
  --example find_the_win
```

---

## Summary

1. **Always use** `RUSTFLAGS="-C target-cpu=native"`
2. **Always use** `--features 'std,simd,rayon'` (not --all-features)
3. **Batch hashing** (`hash_batch_8`) = 3x speedup
4. **Large messages** (≥64MB with `hash_apex`) = 1.5-2x speedup
5. Examples are in `crates/arcanum-primitives/examples/`
6. Criterion results are in `target/criterion/`

---

*Document maintained for AI agent quality-of-life. Last verified: 2025-01-03*
