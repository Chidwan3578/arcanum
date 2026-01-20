# Optimization Lessons Learned

**Repository:** Arcanum Cryptographic Library
**Last Updated:** 2026-01-20
**Purpose:** Document failed optimization attempts and why they didn't work

This document captures optimization attempts that didn't improve performance, along with analysis of why they failed. Understanding what *doesn't* work is as valuable as knowing what does. These lessons can save future contributors significant time.

---

## Table of Contents

1. [Software Pipelining for Fused AEAD](#1-software-pipelining-for-fused-aead)
2. [Inline Assembly vs Intrinsics](#2-inline-assembly-vs-intrinsics)
3. [Adaptive Prefetch Distance](#3-adaptive-prefetch-distance)
4. [Batch SHA-256 with SSE2 (Horizontal SIMD)](#4-batch-sha-256-with-sse2-horizontal-simd)
5. [Non-Temporal Stores Without Alignment Checks](#5-non-temporal-stores-without-alignment-checks)

---

## 1. Software Pipelining for Fused AEAD

**Date:** 2026-01-20
**Module:** `fused.rs`
**Expected Gain:** 5-15%
**Actual Result:** **43% regression**

### The Idea

Overlap keystream generation with XOR and Poly1305 operations by generating the next keystream block while processing the current one:

```rust
// Generate keystream[i+1] while processing keystream[i]
let mut keystream_a = chacha20_blocks_16x(&key, counter, nonce);
counter += 16;

while offset + 2048 <= len {
    // Generate next keystream (pipelined)
    let keystream_b = chacha20_blocks_16x(&key, counter, nonce);
    counter += 16;

    // Process with keystream_a
    xor_and_poly1305_update(chunk_a, &keystream_a);

    // Generate keystream for next iteration
    keystream_a = chacha20_blocks_16x(&key, counter, nonce);
    counter += 16;

    // Process with keystream_b
    xor_and_poly1305_update(chunk_b, &keystream_b);
}
```

### Why It Failed

1. **CPU already saturated**: Modern out-of-order CPUs already overlap independent operations. The AVX-512 execution units were fully utilized with the simpler loop.

2. **Extra bookkeeping overhead**: Managing two keystream buffers and the pipelining state added register pressure and instruction overhead that exceeded any latency hiding benefit.

3. **No memory latency to hide**: At 1 GiB/s throughput, we're compute-bound on the Poly1305 MAC, not memory-bound. Prefetching was already handling memory latency.

4. **Branch prediction disruption**: The more complex control flow introduced branch mispredictions.

### Benchmark Evidence

```
Before (simple loop):  1.06 GiB/s (1MB buffer)
After (pipelined):     0.61 GiB/s (1MB buffer)
                       ^^^^^^^^^ 43% slower!
```

### Lesson Learned

> **Don't try to outsmart the CPU's out-of-order execution engine.** Modern CPUs are extremely good at finding and exploiting instruction-level parallelism. Manual pipelining only helps when there's a clear bottleneck (memory latency, dependency chains) that the CPU can't resolve on its own.

### When Pipelining WOULD Help

- Memory-bound workloads where prefetching can hide latency
- Long dependency chains that prevent out-of-order execution
- GPUs and other in-order processors

---

## 2. Inline Assembly vs Intrinsics

**Date:** 2025-12-26
**Module:** `blake3_asm.rs`
**Expected Gain:** 5-10% (hand-optimized register allocation)
**Actual Result:** **6% slower**

### The Idea

Hand-written inline assembly should produce optimal code without LLVM's overhead:

```rust
macro_rules! g16_asm {
    ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {
        core::arch::asm!(
            "vpaddd {a}, {a}, {b}",
            "vpaddd {a}, {a}, {mx}",
            "vpxord {d}, {d}, {a}",
            "vpshufb {d}, {d}, {rot16}",
            "vpaddd {c}, {c}, {d}",
            "vpxord {b}, {b}, {c}",
            "vprord {b}, {b}, 12",
            // ...
        );
    }
}
```

### Why It Failed

1. **LLVM generates identical instructions**: The intrinsics compile to the exact same machine code (`vprord`, `vpshufb`, etc.).

2. **Lost cross-function optimization**: LLVM can reorder instructions *across* function boundaries when using intrinsics. Inline assembly blocks this.

3. **Register allocation overhead**: The `asm!` macro forces save/restore of registers at block boundaries, while LLVM can keep values in registers across intrinsic calls.

4. **No cross-boundary instruction reordering**: LLVM treats `asm!` blocks as optimization barriers.

### Benchmark Evidence

```
| Implementation | 16-block compress | Throughput |
|----------------|-------------------|------------|
| Inline ASM     | 301.82 ns         | 3.16 GiB/s |
| Intrinsics     | 284.85 ns         | 3.35 GiB/s |
                   ^^^^^^^^^ 6% faster with intrinsics
```

### Lesson Learned

> **Trust LLVM for SIMD code.** Modern compilers generate excellent SIMD code from intrinsics. Hand-written assembly should only be used when profiling shows LLVM is generating suboptimal code for a specific pattern—not as a default optimization strategy.

### When Assembly WOULD Help

- Specific instruction sequences LLVM doesn't generate (rare)
- Very hot inner loops where every cycle matters AND profiling shows suboptimal codegen
- Platform-specific instructions not exposed as intrinsics

---

## 3. Adaptive Prefetch Distance

**Date:** 2026-01-20
**Module:** `fused.rs`
**Expected Gain:** 2-5%
**Actual Result:** **Negligible or negative**

### The Idea

Use larger prefetch distances for bigger buffers to better hide memory latency:

```rust
// Adaptive prefetch: larger for big buffers
let prefetch_dist = if len > 1024 * 1024 { 4096 } else { 2048 };

while offset + 1024 <= len {
    if offset + prefetch_dist < len {
        prefetch_read(buffer.as_ptr().add(offset + prefetch_dist));
    }
    // ... process chunk
}
```

### Why It Failed

1. **Added branch overhead**: The conditional `if offset + prefetch_dist < len` added a branch to every iteration of the hot loop.

2. **Hardware prefetcher already effective**: Modern CPUs have sophisticated hardware prefetchers that detect sequential access patterns. Manual prefetching adds little value for sequential reads.

3. **Fixed distance works fine**: The original `prefetch_ahead(buffer, offset, 1024)` (which prefetches `offset + 2048`) was already optimal for this workload.

4. **Marginal benefit domain**: We're compute-bound on Poly1305, not memory-bound. Better prefetching doesn't help when the CPU is already saturated.

### Lesson Learned

> **Don't add branches to hot loops for marginal optimizations.** The branch overhead often exceeds any benefit. If the hardware prefetcher handles your access pattern, manual prefetching should be minimal and unconditional.

### When Adaptive Prefetch WOULD Help

- Random access patterns where hardware prefetcher fails
- NUMA systems with different memory latencies
- Truly memory-bound workloads (not our case)

---

## 4. Batch SHA-256 with SSE2 (Horizontal SIMD)

**Date:** 2025-12-24
**Module:** `batch.rs`
**Expected Gain:** 4x throughput (4 parallel hashes)
**Actual Result:** **60% slower than sequential**

### The Idea

Process 4 SHA-256 hashes in parallel using SSE2's 128-bit registers:

```rust
// 4 parallel SHA-256 states in SSE2 lanes
let mut state_a = _mm_set_epi32(h[0], h[0], h[0], h[0]);  // 4x state[0]
let mut state_b = _mm_set_epi32(h[1], h[1], h[1], h[1]);  // 4x state[1]
// ... process 4 messages simultaneously
```

### Why It Failed

1. **Horizontal vs Vertical SIMD**: SHA-256's compression function has *sequential* dependencies within each round. You can't parallelize rounds—you can only parallelize *messages*.

2. **Lane-crossing overhead**: SSE2 horizontal operations (`_mm_hadd_epi32`) are slow. SHA-256's inter-word dependencies require frequent lane-crossing.

3. **SHA-NI is the answer**: Hardware SHA instructions (`_mm_sha256rnds2_epu32`) process the compression function in hardware, which is fundamentally faster than any software SIMD approach.

### Benchmark Evidence

```
| Size   | Batch-4x (SSE2) | Sequential-4x | SHA-NI-4x  |
|--------|-----------------|---------------|------------|
| 4096B  | 29.76 µs        | 13.50 µs      | 13.19 µs   |
           ^^^^^^^^^ 2.2x SLOWER than sequential!
```

### Lesson Learned

> **Understand your algorithm's parallelism structure.** SIMD works best for *data-parallel* operations (same operation on different data). SHA-256's round function has sequential dependencies that don't map well to horizontal SIMD. When hardware instructions exist (SHA-NI), use them.

### When Horizontal Batch SIMD WOULD Help

- Algorithms with independent parallel operations (AES-CTR mode, ChaCha20 blocks)
- Merkle tree levels (hashing independent pairs)
- Multiple truly independent computations

---

## 5. Non-Temporal Stores Without Alignment Checks

**Date:** 2026-01-18
**Module:** `fused.rs`
**Expected Gain:** 10-15% for large buffers
**Actual Result:** **2x slower** (50% regression)

### The Idea

Use non-temporal (streaming) stores for large buffers to avoid cache pollution:

```rust
// Always use NT stores for large messages
fn use_non_temporal(total_size: usize) -> bool {
    total_size > 256 * 1024  // > 256KB
}

// AVX-512 non-temporal store
_mm512_stream_si512(data_ptr, result);
```

### Why It Failed

1. **Alignment requirements**: `_mm512_stream_si512` requires 64-byte aligned addresses. Unaligned NT stores cause severe performance penalties or crashes.

2. **User buffers rarely aligned**: Most heap allocations are only 8 or 16-byte aligned. Assuming 64-byte alignment was incorrect.

3. **Fallback path not triggered**: When alignment check was missing, the slow unaligned path was silently used instead of falling back to regular stores.

### The Fix

Check alignment before using NT stores:

```rust
fn use_non_temporal(buffer: &[u8]) -> bool {
    // Size check: only for large buffers
    if buffer.len() < 256 * 1024 {
        return false;
    }
    // Alignment check: NT stores need aligned memory
    let ptr = buffer.as_ptr() as usize;
    ptr % 64 == 0 || ptr % 32 == 0  // AVX-512 or AVX2 alignment
}
```

### Lesson Learned

> **Always check alignment for SIMD streaming stores.** Non-temporal stores have strict alignment requirements. Verify alignment at runtime before using them, and fall back to regular stores when alignment isn't met.

### Correct Usage Pattern

```rust
if use_nt && (ptr as usize) % 64 == 0 {
    _mm512_stream_si512(ptr, value);  // Aligned NT store
} else {
    _mm512_storeu_si512(ptr, value);  // Unaligned regular store
}
```

---

## General Optimization Principles

These lessons reinforce some general principles:

### 1. Measure First, Optimize Second

Every "optimization" in this document was based on reasonable assumptions that turned out to be wrong. Always benchmark before and after changes.

### 2. Modern CPUs Are Smart

Out-of-order execution, branch prediction, hardware prefetching, and speculative execution handle many optimizations automatically. Don't duplicate what the CPU already does.

### 3. Simplicity Often Wins

Complex optimizations (pipelining, adaptive logic) add overhead. Simple, straight-line code often performs better because it's easier for the CPU to predict and optimize.

### 4. Know Your Bottleneck

- **Compute-bound**: More parallelism won't help if execution units are saturated
- **Memory-bound**: Prefetching and cache optimization help
- **Latency-bound**: Pipelining and parallelism help

### 5. Intrinsics > Assembly

Trust the compiler for SIMD code. Hand-written assembly prevents optimizations across instruction boundaries.

---

## Contributing

When adding new entries to this document:

1. Include the date and affected module
2. Explain the expected vs actual results with benchmarks
3. Analyze *why* the optimization failed
4. State the lesson learned clearly
5. Note when the approach *would* work

Failed optimizations are valuable knowledge. Thank you for documenting them!
