# Arcanum Design Notes

This document explains the *why* behind Arcanum's architectural decisions. Understanding the design intent helps contributors make choices that align with the library's purpose.

---

## Batch-First Architecture

**Decision**: Every algorithm has batch variants, not just single-item APIs.

**Rationale**: Modern workloads rarely process single items. Whether hashing filesystem manifests, verifying network messages, or processing database records, real applications work with *sets* of data. The batch API isn't an afterthought—it's the primary interface.

Consider: When would you ever verify just one hash? Audit logs come in batches. File manifests have thousands of entries. Integrity checking is inherently parallel.

**Implication**: Implementations are optimized for amortized overhead across many items, not minimal latency for a single item. If you need the absolute fastest single-item performance, use the underlying RustCrypto primitives directly.

---

## Large Data Optimization Threshold: 512MB

**Decision**: Parallel implementations activate their full optimization at 512MB.

**Rationale**: Below 512MB, thread coordination overhead exceeds parallel benefits. At 512MB, chunk processing across cores shows measurable wins. This isn't arbitrary—it's the empirical crossover point on modern hardware.

Consider: What data regularly exceeds 512MB? Model artifacts. Database snapshots. Encrypted archives. Container images. These are exactly the workloads where integrity verification matters most and where sequential processing becomes a bottleneck.

**Implication**: For files under 512MB, the `blake3` crate provides excellent single-threaded performance. Arcanum's value appears at scale.

---

## Selective Disclosure via Merkle Trees

**Decision**: Deep integration of Merkle trees into HoloCrypt containers.

**Rationale**: Sometimes you need to prove that *part* of your data is authentic without exposing the rest. A 10GB dataset might have a 4KB region that needs verification. Traditional approaches require hashing the entire dataset.

Consider: Proving that layer 47 of a 70-layer structure is unchanged. Proving that record #5,234 in a ledger is authentic. Proving that your credentials include a specific claim without revealing all claims.

**Implication**: HoloCrypt containers maintain Merkle indices at the cost of additional storage overhead. This is the right tradeoff when random-access verification matters.

---

## Property Proofs: Values Without Revelation

**Decision**: Bulletproofs integration for range proofs without trusted setup.

**Rationale**: Sometimes you need to prove a *property* of a value without revealing the value. "This parameter is within bounds" without saying what the parameter is. "This metric exceeds threshold" without exposing the metric.

Consider: Compliance proofs for private data. Capacity attestations without revealing utilization. Age verification without birthdates. Score thresholds without scores.

**Implication**: Range proof generation takes ~1.6ms—fast enough for real-time attestation but not free. Design accordingly.

---

## GPU Acceleration Path

**Decision**: Optional CUDA backend for batch operations.

**Rationale**: When processing tens of thousands of items, GPU parallelism provides 2-3x throughput improvements. The memory transfer overhead makes this unsuitable for small batches, but at scale, GPU acceleration is transformative.

Consider: Batch integrity verification of thousands of components. Parallel key derivation for large user sets. Mass signature verification in network protocols.

**Implication**: The CUDA path is optional and requires explicit enablement. Don't enable it unless you have thousands of items and an NVIDIA GPU.

---

## Threshold Cryptography: No Single Point of Trust

**Decision**: First-class support for FROST, Shamir, and distributed key generation.

**Rationale**: Some secrets are too important for any single party. Threshold cryptography ensures that `k` of `n` parties must cooperate—no single compromise exposes the secret.

Consider: Multi-party custody of high-value assets. Organizational access to critical infrastructure. Distributed trust for irreversible operations.

**Implication**: Threshold operations have protocol overhead. They're not for protecting ephemeral session keys—they're for protecting assets where compromise is catastrophic.

---

## Proactive Share Refresh

**Decision**: Time-bounded security through share refresh protocols.

**Rationale**: Even threshold systems can be compromised over time. If an attacker slowly accumulates shares across years, they eventually reach threshold. Proactive refresh invalidates old shares, bounding the attack window.

Consider: Long-lived secrets in environments with personnel turnover. Multi-year custody arrangements. Institutional secrets that outlive individual participation.

**Implication**: Refresh protocols require coordination. They're not automatic—they're policies that organizations must implement.

---

## Algorithm Agility and Migration

**Decision**: Self-describing containers with algorithm version tags.

**Rationale**: Cryptographic algorithms have lifecycles. Today's recommended algorithm becomes tomorrow's deprecated choice. Containers must describe themselves so future systems can migrate.

Consider: Data encrypted today may need decryption in 20 years. Post-quantum migration requires knowing what classical algorithms were used. Compliance audits need algorithm inventories.

**Implication**: Every sealed container carries metadata overhead. This is the price of future-proofing.

---

## Post-Quantum Envelope

**Decision**: ML-KEM-768 as the default PQC key encapsulation mechanism.

**Rationale**: Harvest-now-decrypt-later attacks target long-lived secrets. Data encrypted today may be stored by adversaries until quantum computers can break classical key exchange. Hybrid (classical + PQC) provides defense-in-depth.

Consider: Government, financial, and healthcare data with decade-plus sensitivity windows. Infrastructure secrets that would be valuable if exposed even years later. Any data where "eventual compromise" has serious consequences.

**Implication**: PQC operations are faster than expected (~25µs for ML-KEM-768) but ciphertexts are larger. Design for the size increase.

---

## Constant-Time as Default

**Decision**: All cryptographic operations are constant-time by default.

**Rationale**: Timing attacks are real and exploitable. Operations on secret data must not leak information through execution time.

Consider: Key comparison. Point validation. Tag verification. Any operation where different inputs could take different times.

**Implication**: We use the `subtle` crate for comparisons. We use explicit constant-time algorithms even when variable-time would be faster. We test timing variance with dudect methodology.

---

## When Not to Use Arcanum

Arcanum is not the right choice when:

1. **Single-item performance is paramount**: Use RustCrypto directly.
2. **Memory is extremely constrained**: Batch APIs require buffering.
3. **No post-quantum concerns**: The overhead isn't justified.
4. **Audited implementation required**: RustCrypto has formal audits.

Arcanum adds value when:

1. **Processing many items**: Batch optimization shines.
2. **Large data integrity**: 512MB+ parallel hashing.
3. **Selective verification**: Merkle proofs for partial data.
4. **Threshold access**: Distributed trust models.
5. **Future-proofing**: Post-quantum and algorithm agility.

---

## Summary

Arcanum is infrastructure for the *next* generation of cryptographic workloads:
- Batch processing of thousands of items
- Integrity verification of very large artifacts
- Selective disclosure of structured data
- Distributed trust without single points of failure
- Migration paths as algorithms evolve

If your workload involves "lots of X" where X is hashing, verification, or cryptographic operations, Arcanum provides the batch-first, scale-ready primitives.

---

*These decisions were made intentionally. When contributing, ask: does this change serve the batch-first, scale-ready design philosophy?*
