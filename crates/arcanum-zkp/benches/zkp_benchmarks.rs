//! Benchmarks for zero-knowledge proof operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

use arcanum_zkp::commitment::{PedersenCommitment, PedersenOpening};
use arcanum_zkp::curve::Scalar;

fn bench_pedersen_commitment(c: &mut Criterion) {
    use rand_core::OsRng;

    let mut group = c.benchmark_group("PedersenCommitment");

    let value = Scalar::from(42u64);
    let blinding = Scalar::random(&mut OsRng);

    group.bench_function("commit", |b| {
        b.iter(|| PedersenCommitment::commit(black_box(&value), black_box(&blinding)))
    });

    let commitment = PedersenCommitment::commit(&value, &blinding);
    let opening = PedersenOpening::new(value, blinding);

    group.bench_function("verify", |b| {
        b.iter(|| black_box(&commitment).verify(black_box(&opening)))
    });

    group.finish();
}

#[cfg(feature = "bulletproofs")]
fn bench_range_proofs(c: &mut Criterion) {
    use arcanum_zkp::range_proof::RangeProof;

    let mut group = c.benchmark_group("RangeProof");

    // Range proofs are expensive, use smaller sample size
    group.sample_size(20);

    // Benchmark different bit sizes
    for n_bits in [8, 16, 32, 64] {
        let value = 42u64;

        group.bench_with_input(
            BenchmarkId::new("prove", n_bits),
            &n_bits,
            |b, &n_bits| {
                b.iter(|| RangeProof::prove(black_box(value), black_box(n_bits)))
            },
        );

        let proof = RangeProof::prove(value, n_bits).unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify", n_bits),
            &n_bits,
            |b, &n_bits| {
                b.iter(|| black_box(&proof).verify(black_box(n_bits)))
            },
        );
    }

    group.finish();
}

#[cfg(feature = "schnorr-proofs")]
fn bench_schnorr_proofs(c: &mut Criterion) {
    use arcanum_zkp::schnorr_proof::{DiscreteLogProof, SchnorrProofBuilder};
    use arcanum_zkp::curve::{RISTRETTO_BASEPOINT_POINT, Scalar};
    use rand_core::OsRng;

    let mut group = c.benchmark_group("SchnorrProof");

    // Discrete log proof
    let secret = Scalar::random(&mut OsRng);
    let public = secret * RISTRETTO_BASEPOINT_POINT;

    group.bench_function("dlog_prove", |b| {
        b.iter(|| DiscreteLogProof::prove(black_box(&secret), black_box(&public)))
    });

    let proof = DiscreteLogProof::prove(&secret, &public).unwrap();

    group.bench_function("dlog_verify", |b| {
        b.iter(|| black_box(&proof).verify(black_box(&public)))
    });

    group.finish();
}

#[cfg(feature = "bulletproofs")]
fn bench_batch_range_proofs(c: &mut Criterion) {
    use arcanum_zkp::range_proof::RangeProofBatch;

    let mut group = c.benchmark_group("RangeProofBatch");
    group.sample_size(10);

    // Benchmark batched verification
    for batch_size in [2, 4, 8] {
        let values: Vec<u64> = (0..batch_size).map(|i| i as u64 * 100 + 42).collect();
        let n_bits = 32;

        group.bench_with_input(
            BenchmarkId::new("prove_batch", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| RangeProofBatch::prove(black_box(&values), black_box(n_bits)))
            },
        );

        let batch_proof = RangeProofBatch::prove(&values, n_bits).unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify_batch", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| black_box(&batch_proof).verify(black_box(n_bits)))
            },
        );
    }

    group.finish();
}

// Build criterion groups based on available features
#[cfg(all(feature = "bulletproofs", feature = "schnorr-proofs"))]
criterion_group!(
    benches,
    bench_pedersen_commitment,
    bench_range_proofs,
    bench_schnorr_proofs,
    bench_batch_range_proofs,
);

#[cfg(all(feature = "bulletproofs", not(feature = "schnorr-proofs")))]
criterion_group!(
    benches,
    bench_pedersen_commitment,
    bench_range_proofs,
    bench_batch_range_proofs,
);

#[cfg(all(not(feature = "bulletproofs"), feature = "schnorr-proofs"))]
criterion_group!(
    benches,
    bench_pedersen_commitment,
    bench_schnorr_proofs,
);

#[cfg(not(any(feature = "bulletproofs", feature = "schnorr-proofs")))]
criterion_group!(benches, bench_pedersen_commitment);

criterion_main!(benches);
