//! Benchmarks for zero-knowledge proof operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use arcanum_zkp::commitment::{PedersenCommitment, PedersenOpening};

fn bench_pedersen_commit(c: &mut Criterion) {
    c.bench_function("pedersen_commit", |b| {
        b.iter(|| {
            black_box(PedersenCommitment::commit(42u64))
        })
    });
}

fn bench_pedersen_verify(c: &mut Criterion) {
    let (commitment, opening) = PedersenCommitment::commit(42u64).unwrap();

    c.bench_function("pedersen_verify", |b| {
        b.iter(|| {
            black_box(commitment.verify(&opening))
        })
    });
}

#[cfg(feature = "bulletproofs")]
fn bench_range_proof(c: &mut Criterion) {
    use arcanum_zkp::range_proof::RangeProof;

    let mut group = c.benchmark_group("range_proof");
    group.sample_size(10); // Range proofs are slow

    group.bench_function("prove_32bit", |b| {
        b.iter(|| {
            black_box(RangeProof::prove(42u64, 32))
        })
    });

    let proof = RangeProof::prove(42u64, 32).unwrap();

    group.bench_function("verify_32bit", |b| {
        b.iter(|| {
            black_box(proof.verify(32))
        })
    });

    group.finish();
}

#[cfg(feature = "bulletproofs")]
criterion_group!(
    benches,
    bench_pedersen_commit,
    bench_pedersen_verify,
    bench_range_proof,
);

#[cfg(not(feature = "bulletproofs"))]
criterion_group!(
    benches,
    bench_pedersen_commit,
    bench_pedersen_verify,
);

criterion_main!(benches);
