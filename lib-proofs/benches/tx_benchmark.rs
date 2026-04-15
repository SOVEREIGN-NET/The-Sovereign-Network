use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(feature = "real-proofs")]
fn benchmark_tx_proof_generation(c: &mut Criterion) {
    use lib_proofs::transaction::circuit::real::prove_transaction;

    // Pre-generate one proof so we can measure pure generation time
    let proof = prove_transaction(1000, 100, 10, 12345, 67890).unwrap();
    // Verify once to ensure the proof is valid before benchmarking
    lib_proofs::transaction::circuit::real::verify_transaction(&proof).unwrap();

    c.bench_function("tx_proof_generation", |b| {
        b.iter(|| {
            let p = prove_transaction(1000, 100, 10, 12345, 67890).unwrap();
            black_box(p);
        })
    });
}

#[cfg(feature = "real-proofs")]
fn benchmark_tx_proof_verification(c: &mut Criterion) {
    use lib_proofs::transaction::circuit::real::{prove_transaction, verify_transaction};

    let proof = prove_transaction(1000, 100, 10, 12345, 67890).unwrap();

    c.bench_function("tx_proof_verification", |b| {
        b.iter(|| {
            verify_transaction(&proof).unwrap();
            black_box(&proof);
        })
    });
}

#[cfg(not(feature = "real-proofs"))]
fn benchmark_tx_proof_generation(c: &mut Criterion) {
    c.bench_function("tx_proof_generation (stub)", |b| {
        b.iter(|| black_box(42))
    });
}

#[cfg(not(feature = "real-proofs"))]
fn benchmark_tx_proof_verification(c: &mut Criterion) {
    c.bench_function("tx_proof_verification (stub)", |b| {
        b.iter(|| black_box(42))
    });
}

criterion_group!(
    benches,
    benchmark_tx_proof_generation,
    benchmark_tx_proof_verification
);
criterion_main!(benches);
