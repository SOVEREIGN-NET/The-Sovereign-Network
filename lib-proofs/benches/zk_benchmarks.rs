use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lib_crypto::random::SecureRng;
use lib_proofs::ZkRangeProof;

fn benchmark_range_proof_generation(c: &mut Criterion) {
    let mut rng = SecureRng::new();
    let blinding = rng.generate_key_material();

    c.bench_function("bulletproofs_range_proof_generation", |b| {
        b.iter(|| {
            let proof = ZkRangeProof::generate(42, 18, 150, blinding).unwrap();
            black_box(proof);
        })
    });
}

fn benchmark_range_proof_verification(c: &mut Criterion) {
    let proof = ZkRangeProof::generate_simple(42, 18, 150).unwrap();

    c.bench_function("bulletproofs_range_proof_verification", |b| {
        b.iter(|| {
            let valid = proof.verify().unwrap();
            black_box(valid);
        })
    });
}

fn benchmark_range_proof_serde_roundtrip(c: &mut Criterion) {
    let proof = ZkRangeProof::generate_simple(42, 18, 150).unwrap();

    c.bench_function("bulletproofs_range_proof_serde_roundtrip", |b| {
        b.iter(|| {
            let bytes = serde_json::to_vec(&proof).unwrap();
            let recovered: ZkRangeProof = serde_json::from_slice(&bytes).unwrap();
            black_box(recovered);
        })
    });
}

criterion_group!(
    benches,
    benchmark_range_proof_generation,
    benchmark_range_proof_verification,
    benchmark_range_proof_serde_roundtrip
);
criterion_main!(benches);
