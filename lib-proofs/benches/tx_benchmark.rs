use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(feature = "real-proofs")]
fn benchmark_tx_proof_generation(c: &mut Criterion) {
    use plonky2::field::types::Field;
    use lib_proofs::transaction::circuit::real::{
        build_merkle_tree, prove_transaction,
    };
    use plonky2::hash::hash_types::NUM_HASH_OUT_ELTS;

    let sender_balance = 1000u64;
    let amount = 100u64;
    let fee = 10u64;
    let sender_secret = 12345u64;
    let nullifier_seed = 67890u64;

    // Build a dummy Merkle tree so the benchmark exercises the Merkle constraints.
    let leaf = vec![nullifier_seed, sender_secret, sender_balance];
    let dummy_leaves: Vec<Vec<u64>> = (0..(1 << lib_proofs::transaction::circuit::MERKLE_DEPTH))
        .map(|i| if i == 0 { leaf.clone() } else { vec![0u64] })
        .collect();
    let (merkle_root_u64, siblings_u64) = build_merkle_tree(&dummy_leaves, 0).unwrap();

    type F = plonky2::field::goldilocks_field::GoldilocksField;
    let merkle_root = merkle_root_u64.map(F::from_canonical_u64);
    let mut siblings = [[F::ZERO; NUM_HASH_OUT_ELTS]; lib_proofs::transaction::circuit::MERKLE_DEPTH];
    for (i, s) in siblings_u64.iter().enumerate() {
        siblings[i] = s.map(F::from_canonical_u64);
    }

    // Pre-generate one proof so we can measure pure generation time
    let proof = prove_transaction(
        sender_balance, amount, fee, sender_secret, nullifier_seed,
        merkle_root, 0, &siblings,
    ).unwrap();
    // Verify once to ensure the proof is valid before benchmarking
    lib_proofs::transaction::circuit::real::verify_transaction(&proof).unwrap();

    c.bench_function("tx_proof_generation_with_merkle", |b| {
        b.iter(|| {
            let p = prove_transaction(
                sender_balance, amount, fee, sender_secret, nullifier_seed,
                merkle_root, 0, &siblings,
            ).unwrap();
            black_box(p);
        })
    });
}

#[cfg(feature = "real-proofs")]
fn benchmark_tx_proof_verification(c: &mut Criterion) {
    use plonky2::field::types::Field;
    use lib_proofs::transaction::circuit::real::{
        build_merkle_tree, prove_transaction, verify_transaction,
    };
    use plonky2::hash::hash_types::NUM_HASH_OUT_ELTS;

    let sender_balance = 1000u64;
    let amount = 100u64;
    let fee = 10u64;
    let sender_secret = 12345u64;
    let nullifier_seed = 67890u64;

    let leaf = vec![nullifier_seed, sender_secret, sender_balance];
    let dummy_leaves: Vec<Vec<u64>> = (0..(1 << lib_proofs::transaction::circuit::MERKLE_DEPTH))
        .map(|i| if i == 0 { leaf.clone() } else { vec![0u64] })
        .collect();
    let (merkle_root_u64, siblings_u64) = build_merkle_tree(&dummy_leaves, 0).unwrap();

    type F = plonky2::field::goldilocks_field::GoldilocksField;
    let merkle_root = merkle_root_u64.map(F::from_canonical_u64);
    let mut siblings = [[F::ZERO; NUM_HASH_OUT_ELTS]; lib_proofs::transaction::circuit::MERKLE_DEPTH];
    for (i, s) in siblings_u64.iter().enumerate() {
        siblings[i] = s.map(F::from_canonical_u64);
    }

    let proof = prove_transaction(
        sender_balance, amount, fee, sender_secret, nullifier_seed,
        merkle_root, 0, &siblings,
    ).unwrap();

    c.bench_function("tx_proof_verification_with_merkle", |b| {
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
