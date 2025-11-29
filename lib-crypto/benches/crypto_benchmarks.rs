//! Benchmark suite for ZHTP crypto operations
//! Performance testing for post-quantum cryptographic primitives

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lib_crypto::{KeyPair, hash_blake3, generate_nonce};
use anyhow::Result;

fn benchmark_keypair_generation(c: &mut Criterion) {
    c.bench_function("keypair_generation", |b| {
        b.iter(|| {
            let _keypair = KeyPair::generate().unwrap();
        })
    });
}

fn benchmark_signing(c: &mut Criterion) {
    let keypair = KeyPair::generate().unwrap();
    let message = b"ZHTP benchmark message for performance testing";

    c.bench_function("signing", |b| {
        b.iter(|| {
            let _signature = keypair.sign(black_box(message)).unwrap();
        })
    });
}

fn benchmark_verification(c: &mut Criterion) {
    let keypair = KeyPair::generate().unwrap();
    let message = b"ZHTP benchmark message for performance testing";
    let signature = keypair.sign(message).unwrap();

    c.bench_function("verification", |b| {
        b.iter(|| {
            let _result = keypair.verify(black_box(&signature), black_box(message)).unwrap();
        })
    });
}

fn benchmark_encryption(c: &mut Criterion) {
    let keypair = KeyPair::generate().unwrap();
    let plaintext = b"ZHTP encryption benchmark data for performance testing";
    let associated_data = b"ZHTP-v1.0";

    c.bench_function("encryption", |b| {
        b.iter(|| {
            let _ciphertext = keypair.encrypt(black_box(plaintext), black_box(associated_data)).unwrap();
        })
    });
}

fn benchmark_decryption(c: &mut Criterion) {
    let keypair = KeyPair::generate().unwrap();
    let plaintext = b"ZHTP encryption benchmark data for performance testing";
    let associated_data = b"ZHTP-v1.0";
    let ciphertext = keypair.encrypt(plaintext, associated_data).unwrap();

    c.bench_function("decryption", |b| {
        b.iter(|| {
            let _plaintext = keypair.decrypt(black_box(&ciphertext), black_box(associated_data)).unwrap();
        })
    });
}

fn benchmark_hashing(c: &mut Criterion) {
    let data = b"ZHTP hashing benchmark data for performance testing with various data sizes";

    c.bench_function("blake3_hashing", |b| {
        b.iter(|| {
            let _hash = hash_blake3(black_box(data));
        })
    });
}

fn benchmark_nonce_generation(c: &mut Criterion) {
    c.bench_function("nonce_generation", |b| {
        b.iter(|| {
            let _nonce = generate_nonce();
        })
    });
}

criterion_group!(
    benches,
    benchmark_keypair_generation,
    benchmark_signing,
    benchmark_verification,
    benchmark_encryption,
    benchmark_decryption,
    benchmark_hashing,
    benchmark_nonce_generation
);

criterion_main!(benches);
