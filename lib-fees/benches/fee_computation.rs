//! Benchmarks for fee computation (FEES-13)
//!
//! Run with: cargo bench --package lib-fees

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use lib_fees::{compute_fee_v2, FeeInput, FeeParams, SigScheme, TxKind};

/// Benchmark compute_fee_v2 with a simple native transfer
fn benchmark_native_transfer(c: &mut Criterion) {
    let params = FeeParams::default();
    let input = FeeInput {
        kind: TxKind::NativeTransfer,
        sig_scheme: SigScheme::Ed25519,
        sig_count: 1,
        envelope_bytes: 200,
        payload_bytes: 32,
        witness_bytes: 64,
        exec_units: 0,
        state_reads: 2,
        state_writes: 2,
        state_write_bytes: 32,
        zk_verify_units: 0,
    };

    let mut group = c.benchmark_group("native_transfer");
    group.throughput(Throughput::Elements(1));
    group.bench_function("ed25519", |b| {
        b.iter(|| compute_fee_v2(black_box(&input), black_box(&params)))
    });
    group.finish();
}

/// Benchmark compute_fee_v2 with a contract call
fn benchmark_contract_call(c: &mut Criterion) {
    let params = FeeParams::default();
    let input = FeeInput {
        kind: TxKind::ContractCall,
        sig_scheme: SigScheme::Dilithium5,
        sig_count: 1,
        envelope_bytes: 500,
        payload_bytes: 256,
        witness_bytes: 4627, // Dilithium5 signature size
        exec_units: 1000,
        state_reads: 10,
        state_writes: 5,
        state_write_bytes: 256,
        zk_verify_units: 0,
    };

    let mut group = c.benchmark_group("contract_call");
    group.throughput(Throughput::Elements(1));
    group.bench_function("dilithium5", |b| {
        b.iter(|| compute_fee_v2(black_box(&input), black_box(&params)))
    });
    group.finish();
}

/// Benchmark compute_fee_v2 with data upload (expensive transaction)
fn benchmark_data_upload(c: &mut Criterion) {
    let params = FeeParams::default();
    let input = FeeInput {
        kind: TxKind::DataUpload,
        sig_scheme: SigScheme::Hybrid,
        sig_count: 1,
        envelope_bytes: 1000,
        payload_bytes: 1024,
        witness_bytes: 4691, // Hybrid signature size
        exec_units: 500,
        state_reads: 5,
        state_writes: 10,
        state_write_bytes: 1024,
        zk_verify_units: 0,
    };

    let mut group = c.benchmark_group("data_upload");
    group.throughput(Throughput::Elements(1));
    group.bench_function("hybrid", |b| {
        b.iter(|| compute_fee_v2(black_box(&input), black_box(&params)))
    });
    group.finish();
}

/// Benchmark compute_fee_v2 across all transaction kinds
fn benchmark_all_tx_kinds(c: &mut Criterion) {
    let params = FeeParams::default();

    let kinds = [
        (TxKind::NativeTransfer, "native_transfer"),
        (TxKind::TokenTransfer, "token_transfer"),
        (TxKind::ContractCall, "contract_call"),
        (TxKind::DataUpload, "data_upload"),
        (TxKind::Governance, "governance"),
        (TxKind::Staking, "staking"),
        (TxKind::Unstaking, "unstaking"),
        (TxKind::ValidatorRegistration, "validator_registration"),
        (TxKind::ValidatorExit, "validator_exit"),
    ];

    let mut group = c.benchmark_group("all_tx_kinds");
    group.throughput(Throughput::Elements(1));

    for (kind, name) in kinds {
        let input = FeeInput {
            kind,
            sig_scheme: SigScheme::Ed25519,
            sig_count: 1,
            envelope_bytes: 200,
            payload_bytes: 64,
            witness_bytes: 64,
            exec_units: 0,
            state_reads: 2,
            state_writes: 2,
            state_write_bytes: 64,
            zk_verify_units: 0,
        };

        group.bench_function(name, |b| {
            b.iter(|| compute_fee_v2(black_box(&input), black_box(&params)))
        });
    }

    group.finish();
}

/// Benchmark compute_fee_v2 across all signature schemes
fn benchmark_all_sig_schemes(c: &mut Criterion) {
    let params = FeeParams::default();

    let schemes = [
        (SigScheme::Ed25519, "ed25519", 64),
        (SigScheme::Dilithium5, "dilithium5", 4627),
        (SigScheme::Hybrid, "hybrid", 4691),
    ];

    let mut group = c.benchmark_group("all_sig_schemes");
    group.throughput(Throughput::Elements(1));

    for (scheme, name, sig_size) in schemes {
        let input = FeeInput {
            kind: TxKind::NativeTransfer,
            sig_scheme: scheme,
            sig_count: 1,
            envelope_bytes: 200,
            payload_bytes: 32,
            witness_bytes: sig_size,
            exec_units: 0,
            state_reads: 2,
            state_writes: 2,
            state_write_bytes: 32,
            zk_verify_units: 0,
        };

        group.bench_function(name, |b| {
            b.iter(|| compute_fee_v2(black_box(&input), black_box(&params)))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_native_transfer,
    benchmark_contract_call,
    benchmark_data_upload,
    benchmark_all_tx_kinds,
    benchmark_all_sig_schemes,
);
criterion_main!(benches);
