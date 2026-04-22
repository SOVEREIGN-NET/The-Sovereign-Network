from __future__ import annotations

import json
from datetime import datetime, UTC
from pathlib import Path

import msgpack

ROOT = Path(__file__).resolve().parent.parent
TEST_DATA_DIR = ROOT / "test_data"
OUTPUT_DIR = TEST_DATA_DIR / "messagepack"

SOURCE_FILES = {
    "blockchain_transactions.msgpack": "blockchain_transactions.json",
    "network_mesh_messages.msgpack": "network_mesh_messages.json",
    "governance_proposals.msgpack": "governance_proposals.json",
    "witness_metadata.msgpack": "witness_metadata.json",
    "token_economics.msgpack": "token_economics.json",
    "identity_records.msgpack": "identity_records.json",
}


def load_json(relative_name: str):
    with (TEST_DATA_DIR / relative_name).open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def build_mixed_workload() -> dict:
    transactions = load_json("blockchain_transactions.json")
    messages = load_json("network_mesh_messages.json")
    governance = load_json("governance_proposals.json")
    witnesses = load_json("witness_metadata.json")
    token_economics = load_json("token_economics.json")

    return {
        "dataset": "sovereign-mixed-workload",
        "encoding": "messagepack",
        "generated_at": datetime.now(UTC).isoformat(),
        "scenarios": {
            "transaction_slice": transactions["transactions"][:25],
            "message_slice": messages["messages"][:25],
            "proposal_slice": governance["proposals"][:15] if isinstance(governance, dict) and "proposals" in governance else governance[:15],
            "witness_slice": witnesses[:20] if isinstance(witnesses, list) else witnesses,
            "economic_snapshot": token_economics,
        },
        "compression_hints": {
            "repeated_keys": [
                "timestamp",
                "message_type",
                "key_id",
                "proof_system",
                "shard_id",
                "compression_ratio",
            ],
            "expected_strengths": [
                "nested objects",
                "repeated hex strings",
                "time-series style records",
                "mixed numeric and binary-friendly fields",
            ],
        },
    }


def pack_file(output_name: str, payload, source_name: str | None = None) -> dict:
    doc = {
        "dataset": output_name.removesuffix(".msgpack"),
        "encoding": "messagepack",
        "generated_at": datetime.now(UTC).isoformat(),
        "source": source_name,
        "payload": payload,
    }
    packed = msgpack.packb(doc, use_bin_type=True)
    output_path = OUTPUT_DIR / output_name
    output_path.write_bytes(packed)
    return {
        "file": output_name,
        "bytes": len(packed),
        "source": source_name,
    }


def write_readme(entries: list[dict]) -> None:
    lines = [
        "# MessagePack Compression Fixtures",
        "",
        "Generated from existing Sovereign Network test fixtures for compression benchmarking.",
        "",
        "## Files",
        "",
    ]
    for entry in entries:
        source = entry["source"] or "synthetic mixed workload"
        lines.append(f"- {entry['file']} — {entry['bytes']} bytes — source: {source}")
    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- Each `.msgpack` file contains a top-level envelope with `dataset`, `encoding`, `generated_at`, `source`, and `payload`.",
            "- `mixed_workload.msgpack` combines slices of multiple Sovereign datasets to stress nested MessagePack structures.",
        ]
    )
    (OUTPUT_DIR / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    manifest: list[dict] = []
    for output_name, source_name in SOURCE_FILES.items():
        manifest.append(pack_file(output_name, load_json(source_name), source_name))

    manifest.append(pack_file("mixed_workload.msgpack", build_mixed_workload(), None))

    manifest_doc = {
        "generated_at": datetime.now(UTC).isoformat(),
        "output_dir": str(OUTPUT_DIR.relative_to(ROOT)).replace("\\", "/"),
        "file_count": len(manifest),
        "files": manifest,
    }
    (OUTPUT_DIR / "manifest.json").write_text(json.dumps(manifest_doc, indent=2), encoding="utf-8")
    write_readme(manifest)

    total_bytes = sum(entry["bytes"] for entry in manifest)
    print(f"Wrote {len(manifest)} MessagePack fixtures to {OUTPUT_DIR}")
    print(f"Total size: {total_bytes} bytes")


if __name__ == "__main__":
    main()
