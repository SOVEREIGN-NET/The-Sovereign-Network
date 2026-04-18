#!/usr/bin/env pwsh
# Sovereign Network Beta Test Dataset Generator
# Creates realistic network/DHT/blockchain data for compression testing

param(
    [string]$OutputDir = "test_data",
    [switch]$Verbose
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Sovereign Network Test Dataset Generator" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
    Write-Host "Created directory: $OutputDir" -ForegroundColor Green
}

# 1. DHT PACKET DATA
Write-Host "[1/10] Generating DHT packet data..." -ForegroundColor Yellow
$dhtPackets = @()
for ($i = 0; $i -lt 1000; $i++) {
    $packet = @{
        type = "DHT_STORE"
        timestamp = (Get-Date).AddSeconds(-$i).ToString("o")
        node_id = "node_" + ($i % 50).ToString().PadLeft(3, '0')
        shard_id = "shard_" + [guid]::NewGuid().ToString()
        data_hash = "blake3_" + [guid]::NewGuid().ToString("N").Substring(0, 16)
        size = Get-Random -Minimum 1024 -Maximum 65536
        ttl = 3600
        hop_count = Get-Random -Minimum 1 -Maximum 10
        route = @("relay_01", "relay_15", "relay_29")
    }
    $dhtPackets += $packet
}
$dhtJson = $dhtPackets | ConvertTo-Json -Depth 5
$dhtJson | Out-File -FilePath "$OutputDir/dht_packets.json" -Encoding UTF8
Write-Host "  Created: dht_packets.json ($($dhtJson.Length) bytes)" -ForegroundColor Green

# 2. BLOCKCHAIN TRANSACTION LOG
Write-Host "[2/10] Generating blockchain transaction log..." -ForegroundColor Yellow
$txLog = ""
for ($i = 0; $i -lt 500; $i++) {
    $from = "0x" + [guid]::NewGuid().ToString("N").Substring(0, 40)
    $to = "0x" + [guid]::NewGuid().ToString("N").Substring(0, 40)
    $amount = (Get-Random -Minimum 1 -Maximum 1000) / 100
    $fee = (Get-Random -Minimum 1 -Maximum 100) / 10000
    $timestamp = (Get-Date).AddMinutes(-$i).ToString("yyyy-MM-dd HH:mm:ss")
    
    $txLog += "[$timestamp] TX from=$from to=$to amount=$amount fee=$fee status=confirmed`n"
}
$txLog | Out-File -FilePath "$OutputDir/blockchain_transactions.log" -Encoding UTF8
Write-Host "  Created: blockchain_transactions.log ($($txLog.Length) bytes)" -ForegroundColor Green

# 3. WITNESS METADATA (JSON array)
Write-Host "[3/10] Generating witness metadata..." -ForegroundColor Yellow
$witnesses = @()
for ($i = 0; $i -lt 200; $i++) {
    $witness = @{
        witness_id = "zkw_" + [guid]::NewGuid().ToString()
        original_file = "file_$i.dat"
        original_size = Get-Random -Minimum 10240 -Maximum 1048576
        shard_count = Get-Random -Minimum 2 -Maximum 20
        merkle_root = "0x" + [guid]::NewGuid().ToString("N")
        created_at = (Get-Date).AddDays(-($i % 30)).ToString("o")
        compression_ratio = [math]::Round((Get-Random -Minimum 200 -Maximum 800) / 100, 2)
        shards = @()
    }
    
    for ($s = 0; $s -lt $witness.shard_count; $s++) {
        $witness.shards += @{
            shard_id = "shard_" + [guid]::NewGuid().ToString()
            offset = $s * 32768
            size = 32768
            hash = "blake3_" + [guid]::NewGuid().ToString("N").Substring(0, 16)
        }
    }
    
    $witnesses += $witness
}
$witnessJson = $witnesses | ConvertTo-Json -Depth 10
$witnessJson | Out-File -FilePath "$OutputDir/witness_metadata.json" -Encoding UTF8
Write-Host "  Created: witness_metadata.json ($($witnessJson.Length) bytes)" -ForegroundColor Green

# 4. NETWORK ROUTING TABLE
Write-Host "[4/10] Generating network routing table..." -ForegroundColor Yellow
$routingTable = "# Sovereign Network Routing Table`n"
$routingTable += "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
$routingTable += "# Format: NodeID | IP:Port | Latency(ms) | Bandwidth(Mbps) | Reputation | Uptime%`n`n"

for ($i = 0; $i -lt 100; $i++) {
    $nodeId = "node_$($i.ToString().PadLeft(3, '0'))"
    $ip = "10.$((Get-Random -Minimum 0 -Maximum 255)).$((Get-Random -Minimum 0 -Maximum 255)).$((Get-Random -Minimum 1 -Maximum 254))"
    $port = Get-Random -Minimum 3000 -Maximum 9000
    $latency = Get-Random -Minimum 5 -Maximum 500
    $bandwidth = Get-Random -Minimum 10 -Maximum 1000
    $reputation = [math]::Round((Get-Random -Minimum 70 -Maximum 100) / 100, 2)
    $uptime = [math]::Round((Get-Random -Minimum 85 -Maximum 100), 1)
    
    $routingTable += "$nodeId | $ip`:$port | $latency | $bandwidth | $reputation | $uptime`n"
}
$routingTable | Out-File -FilePath "$OutputDir/routing_table.txt" -Encoding UTF8
Write-Host "  Created: routing_table.txt ($($routingTable.Length) bytes)" -ForegroundColor Green

# 5. SHARD MANIFEST (repeated patterns)
Write-Host "[5/10] Generating shard manifest with duplicates..." -ForegroundColor Yellow
$shardManifest = @()
$commonShards = @()

# Create 20 common shards that will be heavily duplicated
for ($i = 0; $i -lt 20; $i++) {
    $commonShards += @{
        shard_id = "common_shard_$($i.ToString().PadLeft(2, '0'))"
        hash = "blake3_common_" + [guid]::NewGuid().ToString("N").Substring(0, 16)
        size = 65536
    }
}

# Create manifest entries with lots of duplicates
for ($i = 0; $i -lt 500; $i++) {
    # 70% chance of using a common shard (creates deduplication opportunities)
    if ((Get-Random -Minimum 1 -Maximum 100) -le 70) {
        $idx = Get-Random -Minimum 0 -Maximum ($commonShards.Count - 1)
        $shard = $commonShards[$idx]
    } else {
        $shard = @{
            shard_id = "unique_shard_$i"
            hash = "blake3_" + [guid]::NewGuid().ToString("N").Substring(0, 16)
            size = Get-Random -Minimum 16384 -Maximum 65536
        }
    }
    
    $entry = @{
        manifest_entry = $i
        file_id = "file_" + ($i % 100)
        shard = $shard
        stored_nodes = @("node_" + (Get-Random -Minimum 1 -Maximum 50).ToString().PadLeft(3, '0'))
        replication_factor = 3
        last_verified = (Get-Date).AddHours(-(Get-Random -Minimum 1 -Maximum 48)).ToString("o")
    }
    
    $shardManifest += $entry
}
$manifestJson = $shardManifest | ConvertTo-Json -Depth 5
$manifestJson | Out-File -FilePath "$OutputDir/shard_manifest.json" -Encoding UTF8
Write-Host "  Created: shard_manifest.json ($($manifestJson.Length) bytes)" -ForegroundColor Green

# 6. GOVERNANCE PROPOSALS
Write-Host "[6/10] Generating governance proposals..." -ForegroundColor Yellow
$proposals = @()
$proposalTypes = @("ParameterChange", "NetworkUpgrade", "FeeAdjustment", "NodeRemoval", "TreasuryAllocation")

for ($i = 0; $i -lt 50; $i++) {
    $typeIdx = Get-Random -Minimum 0 -Maximum ($proposalTypes.Count - 1)
    $descCount = Get-Random -Minimum 1 -Maximum 5
    $proposal = @{
        proposal_id = "prop_$($i.ToString().PadLeft(4, '0'))"
        type = $proposalTypes[$typeIdx]
        title = "Proposal $i - Network Improvement"
        description = "This proposal aims to improve the Sovereign Network by adjusting network parameters and optimizing performance. " * $descCount
        proposer = "0x" + [guid]::NewGuid().ToString("N").Substring(0, 40)
        created_at = (Get-Date).AddDays(-($i % 30)).ToString("o")
        voting_ends = (Get-Date).AddDays((Get-Random -Minimum 1 -Maximum 14)).ToString("o")
        votes_for = Get-Random -Minimum 0 -Maximum 10000
        votes_against = Get-Random -Minimum 0 -Maximum 5000
        status = @("Pending", "Active", "Passed", "Rejected")[(Get-Random -Minimum 0 -Maximum 3)]
    }
    $proposals += $proposal
}
$proposalsJson = $proposals | ConvertTo-Json -Depth 5
$proposalsJson | Out-File -FilePath "$OutputDir/governance_proposals.json" -Encoding UTF8
Write-Host "  Created: governance_proposals.json ($($proposalsJson.Length) bytes)" -ForegroundColor Green

# 7. NEURAL MESH TRAINING DATA
Write-Host "[7/10] Generating neural mesh training data..." -ForegroundColor Yellow
$trainingData = "# Neural Mesh Training Log`n"
$trainingData += "# Compression Pattern Learning`n`n"

for ($i = 0; $i -lt 1000; $i++) {
    $epoch = $i
    $loss = [math]::Round(1.0 / ($i + 1) + (Get-Random) * 0.1, 4)
    $accuracy = [math]::Round(($i / 1000.0) * 0.9 + 0.1, 4)
    $patterns_learned = Get-Random -Minimum 100 -Maximum 500
    
    $trainingData += "EPOCH $epoch | loss=$loss accuracy=$accuracy patterns=$patterns_learned semantic_hits=$((Get-Random -Minimum 50 -Maximum 200)) dedup_rate=$([math]::Round((Get-Random) * 0.5, 3))`n"
}
$trainingData | Out-File -FilePath "$OutputDir/neural_training.log" -Encoding UTF8
Write-Host "  Created: neural_training.log ($($trainingData.Length) bytes)" -ForegroundColor Green

# 8. SMART CONTRACT STATE
Write-Host "[8/10] Generating smart contract state data..." -ForegroundColor Yellow
$contractState = @{
    contract_address = "0x" + [guid]::NewGuid().ToString("N").Substring(0, 40)
    contract_name = "SovereignNetworkCore"
    version = "1.0.0"
    total_supply = 1000000000
    circulating_supply = 750000000
    holders = @()
    storage_slots = @{}
}

for ($i = 0; $i -lt 100; $i++) {
    $contractState.holders += @{
        address = "0x" + [guid]::NewGuid().ToString("N").Substring(0, 40)
        balance = Get-Random -Minimum 1000 -Maximum 1000000
        last_tx = (Get-Date).AddDays(-(Get-Random -Minimum 1 -Maximum 365)).ToString("o")
    }
}

for ($i = 0; $i -lt 50; $i++) {
    $key = "storage_$($i.ToString().PadLeft(3, '0'))"
    $contractState.storage_slots[$key] = "0x" + [guid]::NewGuid().ToString("N")
}

$contractJson = $contractState | ConvertTo-Json -Depth 10
$contractJson | Out-File -FilePath "$OutputDir/contract_state.json" -Encoding UTF8
Write-Host "  Created: contract_state.json ($($contractJson.Length) bytes)" -ForegroundColor Green

# 9. NETWORK METRICS (CSV)
Write-Host "[9/10] Generating network metrics CSV..." -ForegroundColor Yellow
$metricsCSV = "timestamp,node_id,cpu_usage,memory_mb,disk_io_mbps,network_in_mbps,network_out_mbps,active_connections,shards_stored,weismann_score`n"

for ($i = 0; $i -lt 1000; $i++) {
    $timestamp = (Get-Date).AddMinutes(-$i).ToString("yyyy-MM-dd HH:mm:ss")
    $nodeId = "node_" + (Get-Random -Minimum 1 -Maximum 50).ToString().PadLeft(3, '0')
    $cpu = [math]::Round((Get-Random) * 100, 1)
    $memory = Get-Random -Minimum 512 -Maximum 8192
    $diskIO = [math]::Round((Get-Random) * 500, 2)
    $netIn = [math]::Round((Get-Random) * 1000, 2)
    $netOut = [math]::Round((Get-Random) * 800, 2)
    $connections = Get-Random -Minimum 5 -Maximum 100
    $shards = Get-Random -Minimum 10 -Maximum 5000
    $weismann = [math]::Round((Get-Random) * 10, 2)
    
    $metricsCSV += "$timestamp,$nodeId,$cpu,$memory,$diskIO,$netIn,$netOut,$connections,$shards,$weismann`n"
}
$metricsCSV | Out-File -FilePath "$OutputDir/network_metrics.csv" -Encoding UTF8
Write-Host "  Created: network_metrics.csv ($($metricsCSV.Length) bytes)" -ForegroundColor Green

# 10. COMPRESSION PATTERNS (highly structured, repetitive)
Write-Host "[10/10] Generating compression pattern dataset..." -ForegroundColor Yellow
$patterns = "# ZKC Compression Patterns Database`n"
$patterns += "# Generated from network-wide deduplication analysis`n`n"

$commonPatterns = @(
    "BEGIN_SHARD_HEADER",
    "END_SHARD_HEADER",
    "WITNESS_PROOF:",
    "MERKLE_ROOT:",
    "BLAKE3_HASH:",
    "TIMESTAMP:",
    "NODE_SIGNATURE:",
    "COMPRESSION_RATIO:",
    "INTEGRITY_CHECK:",
    "REPLICATION_NODES:"
)

for ($i = 0; $i -lt 500; $i++) {
    $patternId = "pattern_$($i.ToString().PadLeft(4, '0'))"
    $patternIdx = Get-Random -Minimum 0 -Maximum ($commonPatterns.Count - 1)
    $pattern = $commonPatterns[$patternIdx]
    $frequency = Get-Random -Minimum 1 -Maximum 10000
    $savings = [math]::Round((Get-Random) * 1024 * 1024, 0)
    
    $patterns += "PATTERN_ID: $patternId | BYTES: $pattern | FREQUENCY: $frequency | SAVINGS: $savings bytes`n"
}
$patterns | Out-File -FilePath "$OutputDir/compression_patterns.txt" -Encoding UTF8
Write-Host "  Created: compression_patterns.txt ($($patterns.Length) bytes)" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Dataset Generation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Generated Files:" -ForegroundColor Cyan
$files = Get-ChildItem -Path $OutputDir -File | Sort-Object Length -Descending
$totalSize = 0
foreach ($file in $files) {
    $sizeKB = [math]::Round($file.Length / 1024, 2)
    $totalSize += $file.Length
    Write-Host "  $($file.Name.PadRight(35)) $sizeKB KB" -ForegroundColor White
}
Write-Host ""
Write-Host "Total Dataset Size: $([math]::Round($totalSize / 1024, 2)) KB" -ForegroundColor Yellow
Write-Host ""
Write-Host "Test these files with:" -ForegroundColor Cyan
Write-Host "  1. Single file: Open http://localhost:3000 and upload any file" -ForegroundColor White
Write-Host "  2. Batch test: Get-ChildItem $OutputDir | ForEach-Object { upload via API }" -ForegroundColor White
Write-Host "  3. Network potential: .\test_network_potential.ps1 (uses test_data files)" -ForegroundColor White
Write-Host ""
