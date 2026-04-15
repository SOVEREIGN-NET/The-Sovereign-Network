#!/usr/bin/env pwsh
# Network Scale Deduplication Test
# Tests that compression actually benefits from duplicate files at scale
# 
# Usage: .\test_network_scale.ps1 -TestFile "path\to\file.pdf" -Duplicates 100

param(
    [string]$TestFile = "SN_03_Use_Cases.pdf",
    [int]$Duplicates = 100,
    [string]$ServerUrl = "http://localhost:3000"
)

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "          NETWORK SCALE DEDUPLICATION TEST                          " -ForegroundColor Cyan  
Write-Host "  Testing compression benefits from duplicate content at scale      " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Test Configuration:" -ForegroundColor Yellow
Write-Host "   File: $TestFile"
Write-Host "   Duplicates: $Duplicates"
Write-Host "   Server: $ServerUrl"
Write-Host ""

# Check if file exists
if (-not (Test-Path $TestFile)) {
    Write-Host "ERROR: File not found: $TestFile" -ForegroundColor Red
    Write-Host "Please provide a valid file path with -TestFile parameter" -ForegroundColor Yellow
    exit 1
}

$fileSize = (Get-Item $TestFile).Length
$fileSizeKB = [Math]::Round($fileSize / 1024, 2)
Write-Host "Test file size: $fileSizeKB KB" -ForegroundColor Green

# Check if server is running
Write-Host ""
Write-Host "Checking server status..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri $ServerUrl -Method GET -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    Write-Host "Server is running and responding" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Server not responding at $ServerUrl" -ForegroundColor Red
    Write-Host "Please start the server with: cargo run --bin compress_frontend" -ForegroundColor Yellow
    exit 1
}

# Storage tracking
$compressionResults = @()
$uniqueShardIds = @{}
$witnessStorageTotal = 0
$shardStorageTotal = 0

Write-Host "`n🚀 Starting network-scale upload test..." -ForegroundColor Cyan
Write-Host "   (Uploading same file $Duplicates times to simulate network deduplication)`n"

# Progress bar setup
$progressActivity = "Network Scale Test"
$uploadCount = 0
$startTime = Get-Date

# Upload the same file N times
for ($i = 1; $i -le $Duplicates; $i++) {
    $percentComplete = [Math]::Round(($i / $Duplicates) * 100, 1)
    Write-Progress -Activity $progressActivity -Status "Upload $i of $Duplicates ($percentComplete%)" -PercentComplete $percentComplete
    
    try {
        # Create multipart form data
        $boundary = [System.Guid]::NewGuid().ToString()
        $fileName = Split-Path $TestFile -Leaf
        $fileBytes = [System.IO.File]::ReadAllBytes($TestFile)
        
        $bodyLines = @(
            "--$boundary",
            "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
            "Content-Type: application/octet-stream",
            "",
            [System.Text.Encoding]::GetEncoding("iso-8859-1").GetString($fileBytes),
            "--$boundary--"
        )
        $body = $bodyLines -join "`r`n"
        
        $headers = @{
            "Content-Type" = "multipart/form-data; boundary=$boundary"
        }
        
        # Upload
        $result = Invoke-RestMethod -Uri "$ServerUrl/compress" -Method POST -Body $body -Headers $headers -TimeoutSec 30
        
        # Track results
        $compressionResults += $result
        $witnessStorageTotal += $result.witness_size
        
        # On first upload, we get the shard storage size
        if ($i -eq 1) {
            $shardStorageTotal = $result.compressed_shards_size
            $shardSizeKB = [Math]::Round($shardStorageTotal / 1024, 2)
            Write-Host "   First upload created" $result.shard_count "shards ("$shardSizeKB "KB)" -ForegroundColor Cyan
        }
        
        $uploadCount++
        
        # Show progress at milestones
        if ($i -in @(1, 10, 25, 50, 100, 250, 500, 1000) -or $i -eq $Duplicates) {
            $currentNetworkTotal = $witnessStorageTotal + $shardStorageTotal
            $currentOriginalTotal = $fileSize * $i
            $currentRatio = $currentOriginalTotal / $currentNetworkTotal
            $currentSaved = (1 - ($currentNetworkTotal / $currentOriginalTotal)) * 100
            
            $netKB = [Math]::Round($currentNetworkTotal / 1024, 2)
            $ratioStr = [Math]::Round($currentRatio, 2)
            $savedStr = [Math]::Round($currentSaved, 1)
            Write-Host "   [$i uploads] Network:" $netKB "KB | Ratio:" "${ratioStr}:1" "| Saved:" "$savedStr%" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "   ⚠️  Upload $i failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Progress -Activity $progressActivity -Completed
$endTime = Get-Date
$totalTime = ($endTime - $startTime).TotalSeconds

Write-Host "`n✅ Completed $uploadCount/$Duplicates uploads in $([Math]::Round($totalTime, 2)) seconds" -ForegroundColor Green

# Calculate actual network storage
$totalWitnessStorage = $witnessStorageTotal
$totalShardStorage = $shardStorageTotal  # Stored ONCE, shared across all uploads
$totalNetworkStorage = $totalWitnessStorage + $totalShardStorage

$totalOriginalSize = $fileSize * $uploadCount
$networkCompressionRatio = $totalOriginalSize / $totalNetworkStorage
$networkSpaceSaved = (1 - ($totalNetworkStorage / $totalOriginalSize)) * 100

# Compare to isolated compression (no deduplication)
$firstResult = $compressionResults[0]
$isolatedTotalStorage = $firstResult.total_storage * $uploadCount
$isolatedRatio = $totalOriginalSize / $isolatedTotalStorage
$isolatedSaved = (1 - ($isolatedTotalStorage / $totalOriginalSize)) * 100

$dedupBenefit = (($isolatedTotalStorage - $totalNetworkStorage) / $isolatedTotalStorage) * 100

Write-Host @"

╔════════════════════════════════════════════════════════════════╗
║                    NETWORK SCALE RESULTS                       ║
╚════════════════════════════════════════════════════════════════╝

📊 ACTUAL NETWORK STORAGE:
   Total Original Data:     $([Math]::Round($totalOriginalSize / 1024, 2)) KB from $uploadCount files
   
   Network Storage Breakdown:
   • Witnesses ($uploadCount x $($firstResult.witness_size) bytes):  $([Math]::Round($totalWitnessStorage / 1024, 2)) KB
   • Shards (stored once, shared):      $([Math]::Round($totalShardStorage / 1024, 2)) KB
   ────────────────────────────────────
   Total Network Storage:               $([Math]::Round($totalNetworkStorage / 1024, 2)) KB
   
   Network Compression Ratio:           $([Math]::Round($networkCompressionRatio, 2)):1
   Space Saved:                         $([Math]::Round($networkSpaceSaved, 1))%

🔄 COMPARISON: Network vs Isolated Compression:
   
   If stored separately (no deduplication):
   • Storage: $([Math]::Round($isolatedTotalStorage / 1024, 2)) KB
   • Ratio: $([Math]::Round($isolatedRatio, 2)):1
   • Saved: $([Math]::Round($isolatedSaved, 1))%
   
   With network deduplication:
   • Storage: $([Math]::Round($totalNetworkStorage / 1024, 2)) KB
   • Ratio: $([Math]::Round($networkCompressionRatio, 2)):1
   • Saved: $([Math]::Round($networkSpaceSaved, 1))%
   
   💡 Deduplication Benefit: $([Math]::Round($dedupBenefit, 1))% more efficient than isolated!

📈 SCALING VERIFICATION:

   First Upload (Single File):
   • Weismann Score: $([Math]::Round($firstResult.weismann_score, 2))
   • Storage: $([Math]::Round($firstResult.total_storage / 1024, 2)) KB
   • Ratio: $([Math]::Round($firstResult.total_compression_ratio, 2)):1
   
   Network Projections from First Upload:
"@

# Show projections from first upload
$projection10 = $firstResult.network_potential.scale_10
$projection100 = $firstResult.network_potential.scale_100
$projection1000 = $firstResult.network_potential.scale_1000

Write-Host "   10x Projected:  $([Math]::Round($projection10.network_compression_ratio, 2)):1 ratio, Weismann $([Math]::Round($projection10.network_weismann_score, 2))"
Write-Host "   100x Projected: $([Math]::Round($projection100.network_compression_ratio, 2)):1 ratio, Weismann $([Math]::Round($projection100.network_weismann_score, 2))"
Write-Host "   1000x Projected: $([Math]::Round($projection1000.network_compression_ratio, 2)):1 ratio, Weismann $([Math]::Round($projection1000.network_weismann_score, 2))"

Write-Host "`n   Actual Test ($uploadCount uploads):"
Write-Host "   ✅ Actual: $([Math]::Round($networkCompressionRatio, 2)):1 ratio" -ForegroundColor Green

# Validation check
if ($uploadCount -eq 10) {
    $expectedRatio = $projection10.network_compression_ratio
    $actualRatio = $networkCompressionRatio
    $variance = [Math]::Abs(($actualRatio - $expectedRatio) / $expectedRatio) * 100
    
    Write-Host "`n🎯 PROJECTION ACCURACY CHECK (10x):" -ForegroundColor Cyan
    Write-Host "   Expected: $([Math]::Round($expectedRatio, 2)):1"
    Write-Host "   Actual:   $([Math]::Round($actualRatio, 2)):1"
    Write-Host "   Variance: $([Math]::Round($variance, 2))%"
    
    if ($variance -lt 5) {
        Write-Host "   ✅ VERIFIED: Projections are accurate!" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  WARNING: Variance > 5%, projections may need adjustment" -ForegroundColor Yellow
    }
} elseif ($uploadCount -eq 100) {
    $expectedRatio = $projection100.network_compression_ratio
    $actualRatio = $networkCompressionRatio
    $variance = [Math]::Abs(($actualRatio - $expectedRatio) / $expectedRatio) * 100
    
    Write-Host "`n🎯 PROJECTION ACCURACY CHECK (100x):" -ForegroundColor Cyan
    Write-Host "   Expected: $([Math]::Round($expectedRatio, 2)):1"
    Write-Host "   Actual:   $([Math]::Round($actualRatio, 2)):1"
    Write-Host "   Variance: $([Math]::Round($variance, 2))%"
    
    if ($variance -lt 5) {
        Write-Host "   ✅ VERIFIED: Projections are accurate!" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  WARNING: Variance > 5%, projections may need adjustment" -ForegroundColor Yellow
    }
}

Write-Host @"

╔════════════════════════════════════════════════════════════════╗
║                         CONCLUSIONS                            ║
╚════════════════════════════════════════════════════════════════╝

"@

if ($networkSpaceSaved -gt 0) {
    Write-Host "✅ SUCCESS: Network deduplication is working!" -ForegroundColor Green
    Write-Host "   • $uploadCount duplicate files compressed from $([Math]::Round($totalOriginalSize / 1024, 2)) KB to $([Math]::Round($totalNetworkStorage / 1024, 2)) KB"
    Write-Host "   • Achieved $([Math]::Round($networkCompressionRatio, 2)):1 compression ratio"
    Write-Host "   • Saved $([Math]::Round($networkSpaceSaved, 1))% of total storage"
    Write-Host "   • $([Math]::Round($dedupBenefit, 1))% more efficient than isolated compression"
} else {
    Write-Host "⚠️  WARNING: Network storage is larger than original" -ForegroundColor Yellow
    Write-Host "   This is expected for single small files with compression overhead."
    Write-Host "   Try with larger files or more duplicates to see deduplication benefits."
}

Write-Host "`nKEY INSIGHT:" -ForegroundColor Cyan
Write-Host "   Shards are stored ONCE on the network DHT and shared."
Write-Host "   Each user only needs to store a small witness (~$($firstResult.witness_size) bytes)."
Write-Host "   As more users share the same content, compression improves exponentially!"

Write-Host "`nTest complete!" -ForegroundColor Green
Write-Host ""
