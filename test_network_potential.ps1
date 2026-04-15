#!/usr/bin/env pwsh
# Quick test to demonstrate network potential scoring

Write-Host ""
Write-Host "Testing single file compression with network potential projections..." -ForegroundColor Cyan
Write-Host ""

$file = "test_sample.txt"
$url = "http://localhost:3000/compress"

if (-not (Test-Path $file)) {
    Write-Host "ERROR: $file not found" -ForegroundColor Red
    exit 1
}

$fileSize = (Get-Item $file).Length
Write-Host "File: $file ($([Math]::Round($fileSize / 1024, 2)) KB)" -ForegroundColor Yellow

# Create multipart form data
$boundary = [System.Guid]::NewGuid().ToString()
$fileName = Split-Path $file -Leaf
$fileBytes = [System.IO.File]::ReadAllBytes($file)

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

Write-Host "Compressing..." -ForegroundColor Cyan

try {
    $result = Invoke-RestMethod -Uri $url -Method POST -Body $body -Headers $headers -TimeoutSec 30
    
    Write-Host ""
    Write-Host "====== SINGLE FILE RESULTS ======" -ForegroundColor Green
    Write-Host "Original Size:      $([Math]::Round($result.original_size / 1024, 2)) KB"
    Write-Host "Witness:            $([Math]::Round($result.witness_size / 1024, 2)) KB"
    Write-Host "Compressed Shards:  $([Math]::Round($result.compressed_shards_size / 1024, 2)) KB"
    Write-Host "Total Storage:      $([Math]::Round($result.total_storage / 1024, 2)) KB"
    Write-Host "Compression Ratio:  $([Math]::Round($result.total_compression_ratio, 2)):1"
    Write-Host "Space Saved:        $([Math]::Round($result.space_saved_percent, 1))%"
    Write-Host "Weismann Score:     $([Math]::Round($result.weismann_score, 2))"
    
    Write-Host ""
    Write-Host "====== NETWORK POTENTIAL (Deduplication at Scale) ======" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "10x Duplicates:" -ForegroundColor Yellow
    $np10 = $result.network_potential.scale_10
    Write-Host "  Total Original:   $([Math]::Round($np10.total_original_size / 1024, 2)) KB (10 copies)"
    Write-Host "  Network Storage:  $([Math]::Round($np10.network_storage_total / 1024, 2)) KB (witnesses + shared shards)"
    Write-Host "  Compression:      $([Math]::Round($np10.network_compression_ratio, 2)):1 ratio"
    Write-Host "  Space Saved:      $([Math]::Round($np10.network_space_saved_percent, 1))%"
    Write-Host "  Weismann Score:   $([Math]::Round($np10.network_weismann_score, 2))"
    Write-Host "  vs Isolated:      $([Math]::Round($np10.storage_efficiency_vs_single, 1))% more efficient!"
    
    Write-Host ""
    Write-Host "100x Duplicates:" -ForegroundColor Yellow
    $np100 = $result.network_potential.scale_100
    Write-Host "  Total Original:   $([Math]::Round($np100.total_original_size / 1024, 2)) KB (100 copies)"
    Write-Host "  Network Storage:  $([Math]::Round($np100.network_storage_total / 1024, 2)) KB"
    Write-Host "  Compression:      $([Math]::Round($np100.network_compression_ratio, 2)):1 ratio"  
    Write-Host "  Space Saved:      $([Math]::Round($np100.network_space_saved_percent, 1))%"
    Write-Host "  Weismann Score:   $([Math]::Round($np100.network_weismann_score, 2))"
    Write-Host "  vs Isolated:      $([Math]::Round($np100.storage_efficiency_vs_single, 1))% more efficient!"
    
    Write-Host ""
    Write-Host "1000x Duplicates:" -ForegroundColor Yellow
    $np1000 = $result.network_potential.scale_1000
    Write-Host "  Total Original:   $([Math]::Round($np1000.total_original_size / 1024, 2)) KB (1000 copies)"
    Write-Host "  Network Storage:  $([Math]::Round($np1000.network_storage_total / 1024, 2)) KB"
    Write-Host "  Compression:      $([Math]::Round($np1000.network_compression_ratio, 2)):1 ratio"
    Write-Host "  Space Saved:      $([Math]::Round($np1000.network_space_saved_percent, 1))%"
    Write-Host "  Weismann Score:   $([Math]::Round($np1000.network_weismann_score, 2))"
    Write-Host "  vs Isolated:      $([Math]::Round($np1000.storage_efficiency_vs_single, 1))% more efficient!"
    
    Write-Host ""
    Write-Host "KEY INSIGHT:" -ForegroundColor Cyan
    Write-Host "Shards are stored ONCE on the network and shared via DHT."
    Write-Host "Each user only stores a tiny witness (~$($result.witness_size) bytes)."
    Write-Host "As duplicate content spreads, compression improves exponentially!"
    
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
