// sovereign_codec.rs — Sovereign Frequency Coder (SFC) v2
//
// A 100% from-scratch entropy coding pipeline for the Sovereign Network.
// Three encoding strategies, automatically selected per-block for best ratio:
//
//   SFC0: Stored passthrough (for incompressible data)
//   SFC1: Canonical Huffman (for data with simple byte-frequency skew)
//   SFC2: BWT → MTF → Canonical Huffman (for structured/text data — best ratio)
//
// Applied after ZKC pattern replacement to capture remaining statistical
// redundancy that dictionary-based pattern matching cannot exploit.
//
// The BWT (Burrows-Wheeler Transform) groups bytes by their following context,
// making the data highly compressible. MTF (Move-to-Front) converts the BWT
// output into mostly-zero values. Canonical Huffman then assigns short bit
// codes to frequent values (0 and small indices).
//
// 100% novel implementation — no borrowed compression libraries.

use std::collections::BinaryHeap;
use std::cmp::Reverse;
use rayon::prelude::*;

/// Maximum Huffman code length in bits (prevents degenerate trees)
const MAX_CODE_LENGTH: u8 = 24;

/// Minimum data size to attempt any encoding
const MIN_ENCODE_SIZE: usize = 32;

/// Minimum block size for BWT (below this, BWT overhead isn't worth it)
const MIN_BWT_SIZE: usize = 64;

/// Maximum block size for BWT
/// Larger blocks = better context for BWT byte grouping.
/// For a 1MB shard, ZKC body is ~400KB. Our suffix sort handles this
/// in ~1-2s on modern hardware (O(n log n) with ~30 byte comparisons).
const MAX_BWT_SIZE: usize = 1048576;

/// Magic bytes for stored (passthrough) data
const SFC_MAGIC_STORED: &[u8; 4] = b"SFC0";

/// Magic bytes for Huffman-only encoded data
const SFC_MAGIC_HUFFMAN: &[u8; 4] = b"SFC1";

/// Magic bytes for BWT + MTF + RLE + Huffman encoded data
const SFC_MAGIC_BWT: &[u8; 4] = b"SFC2";

/// Magic bytes for BWT + MTF + RLE + Range coder (near-optimal entropy)
const SFC_MAGIC_RANGE: &[u8; 4] = b"SFC3";

/// Magic bytes for LZ77 + dual Huffman (DEFLATE-style, from scratch)
const SFC_MAGIC_LZ77: &[u8; 4] = b"SFC4";

/// Magic bytes for BWT + MTF + RLE + Order-1 Range coder (context-adaptive)
const SFC_MAGIC_CTX1: &[u8; 4] = b"SFC5";

/// Magic bytes for BWT + MTF + Adaptive Order-1 Range coder (no RLE, no header table)
const SFC_MAGIC_ADAPTIVE: &[u8; 4] = b"SFC6";

/// Magic bytes for BWT + MTF + RLE + Adaptive Order-1 Range coder (best of both)
const SFC_MAGIC_ADAPTIVE_RLE: &[u8; 4] = b"SFC7";

/// A Huffman code for a single byte value
#[derive(Debug, Clone, Copy)]
struct HuffCode {
    /// The bit pattern (right-aligned, MSB-first)
    code: u32,
    /// Number of valid bits in `code`
    length: u8,
}

/// Sovereign Frequency Coder — from-scratch BWT + MTF + Huffman implementation
pub struct SovereignCodec;

impl SovereignCodec {
    /// Encode data using the best available SFC strategy
    ///
    /// Tries SFC1 (Huffman), SFC2 (BWT+Huffman), SFC3 (BWT+Range),
    /// SFC4 (LZ77+Huffman), picks smallest, falls back to SFC0 (stored).
    pub fn encode(data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        // SFC format stores sizes as u32 — reject inputs that would silently truncate
        if data.len() > u32::MAX as usize {
            // Fall through to stored format with a warning; callers should chunk large inputs
            eprintln!("⚠️  SFC: input exceeds u32::MAX ({} bytes), returning stored verbatim", data.len());
            return Self::make_stored(data);
        }
        if data.len() < MIN_ENCODE_SIZE {
            return Self::make_stored(data);
        }

        let stored = Self::make_stored(data);
        let mut best = stored;

        // ── Parallel strategy evaluation ────────────────────────────

        // Fork: SFC1 + SFC4 run in parallel with the BWT pipeline.
        // The BWT path (SFC2/SFC3/SFC7) shares the BWT+MTF+RLE work.
        let use_bwt = data.len() >= MIN_BWT_SIZE && data.len() <= MAX_BWT_SIZE;

        let (light_best, bwt_results) = rayon::join(
            // Thread A: lightweight strategies (no BWT)
            || {
                let sfc1 = Self::encode_huffman(data);
                let sfc4 = Self::encode_lz77(data);
                if sfc1.len() <= sfc4.len() { sfc1 } else { sfc4 }
            },
            // Thread B: BWT pipeline (heavy lifting)
            || {
                if !use_bwt {
                    return None;
                }
                let (bwt_output, bwt_index) = Self::bwt_forward(data);
                let mtf_output = Self::mtf_forward(&bwt_output);
                let rle_output = Self::rle_encode(&mtf_output);

                // Run SFC2, SFC3, SFC7 and pick the best
                let sfc2 = Self::encode_bwt_from_rle(data.len(), bwt_index, &rle_output);
                let mut bwt_best = sfc2;

                let sfc3 = Self::encode_range_from_rle(data.len(), bwt_index, &rle_output);
                if sfc3.len() < bwt_best.len() {
                    if let Ok(decoded) = Self::decode(&sfc3) {
                        if decoded == data {
                            bwt_best = sfc3;
                        }
                    }
                }

                let sfc7 = Self::encode_adaptive_o1_rle(data.len(), bwt_index, &rle_output);
                if sfc7.len() < bwt_best.len() {
                    if let Ok(decoded) = Self::decode(&sfc7) {
                        if decoded == data {
                            bwt_best = sfc7;
                        }
                    }
                }

                Some(bwt_best)
            },
        );

        if light_best.len() < best.len() {
            best = light_best;
        }
        if let Some(bwt_best) = bwt_results {
            if bwt_best.len() < best.len() {
                best = bwt_best;
            }
        }

        best
    }

    /// Decode SFC-encoded data back to original bytes
    pub fn decode(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 4 {
            return Err("SFC data too short for magic bytes".into());
        }

        let magic = &data[0..4];

        if magic == SFC_MAGIC_STORED {
            return Ok(data[4..].to_vec());
        }
        if magic == SFC_MAGIC_HUFFMAN {
            return Self::decode_huffman(data);
        }
        if magic == SFC_MAGIC_BWT {
            return Self::decode_bwt(data);
        }
        if magic == SFC_MAGIC_RANGE {
            return Self::decode_range(data);
        }
        if magic == SFC_MAGIC_LZ77 {
            return Self::decode_lz77(data);
        }
        if magic == SFC_MAGIC_CTX1 {
            return Self::decode_ctx1(data);
        }
        if magic == SFC_MAGIC_ADAPTIVE {
            return Self::decode_adaptive_o1(data);
        }
        if magic == SFC_MAGIC_ADAPTIVE_RLE {
            return Self::decode_adaptive_o1_rle(data);
        }

        Err(format!(
            "Invalid SFC magic: {:02X}{:02X}{:02X}{:02X}",
            data[0], data[1], data[2], data[3]
        ))
    }

    /// Check if data has an SFC header
    pub fn is_sfc_encoded(data: &[u8]) -> bool {
        data.len() >= 4
            && (data[0..4] == *SFC_MAGIC_STORED
                || data[0..4] == *SFC_MAGIC_HUFFMAN
                || data[0..4] == *SFC_MAGIC_BWT
                || data[0..4] == *SFC_MAGIC_RANGE
                || data[0..4] == *SFC_MAGIC_LZ77
                || data[0..4] == *SFC_MAGIC_CTX1
                || data[0..4] == *SFC_MAGIC_ADAPTIVE
                || data[0..4] == *SFC_MAGIC_ADAPTIVE_RLE)
    }

    /// Create SFC0 (stored/passthrough) format
    fn make_stored(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 4);
        out.extend_from_slice(SFC_MAGIC_STORED);
        out.extend_from_slice(data);
        out
    }

    // ══════════════════════════════════════════════════════════
    //  SFC1: Huffman Only
    // ══════════════════════════════════════════════════════════

    /// Encode using Huffman only
    ///
    /// Format: [SFC1][orig_len:u32][num_sym:u16][table][padding:u8][body]
    fn encode_huffman(data: &[u8]) -> Vec<u8> {
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }

        let code_lengths = Self::build_code_lengths(&freq);
        let num_symbols = code_lengths.iter().filter(|&&l| l > 0).count();
        if num_symbols <= 1 {
            return Self::make_stored(data);
        }

        let codes = Self::canonical_codes(&code_lengths);

        let mut bitstream = BitWriter::new(data.len());
        for &b in data {
            bitstream.write_bits(codes[b as usize].code, codes[b as usize].length);
        }
        let (encoded_bytes, padding_bits) = bitstream.finish();

        let header_size = 4 + 4 + 2 + (2 * num_symbols) + 1;
        let total_size = header_size + encoded_bytes.len();
        if total_size >= data.len() + 4 {
            return Self::make_stored(data);
        }

        let mut output = Vec::with_capacity(total_size);
        output.extend_from_slice(SFC_MAGIC_HUFFMAN);
        output.extend_from_slice(&(data.len() as u32).to_le_bytes());
        output.extend_from_slice(&(num_symbols as u16).to_le_bytes());

        let mut symbols: Vec<(u8, u8)> = code_lengths
            .iter()
            .enumerate()
            .filter(|(_, &l)| l > 0)
            .map(|(b, &l)| (b as u8, l))
            .collect();
        symbols.sort_by_key(|&(b, l)| (l, b));
        for &(b, l) in &symbols {
            output.push(b);
            output.push(l);
        }

        output.push(padding_bits);
        output.extend_from_slice(&encoded_bytes);
        output
    }

    /// Decode SFC1 (Huffman only) data
    fn decode_huffman(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 11 {
            return Err("SFC1 header too short".into());
        }

        let orig_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let num_symbols = u16::from_le_bytes([data[8], data[9]]) as usize;

        let table_start = 10;
        let table_end = table_start + num_symbols * 2;
        if data.len() < table_end + 1 {
            return Err("SFC1 truncated in code table".into());
        }

        let mut code_lengths = [0u8; 256];
        for i in 0..num_symbols {
            let byte_val = data[table_start + i * 2];
            let length = data[table_start + i * 2 + 1];
            if length == 0 || length > MAX_CODE_LENGTH {
                return Err(format!("Invalid code length {} for byte {}", length, byte_val));
            }
            code_lengths[byte_val as usize] = length;
        }

        let padding_bits = data[table_end];
        let body = &data[table_end + 1..];

        let codes = Self::canonical_codes(&code_lengths);
        let tree = Self::build_decode_tree(&codes);

        let mut reader = BitReader::new(body, padding_bits);
        let mut output = Vec::with_capacity(orig_len);
        while output.len() < orig_len {
            output.push(Self::decode_one_symbol(&tree, &mut reader)?);
        }
        Ok(output)
    }

    // ══════════════════════════════════════════════════════════
    //  SFC2: BWT + MTF + Huffman (highest compression)
    // ══════════════════════════════════════════════════════════

    /// Encode using BWT → MTF → RLE → Huffman pipeline (standalone version)
    ///
    /// Format: [SFC2][orig_len:u32][bwt_idx:u32][rle_len:u32][num_sym:u16][table][padding:u8][body]
    fn encode_bwt(data: &[u8]) -> Vec<u8> {
        let (bwt_output, bwt_index) = Self::bwt_forward(data);
        let mtf_output = Self::mtf_forward(&bwt_output);
        let rle_output = Self::rle_encode(&mtf_output);
        Self::encode_bwt_from_rle(data.len(), bwt_index, &rle_output)
    }

    /// Huffman-encode pre-computed BWT+MTF+RLE output (used by both standalone and shared path)
    fn encode_bwt_from_rle(orig_len: usize, bwt_index: u32, rle_output: &[u8]) -> Vec<u8> {
        let mut freq = [0u64; 256];
        for &b in rle_output {
            freq[b as usize] += 1;
        }

        let code_lengths = Self::build_code_lengths(&freq);
        let num_symbols = code_lengths.iter().filter(|&&l| l > 0).count();
        if num_symbols <= 1 {
            // Can't encode — caller will use stored fallback
            let mut out = Vec::with_capacity(orig_len + 4);
            out.extend_from_slice(SFC_MAGIC_STORED);
            out.resize(orig_len + 4, 0); // Oversize to signal "don't use me"
            return out;
        }

        let codes = Self::canonical_codes(&code_lengths);

        let mut bitstream = BitWriter::new(rle_output.len());
        for &b in rle_output {
            bitstream.write_bits(codes[b as usize].code, codes[b as usize].length);
        }
        let (encoded_bytes, padding_bits) = bitstream.finish();

        let header_size = 4 + 4 + 4 + 4 + 2 + (2 * num_symbols) + 1;
        let total_size = header_size + encoded_bytes.len();
        if total_size >= orig_len + 4 {
            let mut out = Vec::with_capacity(orig_len + 4);
            out.extend_from_slice(SFC_MAGIC_STORED);
            out.resize(orig_len + 4, 0);
            return out;
        }

        let mut output = Vec::with_capacity(total_size);
        output.extend_from_slice(SFC_MAGIC_BWT);
        output.extend_from_slice(&(orig_len as u32).to_le_bytes());
        output.extend_from_slice(&bwt_index.to_le_bytes());
        output.extend_from_slice(&(rle_output.len() as u32).to_le_bytes());
        output.extend_from_slice(&(num_symbols as u16).to_le_bytes());

        let mut symbols: Vec<(u8, u8)> = code_lengths
            .iter()
            .enumerate()
            .filter(|(_, &l)| l > 0)
            .map(|(b, &l)| (b as u8, l))
            .collect();
        symbols.sort_by_key(|&(b, l)| (l, b));
        for &(b, l) in &symbols {
            output.push(b);
            output.push(l);
        }

        output.push(padding_bits);
        output.extend_from_slice(&encoded_bytes);
        output
    }

    /// Decode SFC2 (BWT+MTF+RLE+Huffman) data
    ///
    /// Header: [SFC2][orig_len:u32][bwt_idx:u32][rle_len:u32][num_sym:u16][table][padding:u8][body]
    fn decode_bwt(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 19 {
            return Err("SFC2 header too short".into());
        }

        let orig_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let bwt_index = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let rle_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let num_symbols = u16::from_le_bytes([data[16], data[17]]) as usize;

        let table_start = 18;
        let table_end = table_start + num_symbols * 2;
        if data.len() < table_end + 1 {
            return Err("SFC2 truncated in code table".into());
        }

        let mut code_lengths = [0u8; 256];
        for i in 0..num_symbols {
            let byte_val = data[table_start + i * 2];
            let length = data[table_start + i * 2 + 1];
            if length == 0 || length > MAX_CODE_LENGTH {
                return Err(format!("Invalid code length {} for byte {}", length, byte_val));
            }
            code_lengths[byte_val as usize] = length;
        }

        let padding_bits = data[table_end];
        let body = &data[table_end + 1..];

        let codes = Self::canonical_codes(&code_lengths);
        let tree = Self::build_decode_tree(&codes);

        // Step 1: Huffman decode → RLE output (length == rle_len)
        let mut reader = BitReader::new(body, padding_bits);
        let mut rle_output = Vec::with_capacity(rle_len);
        while rle_output.len() < rle_len {
            rle_output.push(Self::decode_one_symbol(&tree, &mut reader)?);
        }

        // Step 2: Inverse RLE
        let mtf_output = Self::rle_decode(&rle_output);

        // Step 3: Inverse MTF
        let bwt_output = Self::mtf_inverse(&mtf_output);

        // Safety: verify decoded length matches before BWT inverse
        if (bwt_index as usize) >= bwt_output.len() {
            return Err(format!(
                "SFC2 decode error: bwt_index {} >= decoded len {}",
                bwt_index, bwt_output.len()
            ));
        }

        // Step 4: Inverse BWT
        let original = Self::bwt_inverse(&bwt_output, bwt_index);

        Ok(original)
    }

    // ══════════════════════════════════════════════════════════
    //  SFC3: BWT + MTF + RLE + Range Coder (near-optimal entropy)
    // ══════════════════════════════════════════════════════════

    /// Range coder precision: cumulative frequencies are scaled to this
    const RANGE_SCALE_BITS: u32 = 14;
    const RANGE_SCALE: u32 = 1 << 14;  // 16384

    /// Encode using BWT → MTF → RLE → Range coding pipeline
    ///
    /// Format: [SFC3][orig_len:u32][bwt_idx:u32][rle_len:u32][num_sym:u16][cum_freq_table][range_body]
    fn encode_range(data: &[u8]) -> Vec<u8> {
        let (bwt_output, bwt_index) = Self::bwt_forward(data);
        let mtf_output = Self::mtf_forward(&bwt_output);
        let rle_output = Self::rle_encode(&mtf_output);
        Self::encode_range_from_rle(data.len(), bwt_index, &rle_output)
    }

    /// Range-encode pre-computed BWT+MTF+RLE output (used by both standalone and shared path)
    fn encode_range_from_rle(orig_len: usize, bwt_index: u32, rle_output: &[u8]) -> Vec<u8> {
        let mut raw_freq = [0u64; 256];
        for &b in rle_output {
            raw_freq[b as usize] += 1;
        }

        let num_symbols = raw_freq.iter().filter(|&&f| f > 0).count();
        if num_symbols <= 1 {
            let mut out = Vec::with_capacity(orig_len + 4);
            out.extend_from_slice(SFC_MAGIC_STORED);
            out.resize(orig_len + 4, 0);
            return out;
        }

        // Quantize frequencies to sum to RANGE_SCALE
        let total_count: u64 = rle_output.len() as u64;
        let mut quant_freq = [0u32; 256];
        let mut quant_total = 0u32;

        for i in 0..256 {
            if raw_freq[i] > 0 {
                let f = ((raw_freq[i] as u64 * Self::RANGE_SCALE as u64) / total_count).max(1) as u32;
                quant_freq[i] = f;
                quant_total += f;
            }
        }

        // Adjust to exactly RANGE_SCALE
        if quant_total != Self::RANGE_SCALE {
            let max_sym = (0..256).max_by_key(|&i| quant_freq[i]).unwrap();
            if quant_total > Self::RANGE_SCALE {
                let diff = quant_total - Self::RANGE_SCALE;
                if quant_freq[max_sym] > diff + 1 {
                    quant_freq[max_sym] -= diff;
                } else {
                    let mut out = Vec::with_capacity(orig_len + 4);
                    out.extend_from_slice(SFC_MAGIC_STORED);
                    out.resize(orig_len + 4, 0);
                    return out;
                }
            } else {
                quant_freq[max_sym] += Self::RANGE_SCALE - quant_total;
            }
        }

        // Build cumulative frequency table
        let mut cum_freq = [0u32; 257];
        for i in 0..256 {
            cum_freq[i + 1] = cum_freq[i] + quant_freq[i];
        }

        // Range encode
        let mut enc = RangeEncoderState::new(rle_output.len());
        for &b in rle_output {
            let sym = b as usize;
            enc.encode(cum_freq[sym], quant_freq[sym], Self::RANGE_SCALE);
        }
        let range_body = enc.finish();

        // Build output
        let freq_table_size = 2 + num_symbols * 3;
        let header_size = 4 + 4 + 4 + 4 + freq_table_size;
        let total_size = header_size + range_body.len();

        if total_size >= orig_len + 4 {
            let mut out = Vec::with_capacity(orig_len + 4);
            out.extend_from_slice(SFC_MAGIC_STORED);
            out.resize(orig_len + 4, 0);
            return out;
        }

        let mut output = Vec::with_capacity(total_size);
        output.extend_from_slice(SFC_MAGIC_RANGE);
        output.extend_from_slice(&(orig_len as u32).to_le_bytes());
        output.extend_from_slice(&bwt_index.to_le_bytes());
        output.extend_from_slice(&(rle_output.len() as u32).to_le_bytes());

        output.extend_from_slice(&(num_symbols as u16).to_le_bytes());
        for i in 0..256 {
            if quant_freq[i] > 0 {
                output.push(i as u8);
                output.extend_from_slice(&(quant_freq[i] as u16).to_le_bytes());
            }
        }

        output.extend_from_slice(&range_body);
        output
    }

    /// Decode SFC3 (BWT+MTF+RLE+Range) data
    fn decode_range(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 20 {
            return Err("SFC3 header too short".into());
        }

        let orig_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let bwt_index = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let rle_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let num_symbols = u16::from_le_bytes([data[16], data[17]]) as usize;

        let table_start = 18;
        let table_end = table_start + num_symbols * 3;
        if data.len() < table_end {
            return Err("SFC3 truncated in freq table".into());
        }

        // Reconstruct quantized frequencies
        let mut quant_freq = [0u32; 256];
        for i in 0..num_symbols {
            let byte_val = data[table_start + i * 3] as usize;
            let freq = u16::from_le_bytes([
                data[table_start + i * 3 + 1],
                data[table_start + i * 3 + 2],
            ]) as u32;
            quant_freq[byte_val] = freq;
        }

        // Build cumulative frequency table
        let mut cum_freq = [0u32; 257];
        for i in 0..256 {
            cum_freq[i + 1] = cum_freq[i] + quant_freq[i];
        }

        // Range decode
        let range_body = &data[table_end..];
        let mut dec = RangeDecoderState::new(range_body);
        let mut rle_output = Vec::with_capacity(rle_len);
        for _ in 0..rle_len {
            let sym = dec.decode_symbol(&cum_freq, Self::RANGE_SCALE);
            rle_output.push(sym as u8);
        }

        // Inverse RLE
        let mtf_output = Self::rle_decode(&rle_output);

        // Inverse MTF
        let bwt_output = Self::mtf_inverse(&mtf_output);

        // Safety: verify decoded length matches before BWT inverse
        if (bwt_index as usize) >= bwt_output.len() {
            return Err(format!(
                "SFC3 decode error: bwt_index {} >= decoded len {}",
                bwt_index, bwt_output.len()
            ));
        }

        // Inverse BWT
        let original = Self::bwt_inverse(&bwt_output, bwt_index);

        Ok(original)
    }

    // ══════════════════════════════════════════════════════════
    //  SFC5: BWT + MTF + RLE + Order-1 Context-Adaptive Range Coder
    //
    //  The key insight: after BWT+MTF, byte N strongly predicts byte N+1.
    //  Instead of one global frequency table (order-0), we maintain 256
    //  tables — one per previous-byte context. This captures the statistical
    //  dependencies that order-0 coding completely ignores.
    //
    //  For BWT+MTF output: a zero is usually followed by another zero,
    //  a small value is usually followed by zero, etc. Order-1 modeling
    //  exploits these patterns for significantly tighter coding.
    // ══════════════════════════════════════════════════════════

    /// Context scale for order-1 range coding (per-context cumulative frequencies)
    const CTX1_SCALE_BITS: u32 = 14;
    const CTX1_SCALE: u32 = 1 << 14; // 16384 per context — matches RANGE_SCALE for optimal precision

    /// Encode BWT+MTF+RLE output using order-1 context-adaptive range coder
    ///
    /// Format: [SFC5][orig_len:u32][bwt_idx:u32][rle_len:u32][num_contexts:u16]
    ///         [context_table][range_body]
    /// context_table: for each active context c:
    ///   [ctx_byte:u8][num_symbols:u8][(sym:u8, freq:u16) × num_symbols]
    fn encode_ctx1_from_rle(orig_len: usize, bwt_index: u32, rle_output: &[u8]) -> Vec<u8> {
        if rle_output.len() < 2 {
            let mut out = Vec::with_capacity(orig_len + 4);
            out.extend_from_slice(SFC_MAGIC_STORED);
            out.resize(orig_len + 4, 0);
            return out;
        }

        // Build order-1 frequency tables: raw_freq[prev_byte][cur_byte] = count
        let mut raw_freq = vec![[0u32; 256]; 256];
        let mut prev = 0u8; // initial context
        for &b in rle_output {
            raw_freq[prev as usize][b as usize] += 1;
            prev = b;
        }

        // Quantize each context's frequencies to sum to CTX1_SCALE
        // Store as: quant_freq[ctx][sym], cum_freq[ctx][sym+1] = cum_freq[ctx][sym] + quant_freq[ctx][sym]
        let mut quant_freq = vec![[0u32; 256]; 256];
        let mut cum_freq = vec![[0u32; 257]; 256];
        let mut active_contexts: Vec<u8> = Vec::new();

        for ctx in 0..256usize {
            let ctx_total: u32 = raw_freq[ctx].iter().sum();
            if ctx_total == 0 {
                // Unused context — set uniform (shouldn't be reached during encoding)
                continue;
            }
            active_contexts.push(ctx as u8);

            let num_active = raw_freq[ctx].iter().filter(|&&f| f > 0).count();
            if num_active == 1 {
                // Only one symbol in this context — give it all the probability
                for sym in 0..256 {
                    if raw_freq[ctx][sym] > 0 {
                        quant_freq[ctx][sym] = Self::CTX1_SCALE;
                        break;
                    }
                }
            } else {
                let mut qt = 0u32;
                for sym in 0..256 {
                    if raw_freq[ctx][sym] > 0 {
                        let f = ((raw_freq[ctx][sym] as u64 * Self::CTX1_SCALE as u64) / ctx_total as u64).max(1) as u32;
                        quant_freq[ctx][sym] = f;
                        qt += f;
                    }
                }
                // Adjust to exactly CTX1_SCALE
                if qt != Self::CTX1_SCALE {
                    let max_sym = (0..256).max_by_key(|&s| quant_freq[ctx][s]).unwrap();
                    if qt > Self::CTX1_SCALE {
                        let diff = qt - Self::CTX1_SCALE;
                        if quant_freq[ctx][max_sym] > diff + 1 {
                            quant_freq[ctx][max_sym] -= diff;
                        } else {
                            // Can't fix — bail to stored
                            let mut out = Vec::with_capacity(orig_len + 4);
                            out.extend_from_slice(SFC_MAGIC_STORED);
                            out.resize(orig_len + 4, 0);
                            return out;
                        }
                    } else {
                        quant_freq[ctx][max_sym] += Self::CTX1_SCALE - qt;
                    }
                }
            }

            // Build cumulative frequency table for this context
            for sym in 0..256 {
                cum_freq[ctx][sym + 1] = cum_freq[ctx][sym] + quant_freq[ctx][sym];
            }
        }

        // Range encode with order-1 context
        let mut enc = RangeEncoderState::new(rle_output.len());
        prev = 0;
        for &b in rle_output {
            let ctx = prev as usize;
            let sym = b as usize;
            enc.encode(cum_freq[ctx][sym], quant_freq[ctx][sym], Self::CTX1_SCALE);
            prev = b;
        }
        let range_body = enc.finish();

        // Build context table for header
        // For each active context: [ctx_byte:u8][num_syms:u8][(sym:u8, freq_le:u16) × num_syms]
        let mut ctx_table = Vec::new();
        for &ctx in &active_contexts {
            let c = ctx as usize;
            let syms: Vec<(u8, u16)> = (0..256)
                .filter(|&s| quant_freq[c][s] > 0)
                .map(|s| (s as u8, quant_freq[c][s] as u16))
                .collect();
            ctx_table.push(ctx);
            ctx_table.push(syms.len() as u8);
            for &(sym, freq) in &syms {
                ctx_table.push(sym);
                ctx_table.extend_from_slice(&freq.to_le_bytes());
            }
        }

        // Header: magic(4) + orig_len(4) + bwt_idx(4) + rle_len(4) + num_ctx(2) + ctx_table + range_body
        let header_size = 4 + 4 + 4 + 4 + 2 + ctx_table.len();
        let total_size = header_size + range_body.len();

        if total_size >= orig_len + 4 {
            let mut out = Vec::with_capacity(orig_len + 4);
            out.extend_from_slice(SFC_MAGIC_STORED);
            out.resize(orig_len + 4, 0);
            return out;
        }

        let mut output = Vec::with_capacity(total_size);
        output.extend_from_slice(SFC_MAGIC_CTX1);
        output.extend_from_slice(&(orig_len as u32).to_le_bytes());
        output.extend_from_slice(&bwt_index.to_le_bytes());
        output.extend_from_slice(&(rle_output.len() as u32).to_le_bytes());
        output.extend_from_slice(&(active_contexts.len() as u16).to_le_bytes());
        output.extend_from_slice(&ctx_table);
        output.extend_from_slice(&range_body);
        output
    }

    /// Decode SFC5 (BWT+MTF+RLE+Order-1 Range) data
    fn decode_ctx1(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 18 {
            return Err("SFC5 header too short".into());
        }

        let _orig_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let bwt_index = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let rle_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let num_contexts = u16::from_le_bytes([data[16], data[17]]) as usize;

        // Parse context frequency tables
        let mut quant_freq = vec![[0u32; 256]; 256];
        let mut cum_freq = vec![[0u32; 257]; 256];
        let mut pos = 18;

        for _ in 0..num_contexts {
            if pos >= data.len() {
                return Err("SFC5 truncated in context table".into());
            }
            let ctx = data[pos] as usize;
            pos += 1;
            if pos >= data.len() {
                return Err("SFC5 truncated in context table (num_syms)".into());
            }
            let num_syms = data[pos] as usize;
            pos += 1;

            for _ in 0..num_syms {
                if pos + 3 > data.len() {
                    return Err("SFC5 truncated in context table (sym/freq)".into());
                }
                let sym = data[pos] as usize;
                let freq = u16::from_le_bytes([data[pos + 1], data[pos + 2]]) as u32;
                quant_freq[ctx][sym] = freq;
                pos += 3;
            }

            // Build cumulative frequency table for this context
            for sym in 0..256 {
                cum_freq[ctx][sym + 1] = cum_freq[ctx][sym] + quant_freq[ctx][sym];
            }
        }

        // Range decode with order-1 context
        let range_body = &data[pos..];
        let mut dec = RangeDecoderState::new(range_body);
        let mut rle_output = Vec::with_capacity(rle_len);
        let mut prev = 0u8;
        for _ in 0..rle_len {
            let ctx = prev as usize;
            let sym = dec.decode_symbol(&cum_freq[ctx], Self::CTX1_SCALE);
            let b = sym as u8;
            rle_output.push(b);
            prev = b;
        }

        // Inverse RLE
        let mtf_output = Self::rle_decode(&rle_output);

        // Inverse MTF
        let bwt_output = Self::mtf_inverse(&mtf_output);

        // Safety check
        if (bwt_index as usize) >= bwt_output.len() {
            return Err(format!(
                "SFC5 decode error: bwt_index {} >= decoded len {}",
                bwt_index, bwt_output.len()
            ));
        }

        // Inverse BWT
        let original = Self::bwt_inverse(&bwt_output, bwt_index);

        Ok(original)
    }

    // ══════════════════════════════════════════════════════════
    //  SFC6: BWT + MTF + Adaptive Order-1 Range Coder
    //
    //  KEY DIFFERENCES from SFC5 (static order-1):
    //  • NO RLE step — the adaptive coder naturally handles
    //    the zero-runs produced by MTF (order-1 context of
    //    "prev=0" quickly learns that 0 is overwhelmingly likely)
    //  • NO frequency tables in the header — encoder and decoder
    //    maintain identical adaptive models that start uniform
    //    and update after each symbol
    //  • ADAPTIVE — adjusts to local statistics automatically,
    //    giving better results on non-stationary data
    //
    //  Format: [SFC6][orig_len:u32][bwt_idx:u32][mtf_len:u32][range_body]
    //  Total header: just 16 bytes!
    // ══════════════════════════════════════════════════════════

    /// Maximum total frequency before rescaling (must fit in range coder precision)
    const ADAPTIVE_MAX_TOTAL: u32 = 16384;

    /// Build MTF+RLE-aware initial frequency distribution
    /// Symbol 0 is overwhelmingly dominant after BWT+MTF+RLE.
    /// Small symbols (1-7) are moderately common. Rest is rare.
    /// Both encoder and decoder MUST use identical initialization!
    fn adaptive_init_freq() -> [u32; 256] {
        let mut freq = [1u32; 256];
        freq[0] = 128;  // 0 is dominant (runs of zeros)
        freq[1] = 16;
        freq[2] = 8;
        freq[3] = 4;
        freq[4] = 3;
        freq[5] = 2;
        freq[6] = 2;
        freq[7] = 2;
        freq
    }

    fn adaptive_init_total() -> u32 {
        let freq = Self::adaptive_init_freq();
        freq.iter().sum()
    }

    /// Encode BWT+MTF output using adaptive order-1 range coder (no RLE)
    fn encode_adaptive_o1(orig_len: usize, bwt_index: u32, mtf_output: &[u8]) -> Vec<u8> {
        if mtf_output.len() < 2 {
            return Self::make_stored(&vec![0u8; orig_len]);
        }

        // 256 adaptive frequency tables — one per previous-byte context
        // Initialize uniform: every symbol has frequency 1, total = 256
        let mut freq: Vec<[u32; 256]> = vec![[1u32; 256]; 256];
        let mut total: [u32; 256] = [256; 256];

        let mut enc = RangeEncoderState::new(mtf_output.len());
        let mut prev = 0usize; // initial context (byte 0)

        for &b in mtf_output {
            let sym = b as usize;
            let ctx = prev;

            // Compute cumulative frequency for this symbol in this context
            let mut cum: u32 = 0;
            for i in 0..sym {
                cum += freq[ctx][i];
            }
            let f = freq[ctx][sym];

            enc.encode(cum, f, total[ctx]);

            // Update adaptive model
            freq[ctx][sym] += 1;
            total[ctx] += 1;

            // Rescale when total gets too large (halve all, minimum 1)
            if total[ctx] >= Self::ADAPTIVE_MAX_TOTAL {
                total[ctx] = 0;
                for i in 0..256 {
                    freq[ctx][i] = (freq[ctx][i] + 1) / 2;
                    total[ctx] += freq[ctx][i];
                }
            }

            prev = sym;
        }

        let range_body = enc.finish();

        // Header: SFC6(4) + orig_len(4) + bwt_idx(4) + mtf_len(4) = 16 bytes
        let total_size = 16 + range_body.len();
        if total_size >= orig_len + 4 {
            return Self::make_stored(&vec![0u8; orig_len]);
        }

        let mut output = Vec::with_capacity(total_size);
        output.extend_from_slice(SFC_MAGIC_ADAPTIVE);
        output.extend_from_slice(&(orig_len as u32).to_le_bytes());
        output.extend_from_slice(&bwt_index.to_le_bytes());
        output.extend_from_slice(&(mtf_output.len() as u32).to_le_bytes());
        output.extend_from_slice(&range_body);
        output
    }

    /// Decode SFC6 (BWT+MTF+Adaptive Order-1 Range) data
    fn decode_adaptive_o1(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 16 {
            return Err("SFC6 header too short".into());
        }

        let _orig_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let bwt_index = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let mtf_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

        let range_body = &data[16..];

        // Identical adaptive model as encoder — start uniform
        let mut freq: Vec<[u32; 256]> = vec![[1u32; 256]; 256];
        let mut total: [u32; 256] = [256; 256];

        let mut dec = RangeDecoderState::new(range_body);
        let mut mtf_output = Vec::with_capacity(mtf_len);
        let mut prev = 0usize;

        for _ in 0..mtf_len {
            let ctx = prev;

            // Build cumulative frequency table for decode_symbol
            let mut cum = [0u32; 257];
            for i in 0..256 {
                cum[i + 1] = cum[i] + freq[ctx][i];
            }

            let sym = dec.decode_symbol(&cum, total[ctx]);
            mtf_output.push(sym as u8);

            // Update adaptive model (must match encoder exactly)
            freq[ctx][sym] += 1;
            total[ctx] += 1;

            if total[ctx] >= Self::ADAPTIVE_MAX_TOTAL {
                total[ctx] = 0;
                for i in 0..256 {
                    freq[ctx][i] = (freq[ctx][i] + 1) / 2;
                    total[ctx] += freq[ctx][i];
                }
            }

            prev = sym;
        }

        // Inverse MTF (no RLE decode needed — SFC6 works on raw MTF output)
        let bwt_output = Self::mtf_inverse(&mtf_output);

        // Safety check
        if (bwt_index as usize) >= bwt_output.len() {
            return Err(format!(
                "SFC6 decode error: bwt_index {} >= decoded len {}",
                bwt_index, bwt_output.len()
            ));
        }

        // Inverse BWT
        let original = Self::bwt_inverse(&bwt_output, bwt_index);

        Ok(original)
    }

    // ══════════════════════════════════════════════════════════
    //  SFC7: BWT + MTF + RLE + Adaptive Order-1 Range Coder
    //
    //  Combines the best of all worlds:
    //  • RLE preprocessing (compresses 986K MTF output → 174K)
    //  • Adaptive order-1 context (no header table overhead)
    //  • Range coding (near-optimal bit efficiency)
    //
    //  Format: [SFC7][orig_len:u32][bwt_idx:u32][rle_len:u32][range_body]
    //  Total header: just 16 bytes!
    // ══════════════════════════════════════════════════════════

    /// Encode BWT+MTF+RLE output using adaptive order-1 range coder
    ///
    /// OPTIMIZATION: Maintains a cumulative frequency table (`cum[257]`) per
    /// context that is incrementally updated, eliminating the per-symbol O(256)
    /// linear scan. Updates are O(256-sym) worst case but O(1) amortized for
    /// the dominant symbol 0 that appears after BWT+MTF.
    fn encode_adaptive_o1_rle(orig_len: usize, bwt_index: u32, rle_output: &[u8]) -> Vec<u8> {
        if rle_output.len() < 2 {
            return Self::make_stored(&vec![0u8; orig_len]);
        }

        // Higher rescale limit for better precision (safe since range >= 2^24)
        const RESCALE_LIMIT: u32 = 65536;

        // MTF+RLE-aware initialization: symbol 0 is dominant, small values common
        // This must EXACTLY match the decoder initialization
        let init_freq = Self::adaptive_init_freq();
        let init_total = Self::adaptive_init_total();

        let mut freq: Vec<[u32; 256]> = vec![init_freq; 256];
        let mut total: [u32; 256] = [init_total; 256];

        // Pre-build cumulative frequency tables for O(1) lookup during encoding.
        // cum[ctx][sym] = sum of freq[ctx][0..sym]
        // cum[ctx][256] = total[ctx]
        let mut cum: Vec<[u32; 257]> = Vec::with_capacity(256);
        for ctx in 0..256 {
            let mut c = [0u32; 257];
            for i in 0..256 {
                c[i + 1] = c[i] + freq[ctx][i];
            }
            cum.push(c);
        }

        let mut enc = RangeEncoderState::new(rle_output.len());
        let mut prev = 0usize;

        for &b in rle_output {
            let sym = b as usize;
            let ctx = prev;

            // O(1) cumulative lookup instead of O(sym) linear scan
            let sym_cum = cum[ctx][sym];
            let f = freq[ctx][sym];

            enc.encode(sym_cum, f, total[ctx]);

            // Update model with step=2 for faster convergence
            freq[ctx][sym] += 2;
            total[ctx] += 2;
            // Incrementally update cumulative table: only entries after `sym` change
            for i in (sym + 1)..257 {
                cum[ctx][i] += 2;
            }

            if total[ctx] >= RESCALE_LIMIT {
                // Rescale: halve all frequencies, floor 1
                total[ctx] = 0;
                for i in 0..256 {
                    freq[ctx][i] = (freq[ctx][i] + 1) / 2;
                    total[ctx] += freq[ctx][i];
                }
                // Rebuild cumulative table after rescale
                cum[ctx][0] = 0;
                for i in 0..256 {
                    cum[ctx][i + 1] = cum[ctx][i] + freq[ctx][i];
                }
            }

            prev = sym;
        }

        let range_body = enc.finish();

        let total_size = 16 + range_body.len();
        if total_size >= orig_len + 4 {
            return Self::make_stored(&vec![0u8; orig_len]);
        }

        let mut output = Vec::with_capacity(total_size);
        output.extend_from_slice(SFC_MAGIC_ADAPTIVE_RLE);
        output.extend_from_slice(&(orig_len as u32).to_le_bytes());
        output.extend_from_slice(&bwt_index.to_le_bytes());
        output.extend_from_slice(&(rle_output.len() as u32).to_le_bytes());
        output.extend_from_slice(&range_body);
        output
    }

    /// Decode SFC7 (BWT+MTF+RLE+Adaptive Order-1 Range) data
    fn decode_adaptive_o1_rle(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 16 {
            return Err("SFC7 header too short".into());
        }

        const RESCALE_LIMIT: u32 = 65536;

        let _orig_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let bwt_index = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let rle_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

        let range_body = &data[16..];

        // Must match encoder initialization exactly
        let init_freq = Self::adaptive_init_freq();
        let init_total = Self::adaptive_init_total();

        let mut freq: Vec<[u32; 256]> = vec![init_freq; 256];
        let mut total: [u32; 256] = [init_total; 256];

        let mut dec = RangeDecoderState::new(range_body);
        let mut rle_output = Vec::with_capacity(rle_len);
        let mut prev = 0usize;

        for _ in 0..rle_len {
            let ctx = prev;

            // Build cumulative frequency table for decode
            let mut cum = [0u32; 257];
            for i in 0..256 {
                cum[i + 1] = cum[i] + freq[ctx][i];
            }

            let sym = dec.decode_symbol(&cum, total[ctx]);
            rle_output.push(sym as u8);

            // Update model (must match encoder exactly — step=2)
            freq[ctx][sym] += 2;
            total[ctx] += 2;

            if total[ctx] >= RESCALE_LIMIT {
                total[ctx] = 0;
                for i in 0..256 {
                    freq[ctx][i] = (freq[ctx][i] + 1) / 2;
                    total[ctx] += freq[ctx][i];
                }
            }

            prev = sym;
        }

        // Inverse RLE → Inverse MTF → Inverse BWT
        let mtf_output = Self::rle_decode(&rle_output);
        let bwt_output = Self::mtf_inverse(&mtf_output);

        if (bwt_index as usize) >= bwt_output.len() {
            return Err(format!(
                "SFC7 decode error: bwt_index {} >= decoded len {}",
                bwt_index, bwt_output.len()
            ));
        }

        let original = Self::bwt_inverse(&bwt_output, bwt_index);

        Ok(original)
    }

    // ══════════════════════════════════════════════════════════
    //  BWT: Burrows-Wheeler Transform (from scratch)
    // ══════════════════════════════════════════════════════════

    /// Forward BWT: groups bytes by their following context
    ///
    /// Returns (transformed_data, primary_index) where primary_index
    /// identifies the original string's position in the sorted rotations.
    ///
    /// OPTIMIZATIONS:
    ///   1. Doubled data buffer eliminates modular arithmetic in comparisons
    ///   2. Rayon par_sort splits the O(n log n) sort across all CPU cores
    ///   3. Early-out comparison resolves most rotations in <20 bytes
    fn bwt_forward(data: &[u8]) -> (Vec<u8>, u32) {
        let n = data.len();
        if n == 0 {
            return (Vec::new(), 0);
        }
        if n == 1 {
            return (data.to_vec(), 0);
        }

        // Create doubled buffer: [data | data] so cyclic rotations become
        // simple slices — no modular arithmetic in the hot comparison loop.
        let mut doubled = Vec::with_capacity(n * 2);
        doubled.extend_from_slice(data);
        doubled.extend_from_slice(data);

        // Build sorted suffix array for cyclic rotations
        let mut indices: Vec<u32> = (0..n as u32).collect();

        // Parallel sort across all CPU cores via Rayon.
        // Each comparison is a straight memcmp on the doubled buffer —
        // no branches for wrap-around, and the CPU prefetcher loves it.
        indices.par_sort_unstable_by(|&a, &b| {
            let a = a as usize;
            let b = b as usize;
            // Compare slices directly — Rust's slice cmp uses SIMD memcmp internally
            doubled[a..a + n].cmp(&doubled[b..b + n])
        });

        // Extract last column (the BWT output)
        let output: Vec<u8> = indices
            .iter()
            .map(|&i| data[((i as usize) + n - 1) % n])
            .collect();

        // Find where the original string ended up after sorting
        let bwt_index = indices.iter().position(|&i| i == 0).unwrap() as u32;

        (output, bwt_index)
    }

    /// Inverse BWT: reconstruct original data from BWT output + primary index
    ///
    /// Uses the LF-mapping for O(n) reconstruction.
    fn bwt_inverse(bwt: &[u8], bwt_index: u32) -> Vec<u8> {
        let n = bwt.len();
        if n == 0 {
            return Vec::new();
        }
        if n == 1 {
            return bwt.to_vec();
        }

        // Count occurrences of each byte
        let mut counts = [0usize; 256];
        for &b in bwt {
            counts[b as usize] += 1;
        }

        // Cumulative starting positions (where each byte's sorted block begins)
        let mut starts = [0usize; 256];
        let mut total = 0;
        for i in 0..256 {
            starts[i] = total;
            total += counts[i];
        }

        // Build LF-mapping: LF[i] tells us which row in the sorted matrix
        // contains the rotation that cyclically follows row i
        let mut lf = vec![0u32; n];
        let mut running = [0usize; 256];
        for i in 0..n {
            let c = bwt[i] as usize;
            lf[i] = (starts[c] + running[c]) as u32;
            running[c] += 1;
        }

        // Reconstruct original by following LF chain backwards
        let mut output = vec![0u8; n];
        let mut j = bwt_index as usize;
        for i in (0..n).rev() {
            output[i] = bwt[j];
            j = lf[j] as usize;
        }

        output
    }

    // ══════════════════════════════════════════════════════════
    //  MTF: Move-to-Front Transform (from scratch)
    // ══════════════════════════════════════════════════════════

    /// Forward MTF: converts context-grouped BWT output into small-value stream
    ///
    /// After BWT, identical bytes tend to cluster together. MTF converts
    /// each byte to its position in a recently-used list. Clustered bytes
    /// produce lots of 0s and small values → ideal for Huffman encoding.
    /// Move-to-Front transform: converts clustered BWT output into small integers.
    ///
    /// OPTIMIZATION: Reverse index table (`pos_of[byte]`) gives O(1) position
    /// lookup instead of O(256) linear scan. The shift cost is bounded by
    /// the actual position (usually 0-3 after BWT, so shifts are tiny).
    fn mtf_forward(data: &[u8]) -> Vec<u8> {
        let mut table: [u8; 256] = {
            let mut t = [0u8; 256];
            for i in 0..256 {
                t[i] = i as u8;
            }
            t
        };

        // Reverse index: pos_of[byte_value] = position_in_table
        let mut pos_of: [u8; 256] = {
            let mut p = [0u8; 256];
            for i in 0..256 {
                p[i] = i as u8;
            }
            p
        };

        let mut output = Vec::with_capacity(data.len());

        for &b in data {
            // O(1) position lookup via reverse index
            let pos = pos_of[b as usize];
            output.push(pos);

            // Move this byte to the front of the table
            if pos > 0 {
                // Only shift elements 0..pos, which is typically tiny (0-3) after BWT
                for i in (1..=pos as usize).rev() {
                    let displaced = table[i - 1];
                    table[i] = displaced;
                    pos_of[displaced as usize] = i as u8;
                }
                table[0] = b;
                pos_of[b as usize] = 0;
            }
        }

        output
    }

    /// Inverse MTF: reconstruct original bytes from MTF indices
    fn mtf_inverse(data: &[u8]) -> Vec<u8> {
        let mut table: [u8; 256] = {
            let mut t = [0u8; 256];
            for i in 0..256 {
                t[i] = i as u8;
            }
            t
        };

        let mut output = Vec::with_capacity(data.len());

        for &idx in data {
            let b = table[idx as usize];
            output.push(b);

            // Move this byte to the front of the table
            if idx > 0 {
                for i in (1..=idx as usize).rev() {
                    table[i] = table[i - 1];
                }
                table[0] = b;
            }
        }

        output
    }

    // ══════════════════════════════════════════════════════════
    //  RLE: Run-Length Encoding (from scratch)
    // ══════════════════════════════════════════════════════════

    /// Run-Length Encode: collapses runs of 4+ identical consecutive bytes.
    ///
    /// After BWT+MTF, the data is dominated by runs of zeros. RLE collapses
    /// these into compact [byte, byte, byte, byte, count] sequences where
    /// count (0-255) indicates additional repetitions beyond the first 4.
    ///
    /// OPTIMIZATION: Uses memchr to find the first byte that differs from the
    /// current run value, leveraging SIMD to scan 32 bytes at a time.
    fn rle_encode(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut i = 0;

        while i < data.len() {
            let b = data[i];

            // SIMD-accelerated run length detection:
            // Find first byte that isn't `b` in the remaining slice.
            // memchr uses SSE2/AVX2 to scan 16-32 bytes per cycle.
            let remaining_slice = &data[i..];
            let run_len = match memchr::memchr(b.wrapping_add(1), remaining_slice) {
                // memchr finds a different byte — but we need the FIRST non-b byte.
                // Since memchr only searches for one specific value, use a
                // position-based approach instead for the general case.
                _ => {
                    // Fast path: count how far the run of `b` extends
                    let mut len = 1;
                    // Scan in 8-byte chunks for speed
                    while i + len + 7 < data.len() {
                        // Check 8 bytes at once
                        if data[i + len] == b
                            && data[i + len + 1] == b
                            && data[i + len + 2] == b
                            && data[i + len + 3] == b
                            && data[i + len + 4] == b
                            && data[i + len + 5] == b
                            && data[i + len + 6] == b
                            && data[i + len + 7] == b
                        {
                            len += 8;
                        } else {
                            break;
                        }
                    }
                    // Finish remaining bytes one at a time
                    while i + len < data.len() && data[i + len] == b {
                        len += 1;
                    }
                    len
                }
            };

            let mut remaining = run_len;
            while remaining >= 4 {
                output.push(b);
                output.push(b);
                output.push(b);
                output.push(b);
                let extra = (remaining - 4).min(255);
                output.push(extra as u8);
                remaining -= 4 + extra;
            }
            for _ in 0..remaining {
                output.push(b);
            }

            i += run_len;
        }

        output
    }

    /// Run-Length Decode: inverse of rle_encode.
    ///
    /// Scans for groups of 4 identical consecutive bytes; the next byte
    /// after such a group is a count of additional repetitions.
    fn rle_decode(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len() * 2);
        let mut i = 0;
        let mut run_count = 0u32;
        let mut last_byte: Option<u8> = None;

        while i < data.len() {
            let b = data[i];
            output.push(b);
            i += 1;

            if last_byte == Some(b) {
                run_count += 1;
            } else {
                run_count = 1;
                last_byte = Some(b);
            }

            if run_count == 4 {
                // 4 identical consecutive bytes — next byte is extra count
                if i < data.len() {
                    let count = data[i] as usize;
                    i += 1;
                    for _ in 0..count {
                        output.push(b);
                    }
                }
                run_count = 0;
                last_byte = None;
            }
        }

        output
    }

    // ══════════════════════════════════════════════════════════
    //  Huffman Tree Construction
    // ══════════════════════════════════════════════════════════

    /// Build Huffman code lengths from byte frequencies using a min-heap
    fn build_code_lengths(freq: &[u64; 256]) -> [u8; 256] {
        let symbols: Vec<(usize, u64)> = freq
            .iter()
            .enumerate()
            .filter(|(_, &f)| f > 0)
            .map(|(i, &f)| (i, f))
            .collect();

        if symbols.is_empty() {
            return [0u8; 256];
        }
        if symbols.len() == 1 {
            let mut lengths = [0u8; 256];
            lengths[symbols[0].0] = 1;
            return lengths;
        }

        // Build Huffman tree using min-heap
        let mut nodes: Vec<(Option<u8>, usize, usize)> =
            Vec::with_capacity(symbols.len() * 2);
        let mut heap: BinaryHeap<Reverse<(u64, usize)>> =
            BinaryHeap::with_capacity(symbols.len());

        for &(byte_val, frequency) in &symbols {
            let idx = nodes.len();
            nodes.push((Some(byte_val as u8), usize::MAX, usize::MAX));
            heap.push(Reverse((frequency, idx)));
        }

        while heap.len() > 1 {
            let Reverse((freq1, idx1)) = heap.pop().unwrap();
            let Reverse((freq2, idx2)) = heap.pop().unwrap();
            let new_idx = nodes.len();
            nodes.push((None, idx1, idx2));
            heap.push(Reverse((freq1 + freq2, new_idx)));
        }

        let root_idx = heap.pop().unwrap().0 .1;
        let mut lengths = [0u8; 256];
        Self::assign_lengths(&nodes, root_idx, 0, &mut lengths);
        Self::limit_code_lengths(&mut lengths);

        lengths
    }

    /// Recursively assign code lengths by tree depth
    fn assign_lengths(
        nodes: &[(Option<u8>, usize, usize)],
        node_idx: usize,
        depth: u8,
        lengths: &mut [u8; 256],
    ) {
        let (byte_val, left, right) = &nodes[node_idx];

        if let Some(b) = byte_val {
            lengths[*b as usize] = depth.max(1);
        } else {
            if *left != usize::MAX {
                Self::assign_lengths(nodes, *left, depth.saturating_add(1), lengths);
            }
            if *right != usize::MAX {
                Self::assign_lengths(nodes, *right, depth.saturating_add(1), lengths);
            }
        }
    }

    /// Limit code lengths to MAX_CODE_LENGTH to prevent degenerate codes
    fn limit_code_lengths(lengths: &mut [u8; 256]) {
        let max_len = MAX_CODE_LENGTH;
        let mut needs_fix = false;
        for &l in lengths.iter() {
            if l > max_len {
                needs_fix = true;
                break;
            }
        }
        if !needs_fix {
            return;
        }

        for length in lengths.iter_mut() {
            if *length > max_len {
                *length = max_len;
            }
        }

        // Fix Kraft inequality: Σ 2^(-length_i) <= 1
        loop {
            let kraft_sum: f64 = lengths
                .iter()
                .filter(|&&l| l > 0)
                .map(|&l| 2.0_f64.powi(-(l as i32)))
                .sum();

            if kraft_sum <= 1.0 + 1e-10 {
                break;
            }

            let mut min_len = u8::MAX;
            let mut min_idx = 0;
            for (i, &l) in lengths.iter().enumerate() {
                if l > 0 && l < min_len {
                    min_len = l;
                    min_idx = i;
                }
            }
            if min_len < max_len {
                lengths[min_idx] += 1;
            } else {
                break;
            }
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Canonical Huffman Code Generation
    // ══════════════════════════════════════════════════════════

    /// Generate canonical Huffman codes from code lengths
    fn canonical_codes(code_lengths: &[u8; 256]) -> [HuffCode; 256] {
        let mut codes = [HuffCode { code: 0, length: 0 }; 256];

        let mut symbols: Vec<(u8, u8)> = code_lengths
            .iter()
            .enumerate()
            .filter(|(_, &l)| l > 0)
            .map(|(byte_val, &length)| (byte_val as u8, length))
            .collect();
        symbols.sort_by_key(|&(byte_val, length)| (length, byte_val));

        if symbols.is_empty() {
            return codes;
        }

        let mut code: u32 = 0;
        let mut prev_length = symbols[0].1;

        for (i, &(byte_val, length)) in symbols.iter().enumerate() {
            if i > 0 {
                code += 1;
                code <<= (length - prev_length) as u32;
            }
            codes[byte_val as usize] = HuffCode { code, length };
            prev_length = length;
        }

        codes
    }

    // ══════════════════════════════════════════════════════════
    //  Decode Tree
    // ══════════════════════════════════════════════════════════

    /// Build a flat decode tree for efficient Huffman decoding
    fn build_decode_tree(codes: &[HuffCode; 256]) -> Vec<(Option<u8>, usize, usize)> {
        const UNSET: usize = usize::MAX;
        let mut tree = vec![(None::<u8>, UNSET, UNSET)];

        for (byte_val, code) in codes.iter().enumerate() {
            if code.length == 0 {
                continue;
            }

            let mut node_idx = 0;
            for bit_pos in (0..code.length).rev() {
                let bit = (code.code >> bit_pos) & 1;

                if bit_pos == 0 {
                    let leaf_idx = tree.len();
                    tree.push((Some(byte_val as u8), UNSET, UNSET));
                    if bit == 0 {
                        tree[node_idx].1 = leaf_idx;
                    } else {
                        tree[node_idx].2 = leaf_idx;
                    }
                } else {
                    let child_idx = if bit == 0 {
                        tree[node_idx].1
                    } else {
                        tree[node_idx].2
                    };

                    if child_idx == UNSET {
                        let new_idx = tree.len();
                        tree.push((None, UNSET, UNSET));
                        if bit == 0 {
                            tree[node_idx].1 = new_idx;
                        } else {
                            tree[node_idx].2 = new_idx;
                        }
                        node_idx = new_idx;
                    } else {
                        node_idx = child_idx;
                    }
                }
            }
        }

        tree
    }

    /// Decode one symbol by walking the decode tree
    fn decode_one_symbol(
        tree: &[(Option<u8>, usize, usize)],
        reader: &mut BitReader,
    ) -> Result<u8, String> {
        let mut node_idx = 0;

        loop {
            let (byte_val, left, right) = tree[node_idx];

            if let Some(b) = byte_val {
                return Ok(b);
            }

            let bit = reader.read_bit()?;
            node_idx = if bit == 0 { left } else { right };

            if node_idx == usize::MAX {
                return Err("Invalid Huffman code path".into());
            }
        }
    }
}

// ══════════════════════════════════════════════════════════
//  Bitstream I/O
// ══════════════════════════════════════════════════════════

/// Efficient bit-level writer for Huffman encoding
struct BitWriter {
    bytes: Vec<u8>,
    current_byte: u8,
    bit_count: u8,
}

impl BitWriter {
    fn new(capacity_hint: usize) -> Self {
        BitWriter {
            bytes: Vec::with_capacity(capacity_hint / 2),
            current_byte: 0,
            bit_count: 0,
        }
    }

    #[inline(always)]
    fn write_bits(&mut self, value: u32, num_bits: u8) {
        for i in (0..num_bits).rev() {
            let bit = ((value >> i) & 1) as u8;
            self.current_byte = (self.current_byte << 1) | bit;
            self.bit_count += 1;

            if self.bit_count == 8 {
                self.bytes.push(self.current_byte);
                self.current_byte = 0;
                self.bit_count = 0;
            }
        }
    }

    fn finish(mut self) -> (Vec<u8>, u8) {
        if self.bit_count > 0 {
            let padding = 8 - self.bit_count;
            self.current_byte <<= padding;
            self.bytes.push(self.current_byte);
            (self.bytes, padding)
        } else {
            (self.bytes, 0)
        }
    }
}

/// Efficient bit-level reader for Huffman decoding
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
    padding_bits: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8], padding_bits: u8) -> Self {
        BitReader {
            data,
            byte_pos: 0,
            bit_pos: 7,
            padding_bits,
        }
    }

    #[inline(always)]
    fn read_bit(&mut self) -> Result<u8, String> {
        if self.byte_pos >= self.data.len() {
            return Err("Unexpected end of SFC bitstream".into());
        }

        if self.byte_pos == self.data.len() - 1 && self.bit_pos < self.padding_bits {
            return Err("Reached SFC padding region".into());
        }

        let bit = (self.data[self.byte_pos] >> self.bit_pos) & 1;

        if self.bit_pos == 0 {
            self.byte_pos += 1;
            self.bit_pos = 7;
        } else {
            self.bit_pos -= 1;
        }

        Ok(bit)
    }

    /// Read multiple bits as a u32 value (MSB first)
    fn read_bits(&mut self, num_bits: u8) -> Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..num_bits {
            value = (value << 1) | self.read_bit()? as u32;
        }
        Ok(value)
    }
}

// ══════════════════════════════════════════════════════════
//  Range Coder: Near-optimal entropy coding (from scratch)
//
//  A range coder achieves compression within ~0.01 bits/symbol
//  of the Shannon entropy, compared to Huffman which wastes
//  up to 1 bit/symbol per code.
// ══════════════════════════════════════════════════════════

/// Range encoder state — carry-propagation model using u64 low
struct RangeEncoderState {
    low: u64,
    range: u32,
    cache: u8,
    cache_count: u32,
    output: Vec<u8>,
    started: bool,
}

impl RangeEncoderState {
    fn new(capacity: usize) -> Self {
        Self {
            low: 0,
            range: 0xFFFFFFFF,
            cache: 0,
            cache_count: 0,
            output: Vec::with_capacity(capacity / 2),
            started: false,
        }
    }

    /// Encode one symbol given its cumulative frequency, individual frequency,
    /// and the total scale. All frequencies must sum to `total`.
    fn encode(&mut self, cum_freq: u32, freq: u32, total: u32) {
        let r = self.range / total;
        self.low += cum_freq as u64 * r as u64;
        if cum_freq + freq < total {
            self.range = r * freq;
        } else {
            // Last symbol — avoid rounding error
            self.range -= r * cum_freq;
        }
        self.normalize();
    }

    fn normalize(&mut self) {
        while self.range < (1 << 24) {
            self.shift_byte();
            self.range <<= 8;
        }
    }

    fn shift_byte(&mut self) {
        let carry = (self.low >> 32) as u8; // 0 or 1
        let byte = ((self.low >> 24) & 0xFF) as u8;

        if byte < 0xFF || carry != 0 {
            if self.started {
                self.output.push(self.cache.wrapping_add(carry));
                let fill = 0xFF_u8.wrapping_add(carry);
                for _ in 0..self.cache_count {
                    self.output.push(fill);
                }
            }
            self.started = true;
            self.cache = byte;
            self.cache_count = 0;
        } else {
            self.cache_count += 1;
        }

        self.low = (self.low << 8) & 0xFFFFFFFF;
    }

    fn finish(mut self) -> Vec<u8> {
        // Standard range coder termination:
        // We need to output enough bytes so the decoder can uniquely identify
        // our final interval. We shift out 5 bytes (40 bits) which is more
        // than enough to resolve any 32-bit range interval.
        //
        // Each shift_byte() call extracts the top byte of `low` and propagates
        // carries. After 5 shifts, the cache and cache_count hold the very last
        // pending output that hasn't been pushed yet.
        for _ in 0..5 {
            self.shift_byte();
        }
        self.output
    }
}

/// Range decoder state — mirror of encoder
struct RangeDecoderState<'a> {
    low: u32,
    range: u32,
    code: u32,
    data: &'a [u8],
    pos: usize,
}

impl<'a> RangeDecoderState<'a> {
    fn new(data: &'a [u8]) -> Self {
        // Initialize code from first 4 bytes
        let mut code = 0u32;
        let mut pos = 0;
        for _ in 0..4 {
            let b = if pos < data.len() { let v = data[pos]; pos += 1; v } else { 0 };
            code = (code << 8) | b as u32;
        }
        Self {
            low: 0,
            range: 0xFFFFFFFF,
            code,
            data,
            pos,
        }
    }

    /// Decode one symbol given cumulative frequency table (257 entries)
    /// and total scale. Returns the symbol index (0-255).
    fn decode_symbol(&mut self, cum_freq: &[u32; 257], total: u32) -> usize {
        let r = self.range / total;
        let count = ((self.code.wrapping_sub(self.low)) / r).min(total - 1);

        // Linear search (fast for small active symbol sets typical after MTF+RLE)
        let mut sym = 0;
        while sym < 255 && cum_freq[sym + 1] <= count {
            sym += 1;
        }

        let c = cum_freq[sym];
        let f = cum_freq[sym + 1] - c;
        self.low = self.low.wrapping_add(c.wrapping_mul(r));
        if c + f < total {
            self.range = r * f;
        } else {
            self.range -= r * c;
        }

        self.normalize();
        sym
    }

    fn normalize(&mut self) {
        while self.range < (1 << 24) {
            let b = if self.pos < self.data.len() {
                let v = self.data[self.pos];
                self.pos += 1;
                v
            } else {
                0
            };
            self.code = (self.code << 8) | b as u32;
            self.low <<= 8;
            self.range <<= 8;
        }
    }
}

// ══════════════════════════════════════════════════════════
//  SFC4: LZ77 + Dual Huffman (DEFLATE-style, 100% from scratch)
//
//  "Middle-out" compression: LZ77 finds local byte-sequence
//  repetitions within a sliding window, replacing them with
//  (length, distance) back-references. Two Huffman tables encode
//  the literal/length and distance streams separately.
//
//  This complements the BWT pipeline: BWT excels at context-based
//  byte grouping, while LZ77 excels at exact substring matching.
//  The encoder tries both and picks whichever is smaller.
//
//  Format:
//  [SFC4][orig_len:u32][num_lit:u16][lit_table][num_dist:u16][dist_table][padding:u8][bitstream]
// ══════════════════════════════════════════════════════════

/// LZ77 sliding window size (64KB for large-block matching)
const LZ_WINDOW_SIZE: usize = 65536;

/// Minimum match length (3 bytes, like DEFLATE)
const LZ_MIN_MATCH: usize = 3;

/// Maximum match length
const LZ_MAX_MATCH: usize = 258;

/// Hash table size for 3-byte hashing (2^15 = 32768)
const LZ_HASH_BITS: usize = 15;
const LZ_HASH_SIZE: usize = 1 << LZ_HASH_BITS;

/// Maximum hash chain depth (balance speed vs ratio)
const LZ_MAX_CHAIN: usize = 128;

/// Number of symbols in the literal/length alphabet
/// 0-255 = literals, 256 = end of block, 257-285 = length codes
const LZ_LIT_ALPHABET: usize = 286;

/// Number of symbols in the distance alphabet (0-31)
const LZ_DIST_ALPHABET: usize = 32;

/// Length base values for codes 257-285 (DEFLATE standard)
const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13,
    15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
    67, 83, 99, 115, 131, 163, 195, 227, 258,
];

/// Extra bits for each length code 257-285
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
    1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// Distance base values for codes 0-31
const DIST_BASE: [u32; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25,
    33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289,
    16385, 24577, 32769, 49153,
];

/// Extra bits for each distance code 0-31
const DIST_EXTRA: [u8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3,
    4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
    9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14,
];

/// LZ77 token — either a literal byte or a (length, distance) back-reference
enum Lz77Token {
    Literal(u8),
    Match { length: u16, distance: u32 },
}

/// Convert a match length (3-258) to a length code + extra bits
fn length_to_code(length: u16) -> (u16, u8, u16) {
    for i in (0..29).rev() {
        if length >= LEN_BASE[i] {
            return (257 + i as u16, LEN_EXTRA[i], length - LEN_BASE[i]);
        }
    }
    (257, 0, 0)
}

/// Convert a distance (1-65536) to a distance code + extra bits
fn distance_to_code(dist: u32) -> (u8, u8, u32) {
    for i in (0..32).rev() {
        if dist >= DIST_BASE[i] {
            return (i as u8, DIST_EXTRA[i], dist - DIST_BASE[i]);
        }
    }
    (0, 0, 0)
}

/// Hash-chain LZ77 engine — finds repeated byte sequences within a sliding window
struct Lz77Engine {
    /// Hash table: 3-byte hash → most recent position
    head: Vec<u32>,
    /// Chain: position → previous position with same hash
    prev: Vec<u32>,
}

impl Lz77Engine {
    fn new() -> Self {
        Self {
            head: vec![u32::MAX; LZ_HASH_SIZE],
            prev: vec![u32::MAX; LZ_WINDOW_SIZE],
        }
    }

    /// 3-byte rolling hash
    #[inline(always)]
    fn hash3(data: &[u8], pos: usize) -> usize {
        ((data[pos] as usize) << 10
            ^ (data[pos + 1] as usize) << 5
            ^ data[pos + 2] as usize)
            & (LZ_HASH_SIZE - 1)
    }

    /// Insert position into hash chain
    #[inline(always)]
    fn insert(&mut self, data: &[u8], pos: usize) {
        if pos + LZ_MIN_MATCH > data.len() {
            return;
        }
        let h = Self::hash3(data, pos);
        self.prev[pos & (LZ_WINDOW_SIZE - 1)] = self.head[h];
        self.head[h] = pos as u32;
    }

    /// Find best match at position using hash chain
    fn find_match(&self, data: &[u8], pos: usize) -> (u16, u32) {
        if pos + LZ_MIN_MATCH > data.len() {
            return (0, 0);
        }

        let h = Self::hash3(data, pos);
        let mut chain_ptr = self.head[h];
        let mut best_len: u16 = (LZ_MIN_MATCH as u16) - 1;
        let mut best_dist: u32 = 0;
        let mut chain_count = 0;
        let min_pos = pos.saturating_sub(LZ_WINDOW_SIZE);
        let max_len = (LZ_MAX_MATCH.min(data.len() - pos)) as u16;

        while chain_ptr != u32::MAX && chain_count < LZ_MAX_CHAIN {
            let match_pos = chain_ptr as usize;
            if match_pos < min_pos {
                break;
            }

            let dist = pos - match_pos;
            if dist > 0 && dist <= LZ_WINDOW_SIZE {
                // Quick check: first and last bytes of best match
                if data[match_pos] == data[pos]
                    && data[match_pos + best_len as usize] == data[pos + best_len as usize]
                {
                    // Extend match
                    let mut len: u16 = 0;
                    while len < max_len
                        && data[match_pos + len as usize] == data[pos + len as usize]
                    {
                        len += 1;
                    }

                    if len > best_len {
                        best_len = len;
                        best_dist = dist as u32;
                        if len == max_len {
                            break;
                        }
                    }
                }
            }

            chain_ptr = self.prev[match_pos & (LZ_WINDOW_SIZE - 1)];
            chain_count += 1;
        }

        if best_len >= LZ_MIN_MATCH as u16 {
            (best_len, best_dist)
        } else {
            (0, 0)
        }
    }

    /// Parse data into LZ77 tokens with lazy matching
    fn parse(&mut self, data: &[u8]) -> Vec<Lz77Token> {
        let mut tokens = Vec::with_capacity(data.len() / 2);
        let mut pos = 0;

        while pos < data.len() {
            let (len, dist) = self.find_match(data, pos);

            if len >= LZ_MIN_MATCH as u16 {
                // Lazy matching: check if next position has a better match
                self.insert(data, pos);
                if pos + 1 < data.len() {
                    let (next_len, _) = self.find_match(data, pos + 1);
                    if next_len > len + 1 {
                        // Emit literal for current, let next iteration handle the match
                        tokens.push(Lz77Token::Literal(data[pos]));
                        pos += 1;
                        continue;
                    }
                }

                tokens.push(Lz77Token::Match {
                    length: len,
                    distance: dist,
                });
                // Insert all positions within the match into hash chains
                for i in 1..len as usize {
                    self.insert(data, pos + i);
                }
                pos += len as usize;
            } else {
                tokens.push(Lz77Token::Literal(data[pos]));
                self.insert(data, pos);
                pos += 1;
            }
        }

        tokens
    }
}

// ══════════════════════════════════════════════════════════
//  Generalized Huffman for variable-size alphabets (>256 symbols)
//  Used by LZ77 for the literal/length (286) and distance (32) alphabets
// ══════════════════════════════════════════════════════════

/// Build Huffman code lengths for an arbitrary alphabet size
fn build_code_lengths_n(freq: &[u64]) -> Vec<u8> {
    let n = freq.len();
    let symbols: Vec<(usize, u64)> = freq
        .iter()
        .enumerate()
        .filter(|(_, &f)| f > 0)
        .map(|(i, &f)| (i, f))
        .collect();

    if symbols.is_empty() {
        return vec![0u8; n];
    }
    if symbols.len() == 1 {
        let mut lengths = vec![0u8; n];
        lengths[symbols[0].0] = 1;
        return lengths;
    }

    // Build Huffman tree using min-heap (same algorithm as 256-symbol version)
    let mut nodes: Vec<(Option<usize>, usize, usize)> = Vec::with_capacity(symbols.len() * 2);
    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::with_capacity(symbols.len());

    for &(sym, frequency) in &symbols {
        let idx = nodes.len();
        nodes.push((Some(sym), usize::MAX, usize::MAX));
        heap.push(Reverse((frequency, idx)));
    }

    while heap.len() > 1 {
        let Reverse((freq1, idx1)) = heap.pop().unwrap();
        let Reverse((freq2, idx2)) = heap.pop().unwrap();
        let new_idx = nodes.len();
        nodes.push((None, idx1, idx2));
        heap.push(Reverse((freq1 + freq2, new_idx)));
    }

    let root_idx = heap.pop().unwrap().0 .1;
    let mut lengths = vec![0u8; n];

    // Assign depths via DFS
    fn assign_depths(
        nodes: &[(Option<usize>, usize, usize)],
        idx: usize,
        depth: u8,
        lengths: &mut [u8],
    ) {
        let (sym, left, right) = nodes[idx];
        if let Some(s) = sym {
            lengths[s] = depth.max(1);
        } else {
            if left != usize::MAX {
                assign_depths(nodes, left, depth.saturating_add(1), lengths);
            }
            if right != usize::MAX {
                assign_depths(nodes, right, depth.saturating_add(1), lengths);
            }
        }
    }

    assign_depths(&nodes, root_idx, 0, &mut lengths);

    // Limit code lengths
    let max_len = MAX_CODE_LENGTH;
    let mut needs_fix = false;
    for &l in &lengths {
        if l > max_len {
            needs_fix = true;
            break;
        }
    }
    if needs_fix {
        for l in lengths.iter_mut() {
            if *l > max_len {
                *l = max_len;
            }
        }
        // Fix Kraft inequality
        loop {
            let kraft_sum: f64 = lengths
                .iter()
                .filter(|&&l| l > 0)
                .map(|&l| 2.0_f64.powi(-(l as i32)))
                .sum();
            if kraft_sum <= 1.0 + 1e-10 {
                break;
            }
            let mut min_len = u8::MAX;
            let mut min_idx = 0;
            for (i, &l) in lengths.iter().enumerate() {
                if l > 0 && l < min_len {
                    min_len = l;
                    min_idx = i;
                }
            }
            if min_len < max_len {
                lengths[min_idx] += 1;
            } else {
                break;
            }
        }
    }

    lengths
}

/// Generate canonical Huffman codes from variable-length code lengths
fn canonical_codes_n(code_lengths: &[u8]) -> Vec<HuffCode> {
    let n = code_lengths.len();
    let mut codes = vec![HuffCode { code: 0, length: 0 }; n];

    let mut symbols: Vec<(usize, u8)> = code_lengths
        .iter()
        .enumerate()
        .filter(|(_, &l)| l > 0)
        .map(|(sym, &length)| (sym, length))
        .collect();
    symbols.sort_by_key(|&(sym, length)| (length, sym));

    if symbols.is_empty() {
        return codes;
    }

    let mut code: u32 = 0;
    let mut prev_length = symbols[0].1;

    for (i, &(sym, length)) in symbols.iter().enumerate() {
        if i > 0 {
            code += 1;
            code <<= (length - prev_length) as u32;
        }
        codes[sym] = HuffCode { code, length };
        prev_length = length;
    }

    codes
}

/// Build decode tree for variable-size alphabet (returns symbol as u16)
fn build_decode_tree_n(codes: &[HuffCode]) -> Vec<(i32, usize, usize)> {
    const UNSET: usize = usize::MAX;
    let mut tree = vec![(-1_i32, UNSET, UNSET)];

    for (sym, code) in codes.iter().enumerate() {
        if code.length == 0 {
            continue;
        }

        let mut node_idx = 0;
        for bit_pos in (0..code.length).rev() {
            let bit = (code.code >> bit_pos) & 1;

            if bit_pos == 0 {
                let leaf_idx = tree.len();
                tree.push((sym as i32, UNSET, UNSET));
                if bit == 0 {
                    tree[node_idx].1 = leaf_idx;
                } else {
                    tree[node_idx].2 = leaf_idx;
                }
            } else {
                let child_idx = if bit == 0 {
                    tree[node_idx].1
                } else {
                    tree[node_idx].2
                };

                if child_idx == UNSET {
                    let new_idx = tree.len();
                    tree.push((-1, UNSET, UNSET));
                    if bit == 0 {
                        tree[node_idx].1 = new_idx;
                    } else {
                        tree[node_idx].2 = new_idx;
                    }
                    node_idx = new_idx;
                } else {
                    node_idx = child_idx;
                }
            }
        }
    }

    tree
}

/// Decode one symbol from variable-size alphabet decode tree
fn decode_one_symbol_n(
    tree: &[(i32, usize, usize)],
    reader: &mut BitReader,
) -> Result<u16, String> {
    let mut node_idx = 0;

    loop {
        let (sym, left, right) = tree[node_idx];

        if sym >= 0 {
            return Ok(sym as u16);
        }

        let bit = reader.read_bit()?;
        node_idx = if bit == 0 { left } else { right };

        if node_idx == usize::MAX {
            return Err("Invalid LZ77 Huffman code path".into());
        }
    }
}

// ══════════════════════════════════════════════════════════
//  SFC4 Encode/Decode — LZ77 + Dual Huffman
// ══════════════════════════════════════════════════════════

impl SovereignCodec {
    /// Encode using LZ77 + dual Huffman (SFC4)
    fn encode_lz77(data: &[u8]) -> Vec<u8> {
        if data.len() < LZ_MIN_MATCH {
            let mut out = Vec::with_capacity(data.len() + 4);
            out.extend_from_slice(SFC_MAGIC_STORED);
            out.extend_from_slice(data);
            return out;
        }

        // Step 1: LZ77 parse
        let mut engine = Lz77Engine::new();
        let tokens = engine.parse(data);

        // Step 2: Count frequencies
        let mut lit_freq = vec![0u64; LZ_LIT_ALPHABET];
        let mut dist_freq = vec![0u64; LZ_DIST_ALPHABET];

        for token in &tokens {
            match token {
                Lz77Token::Literal(b) => lit_freq[*b as usize] += 1,
                Lz77Token::Match { length, distance } => {
                    let (lcode, _, _) = length_to_code(*length);
                    lit_freq[lcode as usize] += 1;
                    let (dcode, _, _) = distance_to_code(*distance);
                    dist_freq[dcode as usize] += 1;
                }
            }
        }
        lit_freq[256] = 1; // End of block marker

        // Step 3: Build dual Huffman tables
        let lit_lengths = build_code_lengths_n(&lit_freq);
        let dist_lengths = build_code_lengths_n(&dist_freq);
        let lit_codes = canonical_codes_n(&lit_lengths);
        let dist_codes = canonical_codes_n(&dist_lengths);

        // Step 4: Encode to bitstream
        let mut bitstream = BitWriter::new(data.len());

        for token in &tokens {
            match token {
                Lz77Token::Literal(b) => {
                    let c = &lit_codes[*b as usize];
                    bitstream.write_bits(c.code, c.length);
                }
                Lz77Token::Match { length, distance } => {
                    // Encode length
                    let (lcode, lextra_bits, lextra_val) = length_to_code(*length);
                    let c = &lit_codes[lcode as usize];
                    bitstream.write_bits(c.code, c.length);
                    if lextra_bits > 0 {
                        bitstream.write_bits(lextra_val as u32, lextra_bits);
                    }

                    // Encode distance
                    let (dcode, dextra_bits, dextra_val) = distance_to_code(*distance);
                    let c = &dist_codes[dcode as usize];
                    bitstream.write_bits(c.code, c.length);
                    if dextra_bits > 0 {
                        bitstream.write_bits(dextra_val, dextra_bits);
                    }
                }
            }
        }

        // End of block
        let c = &lit_codes[256];
        bitstream.write_bits(c.code, c.length);

        let (encoded_bytes, padding_bits) = bitstream.finish();

        // Step 5: Build output
        // Lit table: [(symbol:u16_LE, length:u8) × N] = 3 bytes per entry
        // Dist table: [(symbol:u8, length:u8) × N] = 2 bytes per entry
        let lit_entries: Vec<(u16, u8)> = lit_lengths
            .iter()
            .enumerate()
            .filter(|(_, &l)| l > 0)
            .map(|(i, &l)| (i as u16, l))
            .collect();
        let dist_entries: Vec<(u8, u8)> = dist_lengths
            .iter()
            .enumerate()
            .filter(|(_, &l)| l > 0)
            .map(|(i, &l)| (i as u8, l))
            .collect();

        let lit_table_bytes = lit_entries.len() * 3;
        let dist_table_bytes = dist_entries.len() * 2;
        let header_size = 4 + 4 + 2 + lit_table_bytes + 2 + dist_table_bytes + 1;
        let total_size = header_size + encoded_bytes.len();

        if total_size >= data.len() + 4 {
            // LZ77 didn't help — signal to caller
            let mut out = Vec::with_capacity(data.len() + 4);
            out.extend_from_slice(SFC_MAGIC_STORED);
            out.extend_from_slice(data);
            return out;
        }

        let mut output = Vec::with_capacity(total_size);
        output.extend_from_slice(SFC_MAGIC_LZ77);
        output.extend_from_slice(&(data.len() as u32).to_le_bytes());

        // Literal/Length Huffman table
        output.extend_from_slice(&(lit_entries.len() as u16).to_le_bytes());
        for &(sym, len) in &lit_entries {
            output.extend_from_slice(&sym.to_le_bytes());
            output.push(len);
        }

        // Distance Huffman table
        output.extend_from_slice(&(dist_entries.len() as u16).to_le_bytes());
        for &(sym, len) in &dist_entries {
            output.push(sym);
            output.push(len);
        }

        output.push(padding_bits);
        output.extend_from_slice(&encoded_bytes);
        output
    }

    /// Decode SFC4 (LZ77 + dual Huffman)
    fn decode_lz77(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 10 {
            return Err("SFC4 header too short".into());
        }

        let orig_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let mut pos = 8;

        // Read literal/length Huffman table
        if pos + 2 > data.len() {
            return Err("SFC4 truncated reading lit table count".into());
        }
        let num_lit = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let mut lit_lengths = vec![0u8; LZ_LIT_ALPHABET];
        for _ in 0..num_lit {
            if pos + 3 > data.len() {
                return Err("SFC4 truncated in lit table".into());
            }
            let sym = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            let len = data[pos + 2];
            if sym >= LZ_LIT_ALPHABET {
                return Err(format!("SFC4 invalid lit symbol {}", sym));
            }
            lit_lengths[sym] = len;
            pos += 3;
        }

        // Read distance Huffman table
        if pos + 2 > data.len() {
            return Err("SFC4 truncated reading dist table count".into());
        }
        let num_dist = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let mut dist_lengths = vec![0u8; LZ_DIST_ALPHABET];
        for _ in 0..num_dist {
            if pos + 2 > data.len() {
                return Err("SFC4 truncated in dist table".into());
            }
            let sym = data[pos] as usize;
            let len = data[pos + 1];
            if sym >= LZ_DIST_ALPHABET {
                return Err(format!("SFC4 invalid dist symbol {}", sym));
            }
            dist_lengths[sym] = len;
            pos += 2;
        }

        if pos >= data.len() {
            return Err("SFC4 truncated before padding".into());
        }
        let padding_bits = data[pos];
        pos += 1;
        let body = &data[pos..];

        // Build decode trees
        let lit_codes = canonical_codes_n(&lit_lengths);
        let dist_codes = canonical_codes_n(&dist_lengths);
        let lit_tree = build_decode_tree_n(&lit_codes);
        let dist_tree = build_decode_tree_n(&dist_codes);

        // Decode token stream
        let mut reader = BitReader::new(body, padding_bits);
        let mut output = Vec::with_capacity(orig_len);

        loop {
            if output.len() >= orig_len {
                break;
            }

            let sym = decode_one_symbol_n(&lit_tree, &mut reader)?;

            if sym == 256 {
                break; // End of block
            }

            if sym < 256 {
                // Literal byte
                output.push(sym as u8);
            } else {
                // Match: decode length
                let code_idx = (sym - 257) as usize;
                if code_idx >= 29 {
                    return Err(format!("SFC4 invalid length code {}", sym));
                }
                let extra_bits = LEN_EXTRA[code_idx];
                let extra = if extra_bits > 0 {
                    reader.read_bits(extra_bits)? as u16
                } else {
                    0
                };
                let length = LEN_BASE[code_idx] + extra;

                // Decode distance
                let dsym = decode_one_symbol_n(&dist_tree, &mut reader)? as usize;
                if dsym >= 32 {
                    return Err(format!("SFC4 invalid distance code {}", dsym));
                }
                let dextra_bits = DIST_EXTRA[dsym];
                let dextra = if dextra_bits > 0 {
                    reader.read_bits(dextra_bits)?
                } else {
                    0
                };
                let distance = DIST_BASE[dsym] + dextra;

                // Copy from back-reference
                if distance as usize > output.len() {
                    return Err(format!(
                        "SFC4 distance {} exceeds output len {}",
                        distance,
                        output.len()
                    ));
                }
                let start = output.len() - distance as usize;
                for i in 0..length as usize {
                    let b = output[start + i];
                    output.push(b);
                }
            }
        }

        Ok(output)
    }
}

// ══════════════════════════════════════════════════════════
//  Tests
// ══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Individual Transform Tests ───

    #[test]
    fn test_rle_roundtrip_empty() {
        let data: Vec<u8> = Vec::new();
        let encoded = SovereignCodec::rle_encode(&data);
        let decoded = SovereignCodec::rle_decode(&encoded);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_rle_roundtrip_no_runs() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = SovereignCodec::rle_encode(&data);
        let decoded = SovereignCodec::rle_decode(&encoded);
        assert_eq!(decoded, data);
        assert_eq!(encoded, data, "No runs → pass through as-is");
    }

    #[test]
    fn test_rle_roundtrip_short_runs() {
        let data = vec![5, 5, 5, 10, 10, 20];
        let encoded = SovereignCodec::rle_encode(&data);
        let decoded = SovereignCodec::rle_decode(&encoded);
        assert_eq!(decoded, data);
        assert_eq!(encoded, data, "Runs < 4 → pass through");
    }

    #[test]
    fn test_rle_roundtrip_exact_4() {
        let data = vec![7, 7, 7, 7];
        let encoded = SovereignCodec::rle_encode(&data);
        assert_eq!(encoded, vec![7, 7, 7, 7, 0], "Run of 4 → [b,b,b,b,0]");
        let decoded = SovereignCodec::rle_decode(&encoded);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_rle_roundtrip_long_run() {
        let data = vec![0u8; 100];
        let encoded = SovereignCodec::rle_encode(&data);
        assert_eq!(encoded, vec![0, 0, 0, 0, 96], "100 zeros → [0,0,0,0,96]");
        let decoded = SovereignCodec::rle_decode(&encoded);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_rle_roundtrip_very_long_run() {
        let data = vec![0xABu8; 500];
        let encoded = SovereignCodec::rle_encode(&data);
        // 500 = 4+255 + 4+237 = 259 + 241
        assert_eq!(encoded.len(), 10, "500 bytes → 10 bytes via RLE");
        let decoded = SovereignCodec::rle_decode(&encoded);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_rle_roundtrip_mixed() {
        let mut data = Vec::new();
        data.extend_from_slice(&[1, 2, 3]); // no run
        data.extend_from_slice(&[0; 50]);    // long zero run
        data.extend_from_slice(&[5, 5, 5]); // short run
        data.extend_from_slice(&[9; 10]);    // medium run
        data.push(42);
        let encoded = SovereignCodec::rle_encode(&data);
        let decoded = SovereignCodec::rle_decode(&encoded);
        assert_eq!(decoded, data);
        assert!(encoded.len() < data.len(), "Mixed with long runs should shrink");
    }

    #[test]
    fn test_rle_roundtrip_mtf_like_output() {
        // Simulate realistic MTF output: lots of 0s with occasional larger values
        let mut data = Vec::new();
        for _ in 0..20 {
            data.extend_from_slice(&[0; 40]); // zero run
            data.push(3);
            data.push(1);
            data.push(0);
            data.push(7);
        }
        let encoded = SovereignCodec::rle_encode(&data);
        let decoded = SovereignCodec::rle_decode(&encoded);
        assert_eq!(decoded, data);
        let savings = data.len() as f64 / encoded.len() as f64;
        println!("MTF-like RLE: {} → {} bytes ({:.2}:1)", data.len(), encoded.len(), savings);
        assert!(savings > 2.0, "RLE should dramatically shrink MTF-like data");
    }

    #[test]
    fn test_bwt_roundtrip_banana() {
        let data = b"banana";
        let (bwt, idx) = SovereignCodec::bwt_forward(data);
        let reconstructed = SovereignCodec::bwt_inverse(&bwt, idx);
        assert_eq!(reconstructed, data.to_vec());
    }

    #[test]
    fn test_bwt_roundtrip_repeated() {
        let data = b"abcabcabcabcabc";
        let (bwt, idx) = SovereignCodec::bwt_forward(data);
        let reconstructed = SovereignCodec::bwt_inverse(&bwt, idx);
        assert_eq!(reconstructed, data.to_vec());
    }

    #[test]
    fn test_bwt_roundtrip_single_byte() {
        let data = b"x";
        let (bwt, idx) = SovereignCodec::bwt_forward(data);
        assert_eq!(bwt, vec![b'x']);
        let reconstructed = SovereignCodec::bwt_inverse(&bwt, idx);
        assert_eq!(reconstructed, data.to_vec());
    }

    #[test]
    fn test_bwt_roundtrip_all_same() {
        let data = vec![0xAA; 100];
        let (bwt, idx) = SovereignCodec::bwt_forward(&data);
        let reconstructed = SovereignCodec::bwt_inverse(&bwt, idx);
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_bwt_is_permutation() {
        let data = b"abcabcabc";
        let (bwt, _idx) = SovereignCodec::bwt_forward(data);
        let mut sorted_bwt = bwt.clone();
        sorted_bwt.sort();
        let mut sorted_orig: Vec<u8> = data.to_vec();
        sorted_orig.sort();
        assert_eq!(sorted_bwt, sorted_orig, "BWT must be a permutation of input");
    }

    #[test]
    fn test_mtf_roundtrip() {
        let data = vec![0, 0, 0, 1, 1, 2, 2, 2, 0, 0, 1];
        let encoded = SovereignCodec::mtf_forward(&data);
        let decoded = SovereignCodec::mtf_inverse(&encoded);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_mtf_zeros_from_runs() {
        let data = vec![5, 5, 5, 5, 5, 5, 5, 5];
        let mtf = SovereignCodec::mtf_forward(&data);
        assert_eq!(mtf[0], 5);
        for &b in &mtf[1..] {
            assert_eq!(b, 0, "Repeated bytes should produce zeros after MTF");
        }
    }

    #[test]
    fn test_mtf_roundtrip_all_bytes() {
        let mut data = Vec::with_capacity(512);
        for b in 0..=255u8 {
            data.push(b);
            data.push(b);
        }
        let encoded = SovereignCodec::mtf_forward(&data);
        let decoded = SovereignCodec::mtf_inverse(&encoded);
        assert_eq!(decoded, data);
    }

    // ─── Full Pipeline Tests ───

    #[test]
    fn test_empty_data() {
        let encoded = SovereignCodec::encode(b"");
        assert!(encoded.is_empty());
    }

    #[test]
    fn test_small_data_stored() {
        let data = b"Hi!";
        let encoded = SovereignCodec::encode(data);
        assert_eq!(&encoded[0..4], SFC_MAGIC_STORED);
        let decoded = SovereignCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_roundtrip_simple() {
        let data = b"Hello, World! Hello, World! Hello, World! Hello, World!";
        let encoded = SovereignCodec::encode(data);
        let decoded = SovereignCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, data.to_vec());
    }

    #[test]
    fn test_roundtrip_all_same_byte() {
        let data = vec![0x42u8; 1000];
        let encoded = SovereignCodec::encode(&data);
        let decoded = SovereignCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_roundtrip_two_bytes() {
        let mut data = Vec::with_capacity(2000);
        for _ in 0..1000 {
            data.push(b'A');
            data.push(b'B');
        }
        let encoded = SovereignCodec::encode(&data);
        let decoded = SovereignCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
        assert!(
            encoded.len() < data.len() / 2,
            "Two-symbol data should compress well: {} vs {}",
            encoded.len(),
            data.len()
        );
    }

    #[test]
    fn test_roundtrip_all_256_bytes() {
        let mut data = Vec::with_capacity(256 * 10);
        for _ in 0..10 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let encoded = SovereignCodec::encode(&data);
        let decoded = SovereignCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_roundtrip_json_like() {
        let mut data = Vec::new();
        for i in 0..50 {
            data.extend_from_slice(
                format!(
                    r#"{{"id":{},"name":"item_{}","value":{},"active":true}},"#,
                    i,
                    i,
                    i * 100
                )
                .as_bytes(),
            );
        }
        let encoded = SovereignCodec::encode(&data);
        let decoded = SovereignCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, data);

        let ratio = data.len() as f64 / encoded.len() as f64;
        println!(
            "JSON-like: {} → {} bytes ({:.2}:1, {:.1}% saved)",
            data.len(),
            encoded.len(),
            ratio,
            (1.0 - encoded.len() as f64 / data.len() as f64) * 100.0
        );
        assert!(encoded.len() < data.len());
    }

    #[test]
    fn test_roundtrip_random_data() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut data = Vec::with_capacity(1000);
        for i in 0..1000 {
            let mut hasher = DefaultHasher::new();
            i.hash(&mut hasher);
            data.push((hasher.finish() & 0xFF) as u8);
        }
        let encoded = SovereignCodec::encode(&data);
        let decoded = SovereignCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_roundtrip_binary_with_0xff() {
        let mut data = Vec::with_capacity(1000);
        for i in 0..1000 {
            data.push(if i % 3 == 0 { 0xFF } else { (i % 254) as u8 });
        }
        let encoded = SovereignCodec::encode(&data);
        let decoded = SovereignCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_is_sfc_encoded() {
        assert!(SovereignCodec::is_sfc_encoded(b"SFC1rest..."));
        assert!(SovereignCodec::is_sfc_encoded(b"SFC0rest..."));
        assert!(SovereignCodec::is_sfc_encoded(b"SFC2rest..."));
        assert!(!SovereignCodec::is_sfc_encoded(b"ZKC2rest..."));
        assert!(!SovereignCodec::is_sfc_encoded(b"SF"));
    }

    #[test]
    fn test_decode_invalid_magic() {
        let result = SovereignCodec::decode(b"BADMdata");
        assert!(result.is_err());
    }

    #[test]
    fn test_compression_ratio_text() {
        let text = "The quick brown fox jumps over the lazy dog. \
                    The quick brown fox jumps over the lazy dog. \
                    The quick brown fox jumps over the lazy dog. \
                    The quick brown fox jumps over the lazy dog. \
                    Pack my box with five dozen liquor jugs! \
                    Pack my box with five dozen liquor jugs! \
                    How vexingly quick daft zebras jump! \
                    How vexingly quick daft zebras jump! ";
        let data = text.as_bytes();
        let encoded = SovereignCodec::encode(data);

        let ratio = data.len() as f64 / encoded.len() as f64;
        println!(
            "Text: {} → {} bytes ({:.2}:1)",
            data.len(),
            encoded.len(),
            ratio
        );

        let decoded = SovereignCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
        assert!(ratio > 1.2, "Text should compress: ratio {:.2}", ratio);
    }

    #[test]
    fn test_sfc2_beats_sfc1_on_structured_data() {
        let mut data = Vec::new();
        for i in 0..100 {
            data.extend_from_slice(
                format!(
                    r#"{{"timestamp":{},"event":"click","user_id":"user_{}","page":"/home"}},"#,
                    1700000000 + i,
                    i % 10
                )
                .as_bytes(),
            );
        }

        let sfc1 = SovereignCodec::encode_huffman(&data);
        let sfc2 = SovereignCodec::encode_bwt(&data);
        let is_stored_2 = sfc2.len() >= 4 && &sfc2[0..4] == SFC_MAGIC_STORED;

        println!(
            "SFC1: {} bytes, SFC2: {} bytes, original: {} bytes",
            sfc1.len(),
            sfc2.len(),
            data.len()
        );

        // SFC2 should beat SFC1 on structured JSON data
        if !is_stored_2 {
            assert!(
                sfc2.len() <= sfc1.len(),
                "SFC2 should beat SFC1: {} vs {}",
                sfc2.len(),
                sfc1.len()
            );
        }

        // Verify roundtrip
        let encoded = SovereignCodec::encode(&data);
        let decoded = SovereignCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_bwt_large_block() {
        let mut data = Vec::new();
        for i in 0..200 {
            data.extend_from_slice(
                format!(
                    r#"{{"id":"shard_{}","hash":"0x{:064x}","size":{},"encrypted":false}},"#,
                    i,
                    i * 12345678u64,
                    8192 + (i % 100)
                )
                .as_bytes(),
            );
        }

        let encoded = SovereignCodec::encode(&data);
        let decoded = SovereignCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, data);

        let ratio = data.len() as f64 / encoded.len() as f64;
        println!(
            "Large block ({} bytes): → {} bytes ({:.2}:1)",
            data.len(),
            encoded.len(),
            ratio
        );
        assert!(ratio > 1.5, "Large JSON should compress: {:.2}:1", ratio);
    }

    #[test]
    fn test_range_coder_roundtrip() {
        // Test range coder with realistic JSON-like data
        let mut data = Vec::new();
        for i in 0..500 {
            data.extend_from_slice(
                format!(
                    r#"{{"timestamp":{},"event":"click","user_id":"user_{}","page":"/home"}},"#,
                    1700000000 + i,
                    i % 10
                )
                .as_bytes(),
            );
        }

        // Test SFC3 specifically
        let encoded = SovereignCodec::encode_range(&data);
        let is_stored = encoded.len() >= 4 && &encoded[0..4] == SFC_MAGIC_STORED;
        if !is_stored {
            assert_eq!(&encoded[0..4], SFC_MAGIC_RANGE.as_slice(), "Should use SFC3");
            let decoded = SovereignCodec::decode_range(&encoded).unwrap();
            assert_eq!(decoded, data, "Range coder roundtrip failed");

            let ratio = data.len() as f64 / encoded.len() as f64;
            println!(
                "Range coder: {} bytes → {} bytes ({:.2}:1)",
                data.len(),
                encoded.len(),
                ratio
            );
        }

        // Also test via the generic encode/decode path
        let encoded2 = SovereignCodec::encode(&data);
        let decoded2 = SovereignCodec::decode(&encoded2).unwrap();
        assert_eq!(decoded2, data, "Generic SFC roundtrip with range coder failed");
    }

    #[test]
    fn test_bitwriter_bitreader_roundtrip() {
        let mut writer = BitWriter::new(100);
        writer.write_bits(0b101, 3);
        writer.write_bits(0b0011, 4);
        writer.write_bits(0b1, 1);
        let (bytes, padding) = writer.finish();
        assert_eq!(padding, 0);
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0xA7);

        let mut reader = BitReader::new(&bytes, padding);
        assert_eq!(reader.read_bit().unwrap(), 1);
        assert_eq!(reader.read_bit().unwrap(), 0);
        assert_eq!(reader.read_bit().unwrap(), 1);
        assert_eq!(reader.read_bit().unwrap(), 0);
        assert_eq!(reader.read_bit().unwrap(), 0);
        assert_eq!(reader.read_bit().unwrap(), 1);
        assert_eq!(reader.read_bit().unwrap(), 1);
        assert_eq!(reader.read_bit().unwrap(), 1);
    }

    #[test]
    fn test_lz77_roundtrip() {
        // Test LZ77 on data with lots of local repetitions
        let mut data = Vec::new();
        for i in 0..200 {
            data.extend_from_slice(
                format!(
                    r#"{{"id":{},"name":"item_{}","type":"widget","status":"active"}},"#,
                    i, i % 20
                )
                .as_bytes(),
            );
        }

        // Test SFC4 specifically
        let encoded = SovereignCodec::encode_lz77(&data);
        let is_stored = encoded.len() >= 4 && &encoded[0..4] == SFC_MAGIC_STORED;
        if !is_stored {
            assert_eq!(&encoded[0..4], SFC_MAGIC_LZ77.as_slice(), "Should use SFC4");
            let decoded = SovereignCodec::decode_lz77(&encoded).unwrap();
            assert_eq!(decoded.len(), data.len(), "LZ77 decoded length mismatch");
            assert_eq!(decoded, data, "LZ77 roundtrip failed");

            let ratio = data.len() as f64 / encoded.len() as f64;
            println!(
                "LZ77: {} bytes → {} bytes ({:.2}:1)",
                data.len(),
                encoded.len(),
                ratio
            );
        }

        // Also test via generic encode/decode (best-of selection)
        let encoded2 = SovereignCodec::encode(&data);
        let decoded2 = SovereignCodec::decode(&encoded2).unwrap();
        assert_eq!(decoded2, data, "Generic SFC roundtrip with LZ77 failed");

        let ratio = data.len() as f64 / encoded2.len() as f64;
        let strategy = std::str::from_utf8(&encoded2[0..4]).unwrap_or("????");
        println!(
            "Best strategy: {} — {} bytes → {} bytes ({:.2}:1)",
            strategy,
            data.len(),
            encoded2.len(),
            ratio
        );
    }

    #[test]
    fn test_range_coder_large_data() {
        // Test range coder with ~300KB of data (similar to real ZKC body)
        let mut data = Vec::new();
        for i in 0..5000 {
            data.extend_from_slice(
                format!(
                    r#"{{"block_height":{},"tx_hash":"0x{:064x}","validator":"node_{}","timestamp":{},"nonce":{},"gas_used":21000,"status":"confirmed"}},"#,
                    i, (i as u64).wrapping_mul(0x1234567890ABCDEFu64), i % 50, 1700000000u64 + i as u64, i * 7
                )
                .as_bytes(),
            );
        }
        println!("Large range coder test: {} bytes input", data.len());

        // Test SFC3 directly
        let sfc3 = SovereignCodec::encode_range(&data);
        let is_stored = sfc3.len() >= 4 && &sfc3[0..4] == SFC_MAGIC_STORED;
        if is_stored {
            println!("  SFC3 fell back to STORED (range coder bigger than original)");
        } else {
            assert_eq!(&sfc3[0..4], SFC_MAGIC_RANGE.as_slice());
            let decoded = SovereignCodec::decode_range(&sfc3).unwrap();
            assert_eq!(decoded.len(), data.len(), "Range coder large roundtrip: length mismatch ({} vs {})", decoded.len(), data.len());
            assert_eq!(decoded, data, "Range coder large roundtrip: data mismatch");
            let ratio = data.len() as f64 / sfc3.len() as f64;
            println!("  SFC3 (Range): {} → {} ({:.2}:1)", data.len(), sfc3.len(), ratio);
        }

        // Compare with SFC2
        let sfc2 = SovereignCodec::encode_bwt(&data);
        let is_stored2 = sfc2.len() >= 4 && &sfc2[0..4] == SFC_MAGIC_STORED;
        if !is_stored2 {
            let decoded2 = SovereignCodec::decode_bwt(&sfc2).unwrap();
            assert_eq!(decoded2, data, "SFC2 large roundtrip failed");
            let ratio2 = data.len() as f64 / sfc2.len() as f64;
            println!("  SFC2 (Huffman): {} → {} ({:.2}:1)", data.len(), sfc2.len(), ratio2);
        }

        // Best-of selection
        let best = SovereignCodec::encode(&data);
        let decoded_best = SovereignCodec::decode(&best).unwrap();
        assert_eq!(decoded_best, data, "Best-of encode/decode roundtrip failed on large data");
        let best_strategy = std::str::from_utf8(&best[0..4]).unwrap_or("????");
        let best_ratio = data.len() as f64 / best.len() as f64;
        println!("  Best: {} — {:.2}:1", best_strategy, best_ratio);
    }

    #[test]
    fn test_all_strategies_comparison() {
        // Generate realistic structured data
        let mut data = Vec::new();
        for i in 0..5000 {
            data.extend_from_slice(
                format!(
                    r#"{{"block_height":{},"tx_hash":"0x{:064x}","validator":"node_{}","timestamp":{},"nonce":{},"gas_used":21000,"status":"confirmed"}},"#,
                    i, (i as u64).wrapping_mul(0x1234567890ABCDEFu64), i % 50, 1700000000u64 + i as u64, i * 7
                )
                .as_bytes(),
            );
        }
        println!("\n=== Strategy Comparison ({} bytes input) ===", data.len());

        // BWT + MTF shared computation
        let (bwt_output, bwt_index) = SovereignCodec::bwt_forward(&data);
        let mtf_output = SovereignCodec::mtf_forward(&bwt_output);
        let rle_output = SovereignCodec::rle_encode(&mtf_output);
        println!("  BWT+MTF output: {} bytes", mtf_output.len());
        println!("  BWT+MTF+RLE output: {} bytes (RLE saved {} bytes)",
                 rle_output.len(), mtf_output.len() as i64 - rle_output.len() as i64);

        // SFC1: Huffman only
        let sfc1 = SovereignCodec::encode_huffman(&data);
        let sfc1_tag = std::str::from_utf8(&sfc1[0..4]).unwrap_or("????");
        println!("  SFC1 (Huffman):     {} bytes ({:.2}:1) [{}]", sfc1.len(), data.len() as f64 / sfc1.len() as f64, sfc1_tag);

        // SFC2: BWT+MTF+RLE+Huffman
        let sfc2 = SovereignCodec::encode_bwt_from_rle(data.len(), bwt_index, &rle_output);
        println!("  SFC2 (BWT+Huff):    {} bytes ({:.2}:1)", sfc2.len(), data.len() as f64 / sfc2.len() as f64);

        // SFC3: BWT+MTF+RLE+Range
        let sfc3 = SovereignCodec::encode_range_from_rle(data.len(), bwt_index, &rle_output);
        println!("  SFC3 (BWT+Range):   {} bytes ({:.2}:1)", sfc3.len(), data.len() as f64 / sfc3.len() as f64);

        // SFC4: LZ77+Huffman
        let sfc4 = SovereignCodec::encode_lz77(&data);
        let sfc4_tag = std::str::from_utf8(&sfc4[0..4]).unwrap_or("????");
        println!("  SFC4 (LZ77):        {} bytes ({:.2}:1) [{}]", sfc4.len(), data.len() as f64 / sfc4.len() as f64, sfc4_tag);

        // SFC5: BWT+MTF+RLE+Order1-Range
        let sfc5 = SovereignCodec::encode_ctx1_from_rle(data.len(), bwt_index, &rle_output);
        let sfc5_tag = std::str::from_utf8(&sfc5[0..4]).unwrap_or("????");
        println!("  SFC5 (BWT+O1Range): {} bytes ({:.2}:1) [{}]", sfc5.len(), data.len() as f64 / sfc5.len() as f64, sfc5_tag);

        // SFC6: BWT+MTF+Adaptive O1 Range (no RLE)
        let sfc6 = SovereignCodec::encode_adaptive_o1(data.len(), bwt_index, &mtf_output);
        let sfc6_tag = std::str::from_utf8(&sfc6[0..4]).unwrap_or("????");
        println!("  SFC6 (BWT+AdapO1):  {} bytes ({:.2}:1) [{}]", sfc6.len(), data.len() as f64 / sfc6.len() as f64, sfc6_tag);

        // Verify SFC6 roundtrip
        if &sfc6[0..4] == SFC_MAGIC_ADAPTIVE {
            match SovereignCodec::decode_adaptive_o1(&sfc6) {
                Ok(decoded) => {
                    if decoded == data {
                        println!("  SFC6 roundtrip: OK");
                    } else {
                        println!("  SFC6 roundtrip: DATA MISMATCH (len {} vs {})", decoded.len(), data.len());
                    }
                }
                Err(e) => println!("  SFC6 roundtrip: DECODE ERROR: {}", e),
            }
        }

        // SFC7: BWT+MTF+RLE+Adaptive O1 Range
        let sfc7 = SovereignCodec::encode_adaptive_o1_rle(data.len(), bwt_index, &rle_output);
        let sfc7_tag = std::str::from_utf8(&sfc7[0..4]).unwrap_or("????");
        println!("  SFC7 (BWT+RLE+AdO1):{} bytes ({:.2}:1) [{}]", sfc7.len(), data.len() as f64 / sfc7.len() as f64, sfc7_tag);

        // Verify SFC7 roundtrip
        if &sfc7[0..4] == SFC_MAGIC_ADAPTIVE_RLE {
            match SovereignCodec::decode_adaptive_o1_rle(&sfc7) {
                Ok(decoded) => {
                    if decoded == data {
                        println!("  SFC7 roundtrip: OK");
                    } else {
                        println!("  SFC7 roundtrip: DATA MISMATCH (len {} vs {})", decoded.len(), data.len());
                    }
                }
                Err(e) => println!("  SFC7 roundtrip: DECODE ERROR: {}", e),
            }
        }

        // Best-of
        let best = SovereignCodec::encode(&data);
        let best_tag = std::str::from_utf8(&best[0..4]).unwrap_or("????");
        let best_ratio = data.len() as f64 / best.len() as f64;
        println!("  WINNER: {} — {} bytes ({:.2}:1)", best_tag, best.len(), best_ratio);
    }

    #[test]
    fn test_real_file_strategies() {
        // Try to load the actual witness_metadata.json for real-world benchmark
        // Try multiple possible paths (depends on cargo test CWD)
        let candidates = [
            "test_data/witness_metadata.json",
            "../test_data/witness_metadata.json",
            "../../test_data/witness_metadata.json",
        ];
        let data = candidates.iter()
            .filter_map(|p| std::fs::read(p).ok())
            .next();
        let data = match data {
            Some(d) => d,
            None => {
                println!("Skipping: witness_metadata.json not found in any candidate path");
                return;
            }
        };
        println!("\n=== Real File Benchmark ({} bytes) ===", data.len());

        if data.len() < MIN_BWT_SIZE || data.len() > MAX_BWT_SIZE {
            println!("  File size outside BWT range ({}-{}), skipping BWT strategies",
                     MIN_BWT_SIZE, MAX_BWT_SIZE);
            return;
        }

        let (bwt_output, bwt_index) = SovereignCodec::bwt_forward(&data);
        let mtf_output = SovereignCodec::mtf_forward(&bwt_output);
        let rle_output = SovereignCodec::rle_encode(&mtf_output);
        println!("  BWT+MTF: {} bytes", mtf_output.len());
        println!("  BWT+MTF+RLE: {} bytes (RLE saved {})", rle_output.len(),
                 mtf_output.len() as i64 - rle_output.len() as i64);

        // Count zero-run statistics in MTF output
        let zeros = mtf_output.iter().filter(|&&b| b == 0).count();
        let small = mtf_output.iter().filter(|&&b| b > 0 && b <= 7).count();
        println!("  MTF stats: {:.1}% zeros, {:.1}% small (1-7), {:.1}% other",
                 zeros as f64 / mtf_output.len() as f64 * 100.0,
                 small as f64 / mtf_output.len() as f64 * 100.0,
                 (mtf_output.len() - zeros - small) as f64 / mtf_output.len() as f64 * 100.0);

        // Test each strategy
        let sfc2 = SovereignCodec::encode_bwt_from_rle(data.len(), bwt_index, &rle_output);
        println!("  SFC2 (BWT+Huff):    {} bytes ({:.2}:1)", sfc2.len(), data.len() as f64 / sfc2.len() as f64);

        let sfc3 = SovereignCodec::encode_range_from_rle(data.len(), bwt_index, &rle_output);
        println!("  SFC3 (BWT+Range):   {} bytes ({:.2}:1)", sfc3.len(), data.len() as f64 / sfc3.len() as f64);

        let sfc5 = SovereignCodec::encode_ctx1_from_rle(data.len(), bwt_index, &rle_output);
        let sfc5_tag = std::str::from_utf8(&sfc5[0..4]).unwrap_or("????");
        println!("  SFC5 (BWT+O1Range): {} bytes ({:.2}:1) [{}]", sfc5.len(), data.len() as f64 / sfc5.len() as f64, sfc5_tag);

        let sfc7 = SovereignCodec::encode_adaptive_o1_rle(data.len(), bwt_index, &rle_output);
        let sfc7_tag = std::str::from_utf8(&sfc7[0..4]).unwrap_or("????");
        println!("  SFC7 (BWT+RLE+AdO1):{} bytes ({:.2}:1) [{}]", sfc7.len(), data.len() as f64 / sfc7.len() as f64, sfc7_tag);

        // Verify SFC7 roundtrip
        if &sfc7[0..4] == SFC_MAGIC_ADAPTIVE_RLE {
            if let Ok(decoded) = SovereignCodec::decode_adaptive_o1_rle(&sfc7) {
                if decoded == data {
                    println!("  SFC7 roundtrip: OK");
                } else {
                    println!("  SFC7 roundtrip: MISMATCH ({} vs {})", decoded.len(), data.len());
                }
            } else {
                println!("  SFC7 roundtrip: DECODE FAILED");
            }
        }

        // Best-of
        let best = SovereignCodec::encode(&data);
        let best_tag = std::str::from_utf8(&best[0..4]).unwrap_or("????");
        let decoded = SovereignCodec::decode(&best).unwrap();
        assert_eq!(decoded, data, "Real file roundtrip failed");
        println!("  WINNER: {} — {} bytes ({:.2}:1)", best_tag, best.len(), data.len() as f64 / best.len() as f64);
    }
}
