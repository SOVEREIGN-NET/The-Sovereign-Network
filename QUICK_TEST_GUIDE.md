# Quick Test Guide - Recovery Phrase Validation

## TL;DR - Run All Tests in 30 Seconds

```bash
# Test 1: Unit tests (fastest)
cargo test --test recovery_phrase_validation_test recovery_phrase_tests:: --quiet

# Test 2: Manual validation
./test_recovery_phrases.sh
```

## Tests Available

### ✅ Test 1: Unit Tests (Recommended)
```bash
cargo test --test recovery_phrase_validation_test recovery_phrase_tests::
```
- **Time**: <1 second
- **Dependencies**: None (Rust only)
- **CI/CD Ready**: Yes
- **Result**: 3/3 tests passing ✅

### ✅ Test 2: Manual Validation
```bash
./test_recovery_phrases.sh
```
- **Time**: <1 second
- **Dependencies**: None
- **CI/CD Ready**: Yes
- **Result**: 4/4 scenarios passing ✅

### ⚠️ Test 3: API Integration (Optional)
```bash
# Terminal 1: Start server
cargo run --bin zhtp-server

# Terminal 2: Run API tests
./test_recovery_api.sh
```
- **Time**: ~5 seconds
- **Dependencies**: Running ZHTP server
- **CI/CD Ready**: Not usually
- **Result**: Tests 3 API endpoints with both 20 and 24-word phrases

## What's Being Tested?

### Validation Logic
- ✅ 20-word custom ZHTP recovery phrases → PASS
- ✅ 24-word BIP39 standard recovery phrases → PASS
- ✅ 19-word invalid phrases → ERROR (expected)
- ✅ 23-word invalid phrases → ERROR (expected)
- ✅ Invalid lengths (0, 25+ words) → ERROR (expected)

### API Endpoints
1. **POST /api/v1/identity/backup/verify**
   - Verifies recovery phrases
   - Accepts: 20 or 24 words

2. **POST /api/v1/identity/recover**
   - Recovers identity from phrase
   - Accepts: 20 or 24 words

3. **POST /api/v1/identity/restore/seed**
   - Restores from seed phrase
   - Accepts: 20 or 24 words

### Code Changes Verified
- ✅ Constants defined in `zhtp/src/api/handlers/constants.rs`
- ✅ All three validation endpoints accept both formats
- ✅ Error messages include actual word count
- ✅ Validation logic consistent across endpoints

## Expected Results

### Successful Test Output
```
test recovery_phrase_tests::test_recovery_phrase_word_counts ... ok
test recovery_phrase_tests::test_phrase_validation_logic ... ok
test recovery_phrase_tests::test_error_message_generation ... ok

test result: ok. 3 passed; 0 failed
```

```
Test: 20-word custom ZHTP format
  Words: 20
  Expected: PASS
  Result: ✅ PASS (Valid phrase)

Test: 24-word BIP39 standard format
  Words: 24
  Expected: PASS
  Result: ✅ PASS (Valid phrase)
```

## Error Handling

If tests fail:

1. **Cargo command not found**
   ```bash
   cd /Users/supertramp/Dev/The-Sovereign-Network
   cargo --version  # Should show: cargo 1.x.x
   ```

2. **Script permission denied**
   ```bash
   chmod +x test_recovery_phrases.sh
   chmod +x test_recovery_api.sh
   ```

3. **API server not responding**
   ```bash
   # API tests are optional - only needed for full integration testing
   # Unit tests and manual validation work without a server
   ```

## Test Files Reference

| File | Purpose | Type |
|------|---------|------|
| `zhtp/tests/recovery_phrase_validation_test.rs` | Unit tests | Rust |
| `test_recovery_phrases.sh` | Manual validation | Bash |
| `test_recovery_api.sh` | API integration | Bash |
| `TESTING_RECOVERY_PHRASES.md` | Full testing guide | Documentation |
| `RECOVERY_PHRASE_TEST_RESULTS.md` | Detailed results | Documentation |

## PR #1092 Requirements Met

✅ **Copilot Comment #2**: Recovery phrase format compatibility
- Both 20-word (custom ZHTP) and 24-word (BIP39) formats supported
- Separate code paths identified

✅ **Copilot Comment #3**: Consistent validation
- All three endpoints updated
- Clear error messages
- Centralized constants

## Next Steps

1. Run unit tests: `cargo test --test recovery_phrase_validation_test recovery_phrase_tests::`
2. Run manual validation: `./test_recovery_phrases.sh`
3. (Optional) Start server and run API tests: `./test_recovery_api.sh`
4. Review changes: `git diff HEAD~1`
5. Commit test files: `git add test_*.sh zhtp/tests/recovery_phrase_validation_test.rs`

## Support

For issues or questions:
- Check `TESTING_RECOVERY_PHRASES.md` for detailed guide
- Review `RECOVERY_PHRASE_TEST_RESULTS.md` for test details
- Check Copilot PR #1092 for context on what was fixed
