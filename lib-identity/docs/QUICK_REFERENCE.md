# Password Security - Quick Reference

## 🔐 DID Password Operations

### Set Password (First Time)
```rust
identity_manager.set_identity_password(&identity_id, "password123")?;
```

### Change Password
```rust
identity_manager.change_identity_password(
    &identity_id,
    "oldPassword",  // Required for security
    "newPassword"
)?;
```

### Remove Password
```rust
identity_manager.remove_identity_password(
    &identity_id,
    "currentPassword"  // Required for verification
)?;
```

### Validate Password (Sign In)
```rust
let validation = identity_manager.validate_identity_password(
    &identity_id,
    "password123"
)?;

if validation.valid {
    // User authenticated
}
```

---

## 🛡️ Wallet Password Operations

### Set Wallet Password
```rust
let wallet_manager = &mut identity.wallet_manager;

wallet_manager.set_wallet_password(
    &wallet_id,
    "walletPass123"
)?;
```

### Change Wallet Password
```rust
wallet_manager.change_wallet_password(
    &wallet_id,
    "oldPass",
    "newPass"
)?;
```

### Remove Wallet Password
```rust
wallet_manager.remove_wallet_password(
    &wallet_id,
    "currentPass"
)?;
```

### Validate Wallet Password
```rust
let validation = wallet_manager.validate_wallet_password(
    &wallet_id,
    "walletPass123"
)?;

if validation.valid {
    // Proceed with wallet operation
}
```

### Check if Wallet Has Password
```rust
if wallet_manager.wallet_has_password(&wallet_id) {
    // Wallet is password-protected
}
```

### List All Protected Wallets
```rust
let protected = wallet_manager.list_password_protected_wallets();
for wallet_id in protected {
    println!("Protected: {}", hex::encode(&wallet_id.0[..8]));
}
```

---

## 📋 Password Requirements

| Type | Minimum Length | Can Change | Can Remove |
|------|----------------|------------|------------|
| DID Password | 8 characters | ✅ Yes | ✅ Yes |
| Wallet Password | 6 characters | ✅ Yes | ✅ Yes |
| Master Seed Phrase | 20 words | ❌ Never | ❌ Never |

---

## 🔑 Master Seed Phrase

```rust
// Seed phrase is provided during identity creation
let result = identity_manager.create_citizen_identity(...).await?;

// CRITICAL: Store this offline!
println!("Your 20-word seed phrase:");
println!("{}", result.master_seed_phrase.words.join(" "));
```

### Recovery
```rust
// Import identity from seed phrase on new device
let identity_id = identity_manager.import_identity_from_phrase(
    "word1 word2 word3 ... word20"
).await?;

// Set new password after recovery
identity_manager.set_identity_password(&identity_id, "newPass")?;
```

---

## ⚠️ Security Best Practices

### DO:
✅ Write seed phrase on paper/metal  
✅ Store in multiple secure offline locations  
✅ Use strong, unique passwords (8+ characters)  
✅ Change passwords if you suspect compromise  
✅ Add wallet passwords to high-value wallets  

### DON'T:
❌ Store seed phrase digitally (no photos, no cloud)  
❌ Share seed phrase with anyone  
❌ Use same password for DID and wallets  
❌ Forget to backup seed phrase  
❌ Rely only on passwords (seed phrase is ultimate backup)  

---

## 🎯 Common Use Cases

### Protect Savings Wallet
```rust
// Add extra password to savings wallet
wallet_manager.set_wallet_password(
    &savings_wallet_id,
    "savingsSecure123"
)?;
```

### Change Compromised Password
```rust
// If you think password was compromised
identity_manager.change_identity_password(
    &identity_id,
    "oldCompromisedPass",
    "newSecurePass456"
)?;
```

### Remove Password from Device
```rust
// If device is fully secured, remove password
identity_manager.remove_identity_password(
    &identity_id,
    "currentPassword"
)?;
```

### Secure Transaction
```rust
// Validate wallet password before large transaction
let validation = wallet_manager.validate_wallet_password(
    &wallet_id,
    "walletPassword"
)?;

if validation.valid {
    wallet_manager.transfer_between_wallets(
        &wallet_id,
        &destination_wallet,
        10000,  // Large amount
        "Important transfer".to_string()
    )?;
}
```

---

## 📞 Error Handling

```rust
use lib_identity::auth::PasswordError;

match identity_manager.set_identity_password(&id, "pass") {
    Ok(_) => println!("Password set!"),
    Err(PasswordError::IdentityNotImported) => {
        println!("Must import identity first");
    }
    Err(PasswordError::WeakPassword) => {
        println!("Password too weak (min 8 chars)");
    }
    Err(PasswordError::InvalidPassword) => {
        println!("Wrong password provided");
    }
    Err(PasswordError::PasswordNotSet) => {
        println!("No password to validate");
    }
}
```

---

## 🗂️ Where to Find Code

| Feature | File Location |
|---------|---------------|
| DID passwords | `src/auth/password.rs` |
| Wallet passwords | `src/wallets/wallet_password.rs` |
| Identity manager | `src/identity/manager.rs` |
| Wallet manager | `src/wallets/manager_integration.rs` |

---

## 📚 Full Documentation

For complete guide see: **`docs/PASSWORD_SECURITY_GUIDE.md`**
