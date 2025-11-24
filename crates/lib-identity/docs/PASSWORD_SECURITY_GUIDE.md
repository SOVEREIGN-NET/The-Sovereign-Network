# Password Security Architecture Guide

## Overview

SOVEREIGN_NET provides a **two-layer password security system**:

1. **Master 20-Word Seed Phrase** - Ultimate recovery mechanism
2. **DID Password** - Convenient sign-in/sign-out for imported identities
3. **Optional Wallet Passwords** - Additional protection for specific wallets

---

##  Layer 1: Master 20-Word Seed Phrase

### What It Does
- **Universal Recovery**: Can recover entire DID and all wallets on any device
- **Quantum-Resistant**: Based on post-quantum cryptography
- **Permanent**: Never changes, never expires
- **Critical**: Loss = permanent loss of identity and assets

### When You Get It
```rust
// When creating a new citizen identity
let result = identity_manager.create_citizen_identity(
    "Alice".to_string(),
    vec!["email@example.com".to_string()],
    &mut economic_model,
).await?;

// Seed phrase is in result.wallet_seed_phrases
println!("Master 20-Word Seed Phrase:");
println!("{}", result.master_seed_phrase.words.join(" "));

// MUST be written down and stored securely offline!
```

### Recovery Process
```rust
// Import identity from 20-word phrase on a new device
let identity_id = identity_manager.import_identity_from_phrase(
    "word1 word2 word3 ... word20"
).await?;

// After import, can set a new password
identity_manager.set_identity_password(&identity_id, "newPassword123")?;
```

---

##  Layer 2: DID Password (Optional)

### What It Does
- **Convenient Sign-In**: Password-based authentication on your device
- **Local Security**: Protects against unauthorized access to imported DIDs
- **Changeable**: Can change password anytime
- **Removable**: Can remove password if desired

### Requirements
-  Identity must be **imported** via 20-word seed phrase first
-  Minimum 8 characters
-  Cannot set password on "created" identities (must import first)

### Usage Examples

#### Set Password (After Import)
```rust
// Import identity first
let identity_id = identity_manager.import_identity_from_phrase(
    "word1 word2 ... word20"
).await?;

// Now can set password
identity_manager.set_identity_password(
    &identity_id,
    "mySecurePassword123"
)?;
```

#### Sign In
```rust
// Validate password for sign-in
let validation = identity_manager.validate_identity_password(
    &identity_id,
    "mySecurePassword123"
)?;

if validation.valid {
    println!(" Signed in successfully!");
    // Grant access to DID operations
} else {
    println!(" Invalid password!");
}
```

#### Change Password
```rust
// Change password (requires old password)
identity_manager.change_identity_password(
    &identity_id,
    "oldPassword",
    "newPassword456"
)?;

println!(" Password changed successfully!");
```

#### Remove Password
```rust
// Remove password (requires current password to verify)
identity_manager.remove_identity_password(
    &identity_id,
    "currentPassword"
)?;

println!("🔓 Password removed - DID no longer requires password");
```

---

## 🛡️ Layer 3: Wallet Passwords (Optional)

### What It Does
- **Extra Protection**: Even if someone has DID access, they need wallet password
- **Selective**: Only protect high-value wallets (savings, business, etc.)
- **Independent**: Each wallet can have its own password
- **Flexible**: Add, change, or remove wallet passwords anytime

### Requirements
-  Minimum 6 characters (shorter than DID passwords)
-  Optional - only for wallets you want extra security
-  Works even if DID has no password

### Usage Examples

#### Set Wallet Password
```rust
// Get identity and wallet manager
let identity = identity_manager.get_identity(&identity_id).unwrap();
let wallet_manager = &mut identity.wallet_manager;

// Set password on savings wallet
wallet_manager.set_wallet_password(
    &savings_wallet_id,
    "savingsPass123"
)?;

println!(" Savings wallet now requires password!");
```

#### Use Protected Wallet
```rust
// Before accessing wallet, validate password
let validation = wallet_manager.validate_wallet_password(
    &savings_wallet_id,
    "savingsPass123"
)?;

if validation.valid {
    // Proceed with transaction
    wallet_manager.transfer_between_wallets(
        &savings_wallet_id,
        &primary_wallet_id,
        1000,
        "Transfer".to_string()
    )?;
} else {
    println!(" Invalid wallet password!");
}
```

#### Change Wallet Password
```rust
// Change wallet password (requires old password)
wallet_manager.change_wallet_password(
    &savings_wallet_id,
    "oldWalletPass",
    "newWalletPass456"
)?;

println!(" Wallet password changed!");
```

#### Remove Wallet Password
```rust
// Remove wallet password (requires current password)
wallet_manager.remove_wallet_password(
    &savings_wallet_id,
    "currentWalletPass"
)?;

println!("🔓 Wallet password removed!");
```

#### Check Which Wallets Have Passwords
```rust
// List all password-protected wallets
let protected = wallet_manager.list_password_protected_wallets();
println!("Password-protected wallets: {}", protected.len());

// Check specific wallet
if wallet_manager.wallet_has_password(&wallet_id) {
    println!("This wallet requires a password");
}
```

---

##  Recommended Security Strategy

### For Most Users
1. **Always secure your 20-word seed phrase** offline (paper, metal plate)
2. **Set a DID password** for convenient sign-in on your devices
3. **Add wallet passwords** to:
   - Savings wallets (high balances)
   - Business wallets
   - Any wallet with >10,000 ZHTP

### For Maximum Security
```rust
// Protect all important wallets
let important_wallets = [
    ("savings", savings_wallet_id),
    ("business", business_wallet_id),
    ("dao", dao_wallet_id),
];

for (name, wallet_id) in important_wallets {
    wallet_manager.set_wallet_password(
        &wallet_id,
        &format!("{}SecurePass", name)
    )?;
    println!(" Protected {} wallet", name);
}
```

### Security Hierarchy
```
┌─────────────────────────────────────────────────────┐
│  20-Word Seed Phrase (MASTER - Never Share!)       │
│  └─ Can recover everything                         │
└─────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────┐
│  DID Password (Device Sign-In)                      │
│  └─ Access to DID and all wallets without passwords│
└─────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────┐
│  Wallet Passwords (Extra Protection)                │
│  └─ Individual wallet access control               │
└─────────────────────────────────────────────────────┘
```

---

##  Complete Example: Full Setup

```rust
use lib_identity::identity::IdentityManager;

async fn complete_security_setup() -> Result<()> {
    let mut identity_manager = IdentityManager::new();
    let mut economic_model = EconomicModel::new();
    
    // 1. Create new citizen (gets 20-word seed phrase)
    let result = identity_manager.create_citizen_identity(
        "Bob".to_string(),
        vec!["bob@example.com".to_string()],
        &mut economic_model,
    ).await?;
    
    println!(" CRITICAL: Write down this 20-word seed phrase:");
    println!("{}", result.master_seed_phrase.words.join(" "));
    println!("\n  Store in multiple secure offline locations!");
    
    // 2. Set DID password for convenient sign-in
    let identity_id = result.identity_id;
    identity_manager.set_identity_password(
        &identity_id,
        "myDidPassword123"
    )?;
    println!(" DID password set");
    
    // 3. Get wallet manager
    let identity = identity_manager.get_identity(&identity_id).unwrap();
    let wallet_manager = &mut identity.wallet_manager;
    
    // 4. Add passwords to important wallets
    let wallets_to_protect = [
        (result.wallet_info.savings_wallet_id, "savings"),
        (result.wallet_info.ubi_wallet_id, "ubi"),
    ];
    
    for (wallet_id, name) in wallets_to_protect {
        wallet_manager.set_wallet_password(
            &wallet_id,
            &format!("{}SecurePass", name)
        )?;
        println!(" Protected {} wallet", name);
    }
    
    println!("\n✨ Complete security setup finished!");
    println!("   - 20-word seed: Secured offline");
    println!("   - DID password: Set");
    println!("   - Protected wallets: {}", wallets_to_protect.len());
    
    Ok(())
}
```

---

##  Important Security Notes

### DO:
-  Write 20-word seed phrase on paper/metal
-  Store in multiple secure offline locations
-  Use strong, unique passwords (8+ characters)
-  Change passwords if you suspect compromise
-  Add wallet passwords to high-value wallets

### DON'T:
-  Store seed phrase digitally (no photos, no cloud)
-  Share seed phrase with anyone (not even support)
-  Use same password for DID and wallets
-  Forget to backup seed phrase before creating DID
-  Rely only on passwords (seed phrase is ultimate backup)

---

##  Why Multiple Files?

The codebase is **modular** for maintainability:

- `manager.rs` - High-level identity operations (create citizens, verify)
- `lib_identity.rs` - Core ZhtpIdentity struct (the DID itself)
- `manager_integration.rs` - WalletManager (wallet operations)
- `wallet_password.rs` - Wallet password security layer
- `password.rs` - DID password authentication

Each file has a **specific purpose**, making it easier to:
- Find and fix bugs
- Add new features
- Test components independently
- Understand the system architecture

---

## 📞 Support

If you have questions about the password security system:
1. Check this guide first
2. Read inline code comments
3. Review test cases in `*_test.rs` files
4. Open an issue on GitHub with `[security]` tag
