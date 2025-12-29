# 🚀 ZHTP Node v0.2.0 - Community Testing Release

**Announcement Date**: December 29, 2025

We're excited to announce a major update with significant improvements to Web4 domain management, persistence, and infrastructure. **We need your help testing!**

---

## 🎯 What's New

✅ **Canonical Manifest Architecture** - Crystal clear separation between CLI-deployed content and runtime content
✅ **Persistent Domain Registry** - Domains survive node restarts (no more phantom domains!)
✅ **Enhanced Content Publishing** - Deploy, update, and manage sites with full version control
✅ **Improved CLI** - New commands for domain management and deployment status tracking
✅ **Better Documentation** - Platform-specific build guides (macOS/Windows/Linux) + CLI reference
✅ **Standardized Issue Templates** - Clear categories for bug reports, features, documentation, and testing

---

## 🛠️ Getting Started

### Step 1: Build the Node

Choose your platform and follow the guide:

- **macOS** → [BUILD_AND_RUN_GUIDE.md - macOS Section](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/blob/development/docs/BUILD_AND_RUN_GUIDE.md#macos)
- **Windows** → [BUILD_AND_RUN_GUIDE.md - Windows Section](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/blob/development/docs/BUILD_AND_RUN_GUIDE.md#windows)
- **Linux** → [BUILD_AND_RUN_GUIDE.md - Linux Section](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/blob/development/docs/BUILD_AND_RUN_GUIDE.md#linux)

### Step 2: Learn the CLI

Full command reference at [CLI_USER_GUIDE.md](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/blob/development/CLI_USER_GUIDE.md)

### Step 3: Start Testing!

Pick a testing phase below and share your findings.

---

## 🎯 Testing Phases (Pick Your Adventure)

### **Phase 1: Domain Registration** 🌐

**The Challenge**: Register your first domain and verify persistence

```bash
# Start your node
./target/release/zhtp node start --config my-node.toml

# In another terminal, register a domain
./target/release/zhtp-cli domain register --domain mytest.zhtp --keystore ~/.zhtp/keystore
```

**What We Want to Know**:
- ✅ Can you successfully register a domain?
- ✅ Does the domain persist after restarting the node?
- ✅ Can you register multiple domains?
- ⚠️ Any errors or unexpected behavior?

**Report Your Findings**: Use the `[TEST]` template on [GitHub Issue #537](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/537)

---

### **Phase 2: Deploy Your First Site** 🚀

**The Challenge**: Build a simple site and deploy it to your domain

```bash
# Create a simple site directory
mkdir myapp
echo "<h1>Hello ZHTP!</h1>" > myapp/index.html

# Deploy to your domain
./target/release/zhtp-cli deploy site ./myapp \
  --domain mytest.zhtp \
  --keystore ~/.zhtp/keystore
```

**What We Want to Know**:
- ✅ Does the site deploy successfully?
- ✅ Can you access it via the Web4 gateway?
- ✅ Are all files included in the deployment?
- ⚠️ What was the deployment time?
- 📸 Share a screenshot or the deployed site URL

**Report Your Findings**: Comment on [GitHub Issue #537](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/537) with:
- Platform and hardware specs
- Deployment time
- Screenshot or URL
- Any issues encountered

---

### **Phase 3: Update & Rollback** 📦

**The Challenge**: Update your site and test version rollback

```bash
# Make changes to your site
echo "<h1>Hello ZHTP v2!</h1>" > myapp/index.html

# Deploy the update
./target/release/zhtp-cli deploy update ./myapp \
  --domain mytest.zhtp \
  --keystore ~/.zhtp/keystore

# Check deployment status
./target/release/zhtp-cli deploy status --domain mytest.zhtp

# Check deployment history
./target/release/zhtp-cli deploy history --domain mytest.zhtp

# Rollback to previous version (if supported)
./target/release/zhtp-cli deploy rollback \
  --domain mytest.zhtp \
  --version 1 \
  --keystore ~/.zhtp/keystore
```

**What We Want to Know**:
- ✅ Can you publish site updates?
- ✅ Does version history track correctly?
- ✅ Can you rollback to previous versions?
- ✅ Is the rollback instantaneous?
- ⚠️ Any issues with deployment status commands?

**Report Your Findings**: Add your test report to [GitHub Issue #537](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/537)

---

### **Phase 4: Remote Node Testing** 🔗

**The Challenge**: Connect to a remote node and repeat the workflows

**Setup**:
- You'll receive a bootstrap node address in Discord
- Follow [NODE_CONNECTION_GUIDE.md - Remote Bootstrap Section](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/blob/development/docs/NODE_CONNECTION_GUIDE.md#remote-bootstrap-for-community-testing)

**Test the Same Workflows**:
1. Register a domain on the remote node
2. Deploy a site
3. Update and check history

**Privacy Note**:
- Your IP is visible to the remote node (unavoidable for network connection)
- The node's identity is verified via cryptographic DIDs (not IP-based)
- You remain pseudonymous to other network participants

**What We Want to Know**:
- ✅ Can you connect to a remote bootstrap node?
- ✅ Does everything work the same as local?
- ✅ What's the latency/performance compared to local?
- ✅ Any connection issues or dropouts?

**Report Your Findings**: Comment on [GitHub Issue #537](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/537)

---

### **Phase 5: Edge Cases & Error Handling** 🧪

**The Challenge**: Break things and tell us how it breaks

Try these scenarios:

```bash
# What happens with duplicate domain names?
./target/release/zhtp-cli domain register --domain mytest.zhtp

# What happens with invalid domains?
./target/release/zhtp-cli domain register --domain invalid-123!@#

# What happens with empty deployments?
mkdir emptyapp
./target/release/zhtp-cli deploy site ./emptyapp --domain mytest.zhtp

# What happens with large files?
# (Create a large file and try to deploy)
dd if=/dev/zero of=largefile.bin bs=1M count=100
cp largefile.bin myapp/
./target/release/zhtp-cli deploy update ./myapp --domain mytest.zhtp

# What happens if you stop the node mid-deployment?
# (Start deployment, then kill the process)
```

**What We Want to Know**:
- 🔴 What crashes or errors?
- ⚠️ What behaves unexpectedly?
- 📊 What's the error message?
- 🔧 Can you recover gracefully?

**Report Your Findings**:
- If you found a **bug** → Use `[BUG]` template with exact reproduction steps
- If you have an **idea for improvement** → Use `[FEATURE]` template
- If something is **confusing** → Use `[HELP]` template

Report on [GitHub Issues](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues)

---

## 📋 Issue Templates (Now Available)

We've created standardized templates to make reporting easier:

| Template | Prefix | Use For |
|----------|--------|---------|
| **Bug Report** | `[BUG]` | Something is broken or not working as expected |
| **Feature Request** | `[FEATURE]` | Suggest a new capability or enhancement |
| **Documentation** | `[DOCS]` | Report unclear, missing, or incorrect docs |
| **Testing** | `[TEST]` | Share testing findings and results (linked to #537) |
| **Help/Question** | `[HELP]` | Ask for help or clarification |
| **Performance** | `[PERF]` | Report performance issues with metrics |

**How to Use**:
1. Go to [GitHub Issues](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/new/choose)
2. Choose the template that matches your issue
3. Fill in the sections (they're pre-filled with guidance)
4. Submit!

---

## 💬 How to Report Findings

### Option 1: GitHub (Preferred for Tracking)

Go to [GitHub Issue #537 - Testing Findings](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/537)

**When reporting, include**:
- ✅ Which phase(s) you tested
- ✅ Your platform (macOS/Windows/Linux)
- ✅ Hardware specs (CPU, RAM, disk)
- ✅ What worked well
- ✅ What was confusing
- ✅ Any bugs or errors (with exact reproduction steps)
- ✅ Screenshots or output if relevant

### Option 2: Discord (This Thread)

Share findings here for real-time discussion.

Use this format:
```
**Phase**: [1/2/3/4/5]
**Platform**: [macOS/Windows/Linux]
**Result**: [✅ Passed / ⚠️ Partial Issue / ❌ Failed]

**What happened**:
[description]

**Error message** (if any):
[paste here]
```

---

## 🎁 What You're Helping With

By testing, you're directly helping us:

✅ **Verify persistence** - Ensure domains and deployments survive restarts
✅ **Test edge cases** - Find gaps in error handling
✅ **Identify performance bottlenecks** - Real-world usage patterns
✅ **Improve documentation** - Make it clearer for new users
✅ **Confirm cross-platform compatibility** - Works on all major OS
✅ **Validate Web4 architecture** - The new domain/manifest system works correctly

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| [BUILD_AND_RUN_GUIDE.md](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/blob/development/docs/BUILD_AND_RUN_GUIDE.md) | Platform-specific build instructions for macOS, Windows, Linux |
| [CLI_USER_GUIDE.md](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/blob/development/CLI_USER_GUIDE.md) | Complete CLI command reference |
| [NODE_CONNECTION_GUIDE.md](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/blob/development/docs/NODE_CONNECTION_GUIDE.md) | How to run nodes and connect to remote nodes |
| [This Document](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/blob/development/docs/COMMUNITY_TESTING_v0.2.0.md) | Community testing instructions (you are here) |

---

## ❓ Questions?

- **Setup questions?** → Use `[HELP]` template or ask in Discord
- **Found a bug?** → Use `[BUG]` template with reproduction steps
- **Have an idea?** → Use `[FEATURE]` template with details
- **Need real-time help?** → Jump in the Discord thread

---

## 🙌 Let's Build This Together

Your feedback is critical to making ZHTP production-ready. Whether you:
- ✅ Successfully deployed 100 sites (awesome!)
- ⚠️ Hit an edge case we didn't anticipate (perfect!)
- ❌ Found a blocking bug (we want to know!)
- 💡 Have a suggestion (tell us!)

**Tell us about it.**

The more you test, the more we learn. The more you report, the faster we improve.

---

**Happy testing! 🚀**

Report findings → [GitHub Issue #537](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/537)
