# Contributing to Project Guard

Thank you for your interest in contributing to **Project Guard**! Our mission is to build a modern, high-performance, open-source Antivirus and EDR platform written in pure Rust.

---

## 🛠️ Code of Conduct & Core Principles

1. **Pure Rust & Memory Safety**:
   - Do not introduce unsafe C/C++ native binaries or unverified bindings unless strictly necessary for Windows low-level APIs.
   - All code must pass `cargo check` and `cargo test` without regressions.
2. **Windows Defender Coexistence**:
   - Never disable Windows Defender or attempt to kill `MsMpEng.exe`.
   - Always handle `os error 225` gracefully.
   - Always quarantine files through the XOR `0x5A` vault mechanism.
3. **Deterministic Testing**:
   - Every new engine or feature must include unit tests. Mock filesystem paths using `std::env::temp_dir()`.

---

## 🚀 Setting Up the Development Environment

```powershell
# 1. Clone the repository
git clone https://github.com/your-org/project-guard.git
cd project-guard

# 2. Run unit tests
cargo test

# 3. Build debug binary
cargo build
```

---

## 🧩 How to Add a New Detection Engine

All file scan engines implement the `ScanEngine` trait defined in `src/engines/trait_engine.rs`:

```rust
use anyhow::Result;
use std::path::Path;
use crate::core::Detection;

pub trait ScanEngine: Send + Sync {
    fn name(&self) -> &'static str;
    fn scan(&self, path: &Path, data: &[u8]) -> Result<Option<Detection>>;
}
```

### Steps:
1. Create your engine file in `src/engines/your_engine.rs`.
2. Implement `ScanEngine` for your struct.
3. Export your engine in `src/engines/mod.rs`.
4. Register your engine in `ScanOrchestrator::new()` inside `src/core/orchestrator.rs`.
5. Add unit tests verifying both clean and suspicious samples.

---

## 📝 Submitting Pull Requests

1. Fork the repository and create your branch from `main`:
   ```powershell
   git checkout -b feature/my-new-hunter
   ```
2. Ensure all tests pass:
   ```powershell
   cargo test
   ```
3. Commit with descriptive conventional commit messages:
   ```
   feat(engine): add new cobalt strike beacon config extractor
   fix(service): correct SCM restart delay timeout
   docs: update QUICKSTART.md with driver hunter instructions
   ```
4. Push to your fork and submit a Pull Request.
