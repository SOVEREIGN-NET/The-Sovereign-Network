use std::error::Error;
use std::fs;
use std::path::PathBuf;

mod test_utils {
    use std::env;
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn init_logger() {
        if env::var("RUST_LOG").is_ok() {
            eprintln!("[test_utils] RUST_LOG is set: {}", env::var("RUST_LOG").unwrap());
        } else {
            // Keep logging lightweight for tests: signal default level.
            env::set_var("RUST_LOG", "info");
            eprintln!("[test_utils] RUST_LOG not set; defaulting to info");
        }
    }

    pub fn create_temp_dir(prefix: &str) -> io::Result<PathBuf> {
        let mut base = env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id();
        let name = format!("{}-{}-{}", prefix, pid, nanos);
        base.push(name);
        fs::create_dir(&base)?;
        Ok(base)
    }

    pub fn write_file(path: &Path, contents: &str) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut f = File::create(path)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
        Ok(())
    }

    pub fn read_file(path: &Path) -> io::Result<String> {
        let mut s = String::new();
        let mut f = File::open(path)?;
        f.read_to_string(&mut s)?;
        Ok(s)
    }

    pub fn remove_dir(path: &Path) -> io::Result<()> {
        if path.exists() {
            fs::remove_dir_all(path)?;
        }
        Ok(())
    }
}

use test_utils::*;

#[test]
fn test_create_and_write_file() -> Result<(), Box<dyn Error>> {
    init_logger();
    let tmp = create_temp_dir("sov-test-create")?;
    let file = tmp.join("alpha.txt");
    write_file(&file, "hello world")?;
    let contents = read_file(&file)?;
    assert_eq!(contents, "hello world");
    remove_dir(&tmp)?;
    Ok(())
}

#[test]
fn test_read_file_nonexistent_fails() -> Result<(), Box<dyn Error>> {
    init_logger();
    let tmp = create_temp_dir("sov-test-read")?;
    let file = tmp.join("does-not-exist.txt");
    match read_file(&file) {
        Ok(_) => panic!("expected read_file to fail for missing file"),
        Err(_) => {}
    }
    remove_dir(&tmp)?;
    Ok(())
}

#[test]
fn test_tempdir_uniqueness() -> Result<(), Box<dyn Error>> {
    init_logger();
    let a = create_temp_dir("sov-uniq")?;
    let b = create_temp_dir("sov-uniq")?;
    assert_ne!(a, b, "two temp dirs should be unique");
    remove_dir(&a)?;
    remove_dir(&b)?;
    Ok(())
}

#[test]
fn test_env_var_roundtrip() -> Result<(), Box<dyn Error>> {
    init_logger();
    std::env::set_var("SOV_TEST_VAR", "42");
    let v = std::env::var("SOV_TEST_VAR")?;
    assert_eq!(v, "42");
    std::env::remove_var("SOV_TEST_VAR");
    Ok(())
}

#[test]
fn test_command_echo() -> Result<(), Box<dyn Error>> {
    init_logger();
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg("echo hello-from-test")
        .output()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(s, "hello-from-test");
    Ok(())
}

#[test]
fn test_file_metadata() -> Result<(), Box<dyn Error>> {
    init_logger();
    let tmp = create_temp_dir("sov-meta")?;
    let file = tmp.join("meta.txt");
    write_file(&file, "meta")?;
    let md = std::fs::metadata(&file)?;
    assert!(md.len() > 0);
    remove_dir(&tmp)?;
    Ok(())
}

#[test]
fn test_key_size_check() -> Result<(), Box<dyn Error>> {
    init_logger();
    // Simulate a key of 32 bytes and validate size
    let key = vec![0u8; 32];
    assert_eq!(key.len(), 32);
    Ok(())
}

#[test]
fn test_logging_initialization_idempotent() -> Result<(), Box<dyn Error>> {
    // Calling init multiple times should not panic
    init_logger();
    init_logger();
    Ok(())
}

#[test]
fn test_end_to_end_simulation() -> Result<(), Box<dyn Error>> {
    init_logger();
    let tmp = create_temp_dir("sov-e2e")?;
    let a = tmp.join("sub/one.txt");
    write_file(&a, "payload")?;
    let read = read_file(&a)?;
    assert_eq!(read, "payload");
    remove_dir(&tmp)?;
    Ok(())
}
