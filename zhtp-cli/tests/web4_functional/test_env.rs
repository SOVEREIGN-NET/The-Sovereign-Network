//! Test environment setup and management

use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Isolated test environment with temporary directory and configuration
pub struct TestEnv {
    pub temp_dir: TempDir,
    pub test_name: String,
}

impl TestEnv {
    /// Create a new isolated test environment
    pub fn setup(test_name: &str) -> Self {
        let temp_dir = TempDir::new()
            .expect(&format!("Failed to create temp directory for {}", test_name));
        
        TestEnv {
            temp_dir,
            test_name: test_name.to_string(),
        }
    }
    
    /// Get the temporary directory path
    pub fn path(&self) -> &Path {
        self.temp_dir.path()
    }
    
    /// Create a subdirectory within the test environment
    pub fn create_subdir(&self, name: &str) -> PathBuf {
        let path = self.temp_dir.path().join(name);
        std::fs::create_dir_all(&path)
            .expect(&format!("Failed to create subdirectory: {}", name));
        path
    }
    
    /// Write test data to a file in the environment
    pub fn write_file(&self, relative_path: &str, content: &str) -> PathBuf {
        let path = self.temp_dir.path().join(relative_path);
        
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .expect("Failed to create parent directories");
        }
        
        std::fs::write(&path, content)
            .expect("Failed to write test file");
        
        path
    }
    
    /// Get test name
    pub fn name(&self) -> &str {
        &self.test_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_env_setup() {
        let env = TestEnv::setup("test_setup");
        assert!(env.path().exists());
        assert_eq!(env.name(), "test_setup");
    }
    
    #[test]
    fn test_env_create_subdir() {
        let env = TestEnv::setup("test_subdir");
        let subdir = env.create_subdir("test_sub");
        assert!(subdir.exists());
        assert!(subdir.is_dir());
    }
    
    #[test]
    fn test_env_write_file() {
        let env = TestEnv::setup("test_write");
        let path = env.write_file("test.txt", "test content");
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "test content");
    }
}
