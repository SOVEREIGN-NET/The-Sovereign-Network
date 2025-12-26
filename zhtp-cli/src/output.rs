//! Output abstraction for testable printing
//!
//! Separates I/O from business logic by providing a trait
//! that can be mocked in tests and implemented for real output.

use crate::error::CliResult;

/// Output abstraction for printing results
pub trait Output: Send + Sync {
    /// Print normal output
    fn print(&self, msg: &str) -> CliResult<()>;

    /// Print formatted JSON
    fn print_json(&self, data: &serde_json::Value) -> CliResult<()> {
        self.print(&serde_json::to_string_pretty(data)?)
    }

    /// Print error message
    fn error(&self, msg: &str) -> CliResult<()>;

    /// Print success message with checkmark
    fn success(&self, msg: &str) -> CliResult<()> {
        self.print(&format!("✅ {}", msg))
    }

    /// Print warning message
    fn warning(&self, msg: &str) -> CliResult<()> {
        self.print(&format!("⚠️  {}", msg))
    }

    /// Print info message
    fn info(&self, msg: &str) -> CliResult<()> {
        self.print(&format!("ℹ️  {}", msg))
    }

    /// Print a section header
    fn header(&self, title: &str) -> CliResult<()> {
        self.print(&format!("\n{}\n{}", title, "=".repeat(title.len())))
    }
}

/// Standard console output implementation
pub struct ConsoleOutput;

impl Output for ConsoleOutput {
    fn print(&self, msg: &str) -> CliResult<()> {
        println!("{}", msg);
        Ok(())
    }

    fn error(&self, msg: &str) -> CliResult<()> {
        eprintln!("❌ {}", msg);
        Ok(())
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Mock output for testing - captures all output
    pub struct MockOutput {
        messages: Arc<Mutex<Vec<String>>>,
        errors: Arc<Mutex<Vec<String>>>,
    }

    impl MockOutput {
        pub fn new() -> Self {
            MockOutput {
                messages: Arc::new(Mutex::new(Vec::new())),
                errors: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn get_messages(&self) -> Vec<String> {
            self.messages.lock().unwrap().clone()
        }

        pub fn get_errors(&self) -> Vec<String> {
            self.errors.lock().unwrap().clone()
        }

        pub fn assert_contains_message(&self, substring: &str) {
            let messages = self.get_messages();
            assert!(
                messages.iter().any(|m| m.contains(substring)),
                "Expected message containing '{}', but got: {:?}",
                substring,
                messages
            );
        }

        pub fn assert_contains_error(&self, substring: &str) {
            let errors = self.get_errors();
            assert!(
                errors.iter().any(|e| e.contains(substring)),
                "Expected error containing '{}', but got: {:?}",
                substring,
                errors
            );
        }
    }

    impl Default for MockOutput {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Output for MockOutput {
        fn print(&self, msg: &str) -> CliResult<()> {
            self.messages.lock().unwrap().push(msg.to_string());
            Ok(())
        }

        fn error(&self, msg: &str) -> CliResult<()> {
            self.errors.lock().unwrap().push(msg.to_string());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn test_mock_output_captures_messages() {
        let output = MockOutput::new();
        output.print("test message").unwrap();
        output.print("another message").unwrap();

        let messages = output.get_messages();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], "test message");
        assert_eq!(messages[1], "another message");
    }

    #[test]
    fn test_mock_output_captures_errors() {
        let output = MockOutput::new();
        output.error("test error").unwrap();
        output.error("another error").unwrap();

        let errors = output.get_errors();
        assert_eq!(errors.len(), 2);
    }

    #[test]
    fn test_output_helper_methods() {
        let output = MockOutput::new();
        output.success("Operation complete").unwrap();
        output.warning("Be careful").unwrap();
        output.info("Note this").unwrap();

        let messages = output.get_messages();
        assert!(messages[0].contains("✅"));
        assert!(messages[1].contains("⚠️"));
        assert!(messages[2].contains("ℹ️"));
    }
}
