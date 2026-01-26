//! Pure path normalization logic
//!
//! Handles path expansion (~/), validation, and normalization
//! All functions are pure - they only depend on their inputs

use std::path::PathBuf;
use crate::error::{CliError, CliResult};

/// Expand a path that may contain ~/ prefix
///
/// Pure function - depends only on input and home directory lookup
pub fn expand_home_directory(path: &str) -> CliResult<PathBuf> {
    if path.starts_with("~/") {
        let home = dirs::home_dir()
            .ok_or(CliError::HomeDirectoryNotFound)?;
        Ok(home.join(&path[2..]))
    } else if path == "~" {
        dirs::home_dir().ok_or(CliError::HomeDirectoryNotFound)
    } else {
        Ok(PathBuf::from(path))
    }
}

/// Normalize a path string to PathBuf
///
/// Handles:
/// - Home directory expansion (~/)
/// - Relative path conversion
/// - Path validation
pub fn normalize_path(path: &str) -> CliResult<PathBuf> {
    if path.is_empty() {
        return Err(CliError::PathError("Path cannot be empty".to_string()));
    }

    expand_home_directory(path)
}

/// Join a base path with a relative path
pub fn join_paths(base: &PathBuf, relative: &str) -> CliResult<PathBuf> {
    Ok(base.join(relative))
}

/// Get the filename from a path
pub fn get_filename(path: &PathBuf) -> CliResult<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            CliError::PathError(format!("Cannot extract filename from path: {:?}", path))
        })
}

/// Get the parent directory of a path
pub fn get_parent_dir(path: &PathBuf) -> CliResult<PathBuf> {
    path.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| {
            CliError::PathError(format!("Cannot get parent of path: {:?}", path))
        })
}

/// Validate that a path is a valid directory name (no path separators)
pub fn validate_directory_name(name: &str) -> CliResult<()> {
    if name.is_empty() {
        return Err(CliError::PathError("Directory name cannot be empty".to_string()));
    }

    if name.contains('/') || name.contains('\\') {
        return Err(CliError::PathError(
            "Directory name cannot contain path separators".to_string(),
        ));
    }

    if name.contains('\0') {
        return Err(CliError::PathError(
            "Directory name cannot contain null characters".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_home_directory_with_tilde() {
        let result = expand_home_directory("~/config");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.to_string_lossy().contains("config"));
    }

    #[test]
    fn test_expand_home_directory_with_just_tilde() {
        let result = expand_home_directory("~");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path, dirs::home_dir().unwrap());
    }

    #[test]
    fn test_expand_absolute_path() {
        let result = expand_home_directory("/tmp/test");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("/tmp/test"));
    }

    #[test]
    fn test_normalize_empty_path() {
        let result = normalize_path("");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CliError::PathError(_)));
    }

    #[test]
    fn test_validate_directory_name_valid() {
        assert!(validate_directory_name("my_config").is_ok());
        assert!(validate_directory_name("config123").is_ok());
        assert!(validate_directory_name(".config").is_ok());
    }

    #[test]
    fn test_validate_directory_name_with_slash() {
        let result = validate_directory_name("my/config");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_directory_name_with_backslash() {
        let result = validate_directory_name("my\\config");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_directory_name_empty() {
        let result = validate_directory_name("");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_filename() {
        let path = PathBuf::from("/home/user/config.toml");
        let filename = get_filename(&path);
        assert!(filename.is_ok());
        assert_eq!(filename.unwrap(), "config.toml");
    }

    #[test]
    fn test_get_parent_dir() {
        let path = PathBuf::from("/home/user/config");
        let parent = get_parent_dir(&path);
        assert!(parent.is_ok());
        assert_eq!(parent.unwrap(), PathBuf::from("/home/user"));
    }

    #[test]
    fn test_join_paths() {
        let base = PathBuf::from("/home/user");
        let result = join_paths(&base, "config");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("/home/user/config"));
    }
}
