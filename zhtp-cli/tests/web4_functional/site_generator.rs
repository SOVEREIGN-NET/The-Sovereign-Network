//! Automated test site generator for Web4 functional testing

use std::fs;
use std::path::Path;
use std::collections::HashMap;

/// Generates structured test websites for deployment testing
pub struct SiteGenerator {
    domain: String,
    version: String,
    files: HashMap<String, String>,
}

impl SiteGenerator {
    /// Create a simple test site with basic structure
    pub fn simple(domain: &str, version: &str) -> Self {
        let mut files = HashMap::new();
        
        files.insert(
            "index.html".to_string(),
            format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>{} - Version {}</title>
    <meta charset="utf-8">
    <meta name="version" content="{}">
</head>
<body>
    <h1>Welcome to {}</h1>
    <p>Running on Web4</p>
    <p>Version: {}</p>
</body>
</html>"#,
                domain, version, version, domain, version
            ),
        );
        
        files.insert(
            "manifest.json".to_string(),
            format!(
                r#"{{
  "name": "{}",
  "version": "{}",
  "description": "Test site for {}",
  "files": ["index.html"],
  "created": "{}"
}}"#,
                domain,
                version,
                domain,
                chrono::Utc::now().to_rfc3339()
            ),
        );
        
        SiteGenerator {
            domain: domain.to_string(),
            version: version.to_string(),
            files,
        }
    }
    
    /// Create a test site with custom files
    pub fn with_files(
        domain: &str,
        version: &str,
        files: Vec<(&str, &str)>,
    ) -> Self {
        let mut site = SiteGenerator::simple(domain, version);
        
        for (name, content) in files {
            site.files.insert(name.to_string(), content.to_string());
        }
        
        site
    }
    
    /// Create a multi-page test site
    pub fn multi_page(domain: &str, version: &str, pages: Vec<&str>) -> Self {
        let mut site = SiteGenerator::simple(domain, version);
        
        for page in pages {
            let page_file = format!("{}.html", page);
            let content = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>{} - {}</title>
</head>
<body>
    <h1>{}</h1>
    <p>This is the {} page</p>
    <p>Version: {}</p>
</body>
</html>"#,
                domain,
                page.to_uppercase(),
                page.to_uppercase(),
                page,
                version
            );
            site.files.insert(page_file, content);
        }
        
        site
    }
    
    /// Add a file to the site
    pub fn add_file(mut self, name: &str, content: &str) -> Self {
        self.files.insert(name.to_string(), content.to_string());
        self
    }
    
    /// Add multiple files to the site
    pub fn add_files(mut self, files: Vec<(&str, &str)>) -> Self {
        for (name, content) in files {
            self.files.insert(name.to_string(), content.to_string());
        }
        self
    }
    
    /// Write the generated site to disk
    pub fn write_to(&self, path: &Path) -> std::io::Result<()> {
        fs::create_dir_all(path)?;
        
        for (filename, content) in &self.files {
            let file_path = path.join(filename);
            
            // Create subdirectories if needed
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent)?;
            }
            
            fs::write(&file_path, content)?;
        }
        
        Ok(())
    }
    
    /// Get the domain of this site
    pub fn domain(&self) -> &str {
        &self.domain
    }
    
    /// Get the version of this site
    pub fn version(&self) -> &str {
        &self.version
    }
    
    /// Get number of files in site
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
    
    /// Check if a file exists in the site
    pub fn has_file(&self, name: &str) -> bool {
        self.files.contains_key(name)
    }
    
    /// Get a file's content
    pub fn get_file(&self, name: &str) -> Option<&str> {
        self.files.get(name).map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    
    #[test]
    fn test_simple_site_generation() {
        let site = SiteGenerator::simple("test.web4.local", "1.0");
        assert_eq!(site.domain(), "test.web4.local");
        assert_eq!(site.version(), "1.0");
        assert!(site.has_file("index.html"));
        assert!(site.has_file("manifest.json"));
    }
    
    #[test]
    fn test_site_with_custom_files() {
        let files = vec![
            ("page1.html", "<html>Page 1</html>"),
            ("page2.html", "<html>Page 2</html>"),
        ];
        let site = SiteGenerator::with_files("test.web4.local", "1.0", files);
        
        assert!(site.has_file("page1.html"));
        assert!(site.has_file("page2.html"));
        assert_eq!(site.file_count(), 4); // 2 custom + index + manifest
    }
    
    #[test]
    fn test_site_write_to_disk() {
        let temp = TempDir::new().unwrap();
        let site = SiteGenerator::simple("test.web4.local", "1.0");
        
        site.write_to(temp.path()).unwrap();
        
        assert!(temp.path().join("index.html").exists());
        assert!(temp.path().join("manifest.json").exists());
    }
    
    #[test]
    fn test_multi_page_site() {
        let pages = vec!["about", "contact", "services"];
        let site = SiteGenerator::multi_page("test.web4.local", "1.0", pages);
        
        assert!(site.has_file("about.html"));
        assert!(site.has_file("contact.html"));
        assert!(site.has_file("services.html"));
    }
}
