//! File-based cache backend with atomic writes.
//!
//! Stores authenticated cache records under `dirs::data_dir()/<namespace>/`.
//! Uses temp file + rename for atomic writes.

use crate::cache::format::CacheRecord;
use crate::GatewardenError;
use std::fs;
use std::path::PathBuf;

/// File-based cache backend.
pub struct FileCache {
    /// Directory for cache files.
    cache_dir: PathBuf,
}

impl FileCache {
    /// Create a new file cache with the given namespace.
    ///
    /// Cache files are stored under `dirs::data_dir()/<namespace>/`.
    pub fn new(namespace: &str) -> Result<Self, GatewardenError> {
        let base_dir = dirs::data_dir()
            .ok_or_else(|| GatewardenError::CacheIO("Could not find data directory".to_string()))?;

        let cache_dir = base_dir.join(namespace);

        // Ensure directory exists
        fs::create_dir_all(&cache_dir)
            .map_err(|e| GatewardenError::CacheIO(format!("Failed to create cache dir: {}", e)))?;

        Ok(Self { cache_dir })
    }

    /// Create a file cache at a specific path (for testing).
    #[cfg(test)]
    pub fn with_path(cache_dir: PathBuf) -> Result<Self, GatewardenError> {
        fs::create_dir_all(&cache_dir)
            .map_err(|e| GatewardenError::CacheIO(format!("Failed to create cache dir: {}", e)))?;
        Ok(Self { cache_dir })
    }

    /// Get the path for a license cache file.
    fn license_path(&self, license_key_hash: &str) -> PathBuf {
        // Use first 16 chars of hash as filename to avoid exposing full key
        let safe_name = &license_key_hash[..16.min(license_key_hash.len())];
        self.cache_dir.join(format!("{}.json", safe_name))
    }

    /// Save a cache record atomically.
    ///
    /// Uses temp file + rename for atomic write.
    pub fn save(&self, license_key_hash: &str, record: &CacheRecord) -> Result<(), GatewardenError> {
        let target_path = self.license_path(license_key_hash);
        let temp_path = self.cache_dir.join(format!("{}.tmp", license_key_hash));

        let json = record.to_json()?;

        // Write to temp file
        fs::write(&temp_path, &json)
            .map_err(|e| GatewardenError::CacheIO(format!("Failed to write temp file: {}", e)))?;

        // Atomic rename
        fs::rename(&temp_path, &target_path)
            .map_err(|e| GatewardenError::CacheIO(format!("Failed to rename cache file: {}", e)))?;

        Ok(())
    }

    /// Load a cache record.
    pub fn load(&self, license_key_hash: &str) -> Result<Option<CacheRecord>, GatewardenError> {
        let path = self.license_path(license_key_hash);

        if !path.exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(&path)
            .map_err(|e| GatewardenError::CacheIO(format!("Failed to read cache file: {}", e)))?;

        let record = CacheRecord::from_json(&json)?;
        Ok(Some(record))
    }

    /// Delete a cache record.
    pub fn delete(&self, license_key_hash: &str) -> Result<(), GatewardenError> {
        let path = self.license_path(license_key_hash);

        if path.exists() {
            fs::remove_file(&path)
                .map_err(|e| GatewardenError::CacheIO(format!("Failed to delete cache: {}", e)))?;
        }

        Ok(())
    }

    /// Clear all cache files.
    pub fn clear(&self) -> Result<(), GatewardenError> {
        for entry in fs::read_dir(&self.cache_dir)
            .map_err(|e| GatewardenError::CacheIO(format!("Failed to read cache dir: {}", e)))?
        {
            let entry = entry
                .map_err(|e| GatewardenError::CacheIO(format!("Failed to read entry: {}", e)))?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                fs::remove_file(&path)
                    .map_err(|e| GatewardenError::CacheIO(format!("Failed to delete: {}", e)))?;
            }
        }
        Ok(())
    }
}

/// Compute a SHA-256 hash of the license key for use as cache key.
///
/// This avoids storing the raw license key in filenames.
pub fn hash_license_key(license_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(license_key.as_bytes());
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::format::CacheRecord;
    use crate::clock::MockClock;
    use chrono::{TimeZone, Utc};
    use tempfile::TempDir;

    fn make_test_record(clock: &MockClock) -> CacheRecord {
        CacheRecord::new(
            "Wed, 15 Jan 2025 12:00:00 GMT".to_string(),
            r#"algorithm="ed25519", signature="test""#.to_string(),
            Some("sha-256=abc123".to_string()),
            r#"{"data":{"valid":true}}"#.to_string(),
            "/v1/accounts/test/licenses/abc/actions/validate".to_string(),
            "api.keygen.sh".to_string(),
            clock,
        )
    }

    #[test]
    fn test_file_cache_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let cache = FileCache::with_path(temp_dir.path().to_path_buf()).unwrap();

        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let record = make_test_record(&clock);
        let key_hash = hash_license_key("test-license-key");

        // Save
        cache.save(&key_hash, &record).unwrap();

        // Load
        let loaded = cache.load(&key_hash).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.body, record.body);
        assert_eq!(loaded.date, record.date);
        assert_eq!(loaded.signature, record.signature);
    }

    #[test]
    fn test_file_cache_load_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let cache = FileCache::with_path(temp_dir.path().to_path_buf()).unwrap();

        let key_hash = hash_license_key("nonexistent");
        let loaded = cache.load(&key_hash).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_file_cache_delete() {
        let temp_dir = TempDir::new().unwrap();
        let cache = FileCache::with_path(temp_dir.path().to_path_buf()).unwrap();

        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let record = make_test_record(&clock);
        let key_hash = hash_license_key("test-license-key");

        cache.save(&key_hash, &record).unwrap();
        assert!(cache.load(&key_hash).unwrap().is_some());

        cache.delete(&key_hash).unwrap();
        assert!(cache.load(&key_hash).unwrap().is_none());
    }

    #[test]
    fn test_file_cache_clear() {
        let temp_dir = TempDir::new().unwrap();
        let cache = FileCache::with_path(temp_dir.path().to_path_buf()).unwrap();

        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let record = make_test_record(&clock);

        cache.save(&hash_license_key("key1"), &record).unwrap();
        cache.save(&hash_license_key("key2"), &record).unwrap();

        cache.clear().unwrap();

        assert!(cache.load(&hash_license_key("key1")).unwrap().is_none());
        assert!(cache.load(&hash_license_key("key2")).unwrap().is_none());
    }

    #[test]
    fn test_hash_license_key() {
        let hash1 = hash_license_key("test-key-1");
        let hash2 = hash_license_key("test-key-1");
        let hash3 = hash_license_key("test-key-2");

        // Same input produces same output
        assert_eq!(hash1, hash2);
        // Different input produces different output
        assert_ne!(hash1, hash3);
        // Output is 64 hex chars (256 bits)
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_file_cache_atomic_write() {
        let temp_dir = TempDir::new().unwrap();
        let cache = FileCache::with_path(temp_dir.path().to_path_buf()).unwrap();

        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let record1 = make_test_record(&clock);
        let key_hash = hash_license_key("test-key");

        // Save first record
        cache.save(&key_hash, &record1).unwrap();

        // Create updated record
        let mut record2 = make_test_record(&clock);
        record2.body = r#"{"data":{"valid":false}}"#.to_string();

        // Save updated record (atomic, should not corrupt if interrupted)
        cache.save(&key_hash, &record2).unwrap();

        // Load should give us the updated record
        let loaded = cache.load(&key_hash).unwrap().unwrap();
        assert_eq!(loaded.body, record2.body);
    }
}
