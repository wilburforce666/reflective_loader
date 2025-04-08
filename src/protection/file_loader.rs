


use std::fs;
use std::io::{self, Read};
use std::path::Path;

use aes::Aes256;
use aes::cipher::BlockDecryptMut;
use cbc::{Decryptor, cipher::{KeyIvInit, block_padding::Pkcs7}};

use super::key_generator::{self, KeyGenError};

#[derive(Debug)]
pub enum FileLoadError {
    IoError(io::Error),
    KeyError(KeyGenError),
    DecryptionError(String),
    FileTooLarge(u64),
    InvalidFormat,
}

impl std::fmt::Display for FileLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "I/O error: {}", e),
            Self::KeyError(e) => write!(f, "Key error: {}", e),
            Self::DecryptionError(e) => write!(f, "Decryption error: {}", e),
            Self::FileTooLarge(size) => write!(f, "File too large to load safely: {} bytes", size),
            Self::InvalidFormat => write!(f, "Invalid file format"),
        }
    }
}

impl std::error::Error for FileLoadError {}

impl From<io::Error> for FileLoadError {
    fn from(error: io::Error) -> Self {
        Self::IoError(error)
    }
}

impl From<KeyGenError> for FileLoadError {
    fn from(error: KeyGenError) -> Self {
        Self::KeyError(error)
    }
}

const MAX_SAFE_FILE_SIZE: u64 = 100 * 1024 * 1024;

#[derive(Debug)]
pub struct EncryptedFileMetadata {
    pub original_filename: String,
    pub original_size: u64,
    pub timestamp: u64,
    pub checksum: [u8; 32],
}

#[derive(Debug)]
pub struct ProtectedFile {
    pub content: Vec<u8>,
    pub metadata: Option<EncryptedFileMetadata>,
}

impl ProtectedFile {
    pub fn content(&self) -> &[u8] {
        &self.content
    }
    
    pub fn metadata(&self) -> Option<&EncryptedFileMetadata> {
        self.metadata.as_ref()
    }
    
    pub fn secure_wipe(&mut self) {
        for byte in &mut self.content {
            *byte = 0;
        }
    }
}

impl Drop for ProtectedFile {
    fn drop(&mut self) {
        self.secure_wipe();
    }
}

pub fn load_encrypted_file<P: AsRef<Path>>(
    path: P,
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<ProtectedFile, FileLoadError> {
    let metadata = fs::metadata(&path)?;
    if metadata.len() > MAX_SAFE_FILE_SIZE {
        return Err(FileLoadError::FileTooLarge(metadata.len()));
    }
    
    let mut encrypted_data = Vec::new();
    let mut file = fs::File::open(&path)?;
    file.read_to_end(&mut encrypted_data)?;
    
    let cipher = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| FileLoadError::DecryptionError("Invalid key or IV".to_string()))?;
    
    let mut buffer = vec![0u8; encrypted_data.len()];
    let decrypted_content = cipher
        .decrypt_padded_b2b_mut::<Pkcs7>(&encrypted_data, &mut buffer)
        .map_err(|e| FileLoadError::DecryptionError(format!("Decryption failed: {:?}", e)))?;
    
    Ok(ProtectedFile {
        content: decrypted_content.to_vec(),
        metadata: None,
    })
}

pub fn load_file_with_env_keys<P: AsRef<Path>>(
    path: P,
) -> Result<ProtectedFile, FileLoadError> {
    let key = match std::env::var("AES_KEY") {
        Ok(key_str) if key_str.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(key_str.as_bytes());
            key
        },
        _ => key_generator::generate_aes256_key()?,
    };
    
    let iv = match std::env::var("AES_IV") {
        Ok(iv_str) if iv_str.len() == 16 => {
            let mut iv = [0u8; 16];
            iv.copy_from_slice(iv_str.as_bytes());
            iv
        },
        _ => key_generator::generate_aes_iv()?,
    };
    
    load_encrypted_file(path, &key, &iv)
}

#[cfg(feature = "encryption")]
pub fn encrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<(), FileLoadError> {
    use cbc::{Encryptor, cipher::BlockEncryptMut};
    
    let mut file_data = Vec::new();
    let mut file = fs::File::open(&input_path)?;
    file.read_to_end(&mut file_data)?;
    
    let cipher = Encryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| FileLoadError::DecryptionError("Invalid key or IV".to_string()))?;
    
    let mut buffer = vec![0u8; file_data.len() + 32]; // Add extra space for padding
    
    buffer[..file_data.len()].copy_from_slice(&file_data);
    
    let encrypted_data = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, file_data.len())
        .map_err(|e| FileLoadError::DecryptionError(format!("Encryption failed: {:?}", e)))?;
    
    fs::write(output_path, encrypted_data)?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_protected_file_wipe() {
        let content = vec![1, 2, 3, 4, 5];
        let mut file = ProtectedFile {
            content: content.clone(),
            metadata: None,
        };
        
        assert_eq!(file.content(), &content);
        
        file.secure_wipe();
        assert_eq!(file.content(), &vec![0, 0, 0, 0, 0]);
    }
    
    #[test]
    fn test_file_too_large_error() {
        let err = FileLoadError::FileTooLarge(200_000_000);
        assert!(format!("{}", err).contains("File too large"));
    }
    
    #[cfg(feature = "encryption")]
    #[test]
    fn test_encrypt_and_decrypt() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_content = b"This is a test file for encryption and decryption";
        temp_file.write_all(test_content).unwrap();
        
        let key = key_generator::generate_aes256_key().unwrap();
        let iv = key_generator::generate_aes_iv().unwrap();
        
        let encrypted_file = NamedTempFile::new().unwrap();
        
        encrypt_file(
            temp_file.path(),
            encrypted_file.path(),
            &key,
            &iv,
        ).unwrap();
        
        let protected_file = load_encrypted_file(
            encrypted_file.path(),
            &key,
            &iv,
        ).unwrap();
        
        assert_eq!(protected_file.content(), test_content);
    }
}
