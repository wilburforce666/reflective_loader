

use std::io::{self, Read};

#[derive(Debug)]
pub enum KeyGenError {
    RandomSourceError(io::Error),
    InvalidKeyLength,
}

impl std::fmt::Display for KeyGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RandomSourceError(e) => write!(f, "Random source error: {}", e),
            Self::InvalidKeyLength => write!(f, "Invalid key length requested"),
        }
    }
}

impl std::error::Error for KeyGenError {}

pub fn generate_random_key(length: usize) -> Result<Vec<u8>, KeyGenError> {
    if length == 0 {
        return Err(KeyGenError::InvalidKeyLength);
    }

    let mut key = vec![0u8; length];
    
    #[cfg(target_os = "windows")]
    {
        use std::ptr;
        use windows_sys::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };
        
        let status = unsafe {
            BCryptGenRandom(
                0, // NULL context - use default provider
                key.as_mut_ptr(),
                key.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        
        if status != 0 {
            return Err(KeyGenError::RandomSourceError(io::Error::new(
                io::ErrorKind::Other,
                format!("BCryptGenRandom failed with status: {}", status),
            )));
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        let mut file = std::fs::File::open("/dev/urandom")
            .map_err(KeyGenError::RandomSourceError)?;
            
        file.read_exact(&mut key)
            .map_err(KeyGenError::RandomSourceError)?;
    }
    
    Ok(key)
}

pub fn generate_aes256_key() -> Result<[u8; 32], KeyGenError> {
    let key_vec = generate_random_key(32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec);
    Ok(key)
}

pub fn generate_aes_iv() -> Result<[u8; 16], KeyGenError> {
    let iv_vec = generate_random_key(16)?;
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&iv_vec);
    Ok(iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_key() {
        let key = generate_random_key(32).unwrap();
        assert_eq!(key.len(), 32);
        
        let key2 = generate_random_key(32).unwrap();
        assert_ne!(key, key2);
        
        let result = generate_random_key(0);
        assert!(result.is_err());
        match result {
            Err(KeyGenError::InvalidKeyLength) => (),
            _ => panic!("Expected InvalidKeyLength error"),
        }
    }
    
    #[test]
    fn test_generate_aes256_key() {
        let key = generate_aes256_key().unwrap();
        assert_eq!(key.len(), 32);
    }
    
    #[test]
    fn test_generate_aes_iv() {
        let iv = generate_aes_iv().unwrap();
        assert_eq!(iv.len(), 16);
    }
}
