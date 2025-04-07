
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use anyhow::{Result, Context};

#[cfg(feature = "gpu-packing")]
mod opencl;

mod loader;

#[cfg(feature = "gpu-packing")]
pub use self::opencl::*;
pub use self::loader::*;

#[derive(thiserror::Error, Debug)]
pub enum PackerError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    
    #[error("OpenCL error: {0}")]
    OpenClError(String),
    
    #[error("Invalid file format: {0}")]
    InvalidFormat(String),
    
    #[error("GPU not available")]
    GpuNotAvailable,
    
    #[error("Encryption error: {0}")]
    EncryptionError(String),
}

#[derive(Debug, Clone)]
pub struct PackerConfig {
    pub device_index: usize,
    pub segment_size: usize,
    pub iterations: usize,
    pub use_encryption: bool,
}

impl Default for PackerConfig {
    fn default() -> Self {
        Self {
            device_index: 0,
            segment_size: 4096,
            iterations: 10,
            use_encryption: true,
        }
    }
}

#[derive(Debug)]
pub struct PackedFileMetadata {
    pub original_size: u64,
    pub segment_count: u32,
    pub segment_size: u32,
    pub checksum: [u8; 32],
}

pub fn pack_file_cpu<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    config: &PackerConfig,
) -> Result<(), PackerError> {
    log::info!("Using CPU fallback for packing (GPU not available)");
    
    let mut file_data = Vec::new();
    let mut file = fs::File::open(&input_path)
        .with_context(|| format!("Failed to open input file: {:?}", input_path.as_ref()))
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    file.read_to_end(&mut file_data)
        .with_context(|| "Failed to read input file")
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    let checksum = calculate_checksum(&file_data);
    
    let mut packed_data = Vec::with_capacity(file_data.len());
    let key = generate_packing_key();
    
    for (i, chunk) in file_data.chunks(config.segment_size).enumerate() {
        let mut packed_chunk = Vec::with_capacity(chunk.len());
        
        for (j, &byte) in chunk.iter().enumerate() {
            let key_byte = key[j % key.len()];
            let iteration_factor = (i * config.iterations) % 256;
            let packed_byte = byte ^ key_byte ^ (iteration_factor as u8);
            packed_chunk.push(packed_byte);
        }
        
        packed_data.extend_from_slice(&packed_chunk);
    }
    
    let segment_count = (file_data.len() + config.segment_size - 1) / config.segment_size;
    let metadata = PackedFileMetadata {
        original_size: file_data.len() as u64,
        segment_count: segment_count as u32,
        segment_size: config.segment_size as u32,
        checksum,
    };
    
    let mut output_file = fs::File::create(&output_path)
        .with_context(|| format!("Failed to create output file: {:?}", output_path.as_ref()))
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    output_file.write_all(b"GPUPACKED")
        .with_context(|| "Failed to write magic bytes")
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    output_file.write_all(&metadata.original_size.to_le_bytes())
        .with_context(|| "Failed to write metadata")
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    output_file.write_all(&metadata.segment_count.to_le_bytes())
        .with_context(|| "Failed to write metadata")
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    output_file.write_all(&metadata.segment_size.to_le_bytes())
        .with_context(|| "Failed to write metadata")
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    output_file.write_all(&metadata.checksum)
        .with_context(|| "Failed to write checksum")
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    output_file.write_all(&key)
        .with_context(|| "Failed to write key")
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    output_file.write_all(&packed_data)
        .with_context(|| "Failed to write packed data")
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    log::info!("File packed successfully using CPU fallback");
    Ok(())
}

fn generate_packing_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    
    #[cfg(feature = "gpu-packing")]
    {
        if let Ok(generated_key) = crate::protection::key_generator::generate_aes256_key() {
            key.copy_from_slice(&generated_key);
            return key;
        }
    }
    
    for i in 0..32 {
        key[i] = ((i * 7 + 13) % 256) as u8;
    }
    
    key
}

fn calculate_checksum(data: &[u8]) -> [u8; 32] {
    let mut checksum = [0u8; 32];
    
    for (i, &byte) in data.iter().enumerate() {
        checksum[i % 32] = checksum[i % 32].wrapping_add(byte);
    }
    
    checksum
}

pub fn pack_file<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    config: &PackerConfig,
) -> Result<(), PackerError> {
    #[cfg(feature = "gpu-packing")]
    {
        match opencl::pack_file_gpu(&input_path, &output_path, config) {
            Ok(_) => return Ok(()),
            Err(e) => {
                log::warn!("GPU packing failed: {}, falling back to CPU", e);
                return pack_file_cpu(input_path, output_path, config);
            }
        }
    }
    
    #[cfg(not(feature = "gpu-packing"))]
    {
        pack_file_cpu(input_path, output_path, config)
    }
}

pub fn unpack_file<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
) -> Result<(), PackerError> {
    let mut packed_data = Vec::new();
    let mut file = fs::File::open(&input_path)
        .with_context(|| format!("Failed to open packed file: {:?}", input_path.as_ref()))
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    file.read_to_end(&mut packed_data)
        .with_context(|| "Failed to read packed file")
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    if packed_data.len() < 8 || &packed_data[0..8] != b"GPUPACKED" {
        return Err(PackerError::InvalidFormat("Not a valid packed file".into()));
    }
    
    let mut offset = 8;
    
    if packed_data.len() < offset + 8 {
        return Err(PackerError::InvalidFormat("Invalid metadata: missing original size".into()));
    }
    let mut original_size_bytes = [0u8; 8];
    original_size_bytes.copy_from_slice(&packed_data[offset..offset+8]);
    let original_size = u64::from_le_bytes(original_size_bytes);
    offset += 8;
    
    if packed_data.len() < offset + 4 {
        return Err(PackerError::InvalidFormat("Invalid metadata: missing segment count".into()));
    }
    let mut segment_count_bytes = [0u8; 4];
    segment_count_bytes.copy_from_slice(&packed_data[offset..offset+4]);
    let segment_count = u32::from_le_bytes(segment_count_bytes);
    offset += 4;
    
    if packed_data.len() < offset + 4 {
        return Err(PackerError::InvalidFormat("Invalid metadata: missing segment size".into()));
    }
    let mut segment_size_bytes = [0u8; 4];
    segment_size_bytes.copy_from_slice(&packed_data[offset..offset+4]);
    let segment_size = u32::from_le_bytes(segment_size_bytes);
    offset += 4;
    
    if packed_data.len() < offset + 32 {
        return Err(PackerError::InvalidFormat("Invalid metadata: missing checksum".into()));
    }
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&packed_data[offset..offset+32]);
    offset += 32;
    
    if packed_data.len() < offset + 32 {
        return Err(PackerError::InvalidFormat("Invalid metadata: missing key".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&packed_data[offset..offset+32]);
    offset += 32;
    
    if packed_data.len() <= offset {
        return Err(PackerError::InvalidFormat("Invalid packed file: no data".into()));
    }
    let packed_content = &packed_data[offset..];
    
    let mut unpacked_data = Vec::with_capacity(original_size as usize);
    
    for (i, chunk) in packed_content.chunks(segment_size as usize).enumerate() {
        let mut unpacked_chunk = Vec::with_capacity(chunk.len());
        
        for (j, &byte) in chunk.iter().enumerate() {
            let key_byte = key[j % key.len()];
            let iteration_factor = (i * 10) % 256; // Assuming 10 iterations as in default config
            let unpacked_byte = byte ^ key_byte ^ (iteration_factor as u8);
            unpacked_chunk.push(unpacked_byte);
        }
        
        unpacked_data.extend_from_slice(&unpacked_chunk);
    }
    
    unpacked_data.truncate(original_size as usize);
    
    let calculated_checksum = calculate_checksum(&unpacked_data);
    if calculated_checksum != checksum {
        return Err(PackerError::InvalidFormat("Checksum verification failed".into()));
    }
    
    fs::write(&output_path, &unpacked_data)
        .with_context(|| format!("Failed to write unpacked file: {:?}", output_path.as_ref()))
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    log::info!("File unpacked successfully");
    Ok(())
}
