
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use anyhow::{Result, Context};

use super::{PackerError, PackerConfig};
use crate::reflective_loader::{self, LoaderError};

#[cfg(target_os = "windows")]
pub fn load_packed_executable<P: AsRef<Path>>(
    input_path: P,
    device_index: Option<usize>,
) -> Result<i32, PackerError> {
    log::info!("Loading packed executable: {:?}", input_path.as_ref());
    
    let mut packed_data = Vec::new();
    let mut file = fs::File::open(&input_path)
        .with_context(|| format!("Failed to open packed file: {:?}", input_path.as_ref()))
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    file.read_to_end(&mut packed_data)
        .with_context(|| "Failed to read packed file")
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    load_packed_executable_from_memory(&packed_data, device_index)
}

#[cfg(target_os = "windows")]
pub fn load_packed_executable_from_memory(
    packed_data: &[u8],
    device_index: Option<usize>,
) -> Result<i32, PackerError> {
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
    
    let unpacked_data = if let Some(device_idx) = device_index {
        #[cfg(feature = "gpu-packing")]
        {
            match unpack_with_gpu(packed_content, segment_size as usize, segment_count as usize, &key, device_idx) {
                Ok(data) => data,
                Err(e) => {
                    log::warn!("GPU unpacking failed: {}, falling back to CPU", e);
                    unpack_with_cpu(packed_content, segment_size as usize, segment_count as usize, &key)?
                }
            }
        }
        #[cfg(not(feature = "gpu-packing"))]
        {
            log::warn!("GPU packing feature not enabled, using CPU fallback");
            unpack_with_cpu(packed_content, segment_size as usize, segment_count as usize, &key)?
        }
    } else {
        unpack_with_cpu(packed_content, segment_size as usize, segment_count as usize, &key)?
    };
    
    let calculated_checksum = super::calculate_checksum(&unpacked_data);
    if calculated_checksum != checksum {
        return Err(PackerError::InvalidFormat("Checksum verification failed".into()));
    }
    
    reflective_loader::load_pe(&unpacked_data)
        .map_err(|e| match e {
            LoaderError::IoError(io_err) => PackerError::IoError(io_err),
            _ => PackerError::InvalidFormat(format!("Failed to load PE: {}", e)),
        })
}

#[cfg(target_os = "windows")]
fn unpack_with_cpu(
    packed_content: &[u8],
    segment_size: usize,
    segment_count: usize,
    key: &[u8; 32],
) -> Result<Vec<u8>, PackerError> {
    let mut unpacked_data = Vec::with_capacity(segment_size * segment_count);
    
    for (i, chunk) in packed_content.chunks(segment_size).enumerate() {
        let mut unpacked_chunk = Vec::with_capacity(chunk.len());
        
        for (j, &byte) in chunk.iter().enumerate() {
            let key_byte = key[j % key.len()];
            let iteration_factor = (i * 10) % 256; // Assuming 10 iterations as in default config
            let unpacked_byte = byte ^ key_byte ^ (iteration_factor as u8);
            unpacked_chunk.push(unpacked_byte);
        }
        
        unpacked_data.extend_from_slice(&unpacked_chunk);
    }
    
    Ok(unpacked_data)
}

#[cfg(all(target_os = "windows", feature = "gpu-packing"))]
fn unpack_with_gpu(
    packed_content: &[u8],
    segment_size: usize,
    segment_count: usize,
    key: &[u8; 32],
    device_index: usize,
) -> Result<Vec<u8>, PackerError> {
    use ocl::{ProQue, Buffer, Kernel, SpatialDims};
    
    let platforms = ocl::Platform::list();
    if platforms.is_empty() {
        return Err(PackerError::GpuNotAvailable);
    }
    
    let mut device_found = false;
    let mut platform_idx = 0;
    let mut device_idx = 0;
    let mut global_idx = 0;
    
    'outer: for (p_idx, platform) in platforms.iter().enumerate() {
        let platform_devices = ocl::Device::list(platform, Some(ocl::core::DeviceType::GPU))
            .map_err(|e| PackerError::OpenClError(format!("Failed to list devices: {}", e)))?;
        
        for (d_idx, _) in platform_devices.iter().enumerate() {
            if global_idx == device_index {
                platform_idx = p_idx;
                device_idx = d_idx;
                device_found = true;
                break 'outer;
            }
            global_idx += 1;
        }
    }
    
    if !device_found {
        return Err(PackerError::OpenClError(format!("GPU device with index {} not found", device_index)));
    }
    
    let platform = platforms[platform_idx];
    let devices = ocl::Device::list(&platform, Some(ocl::core::DeviceType::GPU))
        .map_err(|e| PackerError::OpenClError(format!("Failed to list devices: {}", e)))?;
    let device = devices[device_idx];
    
    let context = ocl::Context::builder()
        .platform(platform)
        .devices(device)
        .build()
        .map_err(|e| PackerError::OpenClError(format!("Failed to create OpenCL context: {}", e)))?;
    
    let queue = ocl::Queue::new(&context, device, None)
        .map_err(|e| PackerError::OpenClError(format!("Failed to create command queue: {}", e)))?;
    
    let program = ocl::Program::builder()
        .devices(device)
        .src(super::opencl::PACKER_KERNEL)
        .build(&context)
        .map_err(|e| PackerError::OpenClError(format!("Failed to build OpenCL program: {}", e)))?;
    
    let mut unpacked_data = Vec::with_capacity(segment_size * segment_count);
    
    for (segment_idx, chunk) in packed_content.chunks(segment_size).enumerate() {
        let chunk_size = chunk.len();
        
        let input_buffer = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(ocl::MemFlags::new().read_only())
            .len(chunk_size)
            .copy_host_slice(chunk)
            .build()
            .map_err(|e| PackerError::OpenClError(format!("Failed to create input buffer: {}", e)))?;
        
        let output_buffer = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(ocl::MemFlags::new().write_only())
            .len(chunk_size)
            .build()
            .map_err(|e| PackerError::OpenClError(format!("Failed to create output buffer: {}", e)))?;
        
        let key_buffer = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(ocl::MemFlags::new().read_only())
            .len(key.len())
            .copy_host_slice(key)
            .build()
            .map_err(|e| PackerError::OpenClError(format!("Failed to create key buffer: {}", e)))?;
        
        let kernel = Kernel::builder()
            .program(&program)
            .name("unpack_segment")
            .queue(queue.clone())
            .global_work_size(chunk_size)
            .arg(&input_buffer)
            .arg(&output_buffer)
            .arg(&key_buffer)
            .arg(key.len() as u32)
            .arg(10 as u32) // Assuming 10 iterations as in default config
            .arg(segment_idx as u32)
            .build()
            .map_err(|e| PackerError::OpenClError(format!("Failed to create kernel: {}", e)))?;
        
        unsafe {
            kernel.enq()
                .map_err(|e| PackerError::OpenClError(format!("Failed to enqueue kernel: {}", e)))?;
        }
        
        let mut result = vec![0u8; chunk_size];
        output_buffer.read(&mut result).enq()
            .map_err(|e| PackerError::OpenClError(format!("Failed to read output buffer: {}", e)))?;
        
        unpacked_data.extend_from_slice(&result);
    }
    
    Ok(unpacked_data)
}

#[cfg(not(target_os = "windows"))]
pub fn load_packed_executable<P: AsRef<Path>>(
    _input_path: P,
    _device_index: Option<usize>,
) -> Result<i32, PackerError> {
    Err(PackerError::InvalidFormat("Not supported on this platform".into()))
}

#[cfg(not(target_os = "windows"))]
pub fn load_packed_executable_from_memory(
    _packed_data: &[u8],
    _device_index: Option<usize>,
) -> Result<i32, PackerError> {
    Err(PackerError::InvalidFormat("Not supported on this platform".into()))
}
