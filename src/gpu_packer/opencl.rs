
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use anyhow::{Result, Context};

#[cfg(feature = "gpu-packing")]
use ocl::{Buffer, Kernel};

use super::{PackerConfig, PackerError, PackedFileMetadata, calculate_checksum};

#[cfg(feature = "gpu-packing")]
const PACKER_KERNEL: &str = r#"
__kernel void pack_segment(
    __global const uchar* input,
    __global uchar* output,
    __global const uchar* key,
    const uint key_length,
    const uint iterations,
    const uint segment_index
) {
    const size_t i = get_global_id(0);
    const size_t key_idx = i % key_length;
    
    uchar value = input[i];
    
    for (uint iter = 0; iter < iterations; iter++) {
        value ^= key[key_idx];
        
        value = rotate(value, (iter + segment_index) % 8);
        
        value ^= (uchar)((i * 7 + iter * 13 + segment_index * 31) % 256);
    }
    
    output[i] = value;
}

__kernel void unpack_segment(
    __global const uchar* input,
    __global uchar* output,
    __global const uchar* key,
    const uint key_length,
    const uint iterations,
    const uint segment_index
) {
    const size_t i = get_global_id(0);
    const size_t key_idx = i % key_length;
    
    uchar value = input[i];
    
    for (int iter = iterations - 1; iter >= 0; iter--) {
        value ^= (uchar)((i * 7 + iter * 13 + segment_index * 31) % 256);
        
        value = rotate(value, 8 - ((iter + segment_index) % 8));
        
        value ^= key[key_idx];
    }
    
    output[i] = value;
}
"#;

#[cfg(feature = "gpu-packing")]
pub fn list_gpu_devices() -> Result<Vec<String>, PackerError> {
    let platforms = ocl::Platform::list();
    if platforms.is_empty() {
        return Err(PackerError::GpuNotAvailable);
    }
    
    let mut devices = Vec::new();
    
    for (_platform_idx, platform) in platforms.iter().enumerate() {
        let platform_name = platform.name()
            .map_err(|e| PackerError::OpenClError(format!("Failed to get platform name: {}", e)))?;
        
        let platform_devices = ocl::Device::list(platform, Some(ocl::core::DeviceType::GPU))
            .map_err(|e| PackerError::OpenClError(format!("Failed to list devices: {}", e)))?;
        
        for (_device_idx, device) in platform_devices.iter().enumerate() {
            let device_name = device.name()
                .map_err(|e| PackerError::OpenClError(format!("Failed to get device name: {}", e)))?;
            
            let global_idx = devices.len();
            devices.push(format!("{}: {} - {}", global_idx, platform_name, device_name));
        }
    }
    
    if devices.is_empty() {
        return Err(PackerError::GpuNotAvailable);
    }
    
    Ok(devices)
}

#[cfg(feature = "gpu-packing")]
pub fn pack_file_gpu<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: &P,
    output_path: &Q,
    config: &PackerConfig,
) -> Result<(), PackerError> {
    let mut file_data = Vec::new();
    let mut file = fs::File::open(input_path)
        .with_context(|| format!("Failed to open input file: {:?}", input_path.as_ref()))
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    file.read_to_end(&mut file_data)
        .with_context(|| "Failed to read input file")
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    let checksum = calculate_checksum(&file_data);
    
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
            if global_idx == config.device_index {
                platform_idx = p_idx;
                device_idx = d_idx;
                device_found = true;
                break 'outer;
            }
            global_idx += 1;
        }
    }
    
    if !device_found {
        return Err(PackerError::OpenClError(format!("GPU device with index {} not found", config.device_index)));
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
        .src(PACKER_KERNEL)
        .build(&context)
        .map_err(|e| PackerError::OpenClError(format!("Failed to build OpenCL program: {}", e)))?;
    
    let key = super::generate_packing_key();
    
    let segment_size = config.segment_size;
    let segment_count = (file_data.len() + segment_size - 1) / segment_size;
    let mut packed_data = Vec::with_capacity(file_data.len());
    
    for (segment_idx, chunk) in file_data.chunks(segment_size).enumerate() {
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
            .copy_host_slice(&key)
            .build()
            .map_err(|e| PackerError::OpenClError(format!("Failed to create key buffer: {}", e)))?;
        
        let kernel = Kernel::builder()
            .program(&program)
            .name("pack_segment")
            .queue(queue.clone())
            .global_work_size(chunk_size)
            .arg(&input_buffer)
            .arg(&output_buffer)
            .arg(&key_buffer)
            .arg(key.len() as u32)
            .arg(config.iterations as u32)
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
        
        packed_data.extend_from_slice(&result);
    }
    
    let metadata = PackedFileMetadata {
        original_size: file_data.len() as u64,
        segment_count: segment_count as u32,
        segment_size: segment_size as u32,
        checksum,
    };
    
    let mut output_file = fs::File::create(output_path)
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
    
    log::info!("File packed successfully using GPU acceleration");
    Ok(())
}

#[cfg(feature = "gpu-packing")]
pub fn unpack_file_gpu<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    device_index: usize,
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
    let _segment_count = u32::from_le_bytes(segment_count_bytes);
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
        .src(PACKER_KERNEL)
        .build(&context)
        .map_err(|e| PackerError::OpenClError(format!("Failed to build OpenCL program: {}", e)))?;
    
    let mut unpacked_data = Vec::with_capacity(original_size as usize);
    
    for (segment_idx, chunk) in packed_content.chunks(segment_size as usize).enumerate() {
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
            .copy_host_slice(&key)
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
    
    unpacked_data.truncate(original_size as usize);
    
    let calculated_checksum = calculate_checksum(&unpacked_data);
    if calculated_checksum != checksum {
        return Err(PackerError::InvalidFormat("Checksum verification failed".into()));
    }
    
    fs::write(&output_path, &unpacked_data)
        .with_context(|| format!("Failed to write unpacked file: {:?}", output_path.as_ref()))
        .map_err(|e| PackerError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;
    
    log::info!("File unpacked successfully using GPU acceleration");
    Ok(())
}
