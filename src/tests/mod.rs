
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
}
