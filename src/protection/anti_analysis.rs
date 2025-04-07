

use std::io::Read;
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq)]
pub enum DetectionType {
    Debugger,
    VirtualMachine,
    TimingAnomaly,
    SuspiciousEnvironment,
}

#[derive(Debug)]
pub struct AnalysisResult {
    pub detected: bool,
    pub detections: Vec<DetectionType>,
}

impl AnalysisResult {
    pub fn new() -> Self {
        Self {
            detected: false,
            detections: Vec::new(),
        }
    }

    pub fn add_detection(&mut self, detection: DetectionType) {
        self.detected = true;
        self.detections.push(detection);
    }
}

pub fn is_debugger_present() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        unsafe { IsDebuggerPresent() != 0 }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(mut file) = std::fs::File::open("/proc/self/status") {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                for line in content.lines() {
                    if line.starts_with("TracerPid:") {
                        let tracer_pid = line.split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse::<i32>().ok())
                            .unwrap_or(0);
                        return tracer_pid != 0;
                    }
                }
            }
        }
        false
    }

    #[cfg(target_os = "macos")]
    {
        for var in &["DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE"] {
            if std::env::var(var).is_ok() {
                return true;
            }
        }
        false
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

pub fn is_vm_environment() -> bool {
    #[cfg(target_os = "windows")]
    {
        let vm_services = [
            "VMTools", "VBoxService", "VBoxTray", "vmware-tools",
            "vmware-tray", "Parallels Tools",
        ];
        
        for service in &vm_services {
            if std::process::Command::new("sc")
                .args(&["query", service])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
            {
                return true;
            }
        }
        
        false
    }

    #[cfg(target_os = "linux")]
    {
        let vm_files = [
            "/proc/scsi/scsi", // Check for VM-specific SCSI devices
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
        ];
        
        for file_path in &vm_files {
            if let Ok(mut file) = std::fs::File::open(file_path) {
                let mut content = String::new();
                if file.read_to_string(&mut content).is_ok() {
                    let content_lower = content.to_lowercase();
                    if content_lower.contains("vmware") || 
                       content_lower.contains("virtualbox") || 
                       content_lower.contains("qemu") || 
                       content_lower.contains("parallels") {
                        return true;
                    }
                }
            }
        }
        
        let vm_processes = ["VBoxService", "vmtoolsd", "prl_tools"];
        for process in &vm_processes {
            if std::process::Command::new("pgrep")
                .arg(process)
                .output()
                .map(|output| !output.stdout.is_empty())
                .unwrap_or(false)
            {
                return true;
            }
        }
        
        false
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        false
    }
}

pub fn detect_timing_anomaly() -> bool {
    let start = Instant::now();
    
    let mut sum = 0;
    for i in 0..1000 {
        sum += i;
    }
    
    if sum == 0 {
        return false;
    }
    
    let elapsed = start.elapsed();
    
    elapsed > Duration::from_millis(10)
}

pub fn check_suspicious_environment() -> bool {
    let suspicious_vars = [
        "DEBUG", "_DEBUG", "DEBUGGER",
        "VALGRIND", "MEMCHECK", "CALLGRIND",
        "SANDBOX", "SANDBOXED",
    ];
    
    for var in &suspicious_vars {
        if std::env::var(var).is_ok() {
            return true;
        }
    }
    
    false
}

pub fn analyze_environment() -> AnalysisResult {
    let mut result = AnalysisResult::new();
    
    if is_debugger_present() {
        result.add_detection(DetectionType::Debugger);
    }
    
    if is_vm_environment() {
        result.add_detection(DetectionType::VirtualMachine);
    }
    
    if detect_timing_anomaly() {
        result.add_detection(DetectionType::TimingAnomaly);
    }
    
    if check_suspicious_environment() {
        result.add_detection(DetectionType::SuspiciousEnvironment);
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_result() {
        let mut result = AnalysisResult::new();
        assert!(!result.detected);
        assert_eq!(result.detections.len(), 0);
        
        result.add_detection(DetectionType::Debugger);
        assert!(result.detected);
        assert_eq!(result.detections.len(), 1);
        assert_eq!(result.detections[0], DetectionType::Debugger);
    }
    
    #[test]
    fn test_timing_anomaly() {
        let _ = detect_timing_anomaly();
    }
    
    #[test]
    fn test_analyze_environment() {
        let result = analyze_environment();
        println!("Analysis result: {:?}", result);
    }
}
