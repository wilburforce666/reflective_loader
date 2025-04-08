# Reflective Loader with GPU-Accelerated Packing

## Project Overview
This project implements a Windows-specific reflective loader in Rust that provides secure file protection with GPU-accelerated packing and unique memory loading techniques. The loader can decrypt payloads using AES-256-CBC and execute them in-memory with various obfuscation strategies.

## Key Features

### 1. Reflective Loading
- In-memory PE file execution without touching disk
- Multiple memory allocation strategies
- Customizable section mapping techniques
- Import resolution and relocation handling

### 2. GPU-Accelerated Packing
- Parallel processing of file segments using OpenCL
- CPU fallback for systems without GPU support
- Checksum verification for integrity
- Configurable segment size and iteration count

### 3. Security Features
- AES-256-CBC encryption/decryption
- Environment analysis for anti-debugging
- Secure key generation and management
- Memory-only decryption to prevent disk artifacts

### 4. RUNPE Module
- Process hollowing capabilities
- Unique and obscure memory loading techniques
- Multiple injection strategies
- Configurable target process selection

### 5. Command-Line Interface
- Pack/unpack operations
- GPU device selection
- Direct execution of protected files
- Verbose logging options

## Implementation Details

### Memory Allocation Strategies
- Standard contiguous allocation
- Non-contiguous memory regions
- Random padding between sections
- Reverse order loading
- Hollowed region technique

### Section Mapping Strategies
- Standard sequential mapping
- Random order section loading
- Fragmented section mapping
- Custom protection flags
- Delayed protection application

## Testing
Comprehensive test suite covering:
- Key generation and encryption
- Environment analysis
- GPU packing with CPU fallback
- Reflective loading with various strategies
- RUNPE injection techniques
- Error handling scenarios

## Usage
```bash
# Pack an executable
cargo run -- pack --input original.exe --output protected.exe --gpu-device 0

# Run a protected executable
cargo run -- run --input protected.exe

# Use RUNPE injection
cargo run -- run --input protected.exe --runpe --target explorer.exe
```

## Security Considerations
This tool is designed for legitimate security purposes such as software protection and authorized penetration testing. All techniques are implemented with proper safeguards and documentation to ensure ethical use.
