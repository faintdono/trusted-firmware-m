# Technical Analysis: POX Feature Implementation

## Overview

This document provides a technical deep-dive into the Proof of Execution (POX) feature added in the `pox-dev` branch. The POX feature enables runtime attestation of code execution, providing cryptographic proof that specific code was executed in a trusted environment.

## POX Architecture

### Core Components

#### 1. POX Service Partition
Located in: `secure_fw/partitions/proof_of_execution/`

**Main Files:**
- `pox.c` - Service entry point and IPC handling
- `pox_handler.c/h` - Request message handling
- `pox_execute.c/h` - Execution logic and arbitrary function support
- `pox_report.c/h` - Report generation with CBOR encoding
- `tfm_pox.yaml` - Service manifest defining the secure partition

**Service Characteristics:**
- Runs as a secure partition in TF-M
- Uses IPC (Inter-Process Communication) model
- Waits on `TFM_POX_SERVICE_SIGNAL`
- Handles requests via `pox_ipc_handler()`

#### 2. POX Wire Protocol
Located in: `interface/`

**Files:**
- `tfm_pox_wire.h` - Wire protocol definitions
- `tfm_pox_wire.c` - Serialization/deserialization implementation

**Purpose:**
- Provides serialization for POX requests and responses
- Handles data marshaling between non-secure and secure worlds
- Includes deserializer for input parameters

#### 3. Integration with Initial Attestation Token (IAT)
Located in: `secure_fw/partitions/initial_attestation/`

**Modified Files:**
- `attest_execute.c/h` - Extended to support POX token generation
- `attest_token_encode.c` - CBOR encoding with POX data
- `attest_core.c` - Core attestation logic extended
- `tfm_attest_req_mngr.c` - Request manager for attestation service

**Integration Points:**
- POX tokens can be embedded within attestation tokens
- Shared CBOR encoding infrastructure
- Output handling for both attestation and POX data

## Key Technical Features

### 1. Arbitrary Function Execution
The POX service supports executing arbitrary functions with proof:
- Function pointer support
- Input parameter marshaling
- Output capture and encoding
- Stack overflow protection (fixed in commit `9e2c3a7b6`)

### 2. CBOR Encoding
POX reports use CBOR (Concise Binary Object Representation):
- Compact binary format
- Cryptographically signed
- Compatible with attestation token format
- Supports byte string outputs

### 3. Wire Protocol
Custom serialization protocol for non-secure to secure communication:
- Request serialization
- Response deserialization  
- Parameter marshaling
- Error handling

### 4. Security Features
- Secure partition isolation
- Cryptographic signing of POX reports
- Integration with platform attestation keys
- Stack protection mechanisms

## API Design

### Public API (Non-Secure World)
Expected location: `interface/include/psa/initial_attestation.h.in`

Key functions (based on commit messages):
- `psa_proof_of_execution_get_token()` - Main API to request POX token
- Integration with existing attestation APIs

### Secure API (Internal)
- IPC message handling
- Function execution framework
- Report generation
- Token encoding

## Implementation Timeline

### Phase 1: Foundation (7-9 months ago)
1. **b4e16cd7b** - Initial IAT modification
2. **7269f9e7c** - Import fixed key support
3. **8210052f0** - Add POX API and modify IAT
4. **445b195df** - Integrate POX into IAT

### Phase 2: Serialization (4 months ago)
1. **73b1a6c23** - POX serializer implementation
2. **6e19ab36d** - Wire serializer fixes
3. **01abe5737** - Deserializer implementation
4. **f2b21e933** - Wire serializer updates

### Phase 3: Refinement (3-4 months ago)
1. **b18bb2c59** - Input alignment with new-v2
2. **9e2c3a7b6** - Stack overflow fix
3. **ec630c5e0** - Serializer function fixes
4. **f368477bb** - Arbitrary function fixes
5. **c63f0e34d** - Token generation updates

### Phase 4: Output Handling (Recent)
1. **6eeef6d06** - NS output sent to TF-M (9 weeks ago)
2. **0826d777a** - Output and CBOR enhancement (8 weeks ago)

## Integration with TF-M Architecture

### Secure Partition Configuration
POX operates as a dedicated secure partition:
- Isolated memory space
- Dedicated signal handling
- PSA (Platform Security Architecture) compliant
- Configured via YAML manifest

### Boot Flow Integration
- Initialized during TF-M boot
- Attestation keys provisioned
- Platform-specific HAL integration

### Memory Layout
- Secure partition RAM allocation
- Stack protection mechanisms
- Shared data region for IPC

## Platform Support

The POX feature leverages platform attestation infrastructure:

**Platform HAL Requirements:**
- `tfm_attest_hal.h` - Attestation HAL interface
- Platform-specific attestation key storage
- Hardware-backed cryptography (where available)

**Supported Platforms:**
Based on attestation support, POX should work on:
- ARM Corstone-315
- ARM MPS4
- ARM RSE platforms
- Nordic nRF platforms (with attestation)
- Analog Devices MAX32657
- STM32 platforms
- NXP platforms

## Cryptographic Design

### Token Signing
- Uses platform attestation key
- CBOR-encoded payload
- Compatible with Entity Attestation Token (EAT) format
- Signature algorithm: Platform-dependent (typically ECDSA)

### Key Management
- Fixed key import support (commit `7269f9e7c`)
- Platform-specific key provisioning
- Integration with TF-M crypto service

## Testing Considerations

### Unit Testing
Required tests for POX:
- Service initialization
- IPC message handling
- Function execution
- Serialization/deserialization
- Report generation
- Error handling

### Integration Testing
- Attestation token with POX
- Cross-partition communication
- Platform-specific validation
- Performance benchmarks

### Security Testing
- Privilege escalation attempts
- Input validation
- Stack overflow protection
- Memory safety
- Cryptographic verification

## Performance Impact

### Memory Footprint
- New secure partition overhead
- Wire protocol buffers
- CBOR encoding buffers
- Execution context storage

### Runtime Overhead
- IPC overhead for POX calls
- Serialization/deserialization cost
- Cryptographic signing time
- Report generation

## Known Issues and Fixes

Based on commit history:

1. **Stack Overflow** (Fixed: `9e2c3a7b6`)
   - Issue: Stack overflow in execution path
   - Fix: Stack protection and validation

2. **Serializer Function** (Fixed: `ec630c5e0`)
   - Issue: Serialization bugs
   - Fix: Corrected wire protocol handling

3. **Arbitrary Function** (Fixed: `f368477bb`)
   - Issue: Function pointer execution issues
   - Fix: Improved function call mechanism

4. **Wire Installation** (Fixed: `6e19ab36d`)
   - Issue: Installation and wire protocol issues
   - Fix: Corrected build integration

## Dependencies

### Internal TF-M Dependencies
- Initial Attestation Service
- Crypto Service
- Platform HAL
- PSA IPC framework

### External Dependencies
- CBOR encoding library (t_cose/qcbor)
- mbedTLS (cryptographic operations)
- Platform-specific drivers

## Configuration Options

Expected Kconfig/CMake options:
- `TFM_PARTITION_POX` - Enable POX partition
- POX stack size configuration
- Wire protocol buffer sizes
- Integration with attestation profiles

## Future Enhancements

Potential areas for development:
1. Enhanced function execution framework
2. Multiple function chaining
3. Performance optimization
4. Additional output formats
5. Remote attestation integration
6. Caching mechanisms

## Comparison with Standard IAT

| Aspect | Standard IAT | IAT with POX |
|--------|-------------|--------------|
| Purpose | Platform attestation | Platform + execution attestation |
| Token Size | ~500-1000 bytes | Larger (includes execution proof) |
| Claims | Platform claims only | Platform + execution claims |
| Performance | Faster | Additional overhead |
| Use Case | Platform trust | Runtime code trust |

## Documentation Status

### Available Documentation
- Service integration guide updates
- Attestation guide modifications
- Design document for symmetric attestation

### Missing Documentation
- Dedicated POX user guide
- API reference documentation
- Integration examples
- Performance benchmarks
- Security analysis documentation

## Recommendations for Production Use

1. **Security Audit**: Complete security review required
2. **Performance Testing**: Benchmark on target platforms
3. **Documentation**: Create comprehensive user guide
4. **Testing**: Extensive test coverage needed
5. **Code Review**: Thorough review of all POX components
6. **Platform Validation**: Test on all supported platforms
7. **Compliance**: Verify PSA compliance
8. **Interoperability**: Test with standard verification services

## Conclusion

The POX feature represents a significant enhancement to TF-M's attestation capabilities, enabling runtime code execution attestation. The implementation follows TF-M's secure partition model and integrates cleanly with the existing attestation infrastructure. However, the feature requires thorough testing, documentation, and security review before production deployment.
