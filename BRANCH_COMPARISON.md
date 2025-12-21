# Branch Comparison: main vs pox-dev

## Executive Summary

This document provides a comprehensive comparison between the `main` and `pox-dev` branches of the Trusted Firmware-M repository. The `pox-dev` branch represents a significant development effort focused on adding **Proof of Execution (POX)** capabilities to the TF-M attestation service.

### Overall Statistics
- **Total files changed**: 2,189
- **Lines added**: 115,017
- **Lines removed**: 574,981
- **Net change**: -459,964 lines
- **Commits in pox-dev**: 5,828 commits
- **Key contributor**: Raned Chuphueak (POX feature development)

## Key Differences

### 1. Proof of Execution (POX) Feature - **NEW**

The most significant addition in the `pox-dev` branch is the introduction of a complete Proof of Execution (POX) service. This is an entirely new security feature that enables attestation of code execution.

#### New POX Files Added:
- `secure_fw/partitions/proof_of_execution/pox.c` - Main POX service implementation
- `secure_fw/partitions/proof_of_execution/pox_execute.c` - POX execution logic
- `secure_fw/partitions/proof_of_execution/pox_execute.h` - POX execution header
- `secure_fw/partitions/proof_of_execution/pox_handler.c` - POX IPC handler
- `secure_fw/partitions/proof_of_execution/pox_handler.h` - POX handler header
- `secure_fw/partitions/proof_of_execution/pox_report.c` - POX report generation
- `secure_fw/partitions/proof_of_execution/pox_report.h` - POX report header
- `secure_fw/partitions/proof_of_execution/tfm_pox.yaml` - POX service manifest
- `interface/include/tfm_pox_wire.h` - POX wire protocol header
- `interface/src/tfm_pox_wire.c` - POX wire protocol implementation

#### POX-Related Commits (Most Recent):
1. `0826d777a` - "attest_execute.h now can deal with output also with the cbor part we can add the output as a bytes" (8 weeks ago)
2. `6eeef6d06` - "sent ns_output to tf-m" (9 weeks ago)
3. `c63f0e34d` - "update psa_proof_of_execution_get_token" (3 months ago)
4. `f368477bb` - "fix arbitrary function" (3 months ago)
5. `ec630c5e0` - "fix serializer function" (3 months ago)
6. `9e2c3a7b6` - "fix stackoverflow" (3 months ago)
7. `b18bb2c59` - "change input to be the same as new-v2" (4 months ago)
8. `f2b21e933` - "update serializer wire" (4 months ago)
9. `01abe5737` - "add deserailizer" (4 months ago)
10. `6e19ab36d` - "fix installation file and make wire serializer work as it has to be" (4 months ago)
11. `73b1a6c23` - "pox serializer" (4 months ago)
12. `445b195df` - "IAT now have POX inside it" (7 months ago)
13. `8210052f0` - "Add API and Modify IAT to have POX" (7 months ago)

### 2. Initial Attestation Token (IAT) Modifications

The Initial Attestation service has been significantly modified to integrate POX capabilities:

#### Modified Attestation Files:
- `secure_fw/partitions/initial_attestation/attest_core.c`
- `secure_fw/partitions/initial_attestation/attest_deserializer.c`
- `secure_fw/partitions/initial_attestation/attest_execute.c`
- `secure_fw/partitions/initial_attestation/attest_execute.h`
- `secure_fw/partitions/initial_attestation/attest_token_encode.c`
- `secure_fw/partitions/initial_attestation/tfm_attest_req_mngr.c`
- `interface/include/psa/initial_attestation.h.in`
- `interface/include/tfm_attest_defs.h`
- `interface/include/tfm_attest_iat_defs.h`
- `interface/src/tfm_attest_api.c`

### 3. Boot Loader (BL1/BL2) Updates

Significant changes have been made to the boot loader components:

#### BL1 Changes:
- Modified crypto operations (`bl1/bl1_1/shared_lib/crypto/crypto_mbedcrypto.c`)
- Updated provisioning logic (`bl1/bl1_1/lib/provisioning.c`)
- Enhanced OTP (One-Time Programmable) handling
- Added post-quantum crypto support configuration
- **Deleted**: `bl1/bl1_2/bl1_dummy_rotpk_1.prv` and `.pub` (dummy root of trust keys)
- **Deleted**: Several default configuration headers

#### BL2 (MCUboot) Changes:
- Updated flash map handling
- Modified key management (`bl2/ext/mcuboot/keys.c`)
- Enhanced crypto configuration
- Removed stub files: `bl2/src/crt_exit.c`, `bl2/src/psa_stub_rng.c`

### 4. Platform-Specific Updates

The `pox-dev` branch includes extensive platform support updates, particularly for:

#### Nordic Semiconductor Platforms:
- Added support for nRF54L10 and nRF54L15
- Enhanced MPC (Memory Protection Controller) configuration
- Improved secure UART handling
- Various GPIO and flash fixes

#### Analog Devices (ADI) Platforms:
- MAX32657 support updates
- Protected Storage (PS) partition enhancements
- Increased RAM_CODE size
- Configuration flags for ITS (Internal Trusted Storage) and PS

#### ARM Platforms:
- Updates for Corstone-315, MPS4
- RSE (Runtime Security Engine) common updates

### 5. Documentation Changes

Multiple documentation files have been updated:
- Attestation integration guide updates
- Build instruction refinements
- Removed issue tracking document
- Updated maintainers list
- Configuration profile documentation updates

### 6. Configuration and Build System Changes

- Updated CMake configuration across multiple components
- Modified Kconfig options for various profiles
- Enhanced version tracking
- Improved installation scripts

### 7. Cryptographic Updates

- Added `psa_can_do_cipher()` function
- Enhanced mbedTLS configuration for both BL1 and BL2
- Post-quantum cryptography preparations

## Branch Divergence Analysis

The `pox-dev` branch has diverged significantly from `main`:

### Main Branch Current State:
- Latest commit: `e9ea674ed` - "platform: Add support of frdmmcxn947"
- Focus: Standard TF-M development with platform support additions

### POX-Dev Branch Characteristics:
- Built on top of a merge from `zephyrproject-rtos:main`
- Contains 5,828 commits not in the main branch
- Heavy focus on POX feature development over the past 7-9 months
- Active development with recent bug fixes and improvements

## Notable Deletions

Several files were removed in the `pox-dev` branch:
- `README.md` (root readme)
- Multiple default configuration headers
- Dummy cryptographic keys for BL1
- Issue tracking documentation
- MISRA standards documentation
- Various platform-specific files that may have been reorganized

## Integration Considerations

If merging `pox-dev` into `main`, consider:

1. **POX Feature**: This is a major new feature requiring thorough review and testing
2. **API Changes**: Initial attestation API has been extended with POX capabilities
3. **Breaking Changes**: Possible compatibility issues with existing attestation implementations
4. **Platform Support**: Ensure all platform-specific changes are validated
5. **Documentation**: Comprehensive documentation for POX features needs to be reviewed
6. **Testing**: Extensive testing required for the new POX service and modified attestation flow
7. **Security Review**: POX and crypto changes need security audit
8. **Build System**: Verify all CMake and Kconfig changes work across platforms

## Recommendations

1. **Code Review**: Conduct thorough code review of POX implementation
2. **Security Audit**: Perform security analysis of new POX service
3. **Testing**: Run comprehensive test suite including:
   - Unit tests for POX components
   - Integration tests for attestation with POX
   - Platform-specific validation
4. **Documentation**: Create detailed POX user guide and API documentation
5. **Phased Merge**: Consider merging in phases:
   - Phase 1: Core POX infrastructure
   - Phase 2: Attestation integration
   - Phase 3: Platform-specific updates
6. **Compatibility**: Define clear compatibility and migration path for existing users

## Conclusion

The `pox-dev` branch represents a substantial enhancement to TF-M with the addition of Proof of Execution capabilities. This feature appears to be in active development with regular bug fixes and improvements. The branch includes not only the new POX service but also significant updates to attestation, boot loaders, and platform support.

The large number of changes (over 2,000 files) and the significant line count difference suggest this has been a major development effort over many months. Careful planning and extensive testing will be required before considering any merge to the main branch.
