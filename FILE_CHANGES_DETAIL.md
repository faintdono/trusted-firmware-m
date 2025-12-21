# Detailed File Changes: main vs pox-dev

## Summary Statistics

- **Files Added (A)**: 147
- **Files Deleted (D)**: 922
- **Files Modified (M)**: 847
- **Files Renamed (R)**: 273 (with various similarity percentages)
- **Total Changes**: 2,189 files

## Key New Files (POX-Related)

### Proof of Execution Service
```
A  secure_fw/partitions/proof_of_execution/pox.c
A  secure_fw/partitions/proof_of_execution/pox_execute.c
A  secure_fw/partitions/proof_of_execution/pox_execute.h
A  secure_fw/partitions/proof_of_execution/pox_handler.c
A  secure_fw/partitions/proof_of_execution/pox_handler.h
A  secure_fw/partitions/proof_of_execution/pox_report.c
A  secure_fw/partitions/proof_of_execution/pox_report.h
A  secure_fw/partitions/proof_of_execution/tfm_pox.yaml
```

### POX Interface/API
```
A  interface/include/tfm_pox_wire.h
A  interface/src/tfm_pox_wire.c
```

## Major File Changes by Category

### 1. Initial Attestation (Modified)
```
M  secure_fw/partitions/initial_attestation/CMakeLists.txt
M  secure_fw/partitions/initial_attestation/attest.h
M  secure_fw/partitions/initial_attestation/attest_core.c
M  secure_fw/partitions/initial_attestation/attest_deserializer.c
M  secure_fw/partitions/initial_attestation/attest_execute.c
M  secure_fw/partitions/initial_attestation/attest_execute.h
M  secure_fw/partitions/initial_attestation/attest_token_encode.c
M  secure_fw/partitions/initial_attestation/tfm_attest_req_mngr.c
M  secure_fw/partitions/initial_attestation/tfm_initial_attestation.yaml
M  interface/include/psa/initial_attestation.h.in
M  interface/include/tfm_attest_defs.h
M  interface/include/tfm_attest_iat_defs.h
M  interface/src/tfm_attest_api.c
```

### 2. Boot Loader BL1 Changes
```
M  bl1/Kconfig
M  bl1/bl1_1/CMakeLists.txt
M  bl1/bl1_1/main.c
M  bl1/bl1_1/lib/provisioning.c
M  bl1/bl1_1/shared_lib/CMakeLists.txt
M  bl1/bl1_1/shared_lib/crypto/crypto_mbedcrypto.c
M  bl1/bl1_1/shared_lib/crypto/mbedcrypto_config.h
M  bl1/bl1_1/shared_lib/interface/crypto.h
M  bl1/bl1_1/shared_lib/otp/otp_default.c
M  bl1/bl1_1/shared_lib/pq_crypto/pq_crypto_psa.c
A  bl1/bl1_1/shared_lib/interface/log.h
A  bl1/bl1_1/shared_lib/pq_crypto/mbedtls-pq-cfg.h
A  bl1/bl1_1/shared_lib/trng/trng_dummy.c
D  bl1/bl1_1/default_config/bl1_1_config.h
D  bl1/bl1_2/bl1_dummy_rotpk_1.prv
D  bl1/bl1_2/bl1_dummy_rotpk_1.pub
D  bl1/bl1_2/default_config/bl1_2_config.h
```

### 3. Boot Loader BL2 (MCUboot) Changes
```
M  bl2/CMakeLists.txt
M  bl2/ext/mcuboot/CMakeLists.txt
M  bl2/ext/mcuboot/Kconfig
M  bl2/ext/mcuboot/bl2_main.c
M  bl2/ext/mcuboot/config/mcuboot-mbedtls-cfg.h
M  bl2/ext/mcuboot/config/mcuboot_crypto_config.h
M  bl2/ext/mcuboot/flash_map_extended.c
M  bl2/ext/mcuboot/keys.c
M  bl2/src/default_flash_map.c
M  bl2/src/flash_map.c
M  bl2/src/provisioning.c
M  bl2/src/shared_data.c
D  bl2/src/crt_exit.c
D  bl2/src/psa_stub_rng.c
```

### 4. Platform Support Changes

#### Nordic nRF (Major Updates)
```
A  platform/ext/target/nordic_nrf/common/nrf54l/...
A  platform/ext/target/nordic_nrf/nrf54l10/...
A  platform/ext/target/nordic_nrf/nrf54l15/...
M  platform/ext/target/nordic_nrf/common/core/...
```

#### ARM Platforms
```
M  platform/ext/target/arm/mps4/corstone315/...
M  platform/ext/target/arm/rse/common/...
```

#### Analog Devices (ADI)
```
M  platform/ext/target/adi/max32657/...
```

#### NXP Platforms
```
A  platform/ext/target/nxp/common/Native_Driver/drivers/frdmmcxn947/...
```

#### STM32 Platforms
```
A  docs/platform/stm/common/stm32h5xx/readme.rst
A  docs/platform/stm/common/stm32l5xx/readme.rst
A  docs/platform/stm/common/stm32u5xx/readme.rst
```

### 5. Cryptographic Library Updates
```
M  lib/ext/mbedcrypto/...
M  lib/ext/cryptocell-312-runtime/...
A  lib/ext/cmsis/0001-iar-Add-missing-v8.1m-check.patch
```

### 6. Configuration and Build System
```
M  CMakeLists.txt
M  Kconfig
M  cmake/install.cmake
M  cmake/spe-CMakeLists.cmake
M  cmake/version.cmake
M  config/build_type/*.cmake
M  config/check_config.cmake
M  config/config_base.cmake
M  config/config_base.h
M  config/kconfig.cmake
M  config/profile/*.h
M  config/profile/*.conf
```

### 7. Documentation
```
M  docs/CMakeLists.txt
M  docs/conf.py
M  docs/building/documentation_generation.rst
M  docs/building/tfm_build_instruction.rst
M  docs/design_docs/services/symmetric_initial_attest.rst
M  docs/integration_guide/services/tfm_attestation_integration_guide.rst
M  docs/contributing/coding_guide.rst
M  docs/contributing/maintainers.rst
A  docs/releases/2.1.2.rst
A  docs/security/threat_models/overall-DFD.png
D  docs/contributing/issue_tracking.rst
D  docs/contributing/standards/misra.rst
D  README.md
```

### 8. Testing Infrastructure
```
M  lib/ext/psa_arch_tests/...
M  lib/ext/tf-m-tests/...
```

## Notable Deletions

### Root Level
- `README.md` - Main repository README deleted

### BL1 Deletions
- `bl1/bl1_2/bl1_dummy_rotpk_1.prv` - Dummy private key
- `bl1/bl1_2/bl1_dummy_rotpk_1.pub` - Dummy public key
- `bl1/bl1_1/default_config/bl1_1_config.h` - Default config
- `bl1/bl1_2/default_config/bl1_2_config.h` - Default config
- `bl1/bl1_2/lib/interface/image_layout_bl1_2.h` - Image layout header

### BL2 Deletions
- `bl2/src/crt_exit.c` - C runtime exit stub
- `bl2/src/psa_stub_rng.c` - PSA RNG stub

### Documentation Deletions
- `docs/contributing/issue_tracking.rst` - Issue tracking guide
- `docs/contributing/standards/misra.rst` - MISRA standards doc

### Platform Deletions
- 922 total files deleted, many related to:
  - Old platform configurations
  - Deprecated header files
  - Outdated documentation
  - Legacy test files

## File Renaming Patterns

The branch includes 273 renamed files with similarity ranging from 50% to 100%:
- **126 files** with 100% similarity (exact copies)
- Most renames appear to be repository reorganization
- Platform-specific files moved to new directory structures
- Test files reorganized

## Areas of Concentrated Change

### Top 10 Most Changed Directories
1. `platform/ext/` - Platform support (1000+ files)
2. `lib/ext/` - External libraries (500+ files)
3. `secure_fw/` - Secure firmware partitions (200+ files)
4. `bl1/` - Boot Loader 1 (100+ files)
5. `bl2/` - Boot Loader 2 (80+ files)
6. `docs/` - Documentation (60+ files)
7. `interface/` - Public interfaces (40+ files)
8. `config/` - Configuration files (30+ files)
9. `cmake/` - Build system (20+ files)
10. `tools/` - Build and test tools (15+ files)

## Merge Complexity Assessment

### High Complexity Areas
1. **Attestation Service**: Deep integration with POX requires careful review
2. **Platform Support**: Extensive platform-specific changes need per-platform validation
3. **Boot Loaders**: Critical security component with significant modifications
4. **Build System**: Widespread CMake and Kconfig changes

### Medium Complexity Areas
1. **Documentation**: Many updates but lower risk
2. **External Libraries**: Library updates need compatibility checks
3. **Configuration**: Profile and config changes need testing

### Low Complexity Areas
1. **New POX Files**: Additive changes, lower merge conflict risk
2. **Test Files**: Isolated from core functionality

## Recommended Merge Strategy

1. **Isolate POX Feature**: Extract POX-specific additions first
2. **Update Attestation**: Merge attestation changes separately
3. **Platform Updates**: Merge platform changes per-platform with validation
4. **Boot Loader**: Carefully merge and test BL1/BL2 changes
5. **Build System**: Merge configuration and build changes last
6. **Verification**: Run full test suite after each phase

## Risk Assessment

- **High Risk**: Attestation modifications, boot loader changes
- **Medium Risk**: Platform support updates, crypto library changes
- **Low Risk**: Documentation updates, new file additions
- **Critical**: Security review required for POX and attestation integration
