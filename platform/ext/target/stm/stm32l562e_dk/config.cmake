#-------------------------------------------------------------------------------
# Copyright (c) 2020-2021, Arm Limited. All rights reserved.
# Copyright (c) 2021 STMicroelectronics. All rights reserved.
# Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
# or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

set(PLATFORM_HAS_ISOLATION_L3_SUPPORT   ON          CACHE BOOL      "Platform supports Isolation level 3")

########################## BL2 #################################################

set(MCUBOOT_IMAGE_NUMBER                2           CACHE STRING    "Whether to combine S and NS into either 1 image, or sign each seperately")
set(BL2_TRAILER_SIZE                    0x2000      CACHE STRING    "Trailer size")

################################## Dependencies ################################
set(CONFIG_TFM_USE_TRUSTZONE            ON          CACHE BOOL      "Enable use of TrustZone to transition between NSPE and SPE")
set(TFM_MULTI_CORE_TOPOLOGY             OFF         CACHE BOOL      "Whether to build for a dual-cpu architecture")
set(CRYPTO_HW_ACCELERATOR               ON          CACHE BOOL      "Whether to enable the crypto hardware accelerator on supported platforms")
set(CRYPTO_NV_SEED                      OFF         CACHE BOOL      "Use stored NV seed to provide entropy")
set(MBEDCRYPTO_BUILD_TYPE               minsizerel  CACHE STRING "Build type of Mbed Crypto library")
set(TFM_EXTRA_GENERATED_FILE_LIST_PATH  ${CMAKE_CURRENT_SOURCE_DIR}/platform/ext/target/stm/common/generated_file_list.yaml  CACHE PATH "Path to extra generated file list. Appended to stardard TFM generated file list." FORCE)
