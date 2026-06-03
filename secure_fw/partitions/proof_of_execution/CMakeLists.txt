#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
if (NOT TFM_PARTITION_PROOF_OF_EXECUTION)
    return()
endif()

cmake_minimum_required(VERSION 3.21)

add_library(tfm_app_rot_partition_pox STATIC)

add_dependencies(tfm_app_rot_partition_pox manifest_tool)

target_sources(tfm_app_rot_partition_pox
    PRIVATE
        tfm_pox_reg_mngr.c
        pox_core.c
        pox_execute.c
        pox_deserializer.c
        pox_iat_decoder.c
        pox_encoder.c
        pox_key.c
)

# The generated sources
target_sources(tfm_app_rot_partition_pox
PRIVATE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/proof_of_execution/auto_generated/intermedia_tfm_proof_of_execution.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/proof_of_execution/auto_generated/load_info_tfm_proof_of_execution.c
)

# Set include directory
target_include_directories(tfm_app_rot_partition_pox
    PUBLIC
        .
    PRIVATE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/proof_of_execution
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/proof_of_execution
)

target_link_libraries(tfm_app_rot_partition_pox
    PRIVATE
        platform_s
        tfm_config
        tfm_t_cose_s
        tfm_sprt
        tfm_boot_status
        qcbor
        psa_crypto_config
)

# Plumb Kconfig values down into C code
target_compile_definitions(tfm_app_rot_partition_pox
    PRIVATE
        $<$<BOOL:${POX_ALLOW_RUNTIME_KEY_OVERRIDE}>:POX_ALLOW_RUNTIME_KEY_OVERRIDE=1>
        $<$<BOOL:${POX_ALLOW_PLACEHOLDER_KEY}>:POX_ALLOW_PLACEHOLDER_KEY=1>
)

target_link_libraries(tfm_spm
    PRIVATE
        tfm_app_rot_partition_pox
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_pox
)

target_compile_definitions(tfm_config
    INTERFACE
        TFM_PARTITION_PROOF_OF_EXECUTION
)