#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.21)

add_library(tfm_partitions INTERFACE)
target_link_libraries(tfm_partitions
    INTERFACE
        tfm_spm_defs
)

add_subdirectory(lib/runtime)
add_subdirectory(crypto)
add_subdirectory(initial_attestation)
add_subdirectory(protected_storage)
add_subdirectory(internal_trusted_storage)
add_subdirectory(platform)
add_subdirectory(firmware_update)
add_subdirectory(ns_agent_tz)
add_subdirectory(ns_agent_mailbox)
add_subdirectory(proof_of_execution)

if (CONFIG_TFM_SPM_BACKEND_IPC)
    add_subdirectory(idle_partition)
endif()

if (TFM_EXTRAS_REPO_EXTRA_PARTITIONS)
    set(TMP_EXRAS_REPO_PARTITION ${TFM_EXTRAS_REPO_EXTRA_PARTITIONS})
    list(TRANSFORM TMP_EXRAS_REPO_PARTITION PREPEND ${TFM_EXTRAS_REPO_PATH}/partitions/)
    list(APPEND TEMP_TFM_EXTRA_PARTITION_PATHS ${TMP_EXRAS_REPO_PARTITION})
endif()

list(APPEND TEMP_TFM_EXTRA_PARTITION_PATHS ${TFM_EXTRA_PARTITION_PATHS})

# Remove any duplicate entries to prevent same path appended twice in case of mulitiple runs
list(REMOVE_DUPLICATES TEMP_TFM_EXTRA_PARTITION_PATHS)

if (TEMP_TFM_EXTRA_PARTITION_PATHS)
    set(POSTFIX 1)

    foreach(EXTRA_PARTITION IN LISTS TEMP_TFM_EXTRA_PARTITION_PATHS)
        get_filename_component(EXTRA_PARTITION_NAME ${EXTRA_PARTITION} NAME_WLE)
        set(TEMP_BINARY_EXTRA_PARTITION
            ${CMAKE_CURRENT_BINARY_DIR}/partitions/${EXTRA_PARTITION_NAME}_${POSTFIX})
        add_subdirectory(${EXTRA_PARTITION} ${TEMP_BINARY_EXTRA_PARTITION})

        math(EXPR POSTFIX "${POSTFIX} + 1")
    endforeach()
endif()

target_compile_definitions(tfm_config
    INTERFACE
        $<$<STREQUAL:${TEST_PSA_API},IPC>:PSA_API_TEST_IPC>
)
