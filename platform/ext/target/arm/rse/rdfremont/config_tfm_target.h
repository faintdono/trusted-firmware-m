/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __CONFIG_TFM_TARGET_H__
#define __CONFIG_TFM_TARGET_H__

/* Use stored NV seed to provide entropy */
#define CRYPTO_NV_SEED                         0

/* Use external RNG to provide entropy */
#define CRYPTO_EXT_RNG                         1

/* Set the initial attestation token profile */
#undef ATTEST_TOKEN_PROFILE_PSA_IOT_1
#undef ATTEST_TOKEN_PROFILE_PSA_2_0_0

#define ATTEST_TOKEN_PROFILE_ARM_CCA           1

/* The stack size of the NS Agent Mailbox Secure Partition */
#define NS_AGENT_MAILBOX_STACK_SIZE            0x1000

/* Run the scheduler after handling a secure interrupt if the NSPE was pre-empted */
#define CONFIG_TFM_SCHEDULE_WHEN_NS_INTERRUPTED 1

#endif /* __CONFIG_TFM_TARGET_H__ */
