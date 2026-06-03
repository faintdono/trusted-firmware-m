/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __TFM_POX_DEFS_H__
#define __TFM_POX_DEFS_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Standalone PoX partition SID (must match tfm_proof_of_execution.yaml) */
#define TFM_POX_SERVICE_SID         (0xFFFFF0E1U)
#define TFM_POX_SERVICE_VERSION     (1U)

/* Message type for the single PoX IPC call */
#define TFM_POX_GET_TOKEN           (PSA_IPC_CALL)

#ifdef __cplusplus
}
#endif

#endif /* __TFM_POX_DEFS_H__ */
