/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/*
 * attest_session.h
 *
 * Session authentication for the attestation partition's PoX path
 * (TFM_ATTEST_GET_POX). Self-contained: depends only on the shared
 * wire header, not on the standalone proof_of_execution partition.
 * Same protocol as that partition: the verifier signs the request
 * transcript, this side verifies with the verifier's public key and
 * holds NO session secret. Invalid signature or replay -> reject.
 *
 * Gated by POX_REQUEST_AUTH_ATT (independent from the standalone
 * partition's POX_REQUEST_AUTH) so the two PoX paths can be built
 * authenticated/unauthenticated separately for research comparison.
 */

#ifndef ATTEST_SESSION_H
#define ATTEST_SESSION_H

#include "psa/crypto.h"
#include "tfm_pox_wire.h"
#include <stdint.h>
#include <stddef.h>

/* Kconfig/CMake-driven; default off if not defined by the build. */
#ifndef POX_REQUEST_AUTH_ATT
#  define POX_REQUEST_AUTH_ATT 0
#endif

/* Own copy of pox_log.h's switch, to stay decoupled from that
 * partition. 0 compiles the calls out: benchmark baseline parity. */
#ifndef POX_LOG_ENABLE
#  define POX_LOG_ENABLE 0
#endif

#if POX_LOG_ENABLE
#  include "tfm_sp_log.h"
#  define POX_LOG_INF(...) LOG_INFFMT(__VA_ARGS__)
#  define POX_LOG_ERR(...) LOG_ERRFMT(__VA_ARGS__)
#else
#  define POX_LOG_INF(...) ((void)0)
#  define POX_LOG_ERR(...) ((void)0)
#endif

/*
 * Request transcript. Must stay identical to pox_session.h:
 *   ver | sid_len | sid | nonce_len | nonce | faddr_le32 | epoch_le32 |
 *   seq_le32
 */
#define POX_TRANSCRIPT_VERSION (3u)

/*
 * Claim labels, CBOR private-use range. Must stay identical to
 * pox_common.h so both token flavours decode the same way
 * verifier-side. The verifier's request signature is not echoed: a
 * token is issued only after it verified. -65540 was SESS_SIG;
 * retired, do not reuse.
 */
#ifndef POX_LABEL_SESSION_ID
#  define POX_LABEL_SESSION_ID    (-65537)
#  define POX_LABEL_CALLER_ID     (-65538)
#  define POX_LABEL_BOOT_EPOCH    (-65539)
#  define POX_LABEL_SEQ           (-65541)
#endif

/*
 * Validated session context, passed down to the token encoder. No
 * nonce field on purpose: the verifier nonce IS the token challenge
 * and flows via the nonce claim.
 */
typedef struct {
    const uint8_t *session_id;
    size_t         session_id_len;
    int32_t        caller_id;          /* msg->client_id, SPM-supplied */
    /* Emitted as a claim only after it verified. */
    const uint8_t *sess_sig;
    size_t         sess_sig_len;
#if POX_REQUEST_AUTH_ATT
    uint32_t       boot_epoch;
    uint32_t       seq;            /* verifier-assigned monotonic seq */
#endif
} attest_session_ctx_t;

/**
 * @brief One-shot init from attest_partition_init(): imports the
 *        verifier PUBLIC key as a VOLATILE PSA key. On failure the
 *        PoX path fails closed; IAT services are unaffected.
 */
psa_status_t attest_session_init(void);

/**
 * @brief Verify the transcript (ECDSA-P256-SHA256), then anti-replay
 *        (this partition's own seq high-water mark).
 *        State moves only after the signature verified.
 */
psa_status_t attest_session_authenticate(const sec_pox_view_t *view);

#if POX_REQUEST_AUTH_ATT
/** @brief Current boot epoch (valid after attest_session_init()). */
uint32_t attest_session_get_epoch(void);
#endif

#endif /* ATTEST_SESSION_H */
