/*
 * pox_log.h
 *
 * Compile-time switchable logging for the PoX secure partition.
 * POX_LOG_ENABLE=1 routes to tfm_sp_log; 0 compiles every call out
 * entirely (zero code, zero UART overhead), keeping the instrumented
 * build comparable with the baseline in benchmarks.
 */

#ifndef POX_LOG_H
#define POX_LOG_H

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

#endif /* POX_LOG_H */
