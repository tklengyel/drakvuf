#ifndef PRINT_UTIL_H
#define PRINT_UTIL_H

#include <inttypes.h>
#include <sys/time.h>

typedef enum
{
    OUTPUT_DEFAULT,
    OUTPUT_CSV,
    OUTPUT_KV,
    __OUTPUT_MAX
} output_format_t;

#ifdef __cplusplus
extern "C" {
#endif

// Retrieves system time in seconds and microseconds.
struct timeval get_time();

#ifdef __cplusplus
}
#endif

// Printf helpers for timeval.
#define FORMAT_TIMEVAL "%" PRId64 ".%06" PRId64
#define UNPACK_TIMEVAL(t) (t).tv_sec, (t).tv_usec

#endif // PRINT_UTIL_H
