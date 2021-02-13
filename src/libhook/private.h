#pragma once

#ifndef PRINT_DEBUG
#ifdef DRAKVUF_DEBUG
// This is defined in libdrakvuf
extern bool verbose;

#define PRINT_DEBUG(...) \
    do { \
        if(verbose) { eprint_current_time(); fprintf (stderr, __VA_ARGS__); } \
    } while (0)

#else

#define PRINT_DEBUG(...) \
    do {} while(0)

#endif // DRAKVUF_DEBUG
#endif // PRINT_DEBUG