#include "libhijack.h"
#include "libdrakvuf/libdrakvuf.h"
#include "libinjector/libinjector.h"
#include "private.h"

bool setup_KeBugCheckEx_stack(hijacker_t hijacker, drakvuf_trap_info_t *info)
{
    struct argument args[5];
    init_int_argument(&args[0], 0xE2222222);
    unicode_string_t *s1, *s2, *s3, *s4;
    s1 = convert_utf8_to_utf16("string1");
    s2 = convert_utf8_to_utf16("string2");
    s3 = convert_utf8_to_utf16("string3");
    s4 = convert_utf8_to_utf16("string4");
    init_unicode_argument(&args[1],s1);
    init_unicode_argument(&args[2],s2);
    init_unicode_argument(&args[3],s3);
    init_unicode_argument(&args[4],s4);
    return setup_stack(hijacker->drakvuf, info, args, ARRAY_SIZE(args));
}

bool setup_noError_stack(hijacker_t hijacker, drakvuf_trap_info_t *info)
{
    struct argument args[1];
    init_int_argument(&args[0], 0xE2222222);
    return setup_stack(hijacker->drakvuf, info, args, ARRAY_SIZE(args));
}