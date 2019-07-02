#include "libhijack.h"
#include "libdrakvuf/libdrakvuf.h"
#include "libinjector/libinjector.h"
#include "private.h"

bool setup_stack_from_json(hijacker_t hijacker, drakvuf_trap_info_t *info)
{
    drakvuf_t drakvuf = hijacker->drakvuf;
    json_object *jargs = hijacker->args;
    fprintf(stderr, "in setup stack from json\n"
                    "%s\n", json_object_to_json_string_ext(jargs, JSON_C_TO_STRING_PRETTY));
    int len = json_object_array_length(jargs);
    struct argument *args = g_malloc0(len*sizeof(struct argument)) ; 
    for(int i = 0; i < len; i++)
    {   
        json_object *jarg = json_object_array_get_idx(jargs, i);
        json_object *jtype;
        json_object_object_get_ex(jarg, "type", &jtype);
        const char *type = json_object_get_string(jtype);

        json_object *jval;
        json_object_object_get_ex(jarg, "value", &jval);
        uint64_t val = json_object_get_int(jval);
        if(!strcmp(type, "INTEGER"))
        {
            fprintf(stderr, "Init int arg[%d] with value %ld\n",i, val);
            init_int_argument(&args[i], val);
        }
        else if(!strcmp(type, "STRING"))
        {
            fprintf(stderr, "Init string arg[%d] with value %ld\n",i, val);
        }
    }
    return setup_stack(drakvuf, info, args, len);

}

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

bool setup_add1_stack(hijacker_t hijacker, drakvuf_trap_info_t *info)
{
    struct argument args[1];
    init_int_argument(&args[0], 0xE2222222);
    return setup_stack(hijacker->drakvuf, info, args, ARRAY_SIZE(args));
}