#include "libhijack.h"
#include "libdrakvuf/libdrakvuf.h"
#include "libinjector/libinjector.h"
#include "private.h"

bool setup_stack_from_json(hijacker_t hijacker, drakvuf_trap_info_t *info)
{
    drakvuf_t drakvuf = hijacker->drakvuf;
    json_object *jargs = hijacker->args;
    int len = json_object_array_length(jargs);
    struct argument *args = g_malloc0(len*sizeof(struct argument)) ; 
    for(int i = 0; i < len; i++)
    {
        json_object *jarg = json_object_array_get_idx(jargs, i);
        json_object *jtype;
        json_object_object_get_ex(jarg, "type", &jtype);
        const char *type = json_object_get_string(jtype);

        json_object *jval;
        json_object_object_get_ex(jarg, "type", &jval);
        int val = json_object_get_int(jval);
        fprintf(stderr, "setting up %d",val);
        if(!strcmp(type, "INTEGER"))
        {
            init_int_argument(&args[i], val);
        }
        else if(!strcmp(type, "STRING"))
        {

        }
    }
    return setup_stack(drakvuf, info, args, ARRAY_SIZE(args));

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