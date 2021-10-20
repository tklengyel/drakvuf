#include "method_helpers.h"
#include "win_functions.h"

bool setup_create_file(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = (injector_t)info->trap->data;
    uint8_t buf[FILE_BUF_SIZE] = {0};
    unicode_string_t in;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = injector->payload_addr,
    );

    PRINT_DEBUG("Reading expanded variable\n");
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, info->regs->rax * 2, buf, NULL))
    {
        drakvuf_release_vmi(drakvuf);
        PRINT_DEBUG("Failed to read buffer at %lx\n", info->regs->rax * 2);
        return false;
    }
    drakvuf_release_vmi(drakvuf);
    in.contents = buf;
    in.length = info->regs->rax * 2;
    in.encoding = "UTF-16";

    PRINT_DEBUG("Converting target to UTF-8\n");
    injector->expanded_target = (unicode_string_t*)g_try_malloc0(sizeof(unicode_string_t));
    if (VMI_SUCCESS != vmi_convert_str_encoding(&in, injector->expanded_target, "UTF-8"))
    {
        PRINT_DEBUG("Failed to convert buffer\n");
        return false;
    }

    PRINT_DEBUG("Expanded: %s\n", injector->expanded_target->contents);
    PRINT_DEBUG("Opening file...\n");

    if (!setup_create_file_stack(injector, info->regs))
    {
        PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
        return false;
    }
    return true;
}

bool is_fun_error(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const char* err)
{
    if (info->regs->rax == (~0ULL) || !info->regs->rax)
    {
        injector_t injector = (injector_t)info->trap->data;
        fprintf(stderr, "%s\n", err);
        injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
        injector->error_code.valid = true;
        drakvuf_get_last_error(drakvuf, info, &injector->error_code.code, &injector->error_code.string);
        return true;
    }
    return false;
}

