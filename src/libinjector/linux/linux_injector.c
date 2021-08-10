#include "linux_utils.h"
#include "linux_debug.h"
#include "methods/linux_shellcode.h"

bool check_userspace_int3_trap(injector_t injector, drakvuf_trap_info_t* info)
{

    // check CPL
    unsigned long int CPL = (info->regs->cs_sel & 3);
    PRINT_DEBUG("CPL 0x%lx\n", CPL);

    if ( CPL != 0)
    {
        PRINT_DEBUG("Inside INT3 userspace\n");
    }
    else
    {
        PRINT_DEBUG("INT3 received but CPL is not 0x3\n");
        return false;
    }

    if ( info->proc_data.pid != injector->target_pid )
    {
        PRINT_DEBUG("INT3 received but '%s' PID (%u) doesn't match target process (%u)\n",
            info->proc_data.name, info->proc_data.pid, injector->target_pid);
        return false;
    }

    if (info->regs->rip != info->trap->breakpoint.addr)
    {
        PRINT_DEBUG("INT3 received but BP_ADDR (%lx) doesn't match RIP (%lx)",
            info->trap->breakpoint.addr, info->regs->rip);
        assert(false);
    }

    if (injector->target_tid && (uint32_t)info->proc_data.tid != injector->target_tid)
    {
        PRINT_DEBUG("INT3 received but '%s' TID (%u) doesn't match target process (%u)\n",
            info->proc_data.name, info->proc_data.tid, injector->target_tid);
        return false;
    }

    return true;

}

static event_response_t injector_int3_userspace_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    injector_t injector = info->trap->data;

    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx. vcpu %i. TID %u\n",
        info->regs->rip, info->regs->cr3, info->vcpu, info->proc_data.tid);

    if (!check_userspace_int3_trap(injector, info))
        return VMI_EVENT_RESPONSE_NONE;

    event_response_t event;
    switch (injector->method)
    {
        case INJECT_METHOD_SHELLCODE:
        {
            event = handle_shellcode(drakvuf, info);
            break;
        }
        default:
        {
            PRINT_DEBUG("Should not be here\n");
            assert(false);
        }
    }

    return event;
}

static event_response_t wait_for_target_process_cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    // right now we are in kernel space
    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 ". PID: %u PPID: %u TID: %u\n",
        info->regs->cr3, info->proc_data.pid, info->proc_data.ppid, info->proc_data.tid);

    if (info->proc_data.pid != injector->target_pid && info->proc_data.tid != injector->target_tid)
        return 0;

    // rcx register should have the address for userspace rip
    // for x64 systems
    // if rcx doesn't have it, TODO: try to extract it from stack
    addr_t bp_addr = info->regs->rcx;

    injector->bp = g_try_malloc0(sizeof(drakvuf_trap_t));

    // setup int3 trap
    injector->bp->type = BREAKPOINT;
    injector->bp->name = "injector_int3_userspace_cb";
    injector->bp->cb = injector_int3_userspace_cb;
    injector->bp->data = injector;
    injector->bp->breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp->breakpoint.dtb = info->regs->cr3;
    injector->bp->breakpoint.addr_type = ADDR_VA;
    injector->bp->breakpoint.addr = bp_addr;
    injector->bp->ttl = UNLIMITED_TTL;
    injector->bp->ah_cb = NULL;

    if ( drakvuf_add_trap(injector->drakvuf, injector->bp) )
    {
        PRINT_DEBUG("Usermode Trap Addr: %lx\n", info->regs->rcx);

        // Unsubscribe from the CR3 trap
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
    }
    else
    {
        fprintf(stderr, "Failed to trap trapframe return address\n");
        PRINT_DEBUG("Will keep trying in next callback\n");
        print_registers(info);
        print_stack(drakvuf, info);
        g_free(injector->bp);
    }

    return 0;
}

static bool is_interrupted(drakvuf_t drakvuf, void* data __attribute__((unused)))
{
    return drakvuf_is_interrupted(drakvuf);
}

static bool inject(drakvuf_t drakvuf, injector_t injector)
{

    drakvuf_trap_t trap =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = wait_for_target_process_cr3_cb,
        .data = injector,
    };

    if (!drakvuf_add_trap(drakvuf, &trap))
    {
        PRINT_DEBUG("Failed to set trap wait_for_target_process_cr3_cb callback");
        return false;
    }

    if (!drakvuf_is_interrupted(drakvuf))
    {
        PRINT_DEBUG("Starting drakvuf loop\n");
        drakvuf_loop(drakvuf, is_interrupted, NULL);
        PRINT_DEBUG("Finished drakvuf loop\n");
    }

    if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        injector->rc = INJECTOR_TIMEOUTED;

    return true;
}

bool init_injector(injector_t injector)
{
    switch (injector->method)
    {
        case INJECT_METHOD_SHELLCODE:
        {
            // ret will be appended to shellcode here
            return load_shellcode_from_file(injector, injector->target_file);
            break;
        }
        default:
        {
            fprintf(stderr, "Method not supported for [LINUX]");
            return false;
        }
    }
    return true;
}

injector_status_t injector_start_app_on_linux(
    drakvuf_t drakvuf,
    vmi_pid_t pid,
    uint32_t tid,
    const char* file,
    injection_method_t method,
    output_format_t format,
    int args_count,
    const char** args
)
{
    injector_t injector = (injector_t)g_try_malloc0(sizeof(struct injector));
    injector->drakvuf = drakvuf;
    injector->target_pid = pid;
    injector->target_tid = tid;
    injector->target_file = file;
    if (!injector->target_tid)
        injector->target_tid = pid;
    injector->args_count = args_count;

    injector->args = (const char**)g_try_malloc0(sizeof(const char*)*args_count);

    for ( int i = 0; i<args_count; i++ )
        injector->args[i] = args[i];
    injector->method = method;
    injector->format = format;
    injector->step = STEP1;

    if (init_injector(injector))
    {
        inject(drakvuf, injector);
        injector->result = INJECT_RESULT_SUCCESS;
        injector->rc = INJECTOR_SUCCEEDED;
    }
    else
    {
        injector->result = INJECT_RESULT_METHOD_UNSUPPORTED;
        injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
    }

    injector_status_t rc = injector->rc;
    free_injector(injector);
    return rc;
}
