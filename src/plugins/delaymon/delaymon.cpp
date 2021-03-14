#include "delaymon.h"
#include "plugins/output_format.h"

#include <cmath>

#define PLUGIN_NAME "[DELAYMON]"

static event_response_t trap_NtDelayExecution_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    delaymon* sm = (delaymon*)info->trap->data;

    addr_t delay_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    int64_t delay = 0; // in hundreds of nanoseconds

    {
        ACCESS_CONTEXT(ctx);
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = delay_addr;

        vmi_lock_guard vmi_lg(drakvuf);

        if ( VMI_FAILURE == vmi_read_64(vmi_lg.vmi, &ctx, reinterpret_cast<uint64_t*>(&delay)) )
        {
            fprintf(stderr, PLUGIN_NAME " Couldn't read delay value in %s(...) trap.\n", info->trap->name);
            return 0;
        }
    }

    auto delay_interval_miliseconds = fmt::Fval(delay / 10000.0); // delay in miliseconds

    if (sm->format == OUTPUT_JSON)
    {
        jsonfmt::print("delaymon", drakvuf, info,
            keyval("VCPU", fmt::Nval(info->vcpu)),
            keyval("CR3", fmt::Nval(info->regs->cr3)),
            keyval("DelayIntervalMs", delay_interval_miliseconds)
        );
    }
    else
    {
        fmt::print(sm->format, "delaymon", drakvuf, info,
            keyval("DelayIntervalMs", delay_interval_miliseconds)
        );
    }

    return 0;
}

static void register_trap( drakvuf_t drakvuf, const char* syscall_name,
    drakvuf_trap_t* trap,
    event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    if ( !drakvuf_get_kernel_symbol_rva( drakvuf, syscall_name, &trap->breakpoint.rva) ) throw -1;

    trap->name = syscall_name;
    trap->cb   = hook_cb;
    trap->ttl  = drakvuf_get_limited_traps_ttl(drakvuf);

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}

delaymon::delaymon(drakvuf_t drakvuf, output_format_t output)
    : format{output}
{
    this->pm = drakvuf_get_page_mode(drakvuf);
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->winver = vmi_get_winver(vmi);
    drakvuf_release_vmi(drakvuf);

    register_trap(drakvuf, "NtDelayExecution", &trap, trap_NtDelayExecution_cb);
}

delaymon::~delaymon()
{
}
