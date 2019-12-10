#include "delaymon.h"

#include <cmath>

#define PLUGIN_NAME "[DELAYMON]"

static event_response_t trap_NtDelayExecution_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    delaymon* sm = (delaymon*)info->trap->data;

    addr_t delay_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    int64_t delay = 0; // in hundreds of nanoseconds
    gchar* escaped_pname = NULL;

    {
        access_context_t ctx;
        memset(&ctx, 0, sizeof(access_context_t));
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

    double delay_interval_miliseconds = delay / 10000.0; // delay in miliseconds

    switch (sm->format)
    {
        case OUTPUT_CSV:
            printf("delaymon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",%.4f\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->proc_data.userid,
                   delay_interval_miliseconds);
            break;

        case OUTPUT_KV:
            printf("delaymon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",UserId=%" PRIi64 ",DelayIntervalMs=%.4f\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->proc_data.userid,
                   delay_interval_miliseconds);
            break;

        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            printf( "{"
                    "\"Plugin\" : \"delaymon\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"VCPU\": %" PRIu32 ","
                    "\"CR3\": %" PRIu64 ","
                    "\"ProcessName\": %s,"
                    "\"UserName\": \"%s\","
                    "\"UserId\": %" PRIu64 ","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"DelayIntervalMs\": %.4f"
                    "}\n",
                    UNPACK_TIMEVAL(info->timestamp),
                    info->vcpu, info->regs->cr3, escaped_pname,
                    USERIDSTR(drakvuf), info->proc_data.userid,
                    info->proc_data.pid, info->proc_data.ppid,
                    delay_interval_miliseconds);
            g_free(escaped_pname);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[DELAYMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " DelayIntervalMs:%.4f\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid,
                   delay_interval_miliseconds);
            break;
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
