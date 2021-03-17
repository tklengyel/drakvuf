#include "dummy.h"

event_response_t cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("[DUMMY] CR3 changed\n");
    auto plugin = static_cast<dummy*>(info->trap->data);
    plugin->cr3_hook.reset();
    PRINT_DEBUG("[DUMMY] CR3 unhooked\n");
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t dummy::protectVirtualMemoryCb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    PRINT_DEBUG("[DUMMY] NtProtectVirtualMemory called\n");
    this->ret_hooks.push_back(createReturnHook(info, &dummy::protectVirtualMemoryRetCb));
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t dummy::protectVirtualMemoryRetCb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    PRINT_DEBUG("[DUMMY] NtProtectVirtualMemory Return Hook called\n");
    this->ret_hooks.clear();
    return VMI_EVENT_RESPONSE_NONE;
}

dummy::dummy(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output)
{
    PRINT_DEBUG("[DUMMY] works\n");

    this->cr3_hook = createManualHook(&(this->inject_trap), nullptr);
    this->sys_hook = createSyscallHook("NtProtectVirtualMemory", &dummy::protectVirtualMemoryCb);
}