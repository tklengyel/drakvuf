#pragma once

#include <vector>
#include "plugins/plugins_ex.h"

event_response_t cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

class dummy : public pluginex
{
public:
    dummy(drakvuf_t drakvuf, output_format_t output);

    event_response_t protectVirtualMemoryCb(drakvuf_t, drakvuf_trap_info*);
    event_response_t protectVirtualMemoryRetCb(drakvuf_t, drakvuf_trap_info*);

    drakvuf_trap_t inject_trap =
    {
        .type = REGISTER,
        .reg = CR3,
        .name = "test trap",
        .cb = &cr3_cb,
        .data = this,
    };

    std::unique_ptr<libhook::ManualHook> cr3_hook;
    std::unique_ptr<libhook::SyscallHook> sys_hook;
    std::vector<std::unique_ptr<libhook::ReturnHook>> ret_hooks;
};
