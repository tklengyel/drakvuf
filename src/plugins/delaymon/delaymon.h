#pragma once

#include "plugins/plugins.h"

class delaymon: public plugin
{
public:
    page_mode_t pm;
    output_format_t format;
    win_ver_t winver;

    drakvuf_trap_t trap =
    {
        .breakpoint.lookup_type = LOOKUP_PID,
        .breakpoint.pid = 4,
        .breakpoint.addr_type = ADDR_RVA,
        .breakpoint.module = "ntoskrnl.exe",
        .type = BREAKPOINT,
        .data = (void*)this,
        .name = nullptr,
        .ah_cb = nullptr
    };

    delaymon(drakvuf_t drakvuf, output_format_t output);
    ~delaymon();
    virtual bool stop_impl() override;
};
