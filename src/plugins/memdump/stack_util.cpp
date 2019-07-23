#include <config.h>
#include <libvmi/libvmi.h>

#include "memdump.h"

sptr_type_t check_module_linked_wow(drakvuf_t drakvuf,
                                    vmi_instance_t vmi,
                                    memdump* plugin,
                                    drakvuf_trap_info_t* info,
                                    addr_t dll_base)
{
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    };

    addr_t wow_peb = drakvuf_get_wow_peb(drakvuf, &ctx, info->proc_data.base_addr);

    if (!wow_peb)
        return ERROR;

    addr_t module_list_head;

    if (!drakvuf_get_module_list_wow(drakvuf, &ctx, wow_peb, &module_list_head))
        return ERROR;

    addr_t next_module = module_list_head;
    bool is_first = true;
    sptr_type_t ret = UNLINKED;

    while (1)
    {
        uint32_t tmp_next = 0;
        ctx.addr = next_module;
        if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &tmp_next))
        {
            ret = ERROR;
            break;
        }

        if (module_list_head == (addr_t)tmp_next || !tmp_next)
            break;

        uint32_t tmp_dll_base;
        ctx.addr = next_module + plugin->dll_base_wow_rva;
        if (vmi_read_32(vmi, &ctx, &tmp_dll_base) == VMI_SUCCESS)
        {
            if (dll_base == (addr_t)tmp_dll_base)
            {
                ret = LINKED;
                break;
            }
        }

        next_module = (addr_t)tmp_next;
        is_first = false;
    }

    if (is_first && ret == LINKED)
        ret = MAIN;

    return ret;
}

sptr_type_t check_module_linked(drakvuf_t drakvuf,
                                vmi_instance_t vmi,
                                memdump* plugin,
                                drakvuf_trap_info_t* info,
                                addr_t dll_base)
{
    sptr_type_t sub_ret = check_module_linked_wow(drakvuf, vmi, plugin, info, dll_base);

    if (sub_ret != ERROR && sub_ret != UNLINKED)
        return sub_ret;

    addr_t module_list_head;
    if (!drakvuf_get_module_list(drakvuf, info->proc_data.base_addr, &module_list_head))
        return ERROR;

    addr_t next_module = module_list_head;
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    };

    bool is_first = true;
    sptr_type_t ret = UNLINKED;

    while (1)
    {
        addr_t tmp_next = 0;
        ctx.addr = next_module;
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &tmp_next))
        {
            ret = ERROR;
            break;
        }

        if (module_list_head == tmp_next || !tmp_next)
            break;

        addr_t tmp_dll_base;
        ctx.addr = next_module + plugin->dll_base_rva;
        if (vmi_read_addr(vmi, &ctx, &tmp_dll_base) == VMI_SUCCESS)
        {
            if (dll_base == tmp_dll_base)
            {
                ret = LINKED;
                break;
            }
        }

        is_first = false;
        next_module = tmp_next;
    }

    if (is_first && ret == LINKED)
        ret = MAIN;

    return ret;
}
