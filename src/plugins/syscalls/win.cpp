/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be acquired from the author.         *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/

#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>
#include <string>
#include <vector>

#include <libdrakvuf/ntstatus.h>
#include <libinjector/libinjector.h>

#include "win.h"

using namespace syscalls_ns;

// This is the list of system libraries that use syscalls.
//
static std::string whitelisted_libraries[] =
{
    "windows\\system32\\gdi32.dll",
    "windows\\system32\\imm32.dll",
    "windows\\system32\\ntdll.dll",
    "windows\\system32\\user32.dll",
    "windows\\system32\\wow64win.dll"
};

static bool enum_modules_cb(drakvuf_t dravkuf, const module_info_t* module_info, bool* need_free, bool* need_stop, void* ctx)
{
    auto plugin   = static_cast<win_syscalls*>(ctx);
    auto& modules = plugin->procs[module_info->pid];
    modules.push_back(
    {
        .name = (const char*)module_info->full_name->contents,
        .base = module_info->base_addr,
        .size = module_info->size
    });
    return true;
}

static event_response_t sysret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    //Loads a pointer to the plugin, which is responsible for the trap
    auto s = get_trap_plugin<win_syscalls>(info);

    //get_trap_params reinterprets the pointer of info->trap->data as a pointer to duplicate_result_t
    auto wr = get_trap_params<windows_syscall_trap_data_t>(info);

    //Verifies that the params we got above (preset by the previous trap) match the trap_information this cb got called with.
    if (!wr->verify_result_call_params(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    char exit_status_buf[NTSTATUS_MAX_FORMAT_STR_SIZE] = {0};
    const char* exit_status_str = ntstatus_to_string(ntstatus_t(info->regs->rax));
    if (!exit_status_str)
        exit_status_str = ntstatus_format_string(ntstatus_t(info->regs->rax), exit_status_buf, sizeof(exit_status_buf));

    if (wr->sc)
        info->trap->name = wr->sc->name;
    s->print_sysret(drakvuf, info, wr->num, exit_status_str);

    //Destroys this return trap, because it is specific for the RIP and not usable anymore. This was the trap being called when the physical address got computed.
    //Deletes this trap from the list of existing traps traps
    //Additionally removes the trap and frees the memory
    s->destroy_trap(info->trap);

    return 0;
}

static std::vector<uint64_t> extract_args(drakvuf_t drakvuf, drakvuf_trap_info_t const* info, size_t reg_size, size_t nargs)
{
    std::vector<uint64_t> args(nargs);

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    if (nargs)
    {
        auto vmi = vmi_lock_guard(drakvuf);

        // get arguments only if we know how many to get

        if ( 4 == reg_size )
        {
            // 32 bit os
            ctx.addr = info->regs->rsp + reg_size;  // jump over base pointer

            // multiply num args by 4 for 32 bit systems to get the number of bytes we need
            // to read from the stack.  assumes standard calling convention (cdecl) for the
            // visual studio compile.
            std::vector<uint32_t> tmp_args(nargs);
            size_t sp_size = reg_size * nargs;
            if ( VMI_FAILURE == vmi_read(vmi, &ctx, sp_size, &tmp_args[0], NULL) )
                nargs = 0;

            for (size_t i = 0; i < nargs; ++i)
                args[i] = tmp_args[i];
        }
        else
        {
            // 64 bit os
            if ( nargs > 0 )
                args[0] = info->regs->rcx;
            if ( nargs > 1 )
                args[1] = info->regs->rdx;
            if ( nargs > 2 )
                args[2] = info->regs->r8;
            if ( nargs > 3 )
                args[3] = info->regs->r9;
            if ( nargs > 4 )
            {
                // first 4 agrs passed via rcx, rdx, r8, and r9
                ctx.addr = info->regs->rsp+0x28;  // jump over homing space + base pointer
                size_t sp_size = reg_size * (nargs - 4);
                if ( VMI_FAILURE == vmi_read(vmi, &ctx, sp_size, &args[4], NULL) )
                    nargs = 0;
            }
        }
    }
    args.resize(nargs);

    return args;
}

static std::optional<std::string> resolve_module(drakvuf_t drakvuf, addr_t addr, addr_t process, vmi_pid_t pid, win_syscalls* s)
{
    auto lookup = [&]() -> std::optional<std::string>
    {
        const auto& mods = s->procs.find(pid);
        if (mods != s->procs.end())
        {
            for (const auto& module : mods->second)
            {
                if (addr >= module.base && addr < module.base + module.size)
                {
                    return module.name;
                }
            }
        }
        return {};
    };
    if (auto name = lookup())
    {
        return name;
    }
    // Didn't find in cache, try to resolve.
    //
    if (pid == 4)
    {
        if (drakvuf_enumerate_drivers(drakvuf, enum_modules_cb, s))
        {
            return lookup();
        }
        return {};
    }
    else if (mmvad_info_t mmvad{}; drakvuf_find_mmvad(drakvuf, process, addr, &mmvad))
    {
        auto& mods = s->procs[pid];
        if (mmvad.file_name_ptr)
        {
            if (auto u_name = drakvuf_read_unicode_va(drakvuf, mmvad.file_name_ptr, 0))
            {
                std::string name = (const char*)u_name->contents;
                mods.push_back(
                {
                    .name = std::move(name),
                    .base = mmvad.starting_vpn << 12,
                        .size = (mmvad.ending_vpn - mmvad.starting_vpn) << 12
                });
                vmi_free_unicode_str(u_name);
                return mods.back().name;
            }
        }
    }
    return {};
}

static addr_t get_syscall_retaddr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, privilege_mode_t mode)
{
    vmi_lock_guard vmi(drakvuf);

    if (mode == MAXIMUM_MODE)
    {
        return 0;
    }
    if (mode == KERNEL_MODE)
    {
        // Read return address.
        //
        return drakvuf_get_function_return_address(drakvuf, info);
    }
    // Read usermode address.
    //
    // The qword at offset 0x28 - return address to usermode:
    // -0x00:  mov     rsp, gs:1A8h
    // -0x08:  push    2Bh
    // -0x10:  push    qword ptr gs:10h
    // -0x18:  push    r11
    // -0x20:  push    33h
    // -0x28:  push    rcx
    // -0x28:  mov     rcx, r10
    // -0x30:  sub     rsp, 8
    // -0x38:  push    rbp
    // -0x190: sub     rsp, 158h
    //
    addr_t user_ret_addr{};
    vmi_read_addr_va(vmi, drakvuf_get_rspbase(drakvuf, info) - 0x28, 0, &user_ret_addr);
    return user_ret_addr;
}

static std::optional<std::string> resolve_parent_module(drakvuf_t drakvuf, drakvuf_trap_info_t* info, win_syscalls* s)
{
    vmi_lock_guard vmi(drakvuf);
    addr_t rsp, top;
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, drakvuf_get_rspbase(drakvuf, info) - 0x10, 0, &rsp) ||
        VMI_SUCCESS != vmi_read_addr_va(vmi, rsp, info->attached_proc_data.pid, &top))
    {
        PRINT_DEBUG("[SYSCALLS] Failed to resolve top of the stack\n");
        return {};
    }
    return resolve_module(drakvuf, top, info->attached_proc_data.base_addr, info->attached_proc_data.pid, s);
}

/// Get module that called Nt (syscall) function and previous mode.
///
static std::tuple<privilege_mode_t, std::optional<std::string>, std::optional<std::string>>
    get_syscall_retinfo(drakvuf_t drakvuf, drakvuf_trap_info_t* info, win_syscalls* s)
{
    if (s->is32bit)
    {
        return { MAXIMUM_MODE, {}, {} };
    }

    privilege_mode_t mode = MAXIMUM_MODE;
    if (!drakvuf_get_current_thread_previous_mode(drakvuf, info, &mode))
    {
        PRINT_DEBUG("[SYSCALLS] Failed to get previous mode\n");
    }
    auto ret = get_syscall_retaddr(drakvuf, info, mode);

    if (mode == KERNEL_MODE)
    {
        return { mode, resolve_module(drakvuf, ret, info->proc_data.base_addr, 4, s), {} };
    }
    else if (mode == USER_MODE)
    {
        auto module = resolve_module(drakvuf, ret, info->attached_proc_data.base_addr, info->attached_proc_data.pid, s);
        // Check if module is a dll.
        //
        if (module.has_value())
        {
            auto resolved_lib = module.value();
            for (auto& c : resolved_lib)
                c = std::tolower(c);
            for (const auto& lib : whitelisted_libraries)
            {
                if (resolved_lib.length() >= lib.length() &&
                    resolved_lib.compare(resolved_lib.length() - lib.length(), lib.length(), lib) == 0)
                {
                    return { mode, std::move(resolved_lib), resolve_parent_module(drakvuf, info, s) };
                }
            }
        }
        return { mode, std::move(module), {} };
    }
    return { MAXIMUM_MODE, {}, {} };
}

static event_response_t syscall_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    //Loads a pointer to the plugin, which is responsible for the trap
    auto s = get_trap_plugin<win_syscalls>(info);

    //get_trap_params reinterprets the pointer of info->trap->data as a pointer to duplicate_result_t
    auto wr = get_trap_params<windows_syscall_trap_data_t>(info);

    //Verifies that the params we got above (preset by the previous trap) match the trap_information this cb got called with.
    if (!wr->verify_result_call_params(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    uint32_t status = (uint32_t)info->regs->rax; // NTSTATUS

    s->print_syscall(drakvuf, info, wr->num, wr->type, wr->sc, wr->args, wr->mode, wr->module, wr->parent_module, wr->is_ret, status);

    //Destroys this return trap, because it is specific for the RIP and not usable anymore. This was the trap being called when the physical address got computed.
    //Deletes this trap from the list of existing traps traps
    //Additionally removes the trap and frees the memory
    s->destroy_trap(info->trap);

    return 0;
}

static event_response_t syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto s = get_trap_plugin<win_syscalls>(info);
    auto w = get_trap_params<windows_syscall_trap_data_t>(info);
    const syscall_t* sc = w->sc;
    auto num_args = sc ? sc->num_args : 0;

    auto args = extract_args(drakvuf, info, s->register_size, num_args);
    auto [mode, module, parent_module] = get_syscall_retinfo(drakvuf, info, s);

    if (!w->is_ret)
        s->print_syscall(drakvuf, info, w->num, w->type, sc, args, mode, module, parent_module, w->is_ret, {});

    if ((!w->is_ret && s->disable_sysret) || s->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    if (!ret_addr)
        return VMI_EVENT_RESPONSE_NONE;

    auto trap = s->register_trap<windows_syscall_trap_data_t>(info, w->is_ret ? syscall_ret_cb : sysret_cb, breakpoint_by_dtb_searcher());
    if (!trap)
    {
        PRINT_DEBUG("Failed to trap syscall return %hu\n", w->num);
        return VMI_EVENT_RESPONSE_NONE;
    }
    trap->breakpoint.module = w->type;

    //After the trap got constructed, enrich its details already with some information we already (and just) know here (at this point).

    //wrapper extends from call_result_t which extends from plugin_params
    //get_trap_params reinterprets the pointer of trap->data as a pointer to wrapper
    //Load the information that is saved by hitting the first trap.
    //With params we can preset the params that the newly risen second breakpoint will receive.
    auto wr = get_trap_params<windows_syscall_trap_data_t>(trap);

    //Save the address of the target thread, address of the rsp (this was the rip-address, which we used for construction) and the value of the CR3 register to the params.
    wr->set_result_call_params(info);

    //enrich the params of the new/next trap. This information is used later.
    wr->num = w->num;
    wr->type = w->type;
    wr->sc = w->sc;
    wr->mode = w->mode;

    wr->args = std::move(args);
    wr->is_ret = w->is_ret;
    wr->module = std::move(module);
    wr->parent_module = std::move(parent_module);

    return VMI_EVENT_RESPONSE_NONE;
}

bool win_syscalls::trap_syscall_table_entries(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t cr3, bool ntos, addr_t base, std::array<addr_t, 2> _sst, json_object* json)
{
    unsigned int syscall_count = ntos ? NUM_SYSCALLS_NT : NUM_SYSCALLS_WIN32K;
    const syscall_t** definitions = ntos ? nt : win32k;

    symbols_t* symbols = json ? json_get_symbols(json) : NULL;

    int32_t* table = (int32_t*)g_try_malloc0(_sst[1] * sizeof(int32_t));
    if ( !table )
    {
        drakvuf_free_symbols(symbols);
        return false;
    }

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = cr3;
    ctx.addr = _sst[0];
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, _sst[1] * sizeof(uint32_t), table, NULL) )
    {
        drakvuf_free_symbols(symbols);
        g_free(table);
        return false;
    }

    for ( addr_t syscall_num = 0; syscall_num < _sst[1]; syscall_num++ )
    {
        long offset = 0;
        addr_t syscall_va;

        if ( !this->is32bit )
        {
            /*
             * The offsets in the SSDT are 32-bit RVAs calculated from the table base.
             * bits 0-3 are argument count information that needs to be shifted out.
             * Must be signed long because the offset may be negative.
             */
            offset = table[syscall_num] >> 4;
            syscall_va = _sst[0] + offset;
        }
        else
            syscall_va = table[syscall_num];

        addr_t rva = syscall_va - base;
        if ( this->is32bit )
            rva = static_cast<uint32_t>(rva);

        const struct symbol* symbol = nullptr;
        const syscall_t* definition = nullptr;
        if ( symbols )
        {
            for (unsigned int z=0; z < symbols->count; z++)
            {
                if ( symbols->symbols[z].rva == rva )
                {
                    symbol = &symbols->symbols[z];

                    for (unsigned int d=0; d < syscall_count; d++)
                    {
                        if ( !strcmp(definitions[d]->name, symbol->name) )
                        {
                            definition = definitions[d];
                            break;
                        }
                    }
                    break;
                }
            }
        }

        const char* symbol_name = nullptr;

        if ( !symbol )
            PRINT_DEBUG("\t Syscall %lu @ 0x%lx has no debug information matching it with RVA 0x%lx. Table: 0x%lx Offset: 0x%lx\n", syscall_num, syscall_va, rva, _sst[0], offset);
        else if ( !definition )
        {
            gchar* tmp = g_strdup(symbol->name);
            this->strings_to_free = g_slist_prepend(this->strings_to_free, tmp);
            symbol_name = (const char*)tmp;
            PRINT_DEBUG("\t Syscall %s:%s has no internal definition. New syscall?\n",
                ntos ? "nt" : "wink32k", symbol_name);
        }
        else
            symbol_name = definition->name;

        auto syscall_list_it = this->syscall_list.find(symbol_name);
        if ( !this->syscall_list.empty() && (!symbol_name || syscall_list_it == this->syscall_list.end()) )
        {
            PRINT_DEBUG("Syscall %s filtered out by syscalls list file\n", symbol_name ? symbol_name : "<unknown>");
            continue;
        }

        bool is_ret = this->syscall_list.empty() ? false : syscall_list_it->second;

        breakpoint_by_dtb_searcher bp;
        auto trap = this->register_trap<windows_syscall_trap_data_t>(
                nullptr,
                syscall_cb,
                bp.for_virt_addr(syscall_va).for_dtb(cr3),
                symbol_name);

        if (!trap)
        {
            PRINT_DEBUG("Failed to trap syscall %lu @ 0x%lx\n", syscall_num, syscall_va);
            continue;
        }

        //After the trap got constructed, enrich its details already with some information we already (and just) know here (at this point).

        //wrapper extends from call_result_t which extends from plugin_params
        //get_trap_params reinterprets the pointer of trap->data as a pointer to wrapper
        //Load the information that is saved by hitting the first trap.
        //With params we can preset the params that the newly risen second breakpoint will receive.
        auto w = get_trap_params<windows_syscall_trap_data_t>(trap);

        //enrich the params of the new/next trap. This information is used later.
        w->num = syscall_num;
        w->type = ntos ? "nt" : "win32k";
        w->sc = definition;
        w->is_ret = is_ret;
    }

    drakvuf_free_symbols(symbols);
    g_free(table);

    return true;
}

win_syscalls::win_syscalls(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output)
    : syscalls_base(drakvuf, config, output)
    , win32k_profile{ config->win32k_profile ?: "" }
{
    auto vmi = vmi_lock_guard(drakvuf);

    if ( !this->is32bit )
    {
        system_service_table_x64 _sst[2] = {};
        if ( VMI_FAILURE == vmi_read_ksym(vmi, "KeServiceDescriptorTableShadow", 2*sizeof(system_service_table_x64), (void*)&_sst, NULL) )
        {
            PRINT_DEBUG("[SYSCALLS] Failed to read ksym KeServiceDescriptorTableShadow\n");
            throw -1;
        }

        this->sst[0][0] = _sst[0].ServiceTable;
        this->sst[0][1] = _sst[0].ServiceLimit;
        this->sst[1][0] = _sst[1].ServiceTable;
        this->sst[1][1] = _sst[1].ServiceLimit;
    }
    else
    {
        system_service_table_x86 _sst[2] = {};
        if ( VMI_FAILURE == vmi_read_ksym(vmi, "KeServiceDescriptorTableShadow", 2*sizeof(system_service_table_x86), (void*)&_sst, NULL) )
        {
            PRINT_DEBUG("[SYSCALLS] Failed to read ksym KeServiceDescriptorTableShadow\n");
            throw -1;
        }

        this->sst[0][0] = _sst[0].ServiceTable;
        this->sst[0][1] = _sst[0].ServiceLimit;
        this->sst[1][0] = _sst[1].ServiceTable;
        this->sst[1][1] = _sst[1].ServiceLimit;
    }

    addr_t dtb;
    if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, 0, &dtb) )
    {
        PRINT_DEBUG("[SYSCALLS] Failed to get dtb.\n");
        throw -1;
    }

#ifdef DRAKVUF_DEBUG
    uint16_t ntbuild;
    if ( VMI_FAILURE == vmi_read_16_ksym(vmi, "NtBuildNumber", &ntbuild) )
        throw -1;

    PRINT_DEBUG("Kernel base: 0x%lx\n", this->kernel_base);
    PRINT_DEBUG("Kernel pagetable: 0x%lx\n", dtb);
    PRINT_DEBUG("NtBuildNumber: %u\n", ntbuild);
    PRINT_DEBUG("NT syscall table: 0x%lx. Limit: %lu\n", this->sst[0][0], this->sst[0][1]);
    PRINT_DEBUG("Win32k syscall table: 0x%lx. Limit: %lu\n", this->sst[1][0], this->sst[1][1]);
#endif

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName", &this->image_path_name))
    {
        PRINT_DEBUG("[SYSCALLS] Failed to get ImagePathName from _RTL_USER_PROCESS_PARAMETERS\n");
        throw -1;
    }

    if (!trap_syscall_table_entries(drakvuf, vmi, dtb, true, this->kernel_base, this->sst[0], vmi_get_kernel_json(vmi)))
    {
        PRINT_DEBUG("[SYSCALLS] Failed to trap NT syscall table entries\n");
        throw -1;
    }

    if (!this->setup_win32k_syscalls(drakvuf))
    {
        PRINT_DEBUG("[SYSCALLS] Delay hooks initialization\n");
        this->load_driver_hook = this->createSyscallHook("NtLoadDriver", &win_syscalls::load_driver_cb);
        this->create_process_hook = this->createSyscallHook("NtCreateUserProcess", &win_syscalls::create_process_cb);
    }
    this->delete_process_hook = this->createSyscallHook("PspProcessDelete", &win_syscalls::delete_process_cb);
}

bool win_syscalls::setup_win32k_syscalls(drakvuf_t drakvuf)
{
    auto vmi = vmi_lock_guard(drakvuf);

    if (this->win32k_profile == "")
    {
        PRINT_DEBUG("Skipping second syscall table since no json profile for win32k is provided\n");
        return true;
    }

    addr_t modlist;
    if (VMI_SUCCESS != vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &modlist))
    {
        PRINT_DEBUG("Couldn't read PsLoadedModuleList\n");
        return false;
    }

    addr_t win32k_base;
    if (!drakvuf_get_module_base_addr(drakvuf, modlist, "win32k.sys", &win32k_base))
    {
        PRINT_DEBUG("Couldn't find win32k.sys\n");
        return false;
    }

    addr_t explorer;
    if (!drakvuf_find_process(drakvuf, ~0, "explorer.exe", &explorer))
    {
        PRINT_DEBUG("Couldn't find explorer.exe\n");
        return false;
    }

    addr_t dtb;
    if (!drakvuf_get_process_dtb(drakvuf, explorer, &dtb))
    {
        PRINT_DEBUG("Couldn't find explorer.exe's dtb\n");
        return false;
    }

    PRINT_DEBUG("Found explorer.exe @ 0x%lx. DTB: 0x%lx\n", explorer, dtb);

    json_object* win32k_json = json_object_from_file(this->win32k_profile.data());
    if (!win32k_json)
    {
        PRINT_DEBUG("Failed to load win32k profile\n");
        return false;
    }

    if (!this->trap_syscall_table_entries(drakvuf, vmi, dtb, false, win32k_base, this->sst[1], win32k_json))
    {
        json_object_put(win32k_json);
        PRINT_DEBUG("Failed to trap win32k syscall entries\n");
        return false;
    }

    json_object_put(win32k_json);
    PRINT_DEBUG("Successfully trap win32k syscall entries\n");
    return true;
}

char* win_syscalls::win_extract_string(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val)
{
    switch (arg.type)
    {
        case PUNICODE_STRING:
        {
            char* str = nullptr;
            unicode_string_t* us = drakvuf_read_unicode(drakvuf, info, val);
            if (us)
            {
                str = (char*)us->contents;
                us->contents = nullptr; // move ownership
                vmi_free_unicode_str(us);
            }

            return str;
        }
        case POBJECT_ATTRIBUTES:
            return drakvuf_get_filename_from_object_attributes(drakvuf, info, val);
        case HANDLE:
            if (!strcmp(arg.name, "FileHandle"))
                return drakvuf_get_filename_from_handle(drakvuf, info, val);
            return nullptr;
        default:
            return nullptr;
    }
}

event_response_t win_syscalls::load_driver_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t service_name_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    unicode_string_t* service_name = drakvuf_read_unicode(drakvuf, info, service_name_addr);
    if (!service_name)
        return VMI_EVENT_RESPONSE_NONE;

    PRINT_DEBUG("[SYSCALLS] Load driver: %s\n", service_name->contents);

    gchar* service_name_casefold = g_utf8_casefold(reinterpret_cast<const gchar*>(service_name->contents), -1);
    vmi_free_unicode_str(service_name);

    if (service_name_casefold)
    {
        if (strstr(service_name_casefold, "win32k.sys"))
        {
            this->load_driver_hook = {};

            if (setup_win32k_syscalls(drakvuf))
                this->create_process_hook = {};
        }
        g_free(service_name_casefold);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_syscalls::create_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t user_process_parameters_addr = drakvuf_get_function_argument(drakvuf, info, 9);
    addr_t imagepath_addr = user_process_parameters_addr + this->image_path_name;
    unicode_string_t* image_path = drakvuf_read_unicode(drakvuf, info, imagepath_addr);
    if (!image_path)
        return VMI_EVENT_RESPONSE_NONE;

    PRINT_DEBUG("[SYSCALLS] Create process: %s\n", image_path->contents);

    gchar* image_path_casefold = g_utf8_casefold(reinterpret_cast<const gchar*>(image_path->contents), -1);
    vmi_free_unicode_str(image_path);

    if (image_path_casefold)
    {
        if (strstr(image_path_casefold, "explorer.exe"))
        {
            this->create_process_hook = {};

            auto hook = createReturnHook<PluginResult>(info, &win_syscalls::create_process_ret_cb);
            this->wait_process_creation_hook = std::move(hook);
        }
        g_free(image_path_casefold);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_syscalls::create_process_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<PluginResult>(info);
    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    this->wait_process_creation_hook = {};

    if (setup_win32k_syscalls(drakvuf))
        this->load_driver_hook = {};

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_syscalls::delete_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t process = drakvuf_get_function_argument(drakvuf, info, 1);

    if (vmi_pid_t pid; drakvuf_get_process_pid(drakvuf, process, &pid))
    {
        this->procs.erase(pid);
    }
    return VMI_EVENT_RESPONSE_NONE;
}

void win_syscalls::print_syscall(
    drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    int nr, const char* module, const syscall_t* sc,
    const std::vector<uint64_t>& args, privilege_mode_t mode,
    const std::optional<std::string>& from_dll, const std::optional<std::string>& from_parent_dll,
    bool is_ret, std::optional<uint32_t> status
)
{
    info->trap->name = sc->name;

    fmt_args_t fmt_args;
    fill_fmt_args(fmt_args, sc, info, args, is_ret, status.has_value() && *status == 0 /* STATUS_SUCCESS */ );

    std::optional<fmt::Estr<std::string>> from_dll_opt, from_parent_dll_opt;
    std::optional<fmt::Rstr<const char*>> priv_mode_opt;
    std::optional<fmt::Xval<uint32_t>> status_opt;

    if (from_dll.has_value())
        from_dll_opt = fmt::Estr(std::move(*from_dll));

    if (from_parent_dll.has_value())
        from_dll_opt = fmt::Estr(std::move(*from_parent_dll));

    if (status.has_value())
        status_opt = fmt::Xval(*status);

    if (mode != MAXIMUM_MODE)
        priv_mode_opt = fmt::Rstr(mode == USER_MODE ? "User" : "Kernel");

    fmt::print(this->m_output_format, "syscall", drakvuf, info,
        keyval("Module", fmt::Qstr(std::move(module))),
        keyval("vCPU", fmt::Nval(info->vcpu)),
        keyval("CR3", fmt::Xval(info->regs->cr3)),
        keyval("Syscall", fmt::Nval(nr)),
        keyval("NArgs", fmt::Nval(args.size())),
        keyval("PreviousMode", priv_mode_opt),
        keyval("FromModule", from_dll_opt),
        keyval("FromParentModule", from_parent_dll_opt),
        keyval("ReturnValue", status_opt),
        fmt_args
    );
}

win_syscalls::~win_syscalls()
{
    GSList* loop = this->strings_to_free;
    while (loop)
    {
        g_free(loop->data);
        loop = loop->next;
    }
    g_slist_free(this->strings_to_free);
}
