/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2023 Tamas K Lengyel.                                  *
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

static constexpr auto ki_syscall_user_ret_offset = 0x28;

static event_response_t ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    //Loads a pointer to the plugin, which is responsible for the trap
    auto s = get_trap_plugin<win_syscalls>(info);

    //get_trap_params reinterprets the pointer of info->trap->data as a pointer to duplicate_result_t
    auto wr = get_trap_params<wrapper_t>(info);

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

static bool resolve_dll(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const char* dllname, addr_t* base, addr_t* size)
{
    resolve_ctx_t ctx{ .name = dllname };

    drakvuf_enumerate_process_modules(drakvuf, info->proc_data.base_addr,
        [](drakvuf_t dravkuf, const module_info_t* module_info, bool* need_free, bool* need_stop, void* ctx)
    {
        auto c = static_cast<resolve_ctx_t*>(ctx);

        if (!strcmp((const char*)module_info->base_name->contents, c->name))
        {
            c->base    = module_info->base_addr;
            c->size    = module_info->size;
            *need_stop = true;
        }
        return true;
    }, &ctx);

    if (ctx.size && ctx.base)
    {
        *base = ctx.base;
        *size = ctx.size;
        return true;
    }
    return false;
}

static bool is_inlined_syscall(drakvuf_t drakvuf, drakvuf_trap_info_t* info, win_syscalls* s, const char* subsystem)
{
    // Only x64 nt syscalls are supported.
    if (s->is32bit || !s->kernel_size || strcmp(subsystem, "nt"))
        return false;

    const addr_t rspbase = drakvuf_get_rspbase(drakvuf, info);
    const addr_t diff    = rspbase - info->regs->rsp;
    // Here we check if the call originated from usermode (syscall) or from other driver (iat call).
    // KiSystemCall64 allocates 0x158 + 7 * 8 = 0x190 bytes. The qword at offset 0x28 - return address to usermode:
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
    // Since we hook Nt* functions, there are situations when the call originated from other driver and not from usermode.
    // This checks if stack displacement is less than 0x190 + 8 (call instruction) + N (number of function arguments that are pushed on the stack).
    if (diff > 0x220 || diff < 0x190)
        return false;

    addr_t user_ret_addr = 0;
    addr_t func_ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    // Function return address should be within ntoskrnl.exe.
    if (func_ret_addr < s->kernel_base || s->kernel_base + s->kernel_size < func_ret_addr)
        return false;

    // Read return address to usermode.
    vmi_lock_guard vmi(drakvuf);
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, rspbase - ki_syscall_user_ret_offset, 0, &user_ret_addr))
        return false;

    // Resolve ntdll.dll.
    if (!s->ntdll_base)
    {
        // Should never happen.
        if (!resolve_dll(drakvuf, info, "ntdll.dll", &s->ntdll_base, &s->ntdll_size))
            return false;
    }
    // Is return address outside ntdll.dll?
    bool inlined = s->ntdll_base > user_ret_addr || user_ret_addr > s->ntdll_base + s->ntdll_size;
    // Try to locate wow64cpu.dll at runtime. We can't check if its wow64 process because we are in kernel.
    if (!s->wow64cpu_base && inlined)
        resolve_dll(drakvuf, info, "wow64cpu.dll", &s->wow64cpu_base, &s->wow64cpu_size);
    // The module is outsize ntdll.dll so we check for wow64cpu.dll.
    if (s->wow64cpu_base && inlined)
        inlined = inlined && (user_ret_addr < s->wow64cpu_base || user_ret_addr > s->wow64cpu_base + s->wow64cpu_size);
    return inlined;
}

static event_response_t syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto s = get_trap_plugin<win_syscalls>(info);
    auto w = get_trap_params<wrapper_t>(info);
    const syscall_t* sc = w->sc;

    std::vector<uint64_t> args = extract_args(drakvuf, info, s->register_size, sc ? sc->num_args : 0);

    auto inlined = is_inlined_syscall(drakvuf, info, s, w->type);
    s->print_syscall(drakvuf, info, w->num, w->type, sc, args, inlined);

    if ( s->disable_sysret || s->is_stopping() )
        return 0;

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    if ( !ret_addr )
        return 0;

    auto trap = s->register_trap<wrapper_t>(
            info,
            ret_cb,
            breakpoint_by_dtb_searcher());
    if (!trap)
    {
        PRINT_DEBUG("Failed to trap syscall return %hu\n", w->num);
        return 0;
    }
    trap->breakpoint.module = w->type;

    //After the trap got constructed, enrich its details already with some information we already (and just) know here (at this point).

    //wrapper extends from call_result_t which extends from plugin_params
    //get_trap_params reinterprets the pointer of trap->data as a pointer to wrapper
    //Load the information that is saved by hitting the first trap.
    //With params we can preset the params that the newly risen second breakpoint will receive.
    auto wr = get_trap_params<wrapper_t>(trap);

    //Save the address of the target thread, address of the rsp (this was the rip-address, which we used for construction) and the value of the CR3 register to the params.
    wr->set_result_call_params(info);

    //enrich the params of the new/next trap. This information is used later.
    wr->num = w->num;
    wr->type = w->type;
    wr->sc = w->sc;

    return 0;
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

        if ( !this->filter.empty() && ( !symbol_name || (this->filter.find(symbol_name) == this->filter.end())))
        {
            PRINT_DEBUG("Syscall %s filtered out by syscalls filter file\n", symbol_name ? symbol_name : "<unknown>");
            continue;
        }

        breakpoint_by_dtb_searcher bp;
        auto trap = this->register_trap<wrapper_t>(
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
        auto w = get_trap_params<wrapper_t>(trap);

        //enrich the params of the new/next trap. This information is used later.
        w->num = syscall_num;
        w->type = ntos ? "nt" : "win32k";
        w->sc = definition;
    }

    drakvuf_free_symbols(symbols);
    g_free(table);

    return true;
}

win_syscalls::win_syscalls(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output)
    : syscalls_base(drakvuf, config, output)
    , ntdll_base   { 0 }
    , wow64cpu_base{ 0 }
    , ntdll_size   { 0 }
    , wow64cpu_size{ 0 }
    , win32k_profile{ config->win32k_profile ?: "" }
    , win32k_initialized{ false }
{
    auto vmi = vmi_lock_guard(drakvuf);

    addr_t start = 0;

    if ( !this->is32bit )
    {
        if ( !drakvuf_get_kernel_symbol_rva(drakvuf, "KiSystemServiceStart", &start) )
            throw -1;

        system_service_table_x64 _sst[2] = {};
        if ( VMI_FAILURE == vmi_read_ksym(vmi, "KeServiceDescriptorTableShadow", 2*sizeof(system_service_table_x64), (void*)&_sst, NULL) )
            throw -1;

        this->sst[0][0] = _sst[0].ServiceTable;
        this->sst[0][1] = _sst[0].ServiceLimit;
        this->sst[1][0] = _sst[1].ServiceTable;
        this->sst[1][1] = _sst[1].ServiceLimit;
    }
    else
    {
        if ( !drakvuf_get_kernel_symbol_rva(drakvuf, "KiFastCallEntry", &start) )
            throw -1;

        system_service_table_x86 _sst[2] = {};
        if ( VMI_FAILURE == vmi_read_ksym(vmi, "KeServiceDescriptorTableShadow", 2*sizeof(system_service_table_x86), (void*)&_sst, NULL) )
            throw -1;

        this->sst[0][0] = _sst[0].ServiceTable;
        this->sst[0][1] = _sst[0].ServiceLimit;
        this->sst[1][0] = _sst[1].ServiceTable;
        this->sst[1][1] = _sst[1].ServiceLimit;
    }

    start += this->kernel_base;

    addr_t dtb;
    if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, 0, &dtb) )
        throw -1;

    this->ntdll_base    = 0;
    this->ntdll_size    = 0;
    this->wow64cpu_base = 0;
    this->wow64cpu_size = 0;
    this->kernel_size   = 0;
    // Get ntoskrnl size.
    pass_ctx_t pass;
    pass.plugin = this;
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_LDR_DATA_TABLE_ENTRY", "SizeOfImage", &pass.size_rva) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "_LDR_DATA_TABLE_ENTRY", "BaseDllName", &pass.name_rva))
    {
        PRINT_DEBUG("Failed to get _LDR_DATA_TABLE_ENTRY members rva\n");
        throw -1;
    }

    drakvuf_enumerate_drivers(drakvuf, [](drakvuf_t drakvuf, addr_t ldr_entry, void* ctx)
    {
        pass_ctx_t* pass = static_cast<pass_ctx_t*>(ctx);

        auto name = drakvuf_read_unicode_va(drakvuf, ldr_entry + pass->name_rva, 0);
        if (name != nullptr)
        {
            if (!strcmp((const char*)name->contents, "ntoskrnl.exe"))
            {
                vmi_lock_guard vmi(drakvuf);
                if (VMI_SUCCESS != vmi_read_addr_va(vmi, ldr_entry + pass->size_rva, 0, &static_cast<win_syscalls*>(pass->plugin)->kernel_size))
                    throw -1;
            }
            vmi_free_unicode_str(name);
        }
    }, &pass);

    if (!this->kernel_size)
    {
        PRINT_DEBUG("Failed to get kernel image size\n");
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
    PRINT_DEBUG("Windows syscall entry: 0x%lx\n", start);
#endif

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName", &this->image_path_name))
        throw -1;

    if ( !trap_syscall_table_entries(drakvuf, vmi, dtb, true, this->kernel_base, this->sst[0], vmi_get_kernel_json(vmi)) )
    {
        PRINT_DEBUG("Failed to trap NT syscall table entries\n");
        throw -1;
    }

    if ( !config->win32k_profile )
    {
        PRINT_DEBUG("Skipping second syscall table since no json profile for win32k is provided\n");
        return;
    }

    if (!this->setup_win32k_syscalls(drakvuf))
    {
        PRINT_DEBUG("[SYSCALLS] Delay second syscall table hooks initialization\n");

        this->load_driver_hook = this->createSyscallHook("NtLoadDriver", &win_syscalls::load_driver_cb);
        this->create_process_hook = this->createSyscallHook("NtCreateUserProcess", &win_syscalls::create_process_cb);
    }
}

bool win_syscalls::setup_win32k_syscalls(drakvuf_t drakvuf)
{
    auto vmi = vmi_lock_guard(drakvuf);

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
    vmi_lock_guard vmi(drakvuf);
    if ( arg.type == POBJECT_ATTRIBUTES )
    {
        char* filename = drakvuf_get_filename_from_object_attributes(drakvuf, info, val);
        if ( filename ) return filename;
    }

    if ( !strcmp(arg.name, "FileHandle") )
    {
        char* filename = drakvuf_get_filename_from_handle(drakvuf, info, val);
        if ( filename ) return filename;
    }

    return nullptr;
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

void win_syscalls::print_syscall(
    drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    int nr, std::string&& module, const syscall_t* sc,
    const std::vector<uint64_t>& args, bool inlined
)
{
    if (sc)
        info->trap->name = sc->name;

    this->fmt_args.clear();

    if (sc)
    {
        for (size_t i = 0; i < args.size(); ++i)
        {
            auto str = this->parse_argument(drakvuf, info, sc->args[i], args[i]);
            if ( !str.empty() )
                this->fmt_args.push_back(keyval(sc->args[i].name, fmt::Estr(str)));
            else
            {
                uint64_t val = transform_value(drakvuf, info, sc->args[i], args[i]);
                this->fmt_args.push_back(keyval(sc->args[i].name, fmt::Xval(val)));
            }
        }
    }

    fmt::print(this->m_output_format, "syscall", drakvuf, info,
        keyval("Module", fmt::Qstr(std::move(module))),
        keyval("vCPU", fmt::Nval(info->vcpu)),
        keyval("CR3", fmt::Xval(info->regs->cr3)),
        keyval("Syscall", fmt::Nval(nr)),
        keyval("NArgs", fmt::Nval(args.size())),
        keyval("Inlined", fmt::Qstr(inlined ? "True" : "False")),
        this->fmt_args
    );
}
