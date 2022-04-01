/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2022 Tamas K Lengyel.                                  *
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

#include "syscalls.h"
#include "private.h"
#include "win.h"

static event_response_t ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    //Loads a pointer to the plugin, which is responsible for the trap
    auto s = get_trap_plugin<syscalls>(info);

    //get_trap_params reinterprets the pointer of info->trap->data as a pointer to duplicate_result_t
    auto wr = get_trap_params<wrapper_t>(info);

    //Verifies that the params we got above (preset by the previous trap) match the trap_information this cb got called with.
    if (!wr->verify_result_call_params(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    char exit_status_buf[NTSTATUS_MAX_FORMAT_STR_SIZE] = {0};
    const char* exit_status_str = ntstatus_to_string(ntstatus_t(info->regs->rax));
    if (!exit_status_str)
        exit_status_str = ntstatus_format_string(ntstatus_t(info->regs->rax), exit_status_buf, sizeof(exit_status_buf));

    std::vector<uint64_t> args;
    print_syscall(s, drakvuf, VMI_OS_WINDOWS, false, info, wr->num, std::string(info->trap->breakpoint.module), wr->sc, args, info->regs->rax, exit_status_str);

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

static event_response_t syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto s = get_trap_plugin<syscalls>(info);
    auto w = get_trap_params<wrapper_t>(info);
    const syscall_t* sc = w->sc;

    std::vector<uint64_t> args = extract_args(drakvuf, info, s->reg_size, sc ? sc->num_args : 0);

    print_syscall(s, drakvuf, VMI_OS_WINDOWS, true, info, w->num, std::string(w->type), sc, args, 0, NULL);

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

static bool trap_syscall_table_entries(drakvuf_t drakvuf, vmi_instance_t vmi, syscalls* s,
    addr_t cr3, bool ntos, addr_t base, addr_t* sst)
{
    unsigned int syscall_count = ntos ? NUM_SYSCALLS_NT : NUM_SYSCALLS_WIN32K;
    const syscall_t** definitions = ntos ? nt : win32k;

    json_object* json = ntos ? vmi_get_kernel_json(vmi) : s->win32k_json;
    symbols_t* symbols = json ? json_get_symbols(json) : NULL;

    int32_t* table = (int32_t*)g_try_malloc0(sst[1] * sizeof(int32_t));
    if ( !table )
    {
        drakvuf_free_symbols(symbols);
        return false;
    }

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = cr3;
    ctx.addr = sst[0];
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sst[1] * sizeof(uint32_t), table, NULL) )
    {
        drakvuf_free_symbols(symbols);
        g_free(table);
        return false;
    }

    for ( addr_t syscall_num = 0; syscall_num < sst[1]; syscall_num++ )
    {
        long offset = 0;
        addr_t syscall_va;

        if ( !s->is32bit )
        {
            /*
             * The offsets in the SSDT are 32-bit RVAs calculated from the table base.
             * bits 0-3 are argument count information that needs to be shifted out.
             * Must be signed long because the offset may be negative.
             */
            offset = table[syscall_num] >> 4;
            syscall_va = sst[0] + offset;
        }
        else
            syscall_va = table[syscall_num];

        addr_t rva = syscall_va - base;
        if ( s->is32bit )
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
            PRINT_DEBUG("\t Syscall %lu @ 0x%lx has no debug information matching it with RVA 0x%lx. Table: 0x%lx Offset: 0x%lx\n", syscall_num, syscall_va, rva, sst[0], offset);
        else if ( !definition )
        {
            gchar* tmp = g_strdup(symbol->name);
            s->strings_to_free = g_slist_prepend(s->strings_to_free, tmp);
            symbol_name = (const char*)tmp;
            PRINT_DEBUG("\t Syscall %s:%s has no internal definition. New syscall?\n",
                ntos ? "nt" : "wink32k", symbol_name);
        }
        else
            symbol_name = definition->name;

        if ( s->filter && ( !symbol_name || !g_hash_table_contains(s->filter, symbol_name) ) )
        {
            PRINT_DEBUG("Syscall %s filtered out by syscalls filter file\n", symbol_name ? symbol_name : "<unknown>");
            continue;
        }

        breakpoint_by_dtb_searcher bp;
        auto trap = s->register_trap<wrapper_t>(
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

void setup_windows(drakvuf_t drakvuf, syscalls* s)
{
    auto vmi = vmi_lock_guard(drakvuf);

    addr_t start = 0;

    if ( !s->is32bit )
    {
        if ( !drakvuf_get_kernel_symbol_rva(drakvuf, "KiSystemServiceStart", &start) )
            throw -1;

        system_service_table_x64 sst[2] = {};
        if ( VMI_FAILURE == vmi_read_ksym(vmi, "KeServiceDescriptorTableShadow", 2*sizeof(system_service_table_x64), (void*)&sst, NULL) )
            throw -1;

        s->sst[0][0] = sst[0].ServiceTable;
        s->sst[0][1] = sst[0].ServiceLimit;
        s->sst[1][0] = sst[1].ServiceTable;
        s->sst[1][1] = sst[1].ServiceLimit;
    }
    else
    {
        if ( !drakvuf_get_kernel_symbol_rva(drakvuf, "KiFastCallEntry", &start) )
            throw -1;

        system_service_table_x86 sst[2] = {};
        if ( VMI_FAILURE == vmi_read_ksym(vmi, "KeServiceDescriptorTableShadow", 2*sizeof(system_service_table_x86), (void*)&sst, NULL) )
            throw -1;

        s->sst[0][0] = sst[0].ServiceTable;
        s->sst[0][1] = sst[0].ServiceLimit;
        s->sst[1][0] = sst[1].ServiceTable;
        s->sst[1][1] = sst[1].ServiceLimit;
    }

    start += s->kernel_base;

    addr_t dtb;
    if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, 0, &dtb) )
        throw -1;

#ifdef DRAKVUF_DEBUG
    uint16_t ntbuild;
    if ( VMI_FAILURE == vmi_read_16_ksym(vmi, "NtBuildNumber", &ntbuild) )
        throw -1;

    PRINT_DEBUG("Kernel base: 0x%lx\n", s->kernel_base);
    PRINT_DEBUG("Kernel pagetable: 0x%lx\n", dtb);
    PRINT_DEBUG("NtBuildNumber: %u\n", ntbuild);
    PRINT_DEBUG("NT syscall table: 0x%lx. Limit: %lu\n", s->sst[0][0], s->sst[0][1]);
    PRINT_DEBUG("Win32k syscall table: 0x%lx. Limit: %lu\n", s->sst[1][0], s->sst[1][1]);
    PRINT_DEBUG("Windows syscall entry: 0x%lx\n", start);
#endif

    if ( !trap_syscall_table_entries(drakvuf, vmi, s, dtb, true, s->kernel_base, (addr_t*)&s->sst[0]) )
    {
        PRINT_DEBUG("Failed to trap NT syscall table entries\n");
        throw -1;
    }

    if ( !s->win32k_json )
    {
        PRINT_DEBUG("Skipping second syscall table since no json profile for win32k is provided\n");
        return;
    }

    addr_t modlist;
    if ( VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &modlist) )
    {
        PRINT_DEBUG("Couldn't read PsLoadedModuleList\n");
        throw -1;
    }

    if ( !drakvuf_get_module_base_addr(drakvuf, modlist, "win32k.sys", &s->win32k_base) )
    {
        PRINT_DEBUG("Couldn't find win32k.sys\n");
        throw -1;
    }

    addr_t explorer;
    if ( !drakvuf_find_process(drakvuf, ~0, "explorer.exe", &explorer) )
    {
        PRINT_DEBUG("Couldn't find explorer.exe\n");
        throw -1;
    }

    if ( !drakvuf_get_process_dtb(drakvuf, explorer, &dtb) )
    {
        PRINT_DEBUG("Couldn't find explorer.exe's dtb\n");
        throw -1;
    }

    PRINT_DEBUG("Found explorer.exe @ 0x%lx. DTB: 0x%lx\n", explorer, dtb);

    if ( !trap_syscall_table_entries(drakvuf, vmi, s, dtb, false, s->win32k_base, (addr_t*)&s->sst[1]) )
    {
        PRINT_DEBUG("Failed to trap win32k syscall entries\n");
        throw -1;
    }
}

char* win_extract_string(syscalls* s, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val)
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
