/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  *
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

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <cpuid.h>

#include <libdrakvuf/json-util.h>
#include <libinjector/libinjector.h>

#include "procdump.h"
#include "private.h"
#include "minidump.h"
#include "plugins/output_format.h"

using namespace std::string_literals;

static void save_file_metadata(struct procdump_ctx* ctx, proc_data_t* proc_data)
{
    auto plugin = ctx->plugin;
    FILE* fp = fopen((plugin->procdump_dir + "/"s + ctx->data_file_name + ".metadata"s).c_str(), "w");
    if (!fp)
        return;

    json_object* jobj = json_object_new_object();
    json_object_object_add(jobj, "DumpSize", json_object_new_string_fmt("0x%" PRIx64, ctx->size));
    json_object_object_add(jobj, "PID", json_object_new_int(proc_data->pid));
    json_object_object_add(jobj, "PPID", json_object_new_int(proc_data->ppid));
    json_object_object_add(jobj, "ProcessName", json_object_new_string(proc_data->name));
    json_object_object_add(jobj, "Compression", json_object_new_string(plugin->use_compression ? "gzip" : "none"));

    json_object_object_add(jobj, "DataFileName", json_object_new_string(ctx->data_file_name.c_str()));

    fprintf(fp, "%s\n", json_object_get_string(jobj));
    fclose(fp);

    json_object_put(jobj);
}

static void free_pool(pool_map_t& pools, addr_t va)
{
    auto pool = pools.find(va);
    if (pool != pools.end())
        pool->second = POOL_FREE;
}

static addr_t find_pool(pool_map_t& pools)
{
    for (auto& pool : pools)
        if (POOL_FREE == pool.second)
        {
            pool.second = POOL_USED;
            return pool.first;
        }

    return 0;
}

static bool dump_next_vads(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump_ctx* ctx);

static event_response_t rtlcopymemory_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info);

static event_response_t exallocatepool_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info);

static event_response_t complete_stage1(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump_ctx* ctx);

static event_response_t terminate_process_cb2(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info);

static bool inject_allocate_pool(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump_ctx* ctx)
{
    struct argument args[3] = {};
    init_int_argument(&args[0], 0); // NonPagedPool
    init_int_argument(&args[1], ctx->POOL_SIZE_IN_PAGES * VMI_PS_4KB);
    init_int_argument(&args[2], 0);

    auto vmi = vmi_lock_guard(drakvuf);
    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 3))
        return false;

    info->regs->rip = ctx->plugin->malloc_va;

    ctx->bp->cb = exallocatepool_cb;

    return true;
}

static bool inject_copy_memory(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump_ctx* ctx, addr_t addr, size_t size)
{
    struct argument args[3] = {};
    init_int_argument(&args[0], ctx->pool);
    init_int_argument(&args[1], addr);
    init_int_argument(&args[2], size);

    auto vmi = vmi_lock_guard(drakvuf);
    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 3))
        return false;

    info->regs->rip = ctx->plugin->memcpy_va;

    ctx->bp2->cb = rtlcopymemory_cb;

    return true;
}

// Returns true if next count pages is mapped and false otherwise.
static bool max_contigious_range(const std::vector<uint64_t>& prototype_ptes,
    uint32_t total_number_of_ptes, uint32_t idx,
    uint32_t& count, uint64_t max_pages)
{
    // No check for null pointer for purpose
    count = 0;
    if (idx >= total_number_of_ptes)
        return true;

    bool skip = !IS_MMPTE_DUMPABLE(prototype_ptes[idx]);
    for (auto i = idx; i < total_number_of_ptes && i < idx + max_pages; ++i)
    {
        if (skip == !IS_MMPTE_DUMPABLE(prototype_ptes[i]))
            ++count;
        else
            break;
    }
    return skip;
}

static bool read_vm(drakvuf_t drakvuf, addr_t dtb, addr_t start, size_t size,
    struct procdump_ctx* procdump_ctx)
{
    if (!procdump_ctx || !procdump_ctx->writer)
    {
        return false;
    }

    if (!size) return true;

    vmi_lock_guard vmi(drakvuf);

    ACCESS_CONTEXT(vmi_ctx);
    vmi_ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    vmi_ctx.dtb = dtb;
    vmi_ctx.addr = start;
    auto num_pages = size / VMI_PS_4KB;
    auto access_ptrs = new void* [num_pages] { 0 };

    bool res = true;
    uint8_t zeros[VMI_PS_4KB] = {};
    if (VMI_SUCCESS == vmi_mmap_guest(vmi, &vmi_ctx, num_pages, access_ptrs))
    {
        for (size_t i = 0; i < num_pages; ++i)
        {
            if (access_ptrs[i])
            {
                if (res)
                    res = procdump_ctx->writer->append(static_cast<uint8_t*>(access_ptrs[i]), VMI_PS_4KB);
                munmap(access_ptrs[i], VMI_PS_4KB);
            }
            else if (res)
                res = procdump_ctx->writer->append(zeros, VMI_PS_4KB);
        }
    }
    else
    {
        // unaccessible page, pad with zeros to ensure proper alignment of the data
        for (size_t i = 0; i < num_pages; ++i)
            if (res)
                res = procdump_ctx->writer->append(zeros, VMI_PS_4KB);
    }

    delete[] access_ptrs;
    return res;
}

static void dump_with_mmap(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump_ctx* ctx)
{
    // Try to mmap private or shared virtual address space area
    auto vad = ctx->vads.begin();
    auto start = vad->first + vad->second.idx * VMI_PS_4KB;
    auto size = (vad->second.total_number_of_ptes - vad->second.idx) * VMI_PS_4KB;

    if ( !read_vm(drakvuf, info->regs->cr3, start, size, ctx) )
    {
        PRINT_DEBUG("[PROCDUMP] [PID:%d] [TID:%d] Error: Failed to copy VAD "
            "(start 0x%lx, size 0x%lx) into file "
            "(size 0x%lx) with mmap\n",
            ctx->pid, ctx->tid, ctx->vads.begin()->first,
            size, ctx->size);
    }

    ctx->vads.erase(start);
}

enum rtlcopy_status
{
    RTLCOPY_RETRY_WITH_MMAP,
    RTLCOPY_GO_NEXT_VAD,
    RTLCOPY_INJECT,
};

static enum rtlcopy_status dump_with_rtlcopymemory(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    procdump_ctx* ctx)
{
    auto vad = ctx->vads.begin();

    auto vad_start = vad->first;
    auto prototype_ptes = vad->second.prototype_ptes;
    if (prototype_ptes.empty())
        // Without prototype PTEs RtlCopyMemoryNonTemporal could BSOD the system
        return RTLCOPY_RETRY_WITH_MMAP;

    auto total_number_of_ptes = vad->second.total_number_of_ptes;
    uint32_t ptes_to_dump = 0;
    auto skip = max_contigious_range(prototype_ptes, total_number_of_ptes,
            vad->second.idx, ptes_to_dump, ctx->POOL_SIZE_IN_PAGES);

    if (!ptes_to_dump)
    {
        PRINT_DEBUG("[PROCDUMP] [PID:%d] Error: Dump %u PTEs from %u / %lu\n",
            ctx->pid, ptes_to_dump, vad->second.idx, total_number_of_ptes);
        return RTLCOPY_RETRY_WITH_MMAP;
    }

    if (skip)
    {
        // Mapped region or VAD end should follow not-mapped region
        uint8_t zeros[VMI_PS_4KB] = {};
        for (uint32_t i = 0; i < ptes_to_dump; ++i)
            ctx->writer->append(zeros, VMI_PS_4KB);

        vad->second.idx += ptes_to_dump;
        skip = max_contigious_range(prototype_ptes, total_number_of_ptes,
                vad->second.idx, ptes_to_dump, ctx->POOL_SIZE_IN_PAGES);

        if (0 == ptes_to_dump)
        {
            ctx->vads.erase(vad_start);
            return RTLCOPY_GO_NEXT_VAD;
        }
    }

    if (ptes_to_dump > ctx->POOL_SIZE_IN_PAGES)
        ptes_to_dump = ctx->POOL_SIZE_IN_PAGES;

    const auto idx = vad->second.idx; // cache it because we will change it
    if (idx + ptes_to_dump > total_number_of_ptes)
    {
        PRINT_DEBUG("[PROCDUMP] [PID:%d] Error: Dump %u PTEs from %u / %lu\n",
            ctx->pid, ptes_to_dump, idx, total_number_of_ptes);
        return RTLCOPY_RETRY_WITH_MMAP;
    }

    addr_t start_addr = vad_start + idx * VMI_PS_4KB;
    ctx->current_dump_size = ptes_to_dump * VMI_PS_4KB;

    if (!inject_copy_memory(drakvuf, info, ctx, start_addr, ctx->current_dump_size))
    {
        PRINT_DEBUG("[PROCDUMP] [PID:%d] Error: Failed to inject "
            "RtlCopyMemoryNonTemporal\n",
            ctx->pid);
        return RTLCOPY_RETRY_WITH_MMAP;
    }
    ctx->target_rsp = info->regs->rsp;

    if (idx + ptes_to_dump == total_number_of_ptes)
    {
        ctx->vads.erase(vad_start);
    }
    else if (idx + ptes_to_dump < total_number_of_ptes)
    {
        ctx->vads.begin()->second.idx += ptes_to_dump;
    }

    return RTLCOPY_INJECT;
}

static bool dump_next_dlls(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump_ctx* ctx)
{
    while (!ctx->vads.empty())
    {
        auto vad = ctx->vads.begin();
        if (vad->second.zero_fill)
        {
            uint8_t zeros[VMI_PS_4KB] = {};
            for (uint32_t i = 0; i < vad->second.total_number_of_ptes; ++i)
                ctx->writer->append(zeros, VMI_PS_4KB);
            ctx->vads.erase(vad->first);
        }
        else
        {
            switch (dump_with_rtlcopymemory(drakvuf, info, ctx))
            {
                case RTLCOPY_INJECT:
                    return true;
                case RTLCOPY_GO_NEXT_VAD:
                    break;
                case RTLCOPY_RETRY_WITH_MMAP:
                default:
                    dump_with_mmap(drakvuf, info, ctx);
                    break;
            }
        }
    }

    return false;
}

#define VAD_TYPE_DLL 2

static bool dump_next_vads(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump_ctx* ctx)
{
    while (!ctx->vads.empty())
    {
        if (VAD_TYPE_DLL == ctx->vads.begin()->second.type)
        {
            // To avoid raises (aka BSODs) dump DLLs at stage 2
            auto vad = ctx->vads.begin();
            auto vad_start = vad->first;
            ctx->dlls[vad_start] = vad->second;
            ctx->vads.erase(vad_start);
        }
        else
            dump_with_mmap(drakvuf, info, ctx);
    }

    // Go to stage 2
    complete_stage1(drakvuf, info, ctx);
    ctx->bp2 = (drakvuf_trap_t*)g_slice_new0(drakvuf_trap_t);
    ctx->bp2->type = BREAKPOINT;
    ctx->bp2->cb = terminate_process_cb2;
    ctx->bp2->data = ctx;
    ctx->bp2->name = nullptr;
    ctx->bp2->breakpoint.lookup_type = LOOKUP_DTB;
    ctx->bp2->breakpoint.dtb = info->regs->cr3;
    ctx->bp2->breakpoint.addr_type = ADDR_VA;
    ctx->bp2->breakpoint.addr = ctx->plugin->clean_process_va;
    ctx->bp2->ttl = drakvuf_get_limited_traps_ttl(drakvuf);
    ctx->bp2->ah_cb = nullptr;
    if (drakvuf_add_trap(drakvuf, ctx->bp2))
    {
        ctx->plugin->traps = g_slist_prepend(ctx->plugin->traps, ctx->bp2);
        return true;
    }
    else
    {
        PRINT_DEBUG("[PROCDUMP] Failed to trap return location of injected "
            "function call @ 0x%lx!\n",
            ctx->bp2->breakpoint.addr);
    }
    return false;
}

static void free_trap(gpointer p)
{
    if (!p)
        return;

    drakvuf_trap_t* t = (drakvuf_trap_t*)p;
    if (t->data)
        delete (procdump_ctx*) t->data;

    g_slice_free(drakvuf_trap_t, t);
}

static void restore_registers(drakvuf_trap_info_t* info,
    procdump_ctx* ctx)
{
    // One could not restore all registers at once like this:
    //     memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t)),
    // because thus kernel structures could be affected.
    // For example on Windows 7 x64 GS BASE stores pointer to KPCR. If save
    // GS BASE on vCPU0 and start injections Windows scheduler could switch
    // thread to other vCPU1. After restoring all registers vCPU1's GS BASE
    // would point to KPCR of vCPU0.
    info->regs->rax = ctx->saved_regs.rax;
    info->regs->rcx = ctx->saved_regs.rcx;
    info->regs->rdx = ctx->saved_regs.rdx;
    info->regs->rbx = ctx->saved_regs.rbx;
    info->regs->rbp = ctx->saved_regs.rbp;
    info->regs->rsp = ctx->saved_regs.rsp;
    info->regs->rdi = ctx->saved_regs.rdi;
    info->regs->rsi = ctx->saved_regs.rsi;
    info->regs->r8 = ctx->saved_regs.r8;
    info->regs->r9 = ctx->saved_regs.r9;
    info->regs->r10 = ctx->saved_regs.r10;
    info->regs->r11 = ctx->saved_regs.r11;
    info->regs->r12 = ctx->saved_regs.r12;
    info->regs->r13 = ctx->saved_regs.r13;
    info->regs->r14 = ctx->saved_regs.r14;
    info->regs->r15 = ctx->saved_regs.r15;
}

static event_response_t detach(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump_ctx* ctx)
{
    ctx->writer->finish();

    if (ctx->vads.empty())
    {
        // If there is no VADs left than the file have been processed
        save_file_metadata(ctx, &info->proc_data);
        fmt::print(ctx->plugin->m_output_format, "procdump", drakvuf, info,
            keyval("DumpReason", fmt::Qstr("TerminateProcess")),
            keyval("DumpSize", fmt::Nval(ctx->size)),
            keyval("SN", fmt::Nval(ctx->idx))
        );
    }

    restore_registers(info, ctx);
    free_pool(ctx->plugin->pools, ctx->pool);
    // TODO Check if this would be erased
    ctx->plugin->terminating.at(ctx->pid) = 0;
    ctx->plugin->terminated_processes->insert_or_assign(ctx->pid, true);
    if (ctx->bp)
    {
        ctx->plugin->traps = g_slist_remove(ctx->plugin->traps, ctx->bp);
        drakvuf_remove_trap(drakvuf, ctx->bp, (drakvuf_trap_free_t)free_trap);
        ctx->bp = nullptr;
    }
    if (ctx->bp2)
    {
        ctx->plugin->traps = g_slist_remove(ctx->plugin->traps, ctx->bp2);
        drakvuf_remove_trap(drakvuf, ctx->bp2, (drakvuf_trap_free_t)free_trap);
        ctx->bp2 = nullptr;
    }

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static event_response_t complete_stage1(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump_ctx* ctx)
{
    restore_registers(info, ctx);
    ctx->plugin->traps = g_slist_remove(ctx->plugin->traps, ctx->bp);
    ctx->bp->data = nullptr;
    drakvuf_remove_trap(drakvuf, ctx->bp, (drakvuf_trap_free_t)free_trap);
    ctx->bp = nullptr;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static event_response_t rtlcopymemory_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info)
{
    if (!info->attached_proc_data.pid)
    {
        PRINT_DEBUG("[PROCDUMP] [PID:%d] [TID:%d] Error: Failed to get "
            "attached process\n",
            info->proc_data.pid, info->proc_data.tid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto ctx = static_cast<struct procdump_ctx*>(info->trap->data);

    if (!drakvuf_check_return_context(drakvuf, info, ctx->pid, ctx->tid, ctx->target_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    ctx->target_rsp = 0;

    // Restore stack pointer
    // This is crucial because lots of injections could exhaust the kernel stack
    info->regs->rsp = ctx->saved_regs.rsp;

    if (!read_vm(drakvuf, info->regs->cr3, ctx->pool, ctx->current_dump_size,
            ctx))
    {
        PRINT_DEBUG("[PROCDUMP] [PID:%d] [TID:%d] Error: Failed to copy VAD "
            "(start 0x%lx, size 0x%lx) into file "
            "(size 0x%lx) with injection\n",
            ctx->pid, ctx->tid, ctx->vads.begin()->first,
            ctx->current_dump_size, ctx->size);
    }

    if (dump_next_dlls(drakvuf, info, ctx))
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    else
        return detach(drakvuf, info, ctx);
}

static event_response_t exallocatepool_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info)
{
    if (!info->attached_proc_data.pid)
    {
        PRINT_DEBUG("[PROCDUMP] [PID:%d] [TID:%d] Error: Failed to get "
            "attached process\n",
            info->proc_data.pid, info->proc_data.tid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto ctx = static_cast<struct procdump_ctx*>(info->trap->data);

    if (!drakvuf_check_return_context(drakvuf, info, ctx->pid, ctx->tid, ctx->target_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    ctx->target_rsp = 0;

    // Restore stack pointer
    // This is crucial because lots of injections could exhaust the kernel stack
    info->regs->rsp = ctx->saved_regs.rsp;

    if (info->regs->rax)
    {
        ctx->plugin->pools[info->regs->rax] = POOL_USED;

        ctx->pool = info->regs->rax;
        if (dump_next_vads(drakvuf, info, ctx))
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    else
        PRINT_DEBUG("[PROCDUMP] [PID:%d] Failed to allocate pool\n",
            info->attached_proc_data.pid);

    return detach(drakvuf, info, ctx);
}

static bool dump_mmvad(drakvuf_t drakvuf, mmvad_info_t* mmvad,
    void* callback_data)
{
    uint32_t vad_type = drakvuf_mmvad_type(drakvuf, mmvad);
    uint64_t width = 0;
    uint64_t vad_commit_charge =
        drakvuf_mmvad_commit_charge(drakvuf, mmvad, &width);
    auto ctx = static_cast<procdump_ctx*>(callback_data);
    addr_t vad_start = mmvad->starting_vpn * VMI_PS_4KB;
    uint64_t len_pages = mmvad->ending_vpn - mmvad->starting_vpn + 1;
    uint64_t len_bytes = len_pages * VMI_PS_4KB;

#ifdef DRAKVUF_DEBUG
    bool vad_commit = drakvuf_is_mmvad_commited(drakvuf, mmvad);
#endif

    // Dump only:
    // * Memory allocated with NtAllocateVirtualMemory and committed:
    //   CommitCharge is greater then zero
    // * Mapped image files (.exe or .dll): VadType is 2
    // * Sections mapped with NtMapViewOfSection: VadType is 0
    if (!vad_commit_charge)
        return false;
    if (!(vad_type == VAD_TYPE_DLL || vad_type == 0))
        return false;

    // MiAllocateVad sets CommitCharge to MM_MAX_COMMIT
    // Such VADs doesn't contain any useful data
    if (vad_commit_charge == (1ULL << width) - 1)
    {
        return false;
    }

    if (len_bytes > VMI_PS_1GB)
    {
        // TODO Usually this regions contains several committed pages.
        // Save it with MiniDump
        PRINT_DEBUG(
            "[PROCDUMP] [PID:%d] Warning: VAD (0x%lx; 0x%lx; 0x%lx; 0x%lx) "
            "skipped on size 0x%lx, MemCommit %d, CommitCharge 0x%lx\n",
            ctx->pid, mmvad->starting_vpn, mmvad->ending_vpn, mmvad->flags,
            mmvad->flags1, len_bytes, vad_commit, vad_commit_charge);
        return false;
    }

    std::vector<addr_t> prototype_pte;
    if (vad_type == VAD_TYPE_DLL)
    {
        auto ptes = mmvad->total_number_of_ptes;
        if (len_pages == ptes)
        {
            // When Windows loads resource DLLs the size of VAD could be less
            // then segment size. Dump such VADs with mmap.
            //
            // Otherwise collect prototype PTEs for RtlCopyMemoryNonTemporal.
            auto buf = new addr_t[ptes];
            size_t bytes_read = 0;
            vmi_lock_guard vmi_lg(drakvuf);
            if (VMI_SUCCESS != vmi_read_va(vmi_lg.vmi, mmvad->prototype_pte, 0,
                    sizeof(addr_t) * ptes, buf,
                    &bytes_read) ||
                bytes_read != sizeof(addr_t) * ptes)
            {
                PRINT_DEBUG(
                    "[PROCDUMP] [PID:%4d] [TID:%4d] Error: Failed to dump "
                    "prototype PTEs: TotalNumberOfPtes %u, "
                    "PrototypePte 0x%lx, bytes read %zu\n",
                    ctx->pid, ctx->tid, ptes, mmvad->prototype_pte, bytes_read);
                delete[] buf;
                buf = nullptr;
                ptes = 0;
            }
            for (uint32_t i = 0; i < ptes; ++i)
                prototype_pte.push_back(buf[i]);
            if (buf)
                delete[] buf;
        }
    }

    PRINT_DEBUG("[PID:%d] [%s] MMVAD 0x%13lx, 0x%13lx (%5lu PTEs, "
        "%10zu bytes), MemCommit %d, VadType %d, CommitCharge 0x%lx\n",
        ctx->pid, ctx->name.data(), mmvad->starting_vpn,
        mmvad->ending_vpn, len_pages, len_bytes, vad_commit, vad_type,
        vad_commit_charge);

    ctx->vads[vad_start] = {vad_type, len_pages, prototype_pte, 0, false};
    ctx->size += len_bytes;

    return false;
}

static bool prepare_mdmp_header(drakvuf_t drakvuf, drakvuf_trap_info_t* info, procdump_ctx* ctx)
{
    auto plugin = get_trap_plugin<procdump>(info);

    uint32_t time_stamp = g_get_real_time() / G_USEC_PER_SEC;

    bool is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);

    unicode_string_t* csdversion_us = drakvuf_get_process_csdversion(drakvuf, info->attached_proc_data.base_addr);
    std::wstring csdversion;
    if (csdversion_us)
        csdversion = std::wstring(csdversion_us->contents[0], csdversion_us->contents[csdversion_us->length]);

    vector<struct mdmp_memory_descriptor64> memory_ranges;
    for (auto vad: ctx->vads)
    {
        if (VAD_TYPE_DLL != vad.second.type)
        {
            struct mdmp_memory_descriptor64 range(vad.first,
                vad.second.total_number_of_ptes * VMI_PS_4KB);
            memory_ranges.push_back(range);
        }
    }
    for (auto vad: ctx->vads)
    {
        if (VAD_TYPE_DLL == vad.second.type)
        {
            struct mdmp_memory_descriptor64 range(vad.first,
                vad.second.total_number_of_ptes * VMI_PS_4KB);
            memory_ranges.push_back(range);
        }
    }

    // TODO Store all threads of the process
    struct mdmp_thread thread;
    thread.thread_id = info->attached_proc_data.tid;
    // TODO Get Teb and StackBase from attached thread
    thread.teb = drakvuf_get_current_thread_teb(drakvuf, info);
    thread.stack.start_of_memory_range = drakvuf_get_current_thread_stackbase(drakvuf, info);
    union thread_context thread_ctx;
    // TODO Get registers from attached thread _KTHREAD.TrapFrame
    thread_ctx.set(is32bit, info->regs);

    auto mdmp = minidump(time_stamp,
            is32bit,
            plugin->num_cpus,
            plugin->win_major,
            plugin->win_minor,
            plugin->win_build_number,
            plugin->vendor,
            plugin->version_information,
            plugin->feature_information,
            plugin->amd_extended_cpu_features,
            csdversion,
            memory_ranges,
    {thread},
    {thread_ctx});

    if (!ctx->writer->append((const uint8_t*)&mdmp, sizeof(mdmp)))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to prepare MiniDump file\n");
        return false;
    }

    return true;
}

static event_response_t terminate_process_cb2(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info)
{
    if (!info->attached_proc_data.pid)
    {
        PRINT_DEBUG("[PROCDUMP] [PID:%d] [TID:%d] Error: Failed to get "
            "attached process\n",
            info->proc_data.pid, info->proc_data.tid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto ctx = static_cast<struct procdump_ctx*>(info->trap->data);
    if (!ctx)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (info->attached_proc_data.pid != ctx->pid)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    // The thread could change
    ctx->tid = info->attached_proc_data.tid;
    ctx->plugin->terminating[ctx->pid] = ctx->tid;

    // Get virtual address space map of the process
    drakvuf_traverse_mmvad(drakvuf, info->attached_proc_data.base_addr, dump_mmvad,
        ctx);
    if (ctx->vads.empty())
        return detach(drakvuf, info, ctx);
    else
    {
        for (auto dll = ctx->dlls.begin(); dll != ctx->dlls.end(); ++dll)
        {
            auto vad = ctx->vads.find(dll->first);
            if (vad == ctx->vads.end() ||
                vad->second.total_number_of_ptes != dll->second.total_number_of_ptes ||
                vad->second.prototype_ptes.size() != dll->second.prototype_ptes.size())
            {
                PRINT_DEBUG("[PROCDUMP] DLL at %#lx of %ld PTEs disappered\n",
                    dll->first, dll->second.total_number_of_ptes);
                dll->second.zero_fill = true;
            }
        }

        ctx->vads.clear();
        ctx->vads.swap(ctx->dlls);
    }

    // Save registers to restore process/thread state
    memcpy(&ctx->saved_regs, info->regs, sizeof(x86_registers_t));
    if (dump_next_dlls(drakvuf, info, ctx))
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    else
        return detach(drakvuf, info, ctx);
}

static event_response_t terminate_process_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info)
{
    if (!info->attached_proc_data.pid)
    {
        PRINT_DEBUG("[PROCDUMP] [PID:%d] [TID:%d] Error: Failed to get "
            "attached process\n",
            info->proc_data.pid, info->proc_data.tid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    uint32_t handle = drakvuf_get_function_argument(drakvuf, info, 1);

    // If current process terminates other one we should not dump current
    if (0 != handle && 0xffffffff != handle)
        return VMI_EVENT_RESPONSE_NONE;

    auto plugin = get_trap_plugin<procdump>(info);

    // The callback could be called if other thread invokes NtTerminateProcess
    // or as a return path from injected function.
    // In both cases we should not starting process dump again.
    auto it = plugin->terminating.find(info->attached_proc_data.pid);
    if (it != plugin->terminating.end())
    {
        if (!it->second)
        {
            // TODO Check if this line could be reached (look "detach" function)
            plugin->terminating.erase(info->attached_proc_data.pid);
            plugin->terminated_processes->insert_or_assign(info->attached_proc_data.pid, true);
            if (plugin->terminating.empty() && plugin->is_stopping())
                drakvuf_interrupt(drakvuf, 1);
        }

        return VMI_EVENT_RESPONSE_NONE;
    }
    else
    {
        plugin->terminating[info->attached_proc_data.pid] = info->attached_proc_data.tid;
        plugin->terminated_processes->insert_or_assign(info->attached_proc_data.pid, false);
    }

    // TODO Move into constructor
    auto ctx = new procdump_ctx;
    ctx->pid = info->attached_proc_data.pid;
    ctx->ppid = info->attached_proc_data.ppid;
    ctx->tid = info->attached_proc_data.tid;
    ctx->name = std::string(info->attached_proc_data.name);
    ctx->plugin = plugin;
    ctx->idx = plugin->procdumps_count++;
    ctx->size = 0;
    // Get virtual address space map of the process
    drakvuf_traverse_mmvad(drakvuf, info->attached_proc_data.base_addr, dump_mmvad,
        ctx);
    if (ctx->vads.empty())
    {
        // nothing to do
        delete ctx;
        return VMI_EVENT_RESPONSE_NONE;
    }
    {
        PRINT_DEBUG("[PROCDUMP] [\"%s\":%4d] [PID:%4d] [TID:%4d] [\"%s\"] "
            "Dump 0x%lx (%ld MiB, %lu VADs) SN=%lu\n",
            __FUNCTION__, __LINE__, info->attached_proc_data.pid,
            info->attached_proc_data.tid, info->attached_proc_data.name, ctx->size,
            ctx->size / 1024 / 1024, ctx->vads.size(), ctx->idx);
    }

    try
    {
        std::string data_file_name = "procdump."s + std::to_string(ctx->idx);
        ctx->data_file_name = data_file_name;
        ctx->writer = ProcdumpWriterFactory::build(plugin->procdump_dir + "/"s + data_file_name, plugin->use_compression);
    }
    catch (int)
    {
        PRINT_DEBUG("[PROCDUMP] Failed to create file\n");
        delete ctx;
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!prepare_mdmp_header(drakvuf, info, ctx))
    {
        delete ctx;
        return VMI_EVENT_RESPONSE_NONE;
    }

    // Save registers to restore process/thread state
    memcpy(&ctx->saved_regs, info->regs, sizeof(x86_registers_t));
    ctx->bp = (drakvuf_trap_t*)g_slice_new0(drakvuf_trap_t);
    ctx->pool = find_pool(plugin->pools);
    ctx->bp->type = BREAKPOINT;
    ctx->bp->cb = terminate_process_cb;
    ctx->bp->data = ctx;
    ctx->bp->breakpoint.lookup_type = LOOKUP_DTB;
    ctx->bp->breakpoint.dtb = info->regs->cr3;
    ctx->bp->breakpoint.addr_type = ADDR_VA;
    ctx->bp->breakpoint.addr = info->regs->rip;
    ctx->bp->ttl = drakvuf_get_limited_traps_ttl(drakvuf);
    ctx->bp->ah_cb = nullptr;
    if (drakvuf_add_trap(drakvuf, ctx->bp))
    {
        plugin->traps = g_slist_prepend(plugin->traps, ctx->bp);

        bool is_continue = false;

        if (ctx->pool)
            is_continue = dump_next_vads(drakvuf, info, ctx);
        else
        {
            is_continue = inject_allocate_pool(drakvuf, info, ctx);
            if (is_continue)
                ctx->target_rsp = info->regs->rsp;
        }

        if (is_continue)
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    else
    {
        PRINT_DEBUG("[PROCDUMP] Failed to trap return location of injected "
            "function call @ 0x%lx!\n",
            ctx->bp->breakpoint.addr);
    }

    return detach(drakvuf, info, ctx);
}

static addr_t get_function_va(drakvuf_t drakvuf, const char* lib,
    const char* func_name)
{
    addr_t rva;
    if (!drakvuf_get_kernel_symbol_rva(drakvuf, func_name, &rva))
    {
        PRINT_DEBUG("[PROCDUMP] [Init] Failed to get RVA of %s\n", func_name);
        throw -1;
    }

    addr_t va = drakvuf_exportksym_to_va(drakvuf, 4, nullptr, lib, rva);
    if (!va)
    {
        PRINT_DEBUG("[PROCDUMP] [Init] Failed to get VA of %s\n", func_name);
        throw -1;
    }

    return va;
}

procdump::procdump(drakvuf_t drakvuf, const procdump_config* config,
    output_format_t output)
    : pluginex(drakvuf, output)
    , terminated_processes(config->terminated_processes)
    , procdump_dir{config->procdump_dir ?: ""}
    , use_compression{config->compress_procdumps}
    , traps(nullptr)
    , procdumps_count(0)
    , pools()
    , terminating()
    , malloc_va()
    , memcpy_va()
    , clean_process_va()
    , win_build_number(0)
    , win_major(0)
    , win_minor(0)
    , num_cpus(0)
    , vendor()
    , version_information()
    , feature_information()
    , amd_extended_cpu_features()
{
    if (!config->procdump_dir)
        return;

    this->malloc_va =
        get_function_va(drakvuf, "ntoskrnl.exe", "ExAllocatePoolWithTag");
    this->memcpy_va =
        get_function_va(drakvuf, "ntoskrnl.exe", "RtlCopyMemoryNonTemporal");
    this->clean_process_va =
        get_function_va(drakvuf, "ntoskrnl.exe", "MmCleanProcessAddressSpace");

    vmi_lock_guard vmi(drakvuf);
    num_cpus = vmi_get_num_vcpus(vmi);
    win_build_info_t build_info;
    if (!vmi_get_windows_build_info(vmi.vmi, &build_info))
        throw -1;

    win_build_number = build_info.buildnumber;
    win_major = build_info.major;
    win_minor = build_info.minor;

    uint32_t r0, r1, r2;
    __cpuid(0, r0, vendor[0], vendor[2], vendor[1]);
    __cpuid(1, version_information, r0, r1, feature_information);
    __cpuid(0x80000001, r0, amd_extended_cpu_features, r1, r2);

    breakpoint_in_system_process_searcher bp;
    if (!register_trap(nullptr, terminate_process_cb, bp.for_syscall_name("NtTerminateProcess")))
        throw -1;
}

procdump::~procdump()
{
    GSList* loop = this->traps;
    while (loop)
    {
        free_trap(loop->data);
        loop = loop->next;
    }

    g_slist_free(this->traps);
}

bool procdump::stop_impl()
{
    destroy_all_traps();
    return terminating.empty();
}
