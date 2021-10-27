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

#include <glib.h>
#include <inttypes.h>

#include <libdrakvuf/json-util.h>
#include <libinjector/libinjector.h>

#include "procdump2.h"
#include "private2.h"
#include "minidump2.h"
#include "plugins/output_format.h"

using namespace std::string_literals;

static void save_file_metadata(struct procdump2_ctx* ctx, proc_data_t* proc_data)
{
    auto plugin = ctx->plugin;
    FILE* fp = fopen((plugin->procdump_dir + "/"s + ctx->data_file_name + ".metadata"s).data(), "w");
    if (!fp)
        return;

    json_object* jobj = json_object_new_object();
    json_object_object_add(jobj, "DumpSize", json_object_new_string_fmt("0x%" PRIx64, ctx->size));
    json_object_object_add(jobj, "PID", json_object_new_int(proc_data->pid));
    json_object_object_add(jobj, "PPID", json_object_new_int(proc_data->ppid));
    json_object_object_add(jobj, "ProcessName", json_object_new_string(proc_data->name));
    json_object_object_add(jobj, "TargetPID", json_object_new_int(ctx->target_process_pid));
    json_object_object_add(jobj, "TargetName", json_object_new_string(ctx->target_process_name.data()));
    json_object_object_add(jobj, "Compression", json_object_new_string(plugin->use_compression ? "gzip" : "none"));

    json_object_object_add(jobj, "DataFileName", json_object_new_string(ctx->data_file_name.data()));

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

static void restore_registers(drakvuf_trap_info_t* info,
    procdump2_ctx* ctx)
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

static bool trap_other_process(drakvuf_t drakvuf,
    procdump2* plugin,
    addr_t target_base,
    std::string target_name,
    vmi_pid_t target_pid,
    uint64_t idx,
    bool inject_suspend);

static event_response_t copy_virt_mem_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info);

static event_response_t exallocatepool_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info);

static event_response_t suspend_process_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info);

static event_response_t resume_process_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info);

static event_response_t get_current_irql_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info);

static bool inject_allocate_pool(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump2_ctx* ctx)
{
    struct argument args[3] = {};
    init_int_argument(&args[0], 0); // NonPagedPool
    init_int_argument(&args[1], ctx->POOL_SIZE_IN_PAGES * VMI_PS_4KB);
    init_int_argument(&args[2], 0);

    auto vmi = vmi_lock_guard(drakvuf);
    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 3))
        return false;

    info->regs->rip = ctx->plugin->malloc_va;
    ctx->ret_rsp = info->regs->rsp;
    ctx->bp->cb = exallocatepool_cb;

    return true;
}

static bool inject_copy_memory(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump2_ctx* ctx, addr_t addr, size_t size)
{
    uint64_t read_bytes = 0;
    struct argument args[7] = {};
    init_int_argument(&args[0], ctx->target_process_base);
    init_int_argument(&args[1], addr);
    init_int_argument(&args[2], info->attached_proc_data.base_addr);
    init_int_argument(&args[3], ctx->pool);
    init_int_argument(&args[4], size);
    init_int_argument(&args[5], 0); // UserMode (TODO Is this correct?)
    init_struct_argument(&args[6], read_bytes);

    auto vmi = vmi_lock_guard(drakvuf);
    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 7))
        return false;

    info->regs->rip = ctx->plugin->copy_virt_mem_va;
    ctx->ret_rsp = info->regs->rsp;
    ctx->bp->cb = copy_virt_mem_cb;

    return true;
}

static bool inject_suspend_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump2_ctx* ctx)
{
    struct argument args[1] = {};
    init_int_argument(&args[0], ctx->target_process_base);

    auto vmi = vmi_lock_guard(drakvuf);
    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 1))
        return false;

    info->regs->rip = ctx->plugin->suspend_process_va;
    ctx->ret_rsp = info->regs->rsp;
    ctx->bp->cb = suspend_process_cb;

    return true;
}

static bool inject_resume_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump2_ctx* ctx)
{
    struct argument args[1] = {};
    init_int_argument(&args[0], ctx->target_process_base);

    auto vmi = vmi_lock_guard(drakvuf);
    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 1))
        return false;

    info->regs->rip = ctx->plugin->resume_process_va;
    ctx->ret_rsp = info->regs->rsp;
    ctx->bp->cb = resume_process_cb;

    return true;
}

static bool inject_get_current_irql(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump2_ctx* ctx)
{
    auto vmi = vmi_lock_guard(drakvuf);
    if (!setup_stack_locked(drakvuf, vmi, info->regs, nullptr, 0))
        return false;

    info->regs->rip = ctx->plugin->current_irql_va;
    ctx->ret_rsp = info->regs->rsp;
    ctx->bp->cb = get_current_irql_cb;

    return true;
}

static bool read_vm(drakvuf_t drakvuf, addr_t dtb, addr_t start, size_t size,
    const struct procdump2_ctx* procdump_ctx, bool zero_fill = false)
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
    if (!zero_fill && VMI_SUCCESS == vmi_mmap_guest(vmi, &vmi_ctx, num_pages, access_ptrs))
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

static enum inject_status dump_vad_with_inject(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    procdump2_ctx* ctx, addr_t vad_start, vad_info2& vad)
{
    auto total_number_of_ptes = vad.total_number_of_ptes;
    uint32_t ptes_to_dump = std::min(total_number_of_ptes - vad.idx, ctx->POOL_SIZE_IN_PAGES);
    const auto idx = vad.idx; // cache it because we will change it

    g_assert (ptes_to_dump);
    g_assert (idx + ptes_to_dump <= total_number_of_ptes);

    addr_t start_addr = vad_start + idx * VMI_PS_4KB;
    ctx->current_dump_size = ptes_to_dump * VMI_PS_4KB;

    if (!inject_copy_memory(drakvuf, info, ctx, start_addr, ctx->current_dump_size))
    {
        PRINT_DEBUG("[PROCDUMP] [PID:%d] Error: Failed to inject "
            "RtlCopyMemoryNonTemporal\n",
            ctx->ret_pid);
        return INJECTION_FAILED;
    }

    if (idx + ptes_to_dump == total_number_of_ptes)
        return INJECT_ERASE;

    vad.idx += ptes_to_dump;
    return INJECT_CONTINUE;
}

static bool dump_next_dlls(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump2_ctx* ctx)
{
    if (!ctx->vads.empty())
    {
        auto vad = ctx->vads.begin();
        PRINT_DEBUG("[PROCDUMP] Process VAD: start %#lx, type %#x, ptes %zu, idx %#x\n", vad->first, vad->second.type, vad->second.total_number_of_ptes, vad->second.idx);
        switch (dump_vad_with_inject(drakvuf, info, ctx, vad->first, vad->second))
        {
            case INJECT_ERASE:
                ctx->vads.erase(vad);
            case INJECT_CONTINUE:
                return true;
            case INJECTION_FAILED:
            default:
                vad = ctx->vads.erase(vad);
                break;
        }
    }
    return false;
}

// FIXME The function could break the state
static event_response_t detach(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    procdump2_ctx* ctx)
{
    if (ctx->writer)
    {
        ctx->writer->finish();

        if (ctx->vads.empty())
        {
            // If there is no VADs left than the file have been processed
            save_file_metadata(ctx, &info->proc_data);
            fmt::print(ctx->plugin->m_output_format, "procdump", drakvuf, info,
                keyval("TargetPID", fmt::Nval(ctx->target_process_pid)),
                keyval("TargetName", fmt::Qstr(ctx->target_process_name)),
                keyval("DumpReason", fmt::Qstr("TerminateProcess")),
                keyval("DumpSize", fmt::Nval(ctx->size)),
                keyval("SN", fmt::Nval(ctx->idx))
            );
        }
    }

    ctx->plugin->set_process_finished(ctx->target_process_pid);
    inject_resume_process(drakvuf, info, ctx);

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static event_response_t copy_virt_mem_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info)
{
    auto ctx = static_cast<struct procdump2_ctx*>(info->trap->data);
    if (!ctx)
        return VMI_EVENT_RESPONSE_NONE;

    if (!drakvuf_check_return_context(drakvuf, info, ctx->ret_pid, ctx->ret_tid, ctx->ret_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    ctx->ret_rsp = 0;
    ctx->plugin->last_event_uuid = info->event_uid;

    // Restore stack pointer
    // This is crucial because lots of injections could exhaust the kernel stack
    info->regs->rsp = ctx->saved_regs.rsp;

    bool zero_fill = info->regs->rax != 0;
    if (zero_fill)
        PRINT_DEBUG("[PROCDUMP] Failed to copy memory from target process with status %#lx\n", info->regs->rax);

    if (!read_vm(drakvuf, info->regs->cr3, ctx->pool, ctx->current_dump_size,
            ctx, zero_fill))
    {
        PRINT_DEBUG("[PROCDUMP] [PID:%d] [TID:%d] Error: Failed to copy VAD "
            "(start 0x%lx, size 0x%lx) into file "
            "(size 0x%lx) with injection\n",
            ctx->ret_pid, ctx->ret_tid, ctx->vads.begin()->first,
            ctx->current_dump_size, ctx->size);
    }

    if (dump_next_dlls(drakvuf, info, ctx))
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    else
        return detach(drakvuf, info, ctx);
}

static bool dump_mmvad(drakvuf_t drakvuf, mmvad_info_t* mmvad,
    void* callback_data)
{
    uint32_t vad_type = drakvuf_mmvad_type(drakvuf, mmvad);
    uint64_t width = 0;
    uint64_t vad_commit_charge =
        drakvuf_mmvad_commit_charge(drakvuf, mmvad, &width);
    auto ctx = static_cast<procdump2_ctx*>(callback_data);
    addr_t vad_start = mmvad->starting_vpn * VMI_PS_4KB;
    uint64_t len_pages = mmvad->ending_vpn - mmvad->starting_vpn + 1;
    uint64_t len_bytes = len_pages * VMI_PS_4KB;

    // Dump only:
    // * Memory allocated with NtAllocateVirtualMemory and committed:
    //   CommitCharge is greater then zero
    // * Mapped image files (.exe or .dll): VadType is 2
    // * Sections mapped with NtMapViewOfSection: VadType is 0
    if (!vad_commit_charge)
        return false;

    // MiAllocateVad sets CommitCharge to MM_MAX_COMMIT
    // Such VADs doesn't contain any useful data
    if (vad_commit_charge == (1ULL << width) - 1)
        return false;

    if (len_bytes > VMI_PS_1GB)
    {
        // TODO Usually this regions contains several committed pages.
        // Save it with MiniDump
        PRINT_DEBUG(
            "[PROCDUMP] [PID:%d] Warning: VAD (0x%lx; 0x%lx; 0x%lx; 0x%lx) "
            "skipped on size 0x%lx, CommitCharge 0x%lx\n",
            ctx->ret_pid, mmvad->starting_vpn, mmvad->ending_vpn, mmvad->flags,
            mmvad->flags1, len_bytes, vad_commit_charge);
        return false;
    }

    ctx->vads[vad_start] = {vad_type, len_pages, 0};
    ctx->size += len_bytes;

    return false;
}

static bool prepare_mdmp_header(drakvuf_t drakvuf, drakvuf_trap_info_t* info, procdump2_ctx* ctx)
{
    uint32_t time_stamp = g_get_real_time() / G_USEC_PER_SEC;

    bool is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);

    unicode_string_t* csdversion_us = drakvuf_get_process_csdversion(drakvuf, info->attached_proc_data.base_addr);
    std::wstring csdversion;
    if (csdversion_us)
        csdversion = std::wstring(csdversion_us->contents[0], csdversion_us->contents[csdversion_us->length]);

    /* FIXME Remove hardcoded memory range descriptors
     *
     * Use two output files instead:
     * - minidump header;
     * - minidump data.
     *
     * On every memory range added append data to the header and data files.
     *
     * Afterwards merge two files.

     */
    vector<struct mdmp_memory_descriptor64> memory_ranges;
    for (auto vad: ctx->vads)
    {
        struct mdmp_memory_descriptor64 range(vad.first,
            vad.second.total_number_of_ptes * VMI_PS_4KB);
        memory_ranges.push_back(range);
    }

    // FIXME Gethere the data from ETHREAD and related structures
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
            ctx->plugin->num_cpus,
            ctx->plugin->win_major,
            ctx->plugin->win_minor,
            ctx->plugin->win_build_number,
            ctx->plugin->vendor,
            ctx->plugin->version_information,
            ctx->plugin->feature_information,
            ctx->plugin->amd_extended_cpu_features,
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

static event_response_t resume_process_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info)
{
    auto ctx = static_cast<struct procdump2_ctx*>(info->trap->data);
    if (!ctx)
        return VMI_EVENT_RESPONSE_NONE;
    g_assert(!ctx->plugin->is_new_process(ctx->target_process_pid));

    if (!drakvuf_check_return_context(drakvuf, info, ctx->ret_pid, ctx->ret_tid, ctx->ret_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    ctx->ret_rsp = 0;
    ctx->plugin->last_event_uuid = info->event_uid;

    restore_registers(info, ctx);
    // FIXME Pool should be free at detach (?)
    free_pool(ctx->plugin->pools, ctx->pool);
    auto it = ctx->plugin->active_working_threads.find(ctx->ret_tid);
    g_assert(it != ctx->plugin->active_working_threads.end());
    ctx->plugin->active_working_threads.erase(ctx->ret_tid);
    delete ctx;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static event_response_t main_chain(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info, procdump2_ctx* ctx)
{
    ctx->pool = find_pool(ctx->plugin->pools);
    if (ctx->pool)
    {
        try
        {
            std::string data_file_name = "procdump2."s + std::to_string(ctx->idx);
            ctx->data_file_name = data_file_name;
            ctx->writer = ProcdumpWriterFactory::build(ctx->plugin->procdump_dir + "/"s + data_file_name, ctx->plugin->use_compression);
        }
        catch (int)
        {
            PRINT_DEBUG("[PROCDUMP] Failed to create file\n");
            return detach(drakvuf, info, ctx);
        }

        /* NOTE The order of functions matters here
         *
         * The `drakvuf_traverse_mmvad` should be could before
         * `prepare_mdmp_header`. It fills list of VADs which is used to
         * prepare the correct header.
         */

        // Get virtual address space map of the process
        drakvuf_traverse_mmvad(drakvuf, ctx->target_process_base, dump_mmvad, ctx);

        if (!prepare_mdmp_header(drakvuf, info, ctx))
        {
            PRINT_DEBUG("[PROCDUMP] Failed to prepare Minidump header\n");
            return detach(drakvuf, info, ctx);
        }

        if (ctx->vads.empty())
            return detach(drakvuf, info, ctx);

        if (dump_next_dlls(drakvuf, info, ctx))
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        else
            return detach(drakvuf, info, ctx);
    }
    else
    {
        if (inject_allocate_pool(drakvuf, info, ctx))
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    return detach(drakvuf, info, ctx);
}

static event_response_t exallocatepool_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info)
{
    auto ctx = static_cast<struct procdump2_ctx*>(info->trap->data);
    if (!ctx)
        return VMI_EVENT_RESPONSE_NONE;

    if (!drakvuf_check_return_context(drakvuf, info, ctx->ret_pid, ctx->ret_tid, ctx->ret_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    ctx->ret_rsp = 0;
    ctx->plugin->last_event_uuid = info->event_uid;

    // Restore stack pointer
    // This is crucial because lots of injections could exhaust the kernel stack
    info->regs->rsp = ctx->saved_regs.rsp;

    if (info->regs->rax)
    {
        ctx->plugin->pools[info->regs->rax] = POOL_FREE;
        return main_chain(drakvuf, info, ctx);
    }
    else
    {
        PRINT_DEBUG("[PROCDUMP] [PID:%d] Failed to allocate pool\n",
            info->attached_proc_data.pid);
    }

    return detach(drakvuf, info, ctx);
}

static event_response_t suspend_process_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info)
{
    auto ctx = static_cast<struct procdump2_ctx*>(info->trap->data);
    if (!ctx)
        return VMI_EVENT_RESPONSE_NONE;
    g_assert(!ctx->plugin->is_new_process(ctx->target_process_pid));

    if (!drakvuf_check_return_context(drakvuf, info, ctx->ret_pid, ctx->ret_tid, ctx->ret_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    ctx->ret_rsp = 0;
    // Restore stack pointer
    // This is crucial because lots of injections could exhaust the kernel stack
    info->regs->rsp = ctx->saved_regs.rsp;
    ctx->plugin->last_event_uuid = info->event_uid;

    auto status = info->regs->rax;
    // FIXME May be we should check for not STATUS_SUCCESS?
    if (status == 0) // STATUS_SUCCESS
    {
        // Check of return status prevents endless loop of re-injections
        if (!ctx->plugin->is_process_handled(ctx->target_process_pid) &&
            inject_suspend_process(drakvuf, info, ctx))
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    else
    {
        PRINT_DEBUG("[PROCDUMP] WARNING Self suspend failed with status: %#lx\n", info->regs->rax);
    }

    restore_registers(info, ctx);
    delete ctx;
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static event_response_t get_current_irql_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info)
{
    auto ctx = static_cast<struct procdump2_ctx*>(info->trap->data);
    if (!ctx)
        return VMI_EVENT_RESPONSE_NONE;

    if (!drakvuf_check_return_context(drakvuf, info, ctx->ret_pid, ctx->ret_tid, ctx->ret_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    ctx->ret_rsp = 0;

    // Restore stack pointer
    // This is crucial because lots of injections could exhaust the kernel stack
    info->regs->rsp = ctx->saved_regs.rsp;

    if (info->regs->rax < IRQL_DISPATCH_LEVEL)
    {
        return main_chain(drakvuf, info, ctx);
    }
    else
    {
        if ( trap_other_process(drakvuf,
                ctx->plugin,
                ctx->target_process_base,
                ctx->target_process_name,
                ctx->target_process_pid,
                ctx->idx,
                false) )
        {
            restore_registers(info, ctx);
            drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free_trap);
            delete ctx;

            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        else
            return detach(drakvuf, info, ctx);
    }
}

static event_response_t wait_suspended_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto ctx = static_cast<struct procdump2_ctx*>(info->trap->data);
    if (!ctx)
        return VMI_EVENT_RESPONSE_NONE;

    if (ctx->plugin->last_event_uuid && info->event_uid == ctx->plugin->last_event_uuid)
        return VMI_EVENT_RESPONSE_NONE;
    else
        ctx->plugin->last_event_uuid = info->event_uid;

    // Skip self-terminating process
    if (info->attached_proc_data.pid == ctx->target_process_pid)
        return VMI_EVENT_RESPONSE_NONE;
    /* Skip processes with the same name and already processed (processing).
     *
     * E.g. Firefox creates multiple processes. If at some point Firefox
     * would be terminated then selected working processes would be terminated
     * too.
     */
    // TODO Move check to function (see "wait_to_suspend_cb")
    if (((string)info->attached_proc_data.name == ctx->target_process_name) ||
        !ctx->plugin->is_new_process(info->attached_proc_data.pid))
        return VMI_EVENT_RESPONSE_NONE;

    auto it = ctx->plugin->active_working_threads.find(info->attached_proc_data.tid);
    if (it != ctx->plugin->active_working_threads.end())
        return VMI_EVENT_RESPONSE_NONE;

    std::string proc_name{info->attached_proc_data.name};
    if (proc_name.find("lsass") == std::string::npos &&
        proc_name.find("csrss") == std::string::npos &&
        proc_name.find("conhost") == std::string::npos &&
        proc_name.find("services") == std::string::npos &&
        proc_name.find("svchost") == std::string::npos)
        return VMI_EVENT_RESPONSE_NONE;

    bool is_suspended = false;
    if ( !drakvuf_is_process_suspended(drakvuf, ctx->target_process_base, &is_suspended) )
    {
        PRINT_DEBUG("[PROCDUMP] Failed to check if process suspended\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    if (!is_suspended)
        return VMI_EVENT_RESPONSE_NONE;

    // Set return trap in current process
    memcpy(&ctx->saved_regs, info->regs, sizeof(x86_registers_t));
    ctx->remove_trap();
    ctx->add_trap(info, get_current_irql_cb);
    if (inject_get_current_irql(drakvuf, info, ctx))
    {
        ctx->plugin->active_working_threads.insert(info->attached_proc_data.tid);
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    return detach(drakvuf, info, ctx);
}

static event_response_t wait_to_suspend_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto ctx = static_cast<struct procdump2_ctx*>(info->trap->data);
    if (!ctx)
        return VMI_EVENT_RESPONSE_NONE;

    // TODO Check if should be used with every callback function
    if (ctx->plugin->last_event_uuid && info->event_uid == ctx->plugin->last_event_uuid)
        return VMI_EVENT_RESPONSE_NONE;
    else
        ctx->plugin->last_event_uuid = info->event_uid;

    // Skip self-terminating process
    if (info->attached_proc_data.pid == ctx->target_process_pid)
        return VMI_EVENT_RESPONSE_NONE;
    /* Skip processes with the same name and already processed (processing).
     *
     * E.g. Firefox creates multiple processes. If at some point Firefox
     * would be terminated then selected working processes would be terminated
     * too.
     */
    // TODO Move check to function (see "wait_suspended_cb")
    if (((string)info->attached_proc_data.name == ctx->target_process_name) ||
        !ctx->plugin->is_new_process(info->attached_proc_data.pid))
        return VMI_EVENT_RESPONSE_NONE;

    auto it = ctx->plugin->active_working_threads.find(info->attached_proc_data.tid);
    if (it != ctx->plugin->active_working_threads.end())
        return VMI_EVENT_RESPONSE_NONE;

    std::string proc_name{info->attached_proc_data.name};
    if (proc_name.find("lsass") == std::string::npos &&
        proc_name.find("csrss") == std::string::npos &&
        proc_name.find("conhost") == std::string::npos &&
        proc_name.find("services") == std::string::npos &&
        proc_name.find("svchost") == std::string::npos)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    memcpy(&ctx->saved_regs, info->regs, sizeof(x86_registers_t));
    ctx->remove_trap();
    g_assert(ctx->add_trap(info, suspend_process_cb));

    // FIXME If `trap_other_process` fails then the state would be broken
    if (inject_suspend_process(drakvuf, info, ctx) &&
        trap_other_process(drakvuf,
            ctx->plugin,
            ctx->target_process_base,
            ctx->target_process_name,
            ctx->target_process_pid,
            ctx->idx,
            false))
    {
        ctx->plugin->active_working_threads.insert(info->attached_proc_data.tid);
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    else
    {
        PRINT_DEBUG("[PROCDUMP] Failed to suspend target process %d\n",
            ctx->target_process_pid);
        return detach(drakvuf, info, ctx);
    }
}

static bool trap_other_process(drakvuf_t drakvuf,
    procdump2* plugin,
    addr_t target_base,
    std::string target_name,
    vmi_pid_t target_pid,
    uint64_t idx,
    bool inject_suspend)
{
    // Create new context
    auto ctx = new procdump2_ctx(drakvuf,
        plugin,
        target_base,
        target_name,
        target_pid,
        idx);

    auto cb = inject_suspend ? wait_to_suspend_cb : wait_suspended_cb;
    if (!ctx->add_trap(cb, ctx->plugin->deliver_apc_va))
    {
        delete ctx;
        return false;
    }

    return true;
}

static event_response_t terminate_process_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info)
{
    // Don't handle new processes while stopping
    auto plugin = get_trap_plugin<procdump2>(info);
    if ( plugin->is_stopping() )
    {
        if ( !plugin->is_plugin_active() )
            drakvuf_interrupt(drakvuf, 1);

        return VMI_EVENT_RESPONSE_NONE;
    }

    /* NOTE The check is crucial for processes terminating other processes
     *
     * If process A terminates process B it injects some other functions (
     * e.g. PsSuspendProcess). After the callback for injected function returns
     * the callback for NtTerminateProcess is called. So it is crucial to
     * distinguish the new envocation of the callback from subsequent. To
     * achieve this we use "info->event_uid".
     */
    if (plugin->last_event_uuid && info->event_uid == plugin->last_event_uuid)
        return VMI_EVENT_RESPONSE_NONE;
    else
        plugin->last_event_uuid = info->event_uid;

    procdump2_ctx* ctx = nullptr;
    uint32_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    if (0 == handle || 0xffffffff == handle)
    {
        if (!plugin->is_new_process(info->attached_proc_data.pid))
        {
            // We should reach that after 'self_suspend_process_cb'
            PRINT_DEBUG("[PROCDUMP] [INFO] The process %04d should be processed already!\n",
                info->attached_proc_data.pid);
            return VMI_EVENT_RESPONSE_NONE;
        }

        ctx = new procdump2_ctx(drakvuf, info, plugin, plugin->procdumps_count++);
    }
    else
    {
        /* FIXME Current process coulb not be a working process
         *
         * Use case:
         * 1. Current process terminates other process and both belongs to
         * single application.
         * 2. User terminates whole process (e.g. close the main window).
         * 3. Working process terminates while processing previous one!
         */
        addr_t target_process_base = 0;
        addr_t dtb = 0;
        if ( !drakvuf_get_process_by_handle(drakvuf, info, handle, &target_process_base, &dtb) )
        {
            PRINT_DEBUG("[PROCDUMP] Failed to get process base\n");
            return VMI_EVENT_RESPONSE_NONE;
        }

        vmi_pid_t target_process_pid = 0;
        if ( !drakvuf_get_process_pid(drakvuf, target_process_base, &target_process_pid) )
        {
            PRINT_DEBUG("[PROCDUMP] Failed to get target process PID\n");
            return VMI_EVENT_RESPONSE_NONE;
        }

        // TODO Check if this works now
        if (!plugin->is_new_process(target_process_pid))
        {
            PRINT_DEBUG("[PROCDUMP] [INFO] The process %04d should be processed already!\n",
                target_process_pid);
            /* NOTE The target process is already under processing.
             *
             * If some application creates multiple processes and process A
             * been terminated and then the whole application been terminated
             * then process A could receive a signal from parent process.
             */
            bool is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
            info->regs->rip = drakvuf_get_function_return_address(drakvuf, info);
            info->regs->rsp -= is32bit ? 4 : 8;
            info->regs->rax = 0; // STATUS_SUCCESS
            return VMI_EVENT_RESPONSE_NONE;
        }

        ctx = new procdump2_ctx(drakvuf,
            info,
            plugin,
            target_process_base,
            std::string(drakvuf_get_process_name(drakvuf, target_process_base, true)),
            target_process_pid,
            plugin->procdumps_count++);
    }

    if ( !ctx->add_trap(info, suspend_process_cb) )
    {
        delete ctx;
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (inject_suspend_process(drakvuf, info, ctx))
    {
        if (!trap_other_process(drakvuf,
                plugin,
                ctx->target_process_base,
                ctx->target_process_name,
                ctx->target_process_pid,
                ctx->idx,
                false))
        {
            restore_registers(info, ctx);
            delete ctx;
            return VMI_EVENT_RESPONSE_NONE;
        }

        plugin->insert_new_process(ctx->target_process_pid);
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    delete ctx;
    return VMI_EVENT_RESPONSE_NONE;
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

procdump2::procdump2(drakvuf_t drakvuf, const procdump2_config* config,
    output_format_t output)
    : pluginex(drakvuf, output)
    , procdump_dir{config->procdump_dir ?: ""}
    , procdump_on_finish(config->procdump_on_finish)
    , terminated_processes(config->terminated_processes)
    , use_compression{config->compress_procdumps}
    , drakvuf(drakvuf)
{
    if (!config->procdump_dir)
        return;

    this->malloc_va =
        get_function_va(drakvuf, "ntoskrnl.exe", "ExAllocatePoolWithTag");
    this->suspend_process_va =
        get_function_va(drakvuf, "ntoskrnl.exe", "PsSuspendProcess");
    this->resume_process_va =
        get_function_va(drakvuf, "ntoskrnl.exe", "PsResumeProcess");
    this->copy_virt_mem_va =
        get_function_va(drakvuf, "ntoskrnl.exe", "MmCopyVirtualMemory");
    this->current_irql_va =
        get_function_va(drakvuf, "ntoskrnl.exe", "KeGetCurrentIrql");
    this->deliver_apc_va =
        get_function_va(drakvuf, "ntoskrnl.exe", "KiDeliverApc");

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

procdump2::~procdump2()
{
}

bool procdump2::stop()
{
    destroy_all_traps();
    if (procdump_on_finish && is_new_process(procdump_on_finish))
    {
        addr_t target_process_pid = procdump_on_finish;
        /* NOTE This prevents errors on subsequent calls to the stop method
         *
         * If "wait stop plugins" option been used then multiple calls to stop
         * method would occur.
         */
        procdump_on_finish = 0;
        addr_t target_process_base = 0;
        addr_t dtb = 0;
        if ( !drakvuf_get_process_by_pid(drakvuf, target_process_pid, &target_process_base, &dtb) )
        {
            PRINT_DEBUG("[PROCDUMP] Failed to get process base\n");
        }
        else
        {
            std::string target_process_name{drakvuf_get_process_name(drakvuf, target_process_base, true)};

            if (trap_other_process(drakvuf,
                    this,
                    target_process_base,
                    target_process_name,
                    target_process_pid,
                    procdumps_count++,
                    true))
                insert_new_process(target_process_pid);
            else
                PRINT_DEBUG("[PROCDUMP] Failed to suspend target process\n");
        }
    }
    m_is_stopping = true;
    return !is_plugin_active();
}

bool procdump2::is_plugin_active()
{
    if (!breakpoints.empty())
        return true;

    for (auto p: *terminated_processes)
        if (!p.second)
            return true;

    return false;
}

bool procdump2::is_new_process(vmi_pid_t pid)
{
    // The callback could be called if other thread invokes NtTerminateProcess
    // or as a return path from injected function.
    // In both cases we should not starting process dump again.
    return terminated_processes->find(pid) == terminated_processes->end();
}

bool procdump2::is_process_handled(vmi_pid_t pid)
{
    g_assert(!is_new_process(pid));
    return terminated_processes->at(pid);
}

void procdump2::insert_new_process(vmi_pid_t pid)
{
    g_assert(is_new_process(pid));
    terminated_processes->insert_or_assign(pid, false);
}

void procdump2::set_process_finished(vmi_pid_t pid)
{
    g_assert(!is_new_process(pid));
    terminated_processes->insert_or_assign(pid, true);
}
