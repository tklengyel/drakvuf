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

#include <array>
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

using namespace procdump2_ns;

/*****************************************************************************
 *                             Public interface                              *
 *****************************************************************************/
procdump2::procdump2(drakvuf_t drakvuf, const procdump2_config* config,
    output_format_t output)
    : pluginex(drakvuf, output)
    , timeout{config->timeout}
    , procdump_dir{config->procdump_dir ?: ""}
    , dump_process_on_finish(config->dump_process_on_finish)
    , dump_new_processes_on_finish(config->dump_new_processes_on_finish)
    , use_compression{config->compress_procdumps}
    , pools(std::make_unique<pool_manager>())
    , exclude{config->exclude_file, "[PROCDUMP]"}
{
    if (procdump_dir.empty())
        return;

    if (config->disable_kideliverapc_hook &&
        config->disable_kedelayexecutionthread_hook)
    {
        PRINT_DEBUG("[PROCDUMP] WARNING Hooks are disabled: check arguments\n");
        return;
    }

    vmi_lock_guard vmi(drakvuf);
    bool is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    win_ver_t winver = vmi_get_winver(vmi);

    this->malloc_va =
        drakvuf_kernel_symbol_to_va(drakvuf, "ExAllocatePoolWithTag");
    this->suspend_process_va =
        drakvuf_kernel_symbol_to_va(drakvuf, "PsSuspendProcess");
    this->resume_process_va =
        drakvuf_kernel_symbol_to_va(drakvuf, "PsResumeProcess");
    this->copy_virt_mem_va =
        drakvuf_kernel_symbol_to_va(drakvuf, "MmCopyVirtualMemory");
    this->delay_execution_va =
        drakvuf_kernel_symbol_to_va(drakvuf, "KeDelayExecutionThread");

    if (!this->malloc_va ||
        !this->suspend_process_va ||
        !this->resume_process_va ||
        !this->copy_virt_mem_va ||
        !this->delay_execution_va)
    {
        PRINT_DEBUG("[PROCDUMP] Failed to get function address\n");
        throw -1;
    }

    if (is32bit && VMI_OS_WINDOWS_7 == winver)
    {
        json_object* hal_profile = json_object_from_file(config->hal_profile);
        if (!hal_profile)
        {
            PRINT_DEBUG("Procdump plugin fails to load JSON debug info for hal.dll\n");
            throw -1;
        }

        addr_t func_rva = 0;
        if ( !json_get_symbol_rva(drakvuf, hal_profile, "KeGetCurrentIrql", &func_rva) )
        {
            PRINT_DEBUG("[PROCDUMP] Failed to get RVA of hal!KeGetCurrentIrql\n");
            throw -1;
        }

        addr_t modlist;
        if ( VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &modlist) )
        {
            PRINT_DEBUG("[PROCDUMP] Couldn't read PsLoadedModuleList\n");
            throw -1;
        }

        addr_t hal_base = 0;
        if ( !drakvuf_get_module_base_addr(drakvuf, modlist, "hal.dll", &hal_base) )
        {
            PRINT_DEBUG("[PROCDUMP] Couldn't find hal.dll\n");
            throw -1;
        }

        this->current_irql_va = hal_base + func_rva;

        json_object_put(hal_profile);
    }
    else
    {
        this->current_irql_va =
            drakvuf_kernel_symbol_to_va(drakvuf, "KeGetCurrentIrql");
    }

    num_cpus = vmi_get_num_vcpus(vmi);
    win_build_info_t build_info;
    if (!vmi_get_windows_build_info(vmi, &build_info))
        throw -1;

    win_build_number = build_info.buildnumber;
    win_major = build_info.major;
    win_minor = build_info.minor;

    uint32_t r0, r1, r2;
    __cpuid(0, r0, vendor[0], vendor[2], vendor[1]);
    __cpuid(1, version_information, r0, r1, feature_information);
    __cpuid(0x80000001, r0, amd_extended_cpu_features, r1, r2);

    this->terminate_process_hook = createSyscallHook("NtTerminateProcess", &procdump2::terminate_process_cb);
    this->clean_process_memory_hook = createSyscallHook("MmCleanProcessAddressSpace", &procdump2::clean_process_memory_cb);

    if (!config->disable_kedelayexecutionthread_hook)
        this->delay_execution_hook = createSyscallHook("KeDelayExecutionThread", &procdump2::delay_execution_cb);

    if (!config->disable_kideliverapc_hook)
        this->deliver_apc_hook = createSyscallHook("KiDeliverApc", &procdump2::deliver_apc_cb);

    if (config->dump_new_processes_on_finish)
        running_processes_on_start = get_running_processes();
}

procdump2::~procdump2()
{
}

bool procdump2::stop_impl()
{
    bool is_plugin_enabled = this->delay_execution_hook || this->deliver_apc_hook;

    if (!begin_stop_at)
        begin_stop_at = g_get_real_time() / G_USEC_PER_SEC;

    if (is_plugin_enabled && !is_stopping())
    {
        // On first stop call we collect PIDs for dump

        std::vector<vmi_pid_t> pids;
        if (dump_process_on_finish)
            pids.push_back(dump_process_on_finish);
        if (dump_new_processes_on_finish)
        {
            auto running_processes_on_finish = get_running_processes();
            for (auto pid : running_processes_on_finish)
            {
                auto it = std::find(running_processes_on_start.begin(), running_processes_on_start.end(), pid);
                if (it == running_processes_on_start.end())
                    pids.push_back(pid); // pid is a new process
            }
        }

        // Filter out dead or 'dump already in progress' PIDs
        auto new_end = std::remove_if(pids.begin(), pids.end(), [this](vmi_pid_t pid)
        {
            return is_active_process(pid) || is_process_handled(pid);
        });
        pids.erase(new_end, pids.end());

        for (auto pid : pids)
            this->start_dump_process(pid);
    }

    if (!is_plugin_active())
    {
        destroy_all_traps();
        return true;
    }

    static size_t counter = 0;
    if (counter++ % 100 == 0)
        for (auto const& task: this->active)
        {
            auto ctx = task.second;
            PRINT_DEBUG("[PROCDUMP] Pending task on stop: PID=%d, stage %s\n"
                , ctx->target_process_pid, to_str(ctx->stage()).data()
            );
        }
    return false;
}

void procdump2::start_dump_process(vmi_pid_t pid)
{
    addr_t process_base = 0;
    if (!drakvuf_get_process_by_pid(drakvuf, pid, &process_base, nullptr))
        return;

    auto proc_name = drakvuf_get_process_name(drakvuf, process_base, true);
    if (proc_name && exclude.match(proc_name))
    {
        drakvuf_trap_info_t info = {};
        drakvuf_trap_t trap = {};

        g_free(proc_name);

        info.timestamp = g_get_real_time();
        info.trap = &trap;

        if (!drakvuf_get_process_data(drakvuf, process_base, &info.attached_proc_data))
        {
            PRINT_DEBUG("Failed to get data of process 0x%" PRIx64 "\n", process_base);
            return;
        }

        print_dump_exclusion(&info);

        g_free(const_cast<char*>(info.attached_proc_data.name));
        return;
    }

    auto ctx = std::make_shared<procdump2_ctx>(
            false,
            process_base,
            std::string(proc_name ?: ""),
            pid,
            procdumps_count++,
            procdump_dir,
            use_compression,
            "FinishAnalysis");
    g_free(proc_name);
    ctx->stage(procdump_stage::need_suspend);
    ctx->wait_awaken = false;
    ctx->target.restored = true;
    PRINT_DEBUG("[PROCDUMP] [%d:%d] Dispatch new process\n", pid, to_int(ctx->stage()));

    /* Save new target process into the list */
    this->active[pid] = ctx;
}

/*****************************************************************************
 *                               Hook handlers                               *
 *****************************************************************************/

event_response_t procdump2::delay_execution_cb(drakvuf_t,
    drakvuf_trap_info_t* info)
{
    // TODO It is possible that all threads in System process at PASSIVE_LEVEL
    if (4 == info->attached_proc_data.pid)
        return dispatcher(info);

    return VMI_EVENT_RESPONSE_NONE;
}

/* NOTE Used to capture context switch
 *
 * It have been noticed that usual CR3 switch hook leads to errors:
 * - function call injection results in BSOD;
 * - waiting for "IRQL < DISPATCH" takes too long.
 *
 * The syscall hook works better. We capture KiDeliverApc.
 */
event_response_t procdump2::deliver_apc_cb(drakvuf_t, drakvuf_trap_info_t* info)
{
    std::string proc_name{info->attached_proc_data.name};
    if (proc_name.find("lsass")    != std::string::npos ||
        proc_name.find("csrss")    != std::string::npos ||
        proc_name.find("conhost")  != std::string::npos ||
        proc_name.find("services") != std::string::npos ||
        proc_name.find("explorer") != std::string::npos ||
        proc_name.find("spoolsv")  != std::string::npos ||
        proc_name.find("lsm")      != std::string::npos ||
        proc_name.find("taskhost") != std::string::npos ||
        proc_name.find("svchost")  != std::string::npos)
    {
        return dispatcher(info);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

/* TODO Protect working threads from termination with return injection.
 *
 * We should store the std::pair<vmi_pid_t, uint32_t> for monitoring working
 * processes and threads and inject return from `NtTerminateProcess` in such
 * a case.
 *
 * We should add such processes to queue of processes to terminate.
 */
event_response_t procdump2::terminate_process_cb(drakvuf_t,
    drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] "
        "NtTerminateProcess(%#lx)\n"
        , info->event_uid
        , info->attached_proc_data.pid, info->attached_proc_data.tid
        , drakvuf_get_function_argument(drakvuf, info, 1)
    );

    if (drakvuf_lookup_injection(drakvuf, info))
        drakvuf_remove_injection(drakvuf, info);

    /* Check if current thread is a active one. */
    for (auto it = this->active.cbegin(), next_it = it; it != this->active.cend(); it = next_it)
    {
        ++next_it;
        auto ctx = it->second;
        bool is_target = drakvuf_check_return_context(drakvuf, info,
                ctx->target.ret_pid,
                ctx->target.ret_tid,
                ctx->target.ret_rsp);
        bool is_host = drakvuf_check_return_context(drakvuf, info,
                ctx->host.ret_pid,
                ctx->host.ret_tid,
                ctx->host.ret_rsp);
        if (is_target && dispatch_target_wakeup(info, ctx))
            return VMI_EVENT_RESPONSE_NONE;
        else if (is_host && dispatch_host_wakeup(info, ctx))
            return VMI_EVENT_RESPONSE_NONE;
    }

    /* The host process could become a target one. So dispatch wake up first. */
    if (is_process_handled(info->attached_proc_data.pid))
        return VMI_EVENT_RESPONSE_NONE;

    /* Don't handle new processes while stopping to avoid infinite loop. */
    if ( is_stopping() )
        return VMI_EVENT_RESPONSE_NONE;

    if ( dispatch_new(info) )
        return VMI_EVENT_RESPONSE_NONE;

    return VMI_EVENT_RESPONSE_NONE;
}

/* Hook target process address space removal to prevent kernel panic while
 * memory copy.
 *
 * "MmCopyVirtualMemory" locks pages. If target process terminates while still
 * active the "MmCleanProcessAddressSpace" is called and touches locked pages.
 * This result in kernel panic (aka BSOD).
 *
 * The solution is to inject delay execution call until "MmCopyVirtualMemory"
 * finish.
 */
event_response_t procdump2::clean_process_memory_cb(drakvuf_t,
    drakvuf_trap_info_t* info)
{
    /* Check if current thread is a active one. */
    for (auto& [pid, ctx]: this->active)
    {
        if (info->attached_proc_data.pid == ctx->target_process_pid)
        {
            // The working thread is active - keep alive
            PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                "Target process destroyed.\n"
                , info->event_uid
                , info->attached_proc_data.pid
                , info->attached_proc_data.tid
                , ctx->target_process_pid, to_int(ctx->stage())
            );
            // TODO Move working thread check into function
            if (this->working_threads.find(ctx->working.ret_tid) !=
                this->working_threads.end())
            {
                if (ctx->stage() == procdump_stage::copy_memory)
                    PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d]\t> "
                        "Working thread still active. "
                        "BSOD on locked pages could occur\n"
                        , info->event_uid
                        , info->attached_proc_data.pid
                        , info->attached_proc_data.tid
                        , ctx->target_process_pid, to_int(ctx->stage())
                    );
            }
            else
            {
                // The working thread is not active - finish task
                PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d]\t> "
                    "Working thread finished.\n"
                    , info->event_uid
                    , info->attached_proc_data.pid
                    , info->attached_proc_data.tid
                    , ctx->target_process_pid, to_int(ctx->stage())
                );
            }
        }
    }

    return VMI_EVENT_RESPONSE_NONE;
}

/*****************************************************************************
 *                               Dispatchers                                 *
 *****************************************************************************/

event_response_t procdump2::dispatcher(drakvuf_trap_info_t* info)
{
    if (drakvuf_lookup_injection(drakvuf, info))
        drakvuf_remove_injection(drakvuf, info);

    if (auto ctx = continues_task(info))
    {
        dispatch_active(info, ctx);
        return VMI_EVENT_RESPONSE_NONE;
    }

    /* Check if there is something to processes. */
    if (!is_plugin_active())
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] "
            "Nothing to dispatch\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
        );
        return VMI_EVENT_RESPONSE_NONE;
    }

    /* Search first pending task. */

    /* Ensure that single thread attaches to single target process only.
     *
     * Used MmCopyVirtualmemory wraps KeStackAttachProcess internally. Thus
     * one have to ensure that the thread is not attached to other process.
     *
     * Otherwise one catch BSOD with INVALID_PROCESS_ATTACH_ATTEMPT.
     */
    if (info->proc_data.pid != info->attached_proc_data.pid)
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] "
            "Skip thread attached to other process\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
        );
        return VMI_EVENT_RESPONSE_NONE;
    }

    for (auto it = this->active.cbegin(), next_it = it; it != this->active.cend(); it = next_it)
    {
        ++next_it;
        auto ctx = it->second;
        if (dispatch_pending(info, ctx))
        {
            return VMI_EVENT_RESPONSE_NONE;
        }
    }


    return VMI_EVENT_RESPONSE_NONE;
}

void procdump2::dispatch_active(drakvuf_trap_info_t* info, std::shared_ptr<procdump2_ctx> ctx)
{
    PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
        "Dispatch active process\n"
        , info->event_uid
        , info->attached_proc_data.pid, info->attached_proc_data.tid
        , ctx->target_process_pid, to_int(ctx->stage())
    );

    if (is_stopping() &&
        timeout &&
        g_get_real_time() / G_USEC_PER_SEC - begin_stop_at > timeout &&
        !ctx->is_timed_out())
    {
        ctx->stage(procdump_stage::timeout);
    }

    check_stack_marker(info, ctx, ctx->working);

    switch (ctx->stage())
    {
        case procdump_stage::need_suspend:
        case procdump_stage::pending:
        case procdump_stage::prepare_minidump:
        case procdump_stage::finished:
        {
            PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                "WARNING! Working thread don't handle this stage\n"
                , info->event_uid
                , info->attached_proc_data.pid
                , info->attached_proc_data.tid
                , ctx->target_process_pid, to_int(ctx->stage())
            );
        }
        break;

        case procdump_stage::suspend:
        {
            /* Don't check PsSuspendProcess return code.
             *
             * PsSuspendProcess will only return STATUS_SUCCESS or
             * STATUS_PROCESS_IS_TERMINATING.
             * I believe that both values are acceptible here.
             *
             * After PsSuspendProcess invokation we have to wait until
             * target process would be really suspended. So move the
             * context into pending state.
             */
            restore(info, ctx->working);
            ctx->stage(procdump_stage::pending);
            /* This trick prevents to fetching the task from active list
             * while handline KiDeliverApc hook.
             * TODO Move to function
             */
            ctx->working.ret_pid = 0;
            this->working_threads.erase(info->attached_proc_data.tid);
        }
        break;

        case procdump_stage::get_irql:
        {
            uint8_t irql = info->regs->rax;
            if (irql >= IRQL_DISPATCH_LEVEL)
            {
                /* The current thread's IRQL is high. Search other one. */
                restore(info, ctx->working);
                ctx->stage(procdump_stage::pending);
                /* This trick prevents to fetching the task from active list
                * while handline KiDeliverApc hook.
                * TODO Move to function
                */
                ctx->working.ret_pid = 0;
                this->working_threads.erase(info->attached_proc_data.tid);
            }
            else
            {
                if ( (ctx->pool = this->pools->get()) != 0 )
                {
                    if (!start_copy_memory(info, ctx))
                    {
                        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                            "Resume target process on dump start fail\n"
                            , info->event_uid
                            , info->attached_proc_data.pid
                            , info->attached_proc_data.tid
                            , ctx->target_process_pid, to_int(ctx->stage())
                        );
                        resume(info, ctx);
                    }
                }
                else
                    allocate_pool(info, ctx);
            }
        }
        break;

        case procdump_stage::allocate_pool:
        {
            addr_t pool = info->regs->rax;
            if (pool)
            {
                pools->add(pool);
                ctx->pool = pools->get();
                if (!start_copy_memory(info, ctx))
                {
                    PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                        "Resume target process on dump start fail\n"
                        , info->event_uid
                        , info->attached_proc_data.pid
                        , info->attached_proc_data.tid
                        , ctx->target_process_pid, to_int(ctx->stage())
                    );
                    resume(info, ctx);
                }
            }
            else
            {
                PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                    "Resume target process on pool allocation fail\n"
                    , info->event_uid
                    , info->attached_proc_data.pid, info->attached_proc_data.tid
                    , ctx->target_process_pid, to_int(ctx->stage())
                );
                resume(info, ctx);
            }
        }
        break;

        case procdump_stage::copy_memory:
        {
            uint32_t read_bytes = 0;
            {
                ACCESS_CONTEXT(vmi_ctx);
                vmi_ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
                vmi_ctx.dtb = info->regs->cr3;
                vmi_ctx.addr = ctx->current_read_bytes_va;

                vmi_lock_guard vmi(drakvuf);
                vmi_read_32(vmi, &vmi_ctx, &read_bytes);
            }

            size_t size = 0;
            if (read_bytes == ctx->current_dump_size)
            {
                read_vm(info->regs->cr3, ctx, read_bytes);
                size = read_bytes;
            }
            else if (read_bytes == 0)
            {
                dump_zero_page(ctx);
                size = VMI_PS_4KB;
            }
            else
            {
                read_vm(info->regs->cr3, ctx, read_bytes);
                dump_zero_page(ctx);
                size = read_bytes + VMI_PS_4KB;
            }

            // Dump data region (not memory-mapped file) with zeroes
            if (size < ctx->current_dump_size &&
                !ctx->is_current_memory_mapped_file)
            {
                for (; size < ctx->current_dump_size; size += VMI_PS_4KB)
                    dump_zero_page(ctx);
            }

            if (size == ctx->current_dump_size && ctx->vads.empty())
            {
                // The last region have been fully dumped so finish task
                PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                    "Resume target process on dump finish\n"
                    , info->event_uid
                    , info->attached_proc_data.pid, info->attached_proc_data.tid
                    , ctx->target_process_pid, to_int(ctx->stage())
                );
                resume(info, ctx);
            }
            else if (size == ctx->current_dump_size)
            {
                // The region have been fully dumped so go to next one
                auto [base, size] = get_memory_region(info, ctx);
                PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                    "Copy memory region [%#lx;%#lx]\n"
                    , info->event_uid
                    , info->attached_proc_data.pid
                    , info->attached_proc_data.tid
                    , ctx->target_process_pid, to_int(ctx->stage())
                    , base, size
                );
                copy_memory(info, ctx, base, size);
            }
            else
            {
                /* If we have read more any data (assume 4KB at least) then
                 * after the last read byte the non-accessible page occur.
                 * So skip this page.
                 * If zero bytes have been read then the first page is
                 * non-accessible. So skip this page.
                 */
                auto base = ctx->current_dump_base + size;
                size = ctx->current_dump_size - size;
                PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                    "copy_memory: bytes copied %#x before "
                    "NO_ACCESS page. Continue with [%#lx;%#lx]\n"
                    , info->event_uid
                    , info->attached_proc_data.pid
                    , info->attached_proc_data.tid
                    , ctx->target_process_pid, to_int(ctx->stage())
                    , read_bytes, base, size
                );
                copy_memory(info, ctx, base, size);
            }
        }
        break;

        case procdump_stage::target_awaken:
        case procdump_stage::resume:
        {
            PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                "After resuming target process\n"
                , info->event_uid
                , info->attached_proc_data.pid, info->attached_proc_data.tid
                , ctx->target_process_pid, to_int(ctx->stage())
            );
            /* Assume self-terminating target here. Such a target would
             * remove task after return from PsSuspendProcess.
             *
             * For not self-terminating target this is not the case. The
             * task should be removed here.
             */
            restore(info, ctx->working);
            if (ctx->is_restored())
            {
                ctx->stage(procdump_stage::finished);
                finish_task(info, ctx);
            }
            /* This trick prevents to fetching the task from active list
             * while handline KiDeliverApc hook.
             * TODO Move to function
             */
            ctx->working.ret_pid = 0;
            this->working_threads.erase(info->attached_proc_data.tid);
        }
        break;
        case procdump_stage::timeout:
            resume(info, ctx);
            break;
        case procdump_stage::target_wakeup:
            restore(info, ctx->working);
            /* This trick prevents to fetching the task from active list
             * while handline KiDeliverApc hook.
             * TODO Move to function
             */
            ctx->working.ret_pid = 0;
            this->working_threads.erase(info->attached_proc_data.tid);
    }
}

bool procdump2::dispatch_pending(drakvuf_trap_info_t* info, std::shared_ptr<procdump2_ctx> ctx)
{
    PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
        "Dispatch pending process\n"
        , info->event_uid
        , info->attached_proc_data.pid, info->attached_proc_data.tid
        , ctx->target_process_pid, to_int(ctx->stage())
    );

    if (ctx->stage() == procdump_stage::need_suspend)
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
            "Suspend target process\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        ctx->stage(procdump_stage::suspend);
        // TODO Move to function ... START
        memcpy(&ctx->working.regs, info->regs, sizeof(x86_registers_t));
        ctx->working.restored = false;
        this->working_threads.insert(info->attached_proc_data.tid);
        // ... END
        suspend(info, ctx->target_process_base, ctx->working);
        return true;
    }
    else if (ctx->stage() == procdump_stage::pending)
    {
        if (ctx->old_stage() == procdump_stage::need_suspend)
            check_stack_marker(info, ctx, ctx->working);
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
            "Check if target process suspended\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        bool is_suspended = false;
        if ( !drakvuf_is_process_suspended(drakvuf, ctx->target_process_base, &is_suspended) )
        {
            PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                "Failed to check if process suspended\n"
                , info->event_uid
                , info->attached_proc_data.pid, info->attached_proc_data.tid
                , ctx->target_process_pid, to_int(ctx->stage())
            );
            // TODO Move to function ... START
            memcpy(&ctx->working.regs, info->regs, sizeof(x86_registers_t));
            ctx->working.restored = false;
            this->working_threads.insert(info->attached_proc_data.tid);
            // ... END
            resume(info, ctx);
            return true;
        }
        if (!is_suspended)
            return false;

        // TODO Move to function ... START
        memcpy(&ctx->working.regs, info->regs, sizeof(x86_registers_t));
        ctx->working.restored = false;
        this->working_threads.insert(info->attached_proc_data.tid);
        // ... END
        get_irql(info, ctx);
        return true;
    }
    else
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
            "Wait pending stage here\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        return false;
    }
}

bool procdump2::dispatch_new(drakvuf_trap_info_t* info)
{
    uint32_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t target_process_base = 0;
    std::string target_process_name;
    vmi_pid_t target_process_pid = 0;
    bool is_hosted = false;

    if (0 == handle || 0xffffffff == handle)
    {
        target_process_base = info->attached_proc_data.base_addr;
        target_process_name = std::string(info->attached_proc_data.name);
        target_process_pid = info->attached_proc_data.pid;
    }
    else
    {
        is_hosted = true;
        /* Delay suspend target process.
         *
         * This is not optimal to delay suspend. But we reuse code path
         * with stop method which implements this logic. Thus we reduce
         * code complexity.
         */
        addr_t dtb = 0;
        if ( !drakvuf_get_process_by_handle(drakvuf, info, handle, &target_process_base, &dtb) )
            return false;

        if ( !drakvuf_get_process_pid(drakvuf, target_process_base, &target_process_pid) )
            return false;

        char* name = drakvuf_get_process_name(drakvuf, target_process_base, true);
        target_process_name = std::string(name ?: "");
        g_free(name);
    }

    /* Don't process active and finished tasks.
     *
     * Withing job main process could terminate every process and then
     * terminate whole job with TerminateJobObject API.
     *
     * On first NtTerminateProcess we add target process into the list.
     * On job termination the target process would NtTerminateProcess(-1).
     *
     * And kernel32!ExitProcess calls NtTerminateProcess twice with handle 0
     * and 0xffffffff. Thus we should avoid to dumping process's memory on
     * second call.
     *
     * If this true:
     * - Don't create new task.
     * - Return VMI_EVENT_RESPONSE_NONE.
     * - Current process continue execution of NtTerminateProcess.
     * - Target process would resume.
     * - Target process would be suspended with the plug-in.
     */
    // TODO Check that target process would be suspended.
    // TODO Hook process creation and remove from finished list reused PIDs.
    if (is_active_process(target_process_pid) ||
        is_process_handled(target_process_pid))
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] "
            "Skip active or finished process %d (%s)\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , target_process_pid, target_process_name.data()
        );
        return false;
    }

    if (exclude.match(target_process_name))
    {
        print_dump_exclusion(info);
        return false;
    }

    auto ctx = std::make_shared<procdump2_ctx>(
            is_hosted,
            target_process_base,
            target_process_name,
            target_process_pid,
            procdumps_count++,
            procdump_dir,
            use_compression,
            "TerminateProcess");

    this->active[target_process_pid] = ctx;

    PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
        "Dispatch new process: %s\n"
        , info->event_uid
        , info->attached_proc_data.pid, info->attached_proc_data.tid
        , ctx->target_process_pid, to_int(ctx->stage())
        , target_process_name.data()
    );

    /* Suspend target and/or host processes.
     *
     * If process is self-terminating than inject suspend call here.
     * Otherwise delay suspend of target process and suspend host process here.
     *
     * If later suspended process would be resumed beforehand than it would be
     * suspended once more.
     */
    if (is_hosted)
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
            "Delay target suspend\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        ctx->stage(procdump_stage::need_suspend);
        ctx->host_process_base = info->attached_proc_data.base_addr;
        memcpy(&ctx->host.regs, info->regs, sizeof(x86_registers_t));
        delay_execution(info, ctx->host, 500);
    }
    else
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
            "Suspend self-terminating\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        memcpy(&ctx->target.regs, info->regs, sizeof(x86_registers_t));
        suspend(info, ctx->target_process_base, ctx->target);
    }

    return true;
}

bool procdump2::dispatch_host_wakeup(
    drakvuf_trap_info_t* info,
    std::shared_ptr<procdump2_ctx> ctx)
{
    check_stack_marker(info, ctx, ctx->host);
    switch (ctx->stage())
    {
        case procdump_stage::resume:
        case procdump_stage::target_awaken:
        case procdump_stage::finished:
        case procdump_stage::target_wakeup:
        case procdump_stage::timeout:
            PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                "Delayed host process wake up - restore it\n"
                , info->event_uid
                , info->attached_proc_data.pid, info->attached_proc_data.tid
                , ctx->target_process_pid, to_int(ctx->stage())
            );
            restore(info, ctx->host);
            if (ctx->is_restored())
            {
                ctx->stage(procdump_stage::finished);
                finish_task(info, ctx);
            }
            return true;
        case procdump_stage::need_suspend:
        case procdump_stage::prepare_minidump:
        case procdump_stage::suspend:
        case procdump_stage::pending:
        case procdump_stage::get_irql:
        case procdump_stage::allocate_pool:
        case procdump_stage::copy_memory:
            PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                "Delayed host process wake up - delay it\n"
                , info->event_uid
                , info->attached_proc_data.pid, info->attached_proc_data.tid
                , ctx->target_process_pid, to_int(ctx->stage())
            );
            delay_execution(info, ctx->host, 500);
            return true;
    }
    return true;
}

bool procdump2::dispatch_target_wakeup(
    drakvuf_trap_info_t* info,
    std::shared_ptr<procdump2_ctx> ctx)
{
    check_stack_marker(info, ctx, ctx->target);
    PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
        "Suspended target process wake up\n"
        , info->event_uid
        , info->attached_proc_data.pid, info->attached_proc_data.tid
        , ctx->target_process_pid, to_int(ctx->stage())
    );
    switch (ctx->stage())
    {
        case procdump_stage::target_awaken:
            if (ctx->is_restored())
            {
                ctx->stage(procdump_stage::finished);
                finish_task(info, ctx);
            }
            return false;
        case procdump_stage::finished:
        case procdump_stage::resume:
            restore(info, ctx->target);
            if (ctx->stage() == procdump_stage::resume)
                ctx->stage(procdump_stage::target_awaken);

            if (ctx->is_restored())
            {
                ctx->stage(procdump_stage::finished);
                finish_task(info, ctx);
            }
            return true;
        case procdump_stage::target_wakeup:
            // TODO Move working thread check into function
            if (this->working_threads.find(ctx->working.ret_tid) !=
                this->working_threads.end())
            {
                // The working thread is active - keep alive
                PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                    "Suspended target process wake up while not finished but "
                    "working thread still active - keep alive\n"
                    , info->event_uid
                    , info->attached_proc_data.pid
                    , info->attached_proc_data.tid
                    , ctx->target_process_pid, to_int(ctx->stage())
                );
                delay_execution(info, ctx->target, 100);
            }
            else
            {
                // The working thread is not active - finish task
                PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                    "Suspended target process wake up while not finished and "
                    "working thread finished - finish the task\n"
                    , info->event_uid
                    , info->attached_proc_data.pid
                    , info->attached_proc_data.tid
                    , ctx->target_process_pid, to_int(ctx->stage())
                );
                restore(info, ctx->target);
                finish_task(info, ctx);
            }
            return true;
        case procdump_stage::need_suspend:
        case procdump_stage::prepare_minidump:
        case procdump_stage::timeout:
            PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                "WARNING! Taraget wakeup don't handle this stage\n"
                , info->event_uid
                , info->attached_proc_data.pid
                , info->attached_proc_data.tid
                , ctx->target_process_pid, to_int(ctx->stage())
            );
        case procdump_stage::suspend:
        case procdump_stage::pending:
        case procdump_stage::get_irql:
        case procdump_stage::allocate_pool:
        case procdump_stage::copy_memory:
            if (ctx->on_target_resuspend())
            {
                PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                    "Suspended target process wake up while not finished "
                    "(retries %d)\n"
                    , info->event_uid
                    , info->attached_proc_data.pid
                    , info->attached_proc_data.tid
                    , ctx->target_process_pid, to_int(ctx->stage())
                    , ctx->target_resuspend_count
                );
                suspend(info, ctx->target_process_base, ctx->target);
            }
            else
            {
                ctx->stage(procdump_stage::target_wakeup);
                dispatch_target_wakeup(info, ctx);
            }
            return true;
    }
    return true;
}

/*****************************************************************************
 *                             Injection helpers                             *
 *****************************************************************************/

void procdump2::allocate_pool(
    drakvuf_trap_info_t* info,
    std::shared_ptr<procdump2_ctx> ctx)
{
    x86_registers_t regs;
    memcpy(&regs, info->regs, sizeof(x86_registers_t));

    std::array<argument, 3> args{};
    init_int_argument(&args[0], 0); // NonPagedPool
    init_int_argument(&args[1], ctx->POOL_SIZE_IN_PAGES * VMI_PS_4KB);
    init_int_argument(&args[2], 0);

    if (!inject_function_call(drakvuf, info, info->trap->cb, &regs, args.data(), args.size(), malloc_va, ctx->working.set_stack_marker()))
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
            "Failed to inject ExAllocatePoolWithTag\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        throw -1;
    }

    ctx->working.ret_pid = info->attached_proc_data.pid;
    ctx->working.ret_rsp = regs.rsp;
    ctx->working.ret_tid = info->attached_proc_data.tid;
    ctx->stage(procdump_stage::allocate_pool);
}

void procdump2::copy_memory(drakvuf_trap_info_t* info,
    std::shared_ptr<procdump2_ctx> ctx, addr_t addr, size_t size)
{
    x86_registers_t regs;
    memcpy(&regs, info->regs, sizeof(x86_registers_t));

    uint64_t read_bytes = 0;
    std::array<argument, 7> args{};
    init_int_argument(&args[0], ctx->target_process_base);
    init_int_argument(&args[1], addr);
    init_int_argument(&args[2], info->attached_proc_data.base_addr);
    init_int_argument(&args[3], ctx->pool);
    init_int_argument(&args[4], size);
    init_int_argument(&args[5], 0); // UserMode (TODO Is this correct?)
    init_struct_argument(&args[6], read_bytes);

    if (!inject_function_call(drakvuf, info, info->trap->cb, &regs, args.data(), args.size(), copy_virt_mem_va, ctx->working.set_stack_marker()))
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
            "Failed to inject MmCopyVirtualMemory\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        throw -1;
    }

    ctx->current_dump_base = addr;
    ctx->current_dump_size = size;
    ctx->current_read_bytes_va = args[6].data_on_stack;
    ctx->working.ret_pid = info->attached_proc_data.pid;
    ctx->working.ret_rsp = regs.rsp;
    ctx->working.ret_tid = info->attached_proc_data.tid;
    ctx->stage(procdump_stage::copy_memory);
}

void procdump2::get_irql(drakvuf_trap_info_t* info, std::shared_ptr<procdump2_ctx> ctx)
{
    x86_registers_t regs;
    memcpy(&regs, info->regs, sizeof(x86_registers_t));

    // TODO We should check if CR8 probing would be sufficient and leave comment here.
    if (!inject_function_call(drakvuf, info, info->trap->cb, &regs, nullptr, 0, current_irql_va, ctx->working.set_stack_marker()))
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
            "Failed to inject KeGetCurrentIrql\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        throw -1;
    }

    ctx->working.ret_pid = info->attached_proc_data.pid;
    ctx->working.ret_rsp = regs.rsp;
    ctx->working.ret_tid = info->attached_proc_data.tid;
    ctx->stage(procdump_stage::get_irql);
}

void procdump2::resume(drakvuf_trap_info_t* info, std::shared_ptr<procdump2_ctx> ctx)
{
    x86_registers_t regs;
    memcpy(&regs, info->regs, sizeof(x86_registers_t));

    std::array<argument, 1> args{};
    init_int_argument(&args[0], ctx->target_process_base);

    if (!inject_function_call(drakvuf, info, info->trap->cb, &regs, args.data(), args.size(), resume_process_va, ctx->working.set_stack_marker()))
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
            "Failed to inject PsResumeProcess\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        throw -1;
    }

    ctx->working.ret_pid = info->attached_proc_data.pid;
    ctx->working.ret_rsp = regs.rsp;
    ctx->working.ret_tid = info->attached_proc_data.tid;
    ctx->stage(procdump_stage::resume);
}

/* Inject PsSuspendProcess for target process.
 *
 * Notes
 *
 * The callee should set the correct state and save registers or
 * leave them as is.
 */
void procdump2::suspend(drakvuf_trap_info_t* info, addr_t target_process_base, return_ctx& ctx)
{
    x86_registers_t regs;
    memcpy(&regs, info->regs, sizeof(x86_registers_t));

    std::array<argument, 1> args{};
    init_int_argument(&args[0], target_process_base);

    if (!inject_function_call(drakvuf, info, info->trap->cb, &regs, args.data(), args.size(), suspend_process_va, ctx.set_stack_marker()))
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] "
            "Failed to inject PsSuspendProcess\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
        );
        throw -1;
    }

    ctx.ret_pid = info->attached_proc_data.pid;
    ctx.ret_rsp = regs.rsp;
    ctx.ret_tid = info->attached_proc_data.tid;
}

void procdump2::delay_execution(drakvuf_trap_info_t* info,
    return_ctx& ctx,
    uint16_t msec)
{
    x86_registers_t regs;
    memcpy(&regs, info->regs, sizeof(x86_registers_t));

    std::array<argument, 3> args{};
    int64_t interval = -10000 * static_cast<int64_t>(msec);

    init_int_argument(&args[0], 0); // KernelMode
    init_int_argument(&args[1], 1); // Alertable
    init_struct_argument(&args[2], interval);

    if (!inject_function_call(drakvuf, info, info->trap->cb, &regs, args.data(), args.size(), delay_execution_va, ctx.set_stack_marker()))
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] "
            "Failed to inject KeDelayExecutionThread\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
        );
        throw -1;
    }

    ctx.ret_pid = info->attached_proc_data.pid;
    ctx.ret_rsp = regs.rsp;
    ctx.ret_tid = info->attached_proc_data.tid;
}

/*****************************************************************************
 *                                 Routines                                  *
 *****************************************************************************/

std::shared_ptr<procdump2_ctx> procdump2::continues_task(drakvuf_trap_info_t* info)
{
    /* If current thread is working one then search for task to continue. */
    if (this->working_threads.find(info->attached_proc_data.tid) !=
        this->working_threads.end())
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] "
            "Search task to continue\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
        );

        for (auto& [pid, ctx]: this->active)
        {
            PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                "Check task if to continue\n"
                , info->event_uid
                , info->attached_proc_data.pid, info->attached_proc_data.tid
                , ctx->target_process_pid, to_int(ctx->stage())
            );
            if (ctx->stage() == procdump_stage::finished)
            {
                PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                    "The task is finished\n"
                    , info->event_uid
                    , info->attached_proc_data.pid, info->attached_proc_data.tid
                    , ctx->target_process_pid, to_int(ctx->stage())
                );
                continue;
            }
            else if (drakvuf_check_return_context(drakvuf, info,
                    ctx->working.ret_pid,
                    ctx->working.ret_tid,
                    ctx->working.ret_rsp))
            {
                PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                    "Found task to continue\n"
                    , info->event_uid
                    , info->attached_proc_data.pid, info->attached_proc_data.tid
                    , ctx->target_process_pid, to_int(ctx->stage())
                );
                ctx->working.ret_rsp = 0;
                /* Restore stack pointer after injection.
                 *
                 * This is crucial because lots of injections could exhaust the
                 * kernel stack.
                 */
                info->regs->rsp = ctx->working.regs.rsp;
                return ctx;
            }
        }

        PRINT_DEBUG("[PROCDUMP] [%d:%d] "
            "Working thread failed to get task to continue.\n"
            , info->attached_proc_data.pid, info->attached_proc_data.tid
        );
    }

    return nullptr;
}

void procdump2::finish_task(drakvuf_trap_info_t* info,
    std::shared_ptr<procdump2_ctx> ctx)
{
    ctx->writer->finish();
    save_file_metadata(ctx, &info->attached_proc_data);
    fmt::print(m_output_format, "procdump", drakvuf, info,
        keyval("TargetPID", fmt::Nval(ctx->target_process_pid)),
        keyval("TargetName", fmt::Qstr(ctx->target_process_name)),
        keyval("DumpReason", fmt::Qstr(ctx->dump_reason)),
        keyval("DumpSize", fmt::Nval(ctx->size)),
        keyval("SN", fmt::Nval(ctx->idx)),
        keyval("Status", fmt::Qstr(ctx->status()))
    );

    this->finished.insert(ctx->target_process_pid);
    if (ctx->pool)
        pools->free(ctx->pool);
    this->active.erase(ctx->target_process_pid);
}

void procdump2::print_dump_exclusion(drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("[PROCDUMP] Skip excluded proces %d (%s)\n"
        , info->attached_proc_data.pid
        , info->attached_proc_data.name
    );
    fmt::print(m_output_format, "procdump_skip", drakvuf, info,
        keyval("Message", fmt::Rstr("Excluded by filter"))
    );
}

std::pair<addr_t, size_t> procdump2::get_memory_region(drakvuf_trap_info_t* info,
    std::shared_ptr<procdump2_ctx> ctx)
{
    if (ctx->vads.empty())
    {
        PRINT_DEBUG("[PROCDUMP] [%d:%d] [%d:%d] "
            "No VADs left\n"
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        return std::make_pair(0, 0);
    }

    auto it = ctx->vads.begin();
    auto vad_start = it->first;
    auto& vad = it->second;
    PRINT_DEBUG("[PROCDUMP] [%d:%d] [%d:%d] "
        "VAD: start %#lx, type %#x, ptes %zu, idx %#x\n"
        , info->attached_proc_data.pid, info->attached_proc_data.tid
        , ctx->target_process_pid, to_int(ctx->stage())
        , vad_start, vad.type, vad.total_number_of_ptes, vad.idx
    );

    auto total_number_of_ptes = vad.total_number_of_ptes;
    // Dump first page of memory-mapped files with signle page request.
    auto max_size = (vad.is_memory_mapped_file && vad.idx == 0)
        ? 1
        : ctx->POOL_SIZE_IN_PAGES;

    uint32_t ptes_to_dump = std::min(total_number_of_ptes - vad.idx, max_size);

    if (!ptes_to_dump)
    {
        PRINT_DEBUG("[PROCDUMP] [%d:%d] [%d:%d] "
            "No PTEs left\n"
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        return std::make_pair(0, 0);
    }
    if (vad.idx + ptes_to_dump > total_number_of_ptes)
    {
        PRINT_DEBUG("[PROCDUMP] [%d:%d] [%d:%d] "
            "PTEs overflow: %#x + %#x > %#lx\n"
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
            , vad.idx, ptes_to_dump, total_number_of_ptes
        );
        return std::make_pair(0, 0);
    }

    addr_t start_addr = vad_start + vad.idx * VMI_PS_4KB;
    auto size = static_cast<size_t>(ptes_to_dump) * VMI_PS_4KB;
    ctx->is_current_memory_mapped_file = vad.is_memory_mapped_file;

    if (vad.idx + ptes_to_dump == total_number_of_ptes)
        ctx->vads.erase(it);
    else
        vad.idx += ptes_to_dump;

    return std::make_pair(start_addr, size);
}

bool procdump2::is_plugin_active()
{
    return !this->active.empty();
}

bool procdump2::is_active_process(vmi_pid_t pid)
{
    // The callback could be called if other thread invokes NtTerminateProcess
    // or as a return path from injected function.
    // In both cases we should not starting process dump again.
    return this->active.find(pid) != this->active.end();
}

bool procdump2::is_process_handled(vmi_pid_t pid)
{
    return this->finished.find(pid) != this->finished.end();
}

static bool dump_mmvad(drakvuf_t drakvuf, mmvad_info_t* mmvad,
    void* callback_data)
{
    uint32_t vad_type = drakvuf_mmvad_type(drakvuf, mmvad);
    auto ctx = static_cast<procdump2_ctx*>(callback_data);
    addr_t vad_start = mmvad->starting_vpn * VMI_PS_4KB;
    uint64_t len_pages = mmvad->ending_vpn - mmvad->starting_vpn + 1;
    uint64_t len_bytes = len_pages * VMI_PS_4KB;

    if (len_bytes > VMI_PS_1GB)
    {
        // TODO Usually this regions contains several committed pages.
        // Save it with MiniDump
        PRINT_DEBUG("[PROCDUMP] [%d:%d] "
            "Warning: VAD (0x%lx; 0x%lx; 0x%lx; 0x%lx) "
            "skipped on size 0x%lx, CommitCharge 0x%lx\n"
            , ctx->target_process_pid, to_int(ctx->stage())
            , mmvad->starting_vpn, mmvad->ending_vpn
            , mmvad->flags, mmvad->flags1, len_bytes
            , drakvuf_mmvad_commit_charge(drakvuf, mmvad, nullptr)
        );
        return false;
    }

    ctx->vads[vad_start] = {vad_type, len_pages, 0, mmvad->file_name_ptr > 0};
    ctx->size += len_bytes;

    return false;
}

bool procdump2::prepare_minidump(drakvuf_trap_info_t* info, std::shared_ptr<procdump2_ctx> ctx)
{
    ctx->stage(procdump_stage::prepare_minidump);
    // Get virtual address space map of the process
    drakvuf_traverse_mmvad(drakvuf, ctx->target_process_base, dump_mmvad, ctx.get());
    if (ctx->vads.empty())
        return false;

    uint32_t time_stamp = g_get_real_time() / G_USEC_PER_SEC;

    bool is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);

    unicode_string_t* csdversion_us = drakvuf_get_process_csdversion(drakvuf, info->attached_proc_data.base_addr);
    std::wstring csdversion;
    if (csdversion_us)
        csdversion = std::wstring(csdversion_us->contents[0], csdversion_us->contents[csdversion_us->length]);

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
            num_cpus,
            win_major,
            win_minor,
            win_build_number,
            vendor,
            version_information,
            feature_information,
            amd_extended_cpu_features,
            csdversion,
            memory_ranges,
    {thread},
    {thread_ctx});

    if (!ctx->writer->append((const uint8_t*)&mdmp, sizeof(mdmp)))
    {
        PRINT_DEBUG("[PROCDUMP] [%d:%d] [%d:%d] "
            "Failed to prepare MiniDump file\n"
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        return false;
    }
    return true;
}

void procdump2::dump_zero_page(std::shared_ptr<procdump2_ctx> ctx)
{
    uint8_t zeros[VMI_PS_4KB] = {};
    ctx->writer->append(zeros, VMI_PS_4KB);
}

void procdump2::read_vm(addr_t dtb,
    std::shared_ptr<procdump2_ctx> ctx,
    size_t size)
{
    vmi_lock_guard vmi(drakvuf);

    ACCESS_CONTEXT(vmi_ctx);
    vmi_ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    vmi_ctx.dtb = dtb;
    vmi_ctx.addr = ctx->pool;
    auto num_pages = size / VMI_PS_4KB;
    auto access_ptrs = new void* [num_pages] { 0 };

    if (VMI_SUCCESS == vmi_mmap_guest(vmi, &vmi_ctx, num_pages, PROT_READ, access_ptrs))
    {
        for (size_t i = 0; i < num_pages; ++i)
        {
            if (access_ptrs[i])
            {
                ctx->writer->append(static_cast<uint8_t*>(access_ptrs[i]), VMI_PS_4KB);
                munmap(access_ptrs[i], VMI_PS_4KB);
            }
            else
                dump_zero_page(ctx);
        }
    }
    else
    {
        // unaccessible page, pad with zeros to ensure proper alignment of the data
        for (size_t i = 0; i < num_pages; ++i)
            dump_zero_page(ctx);
    }

    delete[] access_ptrs;
}

void procdump2::restore(drakvuf_trap_info_t* info, return_ctx& ctx)
{
    drakvuf_vmi_response_set_gpr_registers(drakvuf, info, &ctx.regs, true);
    ctx.restored = true;
}

void procdump2::save_file_metadata(std::shared_ptr<procdump2_ctx> ctx, proc_data_t* proc_data)
{
    FILE* fp = fopen((procdump_dir + "/"s + ctx->data_file_name + ".metadata"s).data(), "w");
    if (!fp)
    {
        PRINT_DEBUG("[PROCDUMP] [%d:%d] [%d:%d] "
            "Failed to open metadata file\n"
            , proc_data->pid, proc_data->tid
            , ctx->target_process_pid, to_int(ctx->stage())
        );
        return;
    }

    json_object* jobj = json_object_new_object();
    json_object_object_add(jobj, "DumpSize", json_object_new_string_fmt("0x%" PRIx64, ctx->size));
    json_object_object_add(jobj, "PID", json_object_new_int(proc_data->pid));
    json_object_object_add(jobj, "PPID", json_object_new_int(proc_data->ppid));
    json_object_object_add(jobj, "ProcessName", json_object_new_string(proc_data->name));
    json_object_object_add(jobj, "TargetPID", json_object_new_int(ctx->target_process_pid));
    json_object_object_add(jobj, "TargetName", json_object_new_string(ctx->target_process_name.data()));
    json_object_object_add(jobj, "Compression", json_object_new_string(use_compression ? "gzip" : "none"));
    json_object_object_add(jobj, "Status", json_object_new_string(ctx->status()));
    json_object_object_add(jobj, "DataFileName", json_object_new_string(ctx->data_file_name.data()));
    json_object_object_add(jobj, "SequenceNumber", json_object_new_int(ctx->idx));

    fprintf(fp, "%s\n", json_object_get_string(jobj));
    fclose(fp);

    json_object_put(jobj);
}

bool procdump2::start_copy_memory(drakvuf_trap_info_t* info, std::shared_ptr<procdump2_ctx> ctx)
{
    if (prepare_minidump(info, ctx))
    {
        auto [base, size] = get_memory_region(info, ctx);
        if (base && size)
        {
            PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
                "Copy memory region [%#lx;%#lx]\n"
                , info->event_uid
                , info->attached_proc_data.pid, info->attached_proc_data.tid
                , ctx->target_process_pid, to_int(ctx->stage())
                , base, size
            );
            copy_memory(info, ctx, base, size);
            return true;
        }
    }

    return false;
}

void procdump2::check_stack_marker(
    drakvuf_trap_info_t* info,
    std::shared_ptr<procdump2_ctx> task,
    return_ctx& stack_holder)
{
    vmi_lock_guard vmi(this->drakvuf);

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = stack_holder.stack_marker_va();
    uint64_t stack_marker;

    if ( VMI_SUCCESS == vmi_read_64(vmi, &ctx, &stack_marker) &&
        stack_marker != stack_holder.stack_marker())
    {
        PRINT_DEBUG("[PROCDUMP] [%8zu] [%d:%d] [%d:%d] "
            "Stack marker check failed at %#lx: "
            "expected %#lx, result %#lx\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , task->target_process_pid, to_int(task->stage())
            , stack_holder.stack_marker_va(), stack_holder.stack_marker()
            , stack_marker
        );
    }
}

static void process_visitor(drakvuf_t drakvuf, addr_t process, void* visitor_ctx)
{
    auto ctx = reinterpret_cast<std::vector<vmi_pid_t>*>(visitor_ctx);

    vmi_pid_t pid = 0;
    if (!drakvuf_get_process_pid(drakvuf, process, &pid))
    {
        PRINT_DEBUG("Failed to get PID of process 0x%" PRIx64 "\n", process);
        return;
    }

    ctx->push_back(pid);
}

std::vector<vmi_pid_t> procdump2::get_running_processes()
{
    std::vector<vmi_pid_t> pids;
    drakvuf_enumerate_processes(drakvuf, process_visitor, &pids);
    return pids;
}
