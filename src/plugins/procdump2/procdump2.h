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

#ifndef PROCDUMP2_H
#define PROCDUMP2_H

#include <map>
#include <unordered_map>
#include <set>
#include <string>

#include <libvmi/libvmi.h>

#include "plugins/plugins_ex.h"
#include "plugins/private.h"

struct procdump2_config
{
    uint32_t timeout;
    const char* procdump_dir;
    bool compress_procdumps;
    vmi_pid_t dump_process_on_finish;
    bool dump_new_processes_on_finish;
    const char* hal_profile;
    bool disable_kideliverapc_hook;
    bool disable_kedelayexecutionthread_hook;
};

struct procdump2_ctx;
class pool_manager;
struct return_ctx;

class procdump2 : public pluginex
{
public:
    procdump2(drakvuf_t drakvuf, const procdump2_config* config, output_format_t output);
    ~procdump2();
    virtual bool stop_impl() override;

private:
    /* Config */
    uint32_t                                             timeout{0};
    // TODO Use `std::filesystem::path`
    std::string const                                    procdump_dir;
    vmi_pid_t const                                      dump_process_on_finish;
    bool const                                           dump_new_processes_on_finish;
    bool const                                           use_compression{false};

    /* Internal data */
    uint64_t                                             procdumps_count{0};
    std::unique_ptr<pool_manager>                        pools;
    std::map<vmi_pid_t, std::shared_ptr<procdump2_ctx>>  active;
    uint32_t                                             begin_stop_at{0};
    /* Set of finished tasks.
     *
     * Prevents process dump on second call of NtTerminateProcess.
     *
     * kernel32!ExitProcess calls NtTerminateProcess twice with handle 0
     * and 0xffffffff. Thus we should avoid to dumping process's memory on
     * second call.
     *
     * // FIXME Hook process creation and remove from finished list reused PIDs.
     * // TODO Move this long description into README at the end of development.
     */
    std::set<vmi_pid_t> finished;
    /* Set of used working threads.
     *
     * This set is used in dispatcher routines to check if current thread is
     * working thread already. If not then current thread could be used to
     * process new task.
     *
     * // TODO Move this long description into README at the end of development.
     */
    std::set<uint32_t> working_threads;
    /* List of PIDs of running processes on plugin start.
     *
     * Used only with procdump_new_processes_on_finish.
     */
    std::vector<vmi_pid_t> running_processes_on_start;

    /* Hooks */
    std::unique_ptr<libhook::SyscallHook> terminate_process_hook;
    std::unique_ptr<libhook::SyscallHook> deliver_apc_hook;
    std::unique_ptr<libhook::SyscallHook> delay_execution_hook;
    std::unique_ptr<libhook::SyscallHook> clean_process_memory_hook;

    /* VA of functions to be injected */
    addr_t malloc_va{0};
    addr_t suspend_process_va{0};
    addr_t resume_process_va{0};
    addr_t copy_virt_mem_va{0};
    addr_t current_irql_va{0};
    addr_t delay_execution_va{0};

    /* Minidump info */
    // TODO Move to function
    uint32_t                amd_extended_cpu_features{0};
    uint32_t                feature_information{0};
    uint32_t                num_cpus{0};
    uint16_t                win_build_number{0};
    uint16_t                win_major{0};
    uint16_t                win_minor{0};
    std::array<uint32_t, 3> vendor{0};
    uint32_t                version_information{0};

    /* Hook handlers */
    event_response_t deliver_apc_cb(drakvuf_t, drakvuf_trap_info_t*);
    event_response_t terminate_process_cb(drakvuf_t, drakvuf_trap_info_t*);
    event_response_t delay_execution_cb(drakvuf_t, drakvuf_trap_info_t*);
    event_response_t clean_process_memory_cb(drakvuf_t, drakvuf_trap_info_t*);

    /* Dispatchers */
    event_response_t dispatcher(drakvuf_trap_info_t*);
    void dispatch_active(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>);
    bool dispatch_new(drakvuf_trap_info_t*);
    bool dispatch_pending(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>);
    bool dispatch_host_wakeup(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>);
    bool dispatch_target_wakeup(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>);

    /* Injection helpers */
    void allocate_pool(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>);
    void copy_memory(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>, addr_t, size_t);
    void get_irql(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>);
    void resume(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>);
    void suspend(drakvuf_trap_info_t*, addr_t, return_ctx&);
    void delay_execution(drakvuf_trap_info_t*, return_ctx&, uint16_t msec = 100);

    /* Routines */
    void check_stack_marker(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>, return_ctx&);
    std::shared_ptr<procdump2_ctx> continues_task(drakvuf_trap_info_t*);
    /* The function erases task context from "this->active".
     * So be carefull while iterating over it.
     */
    void finish_task(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>);
    std::pair<addr_t, size_t> get_memory_region(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>);
    bool is_active_process(vmi_pid_t pid);
    bool is_process_handled(vmi_pid_t pid);
    bool is_plugin_active();
    bool prepare_minidump(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>);
    void dump_zero_page(std::shared_ptr<procdump2_ctx>);
    void read_vm(addr_t, std::shared_ptr<procdump2_ctx>, size_t);
    void restore(drakvuf_trap_info_t*, return_ctx&);
    void save_file_metadata(std::shared_ptr<procdump2_ctx>, proc_data_t*);
    bool start_copy_memory(drakvuf_trap_info_t*, std::shared_ptr<procdump2_ctx>);
    void start_dump_process(vmi_pid_t pid);
    std::vector<vmi_pid_t> get_running_processes();
};

#endif
