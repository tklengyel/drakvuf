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

#ifndef PROCDUMP2_PRIVATE_H
#define PROCDUMP2_PRIVATE_H

#include "writer2.h"

using namespace std::string_literals;

using std::string;

class pool_manager
{
public:
    void add(addr_t base)
    {
        if (unused.find(base) != unused.end() ||
            used.find(base) != used.end())
        {
            PRINT_DEBUG("[PROCDUMP] Re-add pool %#lx\n", base);
            throw -1;
        }

        unused.insert(base);
    }

    void free(addr_t base)
    {
        if (used.find(base) == used.end())
        {
            PRINT_DEBUG("[PROCDUMP] Free unused pool %#lx\n", base);
            throw -1;
        }
        used.erase(base);
        unused.insert(base);
    }

    addr_t get()
    {
        if (unused.empty())
            return 0;
        auto it = unused.begin();
        auto base = *it;
        unused.erase(it);
        used.insert(base);
        return base;
    }

private:
    std::set<addr_t> unused;
    std::set<addr_t> used;
};

struct vad_info2
{
    uint32_t type; // TODO Use backed file name instead of type?
    uint64_t total_number_of_ptes;
    uint32_t idx;                       // index in prototype_ptes
};
using vads_t = std::map<addr_t, vad_info2>;

enum class procdump_stage
{
    need_suspend,  // 0
    suspend,       // 1
    pending,       // 2
    get_irql,      // 3
    allocate_pool, // 4
    copy_memory,   // 5
    resume,        // 6
    awaken,        // 7
    finished,      // 8
    invalid        // 9
};

struct return_ctx
{
    vmi_pid_t ret_pid{0};
    addr_t    ret_rsp{0};
    uint32_t  ret_tid{0};
    x86_registers_t regs;
};

// TODO Rename into "task"
// TODO Move stage transition logic here
struct procdump2_ctx
{
    /* Basic context */
    /* For self-terminating process working thread injects PsSuspendProcess.
     * Thus it should remove task.
     */
    bool is_hosted = false;
    /* Processes targeted on analysys finish are not self-terminating neither
     * hosted. So after resuming such a target should be finished.
     */
    bool wait_awaken = true;
    procdump_stage stage{procdump_stage::pending};
    return_ctx host;
    return_ctx target;
    return_ctx working;

    /* Host process info.
     *
     * The process which terminates other process is "host" one.
     * One should suspend such a process and target process.
     * After task finishes one should resume host process. The host process
     * would continue terminating target process.
     */
    addr_t    host_process_base{0};

    /* Target process info.
     *
     * Target process which would be terminated.
     * The process could self terminate. Or it could be terminated by other
     * process (aka "host process").
     *
     * Target process should be suspended to avoid memory modification while
     * processing.
     */
    addr_t    target_process_base{0};
    string    target_process_name;
    vmi_pid_t target_process_pid{0};

    /* Data */
    size_t         current_dump_size{0};
    addr_t         pool{0}; // TODO Use "class pool" here
    const uint64_t POOL_SIZE_IN_PAGES{0x400}; // TODO Move into "class pool"
    size_t         size{0};
    vads_t         vads;

    /* Backup file context */
    string                          data_file_name;
    const uint64_t                  idx{0};
    std::unique_ptr<ProcdumpWriter> writer;

    procdump2_ctx(bool is_hosted,
        addr_t base,
        std::string name,
        vmi_pid_t pid,
        uint64_t idx_,
        std::string procdump_dir,
        bool use_compression)
        : is_hosted(is_hosted)
        , target_process_base(base)
        , target_process_name(name)
        , target_process_pid(pid)
        , idx(idx_)
    {
        data_file_name = "procdump."s + std::to_string(idx);
        writer = ProcdumpWriterFactory::build(
                procdump_dir + "/"s + data_file_name,
                use_compression);
    }
};

#define VAD_TYPE_DLL 2
#define IRQL_DISPATCH_LEVEL 2

enum inject_status
{
    INJECTION_FAILED,
    INJECT_ERASE,
    INJECT_CONTINUE,
};

#endif
