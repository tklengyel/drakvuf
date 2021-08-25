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

using std::string;

enum pool_status
{
    POOL_INVALID,
    POOL_FREE,
    POOL_USED,
};
using pool_status_t = pool_status;
using pool_map_t = std::map<addr_t, int>;

struct vad_info2
{
    uint32_t type; // TODO Use backed file name instead of type?
    uint64_t total_number_of_ptes;
    uint32_t idx;                       // index in prototype_ptes
};
using vads_t = std::map<addr_t, vad_info2>;

static void free_trap(gpointer p)
{
    if ( !p )
        return;

    drakvuf_trap_t* t = (drakvuf_trap_t*)p;
    g_slice_free(drakvuf_trap_t, t);
}

struct procdump2_ctx
{
    /* Basic context */
    drakvuf_trap_t* bp{nullptr};
    drakvuf_t       drakvuf{nullptr};
    procdump2*       plugin{nullptr};

    /* Return context */
    vmi_pid_t ret_pid{0};
    vmi_pid_t ret_ppid{0};
    addr_t    ret_rsp{0};
    uint32_t  ret_tid{0};

    /* Restore state */
    x86_registers_t saved_regs;

    /* Target process info */
    addr_t    target_process_base{0};
    string    target_process_name;
    vmi_pid_t target_process_pid{0};

    /* */
    size_t         current_dump_size{0};
    addr_t         pool{0};
    const uint64_t POOL_SIZE_IN_PAGES{0x400};
    size_t         size{0};
    vads_t         vads;

    /* Backup file context */
    string                          data_file_name;
    const uint64_t                  idx{0};
    std::unique_ptr<ProcdumpWriter> writer;

    procdump2_ctx() = delete;

    procdump2_ctx(drakvuf_t drakvuf_,
        drakvuf_trap_info_t* info,
        procdump2* plugin_,
        uint64_t idx_)
        : drakvuf(drakvuf_)
        , plugin(plugin_)
        , target_process_base(info->attached_proc_data.base_addr)
        , target_process_name(std::string(info->attached_proc_data.name))
        , target_process_pid(info->attached_proc_data.pid)
        , idx(idx_)
    {
        memcpy(&saved_regs, info->regs, sizeof(x86_registers_t));
    }

    procdump2_ctx(drakvuf_t drakvuf_,
        drakvuf_trap_info_t* info,
        procdump2* plugin_,
        addr_t base,
        std::string name,
        vmi_pid_t pid,
        uint64_t idx_)
        : drakvuf(drakvuf_)
        , plugin(plugin_)
        , target_process_base(base)
        , target_process_name(name)
        , target_process_pid(pid)
        , idx(idx_)
    {
        memcpy(&saved_regs, info->regs, sizeof(x86_registers_t));
    }

    procdump2_ctx(drakvuf_t drakvuf_,
        procdump2* plugin_,
        addr_t base,
        std::string name,
        vmi_pid_t pid,
        uint64_t idx_)
        : drakvuf(drakvuf_)
        , plugin(plugin_)
        , target_process_base(base)
        , target_process_name(name)
        , target_process_pid(pid)
        , idx(idx_)
    {
    }

    // TODO Check if we could remove the method
    bool add_trap(drakvuf_trap_info_t* info, event_response_t (*cb)(drakvuf_t, drakvuf_trap_info_t*), addr_t va = 0)
    {
        g_assert(!bp);

        ret_pid = info->attached_proc_data.pid;
        ret_ppid = info->attached_proc_data.ppid;
        ret_tid = info->attached_proc_data.tid;

        // Use `g_slice_new0` here to be able to pass `g_free` into libdrakvuf
        bp = g_slice_new0(drakvuf_trap_t);
        if (!bp)  throw -1;
        bp->ah_cb = nullptr;
        bp->breakpoint.addr = va ? va : info->regs->rip;
        bp->breakpoint.addr_type = ADDR_VA;
        bp->breakpoint.dtb = info->regs->cr3;
        bp->breakpoint.lookup_type = LOOKUP_DTB;
        bp->cb = cb;
        bp->data = this;
        bp->name = "procdump";
        bp->type = BREAKPOINT;
        bp->ttl = UNLIMITED_TTL;
        if (!drakvuf_add_trap(drakvuf, bp))
        {
            PRINT_DEBUG("[PROCDUMP] Failed to setup breakpoint\n");
            return false;
        }
        plugin->breakpoints.insert(bp);
        return true;
    }

    bool add_trap(event_response_t (*cb)(drakvuf_t, drakvuf_trap_info_t*), addr_t va)
    {
        g_assert(!bp);

        bp = g_slice_new0(drakvuf_trap_t);
        if (!bp)  throw -1;
        bp->ah_cb = nullptr;
        bp->breakpoint.addr = va;
        bp->breakpoint.addr_type = ADDR_VA;
        bp->breakpoint.pid = 4;
        bp->breakpoint.lookup_type = LOOKUP_PID;
        bp->cb = cb;
        bp->data = this;
        bp->name = "procdump";
        bp->type = BREAKPOINT;
        bp->ttl = UNLIMITED_TTL;
        if (!drakvuf_add_trap(drakvuf, bp))
        {
            PRINT_DEBUG("[PROCDUMP] Failed to setup breakpoint\n");
            return false;
        }
        plugin->breakpoints.insert(bp);
        return true;
    }

    void remove_trap()
    {
        g_assert(bp);
        auto it = plugin->breakpoints.find(bp);
        g_assert(it != plugin->breakpoints.end());

        plugin->breakpoints.erase(it);
        drakvuf_remove_trap(drakvuf, bp, (drakvuf_trap_free_t)free_trap);
        bp = nullptr;
    }

    ~procdump2_ctx()
    {
        if (bp)
            remove_trap();
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
