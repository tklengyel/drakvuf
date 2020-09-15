/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2020 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be aquired from the author.          *
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

#include <config.h>
#include <array>
#include <inttypes.h>
#include <sys/stat.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <assert.h>
#include <libdrakvuf/json-util.h>
#include <set>

#include "ipt.h"
#include "plugins/output_format.h"
#include "private.h"


/*
 * Dump current IPT logs to disk and annotate them with custom PTWRITE packets
 */
static inline
int annotate_ipt(drakvuf_t drakvuf, ipt* plugin, unsigned int vcpu_id, uint32_t* payloads, size_t num_payloads)
{
    uint64_t offset;
    uint64_t last_offset;
    bool ret = drakvuf_get_ipt_offset(drakvuf, vcpu_id, &offset, &last_offset);
    int fail = 0;

    uint8_t* buf = plugin->vcpus[vcpu_id].buf;
    uint64_t size = plugin->vcpus[vcpu_id].size;
    FILE* fd = plugin->vcpus[vcpu_id].fd;

    if (!ret)
    {
        PRINT_DEBUG("annotate_ipt() failed to get ipt offset for vcpu %d\n", vcpu_id);
        return 0;
    }

    PRINT_DEBUG("annotate_ipt() vCPU: %d IPT_CUR: %llx IPT_LAST: %llx\n", vcpu_id, (unsigned long long)offset, (unsigned long long)last_offset);

    if (offset > last_offset)
    {
        fwrite(buf + last_offset, offset - last_offset, 1, fd);
    }
    else if (offset < last_offset)
    {
        fwrite(buf + last_offset, size - last_offset, 1, fd);
        fwrite(buf, offset, 1, fd);
    }
    else
    {
        PRINT_DEBUG("annotate_ipt() called but no new IPT data is present\n");
        fail = 1;
    }

    uint8_t ptwrite_packet[10] = {0x02, 0x32,};
    uint32_t x1 = PTW_ERROR_EMPTY;
    uint32_t x2 = 0;

    for (size_t i = 0; i < num_payloads && !fail; i++)
    {
        x1 = payloads[(i * 2) + 1];
        x2 = payloads[i * 2];

        memcpy(&ptwrite_packet[2], &x1, sizeof(uint32_t));
        memcpy(&ptwrite_packet[6], &x2, sizeof(uint32_t));
        fwrite(ptwrite_packet, 10, 1, fd);
    }

    if (fail)
    {
        x1 = PTW_ERROR_EMPTY;
        x2 = 0;

        memcpy(&ptwrite_packet[2], &x1, sizeof(uint32_t));
        memcpy(&ptwrite_packet[6], &x2, sizeof(uint32_t));
        fwrite(ptwrite_packet, 10, 1, fd);
    }

    return 1;
}

struct exec_fault_data
{
    ipt* plugin;
    addr_t rip;
};

struct access_fault_result_t: public call_result_t
{
    access_fault_result_t() : call_result_t(), fault_va() {}

    addr_t fault_va;
};

static event_response_t execute_faulted_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct exec_fault_data* ef_data = (struct exec_fault_data*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = ef_data->rip
    };

    size_t bytes_read = 0;
    uint8_t pagebuf[4096] = {0,};

    vmi_read(vmi, &ctx, 4096, pagebuf, &bytes_read);

    std::stringstream ss;
    ss << ef_data->plugin->ipt_dir;
    ss << "/frames/frame_";
    ss << std::setfill('0') << std::setw(5) << ef_data->plugin->frame_num;

    std::string frame_fn = ss.str();

    FILE* fp = fopen(frame_fn.c_str(), "wb");

    if (!fp)
    {
        PRINT_DEBUG("[IPT] Frame save path not accessible: %s\n", frame_fn.c_str());
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    fwrite(pagebuf, 1, bytes_read, fp);
    fclose(fp);

    uint64_t tsc = __rdtsc();

    mmvad_info_t mmvad;
    unicode_string_t* dll_name = nullptr;
    char* dll_name_str = nullptr;
    char missing_dll_name[] = "(null)";

    addr_t base_va = 0;
    addr_t end_va = 0;

    if (drakvuf_find_mmvad(drakvuf, info->proc_data.base_addr, ef_data->rip, &mmvad))
    {
        dll_name = drakvuf_read_unicode_va(vmi, mmvad.file_name_ptr, 0);
        dll_name_str = dll_name != nullptr ? (char*)dll_name->contents : nullptr;

        base_va = mmvad.starting_vpn << 12;
        end_va = ((mmvad.ending_vpn + 1) << 12) - 1;
    }

    if (!dll_name_str)
        dll_name_str = missing_dll_name;

    jsonfmt::print("execframe", drakvuf, info,
                   keyval("FrameFile", fmt::Qstr(frame_fn.c_str())),
                   keyval("FrameVA", fmt::Xval(ef_data->rip)),
                   keyval("TrapPA", fmt::Xval(info->trap_pa)),
                   keyval("CR3", fmt::Xval(info->regs->cr3)),
                   keyval("TSC", fmt::Nval(tsc)),
                   keyval("VADName", fmt::Qstr(dll_name_str)),
                   keyval("VADBase", fmt::Xval(base_va)),
                   keyval("VADEnd", fmt::Xval(end_va))
                  );

    if (dll_name)
        vmi_free_unicode_str(dll_name);

    ef_data->plugin->frame_num++;

    PRINT_DEBUG("[IPT] Caught X on PA 0x%lx, frame VA %llx, CR3 %lx\n", info->trap_pa, (unsigned long long)info->regs->rip, info->regs->cr3);

    drakvuf_release_vmi(drakvuf);

    drakvuf_remove_trap(drakvuf, info->trap, nullptr);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t mm_access_fault_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<ipt>(info);
    auto params = get_trap_params<access_fault_result_t>(info);

    if (!params->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    page_info_t p_info = {};
    if (VMI_SUCCESS != vmi_pagetable_lookup_extended(vmi, info->regs->cr3, params->fault_va, &p_info))
    {
        PRINT_DEBUG("[MEMDUMP] failed to lookup page info\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    jsonfmt::print("pagefault", drakvuf, info,
                   keyval("CR3", fmt::Xval(info->regs->cr3)),
                   keyval("VA", fmt::Xval(params->fault_va)),
                   keyval("PA", fmt::Xval(p_info.paddr))
                  );

    struct exec_fault_data* ef_data = (struct exec_fault_data*)malloc(sizeof(struct exec_fault_data));
    ef_data->plugin = plugin;
    ef_data->rip = ((params->fault_va >> 12) << 12);
    drakvuf_trap_t* exec_trap = (drakvuf_trap_t*)malloc(sizeof(drakvuf_trap_t));

    exec_trap->type = MEMACCESS;
    exec_trap->memaccess.gfn = p_info.paddr >> 12;
    exec_trap->memaccess.type = PRE;
    exec_trap->memaccess.access = VMI_MEMACCESS_X;
    exec_trap->data = ef_data; // FIXME memleak
    exec_trap->cb = execute_faulted_cb;
    exec_trap->name = nullptr;

    drakvuf_add_trap(drakvuf, exec_trap);
    PRINT_DEBUG("[IPT] Trap X on GFN 0x%lx\n", p_info.paddr >> 12);

    drakvuf_release_vmi(drakvuf);

    plugin->destroy_trap(info->trap);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t mm_access_fault_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t fault_va = drakvuf_get_function_argument(drakvuf, info, 2);
    PRINT_DEBUG("[IPT] MmAccessFault(%d, %lx)\n", info->proc_data.pid, fault_va);

    if (fault_va & (1ULL << 63))
    {
        PRINT_DEBUG("[IPT] Don't trap in kernel %d %lx\n", info->proc_data.pid, fault_va);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto plugin = get_trap_plugin<ipt>(info);

    auto trap = plugin->register_trap<access_fault_result_t>(
                    info,
                    mm_access_fault_return_hook_cb,
                    breakpoint_by_pid_searcher());
    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto params = get_trap_params<access_fault_result_t>(trap);
    params->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));
    params->fault_va = fault_va;

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t ipt_cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint32_t payloads[4] =
    {
        PTW_CURRENT_CR3, (uint32_t) info->regs->cr3,
        PTW_CURRENT_TID, info->proc_data.tid
    };

    annotate_ipt(drakvuf, (ipt*)info->trap->data, info->vcpu, payloads, 2);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t ipt_catchall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint32_t payloads[2] =
    {
        PTW_EVENT_ID, (uint32_t) info->event_uid
    };

    annotate_ipt(drakvuf, (ipt*)info->trap->data, info->vcpu, payloads, 1);
    return VMI_EVENT_RESPONSE_NONE;
}

ipt::ipt(drakvuf_t drakvuf, const ipt_config& c, output_format_t output)
    : pluginex(drakvuf, output)
{
    this->num_vcpus = 0;
    this->ipt_dir = c.ipt_dir;

    if (!this->ipt_dir)
    {
        PRINT_DEBUG("[IPT] Target directory not provided, not activating IPT plugin\n");
        return;
    }

    {
        std::stringstream ss;
        ss << this->ipt_dir;
        ss << "/frames";

        std::string frame_dir = ss.str();

        int res = mkdir(frame_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

        if (res != 0 && errno != EEXIST)
        {
            PRINT_DEBUG("[IPT] Failed to create %s\n", frame_dir.c_str());
            throw -1;
        }
    }

    {
        auto vmi = vmi_lock_guard(drakvuf);
        this->num_vcpus = vmi_get_num_vcpus(vmi);
    }

    if (IPT_MAX_VCPUS < num_vcpus)
    {
        PRINT_DEBUG("[IPT] Too many vCPUs, the excess ones will be not monitored.\n");
        num_vcpus = IPT_MAX_VCPUS;
    }

    for (unsigned int i = 0; i < num_vcpus; i++)
    {
        if (!drakvuf_enable_ipt(drakvuf, i, &this->vcpus[i].buf, &this->vcpus[i].size))
        {
            PRINT_DEBUG("[IPT] Failed to enable IPT on vCPU %d\n", i);
            throw -1;
        }

        std::stringstream ss;
        ss << this->ipt_dir;
        ss << "/ipt_stream_vcpu";
        ss << i;

        this->vcpus[i].fd = fopen(ss.str().c_str(), "wb");

        if (!this->vcpus[i].fd)
        {
            PRINT_DEBUG("[IPT] Failed to create file %s\n", ss.str().c_str());
            throw -1;
        }
    }

    if (!drakvuf_add_trap(drakvuf, &cr3_trap))
    {
        PRINT_DEBUG("Failed to add CR3 trap\n");
        throw -1;
    }

    if (!drakvuf_add_trap(drakvuf, &bp_trap))
    {
        PRINT_DEBUG("Failed to add CATCHALL_BREAKPOINT\n");
        throw -1;
    }

    breakpoint_in_system_process_searcher bp;

    if (!register_trap(nullptr, mm_access_fault_hook_cb, bp.for_syscall_name("MmAccessFault")))
    {
        throw -1;
    }
}

ipt::~ipt()
{
    for (auto& vcpu : this->vcpus)
    {
        if (vcpu.fd)
            fclose(vcpu.fd);
    }
}
