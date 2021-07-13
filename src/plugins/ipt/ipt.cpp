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
#include <sstream>
#include <inttypes.h>
#include <sys/stat.h>
#include <libvmi/libvmi.h>

#include "ipt.h"
#include "filesystem.hpp"
#include "plugins/output_format.h"
#include "private.h"

namespace
{

uint64_t pack_payload(uint32_t cmd, uint32_t data)
{
    return (static_cast<uint64_t>(cmd) << 32) | data;
}

void emit_ptwrite64(std::ofstream& stream, uint64_t payload)
{
    // ptwrite packet
    stream.put(0x02);
    // no FUP, 8 bytes of payload
    stream.put(0x32);
    stream.write(reinterpret_cast<char*>(&payload), sizeof(payload));
}


event_response_t ipt_cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<ipt>(info);
    auto& vcpu = plugin->vcpus[info->vcpu];

    vcpu.flush(info->regs->vmtrace_pos);

    vcpu.annotate(pack_payload(PTW_CURRENT_CR3, info->regs->cr3));
    vcpu.annotate(pack_payload(PTW_CURRENT_TID, info->proc_data.tid));

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t ipt_catchall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<ipt>(info);
    auto& vcpu = plugin->vcpus[info->vcpu];

    vcpu.flush(info->regs->vmtrace_pos);

    vcpu.annotate(pack_payload(PTW_EVENT_ID, info->event_uid));

    return VMI_EVENT_RESPONSE_NONE;
}

} // unnamed namespace

void ipt_vcpu::annotate(uint64_t payload)
{
    emit_ptwrite64(this->output_stream, payload);
}

void ipt_vcpu::flush(uint64_t offset)
{
    // update last offset
    uint64_t prev = this->last_offset;
    this->last_offset = offset;

    PRINT_DEBUG("[IPT] Flushing vCPU %d offset: %" PRIx64 " last offset: %" PRIx64 "\n",
        id, offset, prev);

    if (!this->output_stream.good())
    {
        throw -1;
    }

    // Cast uint8_t* to char* to satisfy std::ofstream requirements
    // https://stackoverflow.com/questions/16260033/reinterpret-cast-between-char-and-stduint8-t-safe
    auto data = reinterpret_cast<char*>(this->buf);
    if (offset > prev)
    {
        // Normal case, some data was appended to buffer
        this->output_stream.write(data + prev, offset - prev);
    }
    else if (offset < prev)
    {
        // Buffer wrapped - write from last offset to the end of the buffer
        // and then from the beginning to last written packet
        // This assumes that IPT buffer is large enough to not overflow between
        // calls to ipt_annotate
        this->output_stream.write(data + prev, this->size - prev);
        this->output_stream.write(data, offset);
    }
    else
    {
        PRINT_DEBUG("[IPT] flush_ipt_stream() called but no new IPT data is present\n");
        // In theory this should be unreachable, since it's hard to generate
        // no data between events. Handle this, just in case something is wrong
        this->annotate(pack_payload(PTW_ERROR_EMPTY, 0));
    }
}


drakvuf_trap_t* ipt::reg_cr3_trap(drakvuf_t drakvuf, drakvuf_trap_info_t* info, drakvuf_trap_t* trap)
{
    trap->type = REGISTER;
    trap->reg = CR3;

    if (!drakvuf_add_trap(drakvuf, trap))
        return nullptr;

    return trap;
}

drakvuf_trap_t* ipt::reg_catchall_trap(drakvuf_t drakvuf, drakvuf_trap_info_t* info, drakvuf_trap_t* trap)
{
    trap->type = CATCHALL_BREAKPOINT;

    if (!drakvuf_add_trap(drakvuf, trap))
        return nullptr;

    return trap;
}

ipt::ipt(drakvuf_t drakvuf, const ipt_config& config, output_format_t output)
    : pluginex(drakvuf, output)
    , num_vcpus_{0}
    , drakvuf_{drakvuf}
{
    if (!config.ipt_dir)
    {
        PRINT_DEBUG("[IPT] Target directory not provided, not activating IPT plugin\n");
        return;
    }

    auto ipt_dir = std::filesystem::path(config.ipt_dir);
    if (!std::filesystem::is_directory(ipt_dir))
    {
        PRINT_DEBUG("[IPT] Target directory doesn't exist. Creating...\n");
        if (!std::filesystem::create_directory(ipt_dir))
        {
            PRINT_DEBUG("[IPT] Failed to create %s directory\n", ipt_dir.c_str());
            throw -1;
        }
    }

    {
        auto vmi = vmi_lock_guard(drakvuf);
        num_vcpus_ = vmi_get_num_vcpus(vmi);

        // This is a DRAKVUF limitation
        if (num_vcpus_ > MAX_DRAKVUF_VCPU)
        {
            PRINT_DEBUG("[IPT] Only first %d vCPUs will be traced\n", MAX_DRAKVUF_VCPU);
            num_vcpus_ = MAX_DRAKVUF_VCPU;
        }
    }

    // Always trace code branches, traces become kinda boring without them
    // Ret compression may be sometimes problematic to reconstruct, disable it
    uint64_t ipt_flags = DRAKVUF_IPT_BRANCH_EN | DRAKVUF_IPT_DIS_RETC;

    if (config.trace_os)
    {
        PRINT_DEBUG("[IPT] Tracing OS\n");
        ipt_flags |= DRAKVUF_IPT_TRACE_OS;
    }
    if (config.trace_user)
    {
        PRINT_DEBUG("[IPT] Tracing userspace\n");
        ipt_flags |= DRAKVUF_IPT_TRACE_USR;
    }

    for (int i = 0; i < num_vcpus_; i++)
    {
        auto& vcpu = this->vcpus[i];
        vcpu.id = i;
        vcpu.last_offset = 0;
        if (!drakvuf_enable_ipt(drakvuf, i, &vcpu.buf, &vcpu.size, ipt_flags))
        {
            PRINT_DEBUG("[IPT] Failed to enable IPT on vCPU %d\n", i);
            throw -1;
        }

        std::stringstream ss;
        ss << "ipt_stream_vcpu" << i;
        auto stream_path = ipt_dir / ss.str();

        vcpu.output_stream = std::ofstream(stream_path, std::ios::binary);
        if (!vcpu.output_stream.is_open())
        {
            PRINT_DEBUG("Failed to open stream file for vCPU %d\n", i);
            throw -1;
        }
    }


    auto tr1 = register_trap(nullptr, &::ipt_cr3_cb, ipt::reg_cr3_trap, "ipt_cr3", UNLIMITED_TTL);

    if (!tr1)
    {
        PRINT_DEBUG("[IPT] Failed to register CR3 trap");
        throw -1;
    }

    auto tr2 = register_trap(nullptr, &::ipt_catchall_cb, ipt::reg_catchall_trap, "ipt_catchall", UNLIMITED_TTL);

    if (!tr2)
    {
        PRINT_DEBUG("[IPT] Failed to register catchall trap");
        throw -1;
    }
}

ipt::~ipt()
{
    for (int i = 0; i < num_vcpus_; i++)
    {
        drakvuf_disable_ipt(drakvuf_, i);
    }
}
