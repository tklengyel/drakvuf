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
#include <libvmi/libvmi.h>

#include "exmon.h"
#include "plugins/output_format.h"

enum offset
{
    KTRAP_FRAME_EIP,
    KTRAP_FRAME_EAX,
    KTRAP_FRAME_EBX,
    KTRAP_FRAME_ECX,
    KTRAP_FRAME_EDX,
    KTRAP_FRAME_EDI,
    KTRAP_FRAME_ESI,
    KTRAP_FRAME_EBP,
    KTRAP_FRAME_HWESP,
    KTRAP_FRAME_RIP,
    KTRAP_FRAME_RAX,
    KTRAP_FRAME_RBX,
    KTRAP_FRAME_RCX,
    KTRAP_FRAME_RDX,
    KTRAP_FRAME_RSP,
    KTRAP_FRAME_RBP,
    KTRAP_FRAME_RSI,
    KTRAP_FRAME_RDI,
    KTRAP_FRAME_R8,
    KTRAP_FRAME_R9,
    KTRAP_FRAME_R10,
    KTRAP_FRAME_R11,
    __OFFSET_MAX
};

static const char* offset_names[__OFFSET_MAX][2] =
{
    [KTRAP_FRAME_EIP] = {"_KTRAP_FRAME", "Eip"},
    [KTRAP_FRAME_EAX] = {"_KTRAP_FRAME", "Eax"},
    [KTRAP_FRAME_EBX] = {"_KTRAP_FRAME", "Ebx"},
    [KTRAP_FRAME_ECX] = {"_KTRAP_FRAME", "Ecx"},
    [KTRAP_FRAME_EDX] = {"_KTRAP_FRAME", "Edx"},
    [KTRAP_FRAME_EDI] = {"_KTRAP_FRAME", "Edi"},
    [KTRAP_FRAME_ESI] = {"_KTRAP_FRAME", "Esi"},
    [KTRAP_FRAME_EBP] = {"_KTRAP_FRAME", "Ebp"},
    [KTRAP_FRAME_HWESP] = {"_KTRAP_FRAME", "HardwareEsp"},
    [KTRAP_FRAME_RIP] = {"_KTRAP_FRAME", "Rip"},
    [KTRAP_FRAME_RAX] = {"_KTRAP_FRAME", "Rax"},
    [KTRAP_FRAME_RBX] = {"_KTRAP_FRAME", "Rbx"},
    [KTRAP_FRAME_RCX] = {"_KTRAP_FRAME", "Rcx"},
    [KTRAP_FRAME_RDX] = {"_KTRAP_FRAME", "Rdx"},
    [KTRAP_FRAME_RSP] = {"_KTRAP_FRAME", "Rsp"},
    [KTRAP_FRAME_RBP] = {"_KTRAP_FRAME", "Rbp"},
    [KTRAP_FRAME_RSI] = {"_KTRAP_FRAME", "Rsi"},
    [KTRAP_FRAME_RDI] = {"_KTRAP_FRAME", "Rdi"},
    [KTRAP_FRAME_R8] = {"_KTRAP_FRAME", "R8"},
    [KTRAP_FRAME_R9] = {"_KTRAP_FRAME", "R9"},
    [KTRAP_FRAME_R10] = {"_KTRAP_FRAME", "R10"},
    [KTRAP_FRAME_R11] = {"_KTRAP_FRAME", "R11"},
};

static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    exmon* e = (exmon*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    uint32_t first_chance;
    char* trap_frame=(char*)g_try_malloc0(e->ktrap_frame_size);  // Generic pointer that allows addressing byte-aligned offests

    if (!trap_frame)
    {
        printf("[EXMON] Memory allocation failed!\n");
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    std::optional<fmt::Qstr<const char*>> proc_name_opt;

    if (e->pm != VMI_PM_IA32E)
    {
        reg_t exception_record = 0;
        reg_t ptrap_frame = 0;
        reg_t exception_code = 0;
        uint8_t previous_mode;
        uint32_t eip, eax, ebx, ecx, edx, edi, esi, ebp, hwesp;

        ctx.addr = info->regs->rsp+4;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&exception_record) )
            goto done;

        ctx.addr = info->regs->rsp+12;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&ptrap_frame) )
            goto done;

        ctx.addr = info->regs->rsp+16;
        if ( VMI_FAILURE == vmi_read_8(vmi, &ctx, &previous_mode) )
            goto done;

        ctx.addr = info->regs->rsp+20;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &first_chance) )
            goto done;

        ctx.addr = ptrap_frame;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, e->ktrap_frame_size, trap_frame, NULL) )
            goto done;

        ctx.addr = exception_record;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&exception_code) )
            goto done;

        memcpy_s(&eip, sizeof(eip), trap_frame+e->offsets[KTRAP_FRAME_EIP], sizeof(uint32_t));
        memcpy_s(&eax, sizeof(eax), trap_frame+e->offsets[KTRAP_FRAME_EAX], sizeof(uint32_t));
        memcpy_s(&ebx, sizeof(ebx), trap_frame+e->offsets[KTRAP_FRAME_EBX], sizeof(uint32_t));
        memcpy_s(&ecx, sizeof(ecx), trap_frame+e->offsets[KTRAP_FRAME_ECX], sizeof(uint32_t));
        memcpy_s(&edx, sizeof(edx), trap_frame+e->offsets[KTRAP_FRAME_EDX], sizeof(uint32_t));
        memcpy_s(&edi, sizeof(edi), trap_frame+e->offsets[KTRAP_FRAME_EDI], sizeof(uint32_t));
        memcpy_s(&esi, sizeof(esi), trap_frame+e->offsets[KTRAP_FRAME_ESI], sizeof(uint32_t));
        memcpy_s(&ebp, sizeof(ebp), trap_frame+e->offsets[KTRAP_FRAME_EBP], sizeof(uint32_t));
        memcpy_s(&hwesp, sizeof(hwesp), trap_frame+e->offsets[KTRAP_FRAME_HWESP], sizeof(uint32_t));

        if (previous_mode == 1)
            proc_name_opt = fmt::Qstr(info->attached_proc_data.base_addr ? info->attached_proc_data.name : "NOPROC");

        fmt::print(e->format, "exmon", drakvuf, info,
            keyval("RSP", fmt::Xval(info->regs->rsp, false)),
            keyval("ExceptionRecord", fmt::Xval(exception_record)),
            keyval("ExceptionCode", fmt::Xval(exception_code)),
            keyval("FirstChance", fmt::Nval(first_chance)),
            keyval("EIP", fmt::Xval(eip, false)),
            keyval("EAX", fmt::Xval(eax, false)),
            keyval("EBX", fmt::Xval(ebx, false)),
            keyval("ECX", fmt::Xval(ecx, false)),
            keyval("EDX", fmt::Xval(edx, false)),
            keyval("EDI", fmt::Xval(edi, false)),
            keyval("ESI", fmt::Xval(esi, false)),
            keyval("EBP", fmt::Xval(ebp, false)),
            keyval("ESP", fmt::Xval(hwesp, false)),
            keyval("Name", proc_name_opt)
        );
    }
    else
    {
        reg_t exception_record = 0;
        reg_t exception_code = 0;
        uint64_t rip = 0, rax = 0, rbx = 0, rcx = 0, rdx = 0, rsp = 0, rbp = 0, rsi = 0, rdi = 0;
        uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;

        ctx.addr = info->regs->r8;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, e->ktrap_frame_size, trap_frame, NULL) )
            goto done;

        ctx.addr = info->regs->rcx;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&exception_code) )
            goto done;

        ctx.addr = info->regs->rsp+40; // Return address + 32 byte shadow space
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&first_chance) )
            goto done;

        memcpy_s(&rip, sizeof(rip), trap_frame+e->offsets[KTRAP_FRAME_RIP], sizeof(uint64_t));
        memcpy_s(&rax, sizeof(rax), trap_frame+e->offsets[KTRAP_FRAME_RAX], sizeof(uint64_t));
        memcpy_s(&rbx, sizeof(rbx), trap_frame+e->offsets[KTRAP_FRAME_RBX], sizeof(uint64_t));
        memcpy_s(&rcx, sizeof(rcx), trap_frame+e->offsets[KTRAP_FRAME_RCX], sizeof(uint64_t));
        memcpy_s(&rdx, sizeof(rdx), trap_frame+e->offsets[KTRAP_FRAME_RDX], sizeof(uint64_t));
        memcpy_s(&rsp, sizeof(rsp), trap_frame+e->offsets[KTRAP_FRAME_RSP], sizeof(uint64_t));
        memcpy_s(&rbp, sizeof(rbp), trap_frame+e->offsets[KTRAP_FRAME_RBP], sizeof(uint64_t));
        memcpy_s(&rsi, sizeof(rsi), trap_frame+e->offsets[KTRAP_FRAME_RSI], sizeof(uint64_t));
        memcpy_s(&rdi, sizeof(rdi), trap_frame+e->offsets[KTRAP_FRAME_RDI], sizeof(uint64_t));
        memcpy_s(&r8, sizeof(r8), trap_frame+e->offsets[KTRAP_FRAME_R8], sizeof(uint64_t));
        memcpy_s(&r9, sizeof(r9), trap_frame+e->offsets[KTRAP_FRAME_R9], sizeof(uint64_t));
        memcpy_s(&r10, sizeof(r10), trap_frame+e->offsets[KTRAP_FRAME_R10], sizeof(uint64_t));
        memcpy_s(&r11, sizeof(r11), trap_frame+e->offsets[KTRAP_FRAME_R11], sizeof(uint64_t));

        auto previous_mode = info->regs->r9 & 0xfful;
        if (previous_mode == 1)
            proc_name_opt = fmt::Qstr(info->attached_proc_data.base_addr ? info->attached_proc_data.name : "NOPROC");

        exception_record = info->regs->rcx;

        fmt::print(e->format, "exmon", drakvuf, info,
            keyval("RSP", fmt::Nval(info->regs->rsp)),
            keyval("ExceptionRecord", fmt::Xval(exception_record)),
            keyval("ExceptionCode", fmt::Xval(exception_code)),
            keyval("FirstChance", fmt::Nval(first_chance & 1)),
            keyval("RIP", fmt::Xval(rip, false)),
            keyval("RAX", fmt::Xval(rax, false)),
            keyval("RBX", fmt::Xval(rbx, false)),
            keyval("RCX", fmt::Xval(rcx, false)),
            keyval("RDX", fmt::Xval(rdx, false)),
            keyval("RDI", fmt::Xval(rdi, false)),
            keyval("RSI", fmt::Xval(rsi, false)),
            keyval("RBP", fmt::Xval(rbp, false)),
            keyval("RSP", fmt::Xval(rsp, false)),
            keyval("R8", fmt::Xval(r8, false)),
            keyval("R9", fmt::Xval(r9, false)),
            keyval("R10", fmt::Xval(r10, false)),
            keyval("R11", fmt::Xval(r11, false)),
            keyval("Name", proc_name_opt)
        );
    }

done:
    g_free(trap_frame);
    drakvuf_release_vmi(drakvuf);
    return 0;
}

exmon::exmon(drakvuf_t drakvuf, output_format_t output)
    : format{output}
{
    if ( !drakvuf_get_kernel_symbol_rva(drakvuf, "KiDispatchException", &this->trap.breakpoint.rva) )
        throw -1;

    this->trap.cb = cb;
    this->offsets = (addr_t*)g_try_malloc0(__OFFSET_MAX*sizeof(addr_t));
    this->ktrap_frame_size = 0;

    this->pm = drakvuf_get_page_mode(drakvuf);

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, __OFFSET_MAX, this->offsets))
        PRINT_DEBUG("Failed to find all kernel struct member rvas for exmon.\n");

    if ( !drakvuf_get_kernel_struct_size(drakvuf, "_KTRAP_FRAME", &this->ktrap_frame_size) )
    {
        g_free(this->offsets);
        throw -1;
    }

    this->trap.ttl = drakvuf_get_limited_traps_ttl(drakvuf);
    if ( !drakvuf_add_trap(drakvuf, &this->trap) )
    {
        g_free(this->offsets);
        throw -1;
    }
}

exmon::~exmon()
{
    g_free(this->offsets);
}

bool exmon::stop_impl()
{
    return true;
}
