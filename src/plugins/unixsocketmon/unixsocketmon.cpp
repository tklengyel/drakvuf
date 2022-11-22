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

#include <libdrakvuf/libdrakvuf.h>
#include <libvmi/libvmi.h>

#include "unixsocketmon.h"
#include "private.h"
#include "plugins/output_format.h"

bool unixsocketmon::get_socket_family_type(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* family_type)
{
    addr_t sock = drakvuf_get_function_argument(drakvuf, info, 1);

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = sock + this->socket_ops
    );

    addr_t ops;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ops))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to read proto_ops from socket struct\n");
        return false;
    }

    ctx.addr = ops + this->proto_ops_family;
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, family_type))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to get socket family type\n");
        return false;
    }

    return true;
}

std::vector<uint8_t> unixsocketmon::get_socket_message(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint64_t* ret_size)
{
    addr_t msghdr = drakvuf_get_function_argument(drakvuf, info, 2);

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    addr_t iovec;
    ctx.addr = msghdr + this->msghdr_msg_iter + this->iov_iter_iov;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &iovec))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to get iovec from msghdr\n");
        return {};
    }

    addr_t buf;
    ctx.addr = iovec + this->iovec_iov_base;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &buf))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to get buffer from iovec struct\n");
        return {};
    }

    uint64_t size;
    ctx.addr = iovec + this->iovec_iov_len;
    if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &size))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to get size of buffer\n");
        return {};
    }

    auto print_size = std::min(size, this->print_max_size);

    std::vector<uint8_t> data(print_size, 0);
    ctx.addr = buf;
    size_t bytes_read;
    if (VMI_FAILURE == vmi_read(vmi, &ctx, print_size, data.data(), &bytes_read))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to read data\n");
        return {};
    }

    data.resize(bytes_read);
    if (ret_size) *ret_size = size;
    return data;
}

event_response_t unixsocketmon::sock_send_msg_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    uint32_t family_type;
    if (!get_socket_family_type(drakvuf, info, &family_type))
        return VMI_EVENT_RESPONSE_NONE;
    auto socket_family_str = socket_family_to_str((socket_family_t)family_type);

    uint64_t size = 0;
    auto message = get_socket_message(drakvuf, info, &size);

    unicode_string_t msg =
    {
        .length = message.size(),
        .contents = message.data(),
        .encoding = "UTF-8"
    };

    unicode_string_t out;
    status_t rc = vmi_convert_str_encoding(&msg, &out, "UTF-8");

    if (VMI_FAILURE == rc)
    {
        fmt::print(this->m_output_format, "unixsocketmon", drakvuf, info,
            keyval("Type", fmt::Rstr(socket_family_str)),
            keyval("Size", fmt::Nval(size)),
            keyval("Value", fmt::BinaryString(message.data(), message.size()))
        );
    }
    else
    {
        fmt::print(this->m_output_format, "unixsocketmon", drakvuf, info,
            keyval("Type", fmt::Rstr(socket_family_str)),
            keyval("Size", fmt::Nval(size)),
            keyval("Value", fmt::Estr(reinterpret_cast<char*>(out.contents)))
        );
    }

    g_free(out.contents);

    return VMI_EVENT_RESPONSE_NONE;
}

unixsocketmon::unixsocketmon(drakvuf_t drakvuf, const unixsocketmon_config* config, output_format_t output)
    :pluginex(drakvuf, output), print_max_size{config->print_max_size}
{
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "socket", "ops", &socket_ops))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to get struct member\n");
        return;
    }

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "proto_ops", "family", &proto_ops_family))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to get proto_ops family\n");
        return;
    }

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "msghdr", "msg_iter", &msghdr_msg_iter))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to get msg_iter\n");
        return;
    }

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "iov_iter", "iov", &iov_iter_iov))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to get iov_iter\n");
        return;
    }

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "iovec", "iov_base", &iovec_iov_base))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to get iov_base\n");
        return;
    }

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "iovec", "iov_len", &iovec_iov_len))
    {
        PRINT_DEBUG("[UNIXSOCKETMON] Failed to get iov_base\n");
        return;
    }

    sockethook = createSyscallHook("sock_sendmsg", &unixsocketmon::sock_send_msg_cb);
}