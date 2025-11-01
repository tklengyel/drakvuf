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

#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>
#include <array>
#include <vector>
#include <libdrakvuf/json-util.h>

#include "plugins/output_format.h"
#include "private.h"
#include "tlsmon.h"


static std::optional<std::string> ssl_get_master_key(
    drakvuf_t drakvuf, drakvuf_trap_info* info, vmi_instance_t vmi, access_context_t ctx
)
{
    tlsmon_priv::ssl_master_secret_t master_secret;

    // We first extract master key by tracing down relevant structures starting with master_key_handle.
    addr_t ncrypt_ssl_key_addr = drakvuf_get_function_argument(drakvuf, info, 2);

    // master_key_handle points to NCryptSslKey structure.
    tlsmon_priv::ncrypt_ssl_key_t ncrypt_ssl_key;
    ctx.addr = ncrypt_ssl_key_addr;
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(ncrypt_ssl_key), &ncrypt_ssl_key, nullptr))
    {
        PRINT_DEBUG("[TLSMON] Can't read NCryptSslKey structure\n");
        return {};
    }

    // We can validate that we indeed found NCryptSslKey by checking magic bytes value.
    if (ncrypt_ssl_key.magic != tlsmon_priv::NCRYPT_SSL_KEY_MAGIC_BYTES)
    {
        PRINT_DEBUG("[TLSMON] Wrong NCryptSslKey magic\n");
        return {};
    }

    // NCryptSslKey contains a pointer to SslMasterSecret structure.
    ctx.addr = (addr_t) ncrypt_ssl_key.master_secret;
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(master_secret), &master_secret, nullptr))
    {
        PRINT_DEBUG("[TLSMON] Can't read SslMasterSecret structure\n");
        return {};
    }

    // Again we can validate that we found SslMasterSecret structure bychecking magic bytes.
    if (master_secret.magic != tlsmon_priv::MASTER_SECRET_MAGIC_BYTES)
    {
        PRINT_DEBUG("[TLSMON] Wrong SslMasterSecret magic\n");
        return {};
    }

    // Output retrieved master secret in hex format.
    std::string master_key_str = tlsmon_priv::byte2str(master_secret.master_key, tlsmon_priv::MASTER_KEY_SZ);
    return master_key_str;
}

static
std::optional< std::vector<tlsmon_priv::ncrypt_buffer_t> > ssl_get_ncrypt_buffers(
    drakvuf_t drakvuf, drakvuf_trap_info* info, vmi_instance_t vmi, access_context_t ctx
)
{
    // Now retrieve client random and server random values. pParameterList points to an array of
    // NCryptBuffer buffers which contains at least client and server random
    // values.
    ctx.addr = drakvuf_get_function_argument(drakvuf, info, 5);
    tlsmon_priv::ncrypt_buffer_desc_t ncrypt_buffer_desc;
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(ncrypt_buffer_desc), &ncrypt_buffer_desc, nullptr))
    {
        PRINT_DEBUG("[TLSMON] Failed to read ncrypt parameter list\n");
        return {};
    }

    size_t ncrypt_buffers_size = ncrypt_buffer_desc.cbuffers;
    if ( ncrypt_buffers_size != 2 )
    {
        PRINT_DEBUG("[TLSMON] Ncrypt parameter list has different size than 2\n");
        return {};
    }

    std::vector<tlsmon_priv::ncrypt_buffer_t> ncrypt_buffers = std::vector<tlsmon_priv::ncrypt_buffer_t>(ncrypt_buffers_size);
    ctx.addr = (addr_t) ncrypt_buffer_desc.buffers;
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, (ncrypt_buffers_size * sizeof(tlsmon_priv::ncrypt_buffer_t)), ncrypt_buffers.data(), nullptr))
    {
        PRINT_DEBUG("[TLSMON] Failed to read ncrypt parameter list buffers\n");
        return {};
    }
    return ncrypt_buffers;
}


/**
 * Sets a trap on return from SslGenerateSessionKeys function to obtain the
 * calculated master key.
 */
static
event_response_t ssl_generate_session_keys_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    auto plugin = static_cast<tlsmon*>(drakvuf_get_extra_from_running_trap(info->trap));
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    auto vmi = vmi_lock_guard(drakvuf);

    auto master_key = ssl_get_master_key(drakvuf, info, vmi, ctx);
    if (!master_key)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto ncrypt_buffers = ssl_get_ncrypt_buffers(drakvuf, info, vmi, ctx);
    if (!ncrypt_buffers)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    // buffer for both ClientRandom and ServerRandom
    std::array<char, tlsmon_priv::CLIENT_RANDOM_SZ> randoms_buffer = std::array<char,  tlsmon_priv::CLIENT_RANDOM_SZ>();

    for (tlsmon_priv::ncrypt_buffer_t ncrypt_buffer_iter: *ncrypt_buffers)
    {
        uint32_t buffer_type = ncrypt_buffer_iter.buffer_type;
        uint32_t size = ncrypt_buffer_iter.cbbuffer;;
        if ( size != tlsmon_priv::CLIENT_RANDOM_SZ )
        {
            PRINT_DEBUG("[TLSMON] Wrong ncrypt buffer size\n");
            continue;
        }

        // read the buffer
        ctx.addr = (addr_t) ncrypt_buffer_iter.buffer;
        if (VMI_SUCCESS != vmi_read(vmi, &ctx, randoms_buffer.size(), randoms_buffer.data(), nullptr))
        {
            PRINT_DEBUG("[TLSMON] Failed to read ncrypt buffer\n");
            continue;
        }
        // convert bytes to string
        std::string client_random_str = tlsmon_priv::byte2str((unsigned char*)randoms_buffer.data(), 32);

        if (buffer_type == tlsmon_priv::NCRYPTBUFFER_SSL_CLIENT_RANDOM)
        {
            fmt::print(plugin->m_output_format, "tlsmon", drakvuf, info,
                keyval("client_random", fmt::Qstr(client_random_str)),
                keyval("master_key", fmt::Qstr(*master_key))
            );
        }
        else if (buffer_type != tlsmon_priv::NCRYPTBUFFER_SSL_SERVER_RANDOM)
        {
            PRINT_DEBUG("[TLSMON] Unknown ncrypt buffer type.\n");
            continue;
        }
    }
    return VMI_EVENT_RESPONSE_NONE;
}


/**
 * Sets a hook on running lsass process. In Windows, processes that want to
 * establish TLS connection with Schannel API, do so by using lsass under the
 * hood. This way, lsass will perform TLS handshake on behalf of the process
 * initiating the connection and secrets will never leave lsass's memory.
 */
void tlsmon::hook_lsass(drakvuf_t drakvuf)
{
    addr_t lsass_base = 0;
    if (!drakvuf_find_process(drakvuf, ~0, "lsass.exe", &lsass_base))
        return;
    drakvuf_request_userhook_on_running_process(drakvuf, lsass_base, "ncrypt.dll", "SslGenerateSessionKeys", ssl_generate_session_keys_cb, this);
}


tlsmon::tlsmon(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output)
{
    if (!drakvuf_are_userhooks_supported(drakvuf))
    {
        PRINT_DEBUG("[TLSMON] Usermode hooking not supported.\n");
        return;
    }

    this->hook_lsass(drakvuf);
}


tlsmon::~tlsmon() {}
