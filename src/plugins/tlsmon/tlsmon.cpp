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
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <assert.h>
#include <array>
#include <vector>
#include <libdrakvuf/json-util.h>

#include "plugins/output_format.h"
#include "private.h"
#include "tlsmon.h"



struct ssl_generate_master_key_result_t: public call_result_t
{
    addr_t master_key_handle_addr;
    addr_t parameter_list_addr;
    ssl_generate_master_key_result_t(): call_result_t(), master_key_handle_addr(), parameter_list_addr() {}
};


/**
 * Extracts and logs 48-bytes-long master key along with client random which
 * can be then loaded to wireshark to automatically decrypt the TLS traffic.
 */
static
event_response_t ssl_generate_master_key_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    vmi_lock_guard lg(drakvuf);

    auto plugin = get_trap_plugin<tlsmon>(info);
    auto params = get_trap_params<ssl_generate_master_key_result_t>(info);
    if (!params->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    // We first extract master key by tracing down relevant structures starting
    // with master_key_handle.
    addr_t ncrypt_sll_key_addr = 0;
    ctx.addr = params->master_key_handle_addr;
    if (VMI_SUCCESS != vmi_read_addr(lg.vmi, &ctx, &ncrypt_sll_key_addr))
    {
        plugin->destroy_trap(info->trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // master_key_handle points to NCryptSslKey structure.
    tlsmon_priv::__ncrypt_ssl_key_t ncrypt_ssl_key;
    ctx.addr = ncrypt_sll_key_addr;
    if (VMI_SUCCESS != vmi_read(lg.vmi, &ctx, sizeof(ncrypt_ssl_key), &ncrypt_ssl_key, nullptr))
    {
        plugin->destroy_trap(info->trap);
        return VMI_EVENT_RESPONSE_NONE;
    }
    // We can validate that we indeed found NCryptSslKey by checking magic
    // bytes value.
    if (ncrypt_ssl_key.magic != tlsmon_priv::NCRYPT_SSL_KEY_MAGIC_BYTES)
    {
        plugin->destroy_trap(info->trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // NCryptSslKey contains a pointer to SslMasterSecret structure.
    tlsmon_priv::__ssl_master_secret_t master_secret;
    ctx.addr = (addr_t) ncrypt_ssl_key.master_secret;
    if (VMI_SUCCESS != vmi_read(lg.vmi, &ctx, sizeof(master_secret), &master_secret, nullptr))
    {
        plugin->destroy_trap(info->trap);
        return VMI_EVENT_RESPONSE_NONE;
    }
    // Again we can validate that we found SslMasterSecret structure by
    // checking magic bytes.
    if (master_secret.magic != tlsmon_priv::MASTER_SECRET_MAGIC_BYTES)
    {
        plugin->destroy_trap(info->trap);
        return VMI_EVENT_RESPONSE_NONE;
    }


    // Now retrieve client random value. pParameterList points to an array of
    // NCryptBuffer buffers which contains at least client and server random
    // values.
    ctx.addr = params->parameter_list_addr;
    tlsmon_priv::__ncrypt_buffer_desc_t ncrypt_buffer_desc;
    if (VMI_SUCCESS != vmi_read(lg.vmi, &ctx, sizeof(ncrypt_buffer_desc), &ncrypt_buffer_desc, nullptr))
    {
        plugin->destroy_trap(info->trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    std::vector<tlsmon_priv::__ncrypt_buffer_t> ncrypt_buffers = std::vector<tlsmon_priv::__ncrypt_buffer_t>(ncrypt_buffer_desc.cbuffers);
    ctx.addr = (addr_t) ncrypt_buffer_desc.buffers;
    if (VMI_SUCCESS != vmi_read(lg.vmi, &ctx, ncrypt_buffer_desc.cbuffers * sizeof(tlsmon_priv::__ncrypt_buffer_t), ncrypt_buffers.data(), nullptr))
    {
        plugin->destroy_trap(info->trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // Find the buffer containing client random.
    auto it = std::find_if(ncrypt_buffers.begin(), ncrypt_buffers.end(), [&](const auto& e)
    {
        return e.buffer_type == tlsmon_priv::NCRYPTBUFFER_SSL_CLIENT_RANDOM;
    });
    if (it == ncrypt_buffers.end())
    {
        plugin->destroy_trap(info->trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // And finally read it.
    std::array<char, tlsmon_priv::CLIENT_RANDOM_SZ> client_random = std::array<char, tlsmon_priv::CLIENT_RANDOM_SZ>();
    ctx.addr = (addr_t) it->buffer;
    if (VMI_SUCCESS != vmi_read(lg.vmi, &ctx, client_random.size(), client_random.data(), nullptr))
    {
        plugin->destroy_trap(info->trap);
        return VMI_EVENT_RESPONSE_NONE;
    }


    // Output retrieved data in hex format.
    std::string master_key_str = tlsmon_priv::byte2str((unsigned char*)master_secret.master_key, tlsmon_priv::MASTER_KEY_SZ);
    std::string client_random_str = tlsmon_priv::byte2str((unsigned char*)client_random.data(), tlsmon_priv::CLIENT_RANDOM_SZ);
    fmt::print(plugin->m_output_format, "tlsmon", drakvuf, info,
               keyval("client_random", fmt::Qstr(client_random_str)),
               keyval("master_key", fmt::Qstr(master_key_str))
              );

    plugin->destroy_trap(info->trap);
    return VMI_EVENT_RESPONSE_NONE;
}


/**
 * Sets a trap on return from SslGenerateMasterKey function to obtain the
 * calculated master key.
 */
static
event_response_t ssl_generate_master_key_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    tlsmon* plugin = static_cast<tlsmon*>(info->trap->data);

    auto trap = plugin->register_trap<ssl_generate_master_key_result_t>(
                    info,
                    ssl_generate_master_key_ret_cb,
                    breakpoint_by_dtb_searcher(),
                    "SslGenerateMasterKey"
                );
    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto params = get_trap_params<ssl_generate_master_key_result_t>(trap);
    params->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));
    params->master_key_handle_addr = drakvuf_get_function_argument(drakvuf, info, 4);
    params->parameter_list_addr = drakvuf_get_function_argument(drakvuf, info, 7);
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
    drakvuf_request_userhook_on_running_process(drakvuf, lsass_base, "ncrypt.dll", "SslGenerateMasterKey", ssl_generate_master_key_cb, this);
}


tlsmon::tlsmon(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output)
{
    this->hook_lsass(drakvuf);
}


tlsmon::~tlsmon() {}
