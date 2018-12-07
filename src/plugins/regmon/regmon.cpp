/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
*                                                                         *
* DRAKVUF (C) 2014-2017 Tamas K Lengyel.                                  *
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

#include <glib.h>
#include <config.h>
#include <inttypes.h>
#include <libvmi/x86.h>
#include <assert.h>

#include "../plugins.h"
#include "regmon.h"

#include <vector>
#include <memory>
#include <functional>
#include <cstring>

#define PLUGIN_NAME "[REGMON]"

static event_response_t log_reg_hook( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
                                      addr_t key_handle_addr,
                                      addr_t value_name_addr, bool with_value_name,
                                      unicode_string_t* data_us = nullptr)
{
    if ( key_handle_addr )
    {
        const char* syscall_name = info->trap->name;
        gchar* key_path = drakvuf_reg_keyhandle_path( drakvuf, info, key_handle_addr, 0 );

        unicode_string_t* value_name_us = drakvuf_read_unicode( drakvuf, info, value_name_addr );
        char const* value_name = (value_name_us && value_name_us->length > 0) ? reinterpret_cast<char const*>(value_name_us->contents) : "(Default)";

        if ( key_path )
        {
            regmon* reg = (regmon*)info->trap->data;

            switch ( reg->format )
            {
                case OUTPUT_CSV:
                    printf("regmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%s",
                           UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, syscall_name, key_path );
                    if (with_value_name)
                        printf(",%s", value_name);
                    if (data_us)
                        printf(",\"%s\"", data_us->contents);
                    printf("\n");
                    break;

                case OUTPUT_KV:
                    printf("regmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,Key=\"%s\"",
                           UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                           info->trap->name, key_path);
                    if (with_value_name)
                        printf(",ValueName=\"%s\"", value_name);
                    if (data_us)
                        printf(",Value=\"%s\"", data_us->contents);
                    printf("\n");
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[REGMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ", EPROCESS:0x%" PRIx64 ", PID:%d, PPID:%d, \"%s\" %s:%" PRIi64 " %s:%s",
                           UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.base_addr, info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                           USERIDSTR(drakvuf), info->proc_data.userid, syscall_name, key_path );
                    if (with_value_name)
                        printf(",%s", value_name);
                    if (data_us)
                        printf(", VALUE:\"%s\"", data_us->contents);
                    printf("\n");
                    break;
            }

            if (data_us)
                vmi_free_unicode_str(data_us);
        }

        if (value_name_us) vmi_free_unicode_str(value_name_us);
        g_free( key_path );

    }

    return 0;
}

static event_response_t log_reg_hook_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    addr_t key_handle_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    return log_reg_hook( drakvuf, info, key_handle_addr, 0L, false );
}

static event_response_t log_reg_objattr_hook(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t attr)
{
    if ( !attr )
    {
        return 0;
    }

    const char* syscall_name = info->trap->name;
    regmon* reg = (regmon*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    ctx.addr = attr + reg->objattr_root;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ctx.addr) )
    {
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    gchar* key_root_p = drakvuf_reg_keyhandle_path( drakvuf, info, ctx.addr, 0 );

    ctx.addr = attr + reg->objattr_name;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ctx.addr) )
    {
        g_free(key_root_p);
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    unicode_string_t* us = vmi_read_unicode_str(vmi, &ctx);
    if ( !us )
    {
        g_free(key_root_p);
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    unicode_string_t str2 = { .contents = NULL };

    if (VMI_SUCCESS == vmi_convert_str_encoding(us, &str2, "UTF-8"))
    {
        const char* key_root = key_root_p ?: "";
        const char* key_name = (const char*)str2.contents ?: "";
        const char* key_sep = key_root_p ? "\\" : "";

        switch ( reg->format )
        {
            case OUTPUT_CSV:
                printf("regmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%s%s%s\n",
                       UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, syscall_name, key_root, key_sep, key_name );
                break;

            case OUTPUT_KV:
                printf("regmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,Key=\"%s%s%s\"\n",
                       UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                       info->trap->name, key_root, key_sep, key_name );
                break;

            default:
            case OUTPUT_DEFAULT:
                printf("[REGMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ", EPROCESS:0x%" PRIx64 ", PID:%d, PPID:%d, \"%s\" %s:%" PRIi64 " %s:%s%s%s\n",
                       UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.base_addr, info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                       USERIDSTR(drakvuf), info->proc_data.userid, syscall_name, key_root, key_sep, key_name );
                break;
        }

        g_free(str2.contents);
    }

    g_free(key_root_p);
    vmi_free_unicode_str(us);
    drakvuf_release_vmi(drakvuf);

    return 0;
}

static event_response_t log_reg_objattr_hook_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    return log_reg_objattr_hook( drakvuf, info, objattr_addr );
}

static event_response_t log_reg_value_hook_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    addr_t key_handle_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t value_name_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    return log_reg_hook( drakvuf, info, key_handle_addr, value_name_addr, true );
}

static event_response_t log_reg_set_value_hook_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{

    enum RegistryValueTypes
    {
        REG_NONE = 0
        ,REG_SZ
        ,REG_EXPAND_SZ
        ,REG_BINARY
        ,REG_DWORD
        ,REG_DWORD_LITTLE_ENDIAN = REG_DWORD
        ,REG_DWORD_BIG_ENDIAN
        ,REG_LINK
        ,REG_MULTI_SZ
        ,REG_RESOURCE_LIST
        ,REG_FULL_RESOURCE_DESCRIPTOR
        ,REG_RESOURCE_REQUIREMENTS_LIST
        ,REG_QWORD
        ,REG_QWORD_LITTLE_ENDIAN = REG_QWORD
    };

    addr_t key_handle_addr = drakvuf_get_function_argument(drakvuf, info, 1);

    if (!key_handle_addr)
        return 0;

    addr_t value_name_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    uint32_t type = drakvuf_get_function_argument(drakvuf, info, 4);
    addr_t data_addr = drakvuf_get_function_argument(drakvuf, info, 5);
    uint32_t data_size = drakvuf_get_function_argument(drakvuf, info, 6);

    unicode_string_t* data_us = nullptr;

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = data_addr;

    if ((type == REG_SZ) || (type == REG_LINK) || (type == REG_EXPAND_SZ))
    {
        vmi_lock_guard vmi_lg(drakvuf);
        data_us = drakvuf_read_wchar_string(vmi_lg.vmi, &ctx);
    }
    else
    {
        std::vector<uint8_t> data_bytes(data_size, 0);

        {
            size_t bytes_read = 0;
            vmi_lock_guard vmi_lg(drakvuf);
            vmi_read(vmi_lg.vmi, &ctx, data_size, data_bytes.data(), &bytes_read);

            if (bytes_read != data_size)
            {
                fprintf(stderr, PLUGIN_NAME "  Error, reading data, expected %" PRIu32 " bytes, but actually read %zu \n", data_size, bytes_read );
                return log_reg_hook( drakvuf, info, key_handle_addr, value_name_addr, true, nullptr );
            }
        }

        char** strings;
        size_t number_of_strings = 0;
        const char* spacer;

        data_us = (unicode_string_t*)g_malloc0(sizeof(unicode_string_t));
        data_us->encoding = "UTF-8";

        if (type == REG_MULTI_SZ) // double-zero terminated Unicode strings array
        {
            std::vector< std::unique_ptr<unicode_string_t, std::function<void(unicode_string_t*)>> > multiple_strings;
            multiple_strings.reserve(100); // allocate space for 100 string pointers at once
            {
                vmi_lock_guard vmi_lg(drakvuf);
                ctx.addr = data_addr;
                for (uint32_t i = 0 ; i < data_bytes.size() ; i += 2)
                {
                    uint16_t& value_word = *(reinterpret_cast<uint16_t*>(&data_bytes[i]));
                    const uint32_t value_dword = *(reinterpret_cast<uint32_t*>(&data_bytes[i]));

                    if (value_word == 0)
                    {
                        // Read current wchar string
                        multiple_strings.emplace_back(
                            drakvuf_read_wchar_string(vmi_lg.vmi, &ctx),
                            [](unicode_string_t* p)
                        {
                            vmi_free_unicode_str(p);
                        }
                        );
                        ctx.addr = data_addr + i + 2;
                    }

                    if ((value_dword == 0) && ((i + 4) >= data_bytes.size()))
                        break;
                }
            }

            number_of_strings = multiple_strings.size() + 1;
            strings = (char**)g_malloc0(sizeof(char*) * number_of_strings);

            for (size_t i = 0; i < multiple_strings.size(); ++i)
            {
                size_t quoted_str_len = multiple_strings[i]->length + 3;
                strings[i] = (char*)g_malloc0(quoted_str_len);
                snprintf(strings[i], quoted_str_len, "'%s'", multiple_strings[i]->contents);
            }
            spacer = ",";
        }
        else
        {
            const size_t bytes_an_item = 2;
            number_of_strings = data_bytes.size() + 1;
            strings = (char**)g_malloc0(sizeof(char*) * number_of_strings);

            for (size_t i = 0; i < data_bytes.size(); ++i)
            {
                strings[i] = (char*)g_malloc0(bytes_an_item + 1);
                snprintf(strings[i], bytes_an_item + 1, "%02x", (int)(data_bytes[i] & 0xff));
            }
            spacer = " ";
        }

        data_us->contents = (uint8_t*)g_strjoinv(spacer, strings);
        data_us->length = std::strlen((char*)data_us->contents) + 1;

        for (size_t i = 0; i < number_of_strings; ++i)
            if (strings[i])
                g_free(strings[i]);
        g_free(strings);
    }

    return log_reg_hook( drakvuf, info, key_handle_addr, value_name_addr, true, data_us );
}

static void register_trap( drakvuf_t drakvuf, const char* syscall_name,
                           drakvuf_trap_t* trap,
                           event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    if ( !drakvuf_get_function_rva( drakvuf, syscall_name, &trap->breakpoint.rva) ) throw -1;

    trap->name = syscall_name;
    trap->cb   = hook_cb;

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}


regmon::regmon(drakvuf_t drakvuf, const void* config, output_format_t output)
{
    this->format = output;

    if ( !drakvuf_get_struct_member_rva(drakvuf, "_OBJECT_ATTRIBUTES", "ObjectName", &this->objattr_name) )
        throw -1;
    if ( !drakvuf_get_struct_member_rva(drakvuf, "_OBJECT_ATTRIBUTES", "RootDirectory", &this->objattr_root) )
        throw -1;

    assert(sizeof(traps) / sizeof(traps[0]) > 13);
    register_trap(drakvuf, "NtDeleteKey",            &traps[0], log_reg_hook_cb);
    register_trap(drakvuf, "NtSetValueKey",          &traps[1], log_reg_set_value_hook_cb);
    register_trap(drakvuf, "NtDeleteValueKey",       &traps[2], log_reg_value_hook_cb);
    register_trap(drakvuf, "NtCreateKey",            &traps[3], log_reg_objattr_hook_cb);
    register_trap(drakvuf, "NtCreateKeyTransacted",  &traps[4], log_reg_objattr_hook_cb);
    register_trap(drakvuf, "NtEnumerateKey",         &traps[5], log_reg_hook_cb);
    register_trap(drakvuf, "NtEnumerateValueKey",    &traps[6], log_reg_hook_cb);
    register_trap(drakvuf, "NtOpenKey",              &traps[7], log_reg_objattr_hook_cb);
    register_trap(drakvuf, "NtOpenKeyEx",            &traps[8], log_reg_objattr_hook_cb);
    register_trap(drakvuf, "NtOpenKeyTransacted",    &traps[9], log_reg_objattr_hook_cb);
    register_trap(drakvuf, "NtOpenKeyTransactedEx",  &traps[10], log_reg_objattr_hook_cb);
    register_trap(drakvuf, "NtQueryKey",             &traps[11], log_reg_hook_cb);
    register_trap(drakvuf, "NtQueryMultipleValueKey",&traps[12], log_reg_hook_cb);
    register_trap(drakvuf, "NtQueryValueKey",        &traps[13], log_reg_value_hook_cb);
}

regmon::~regmon(void) {}
