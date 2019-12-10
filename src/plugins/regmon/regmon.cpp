/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
*                                                                         *
* DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                  *
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
#include <string>
#include <sstream>
#include <iomanip>

enum RegistryValueTypes
{
    REG_NONE = 0,
    REG_SZ,
    REG_EXPAND_SZ,
    REG_BINARY,
    REG_DWORD,
    REG_DWORD_LITTLE_ENDIAN = REG_DWORD,
    REG_DWORD_BIG_ENDIAN,
    REG_LINK,
    REG_MULTI_SZ,
    REG_RESOURCE_LIST,
    REG_FULL_RESOURCE_DESCRIPTOR,
    REG_RESOURCE_REQUIREMENTS_LIST,
    REG_QWORD,
    REG_QWORD_LITTLE_ENDIAN = REG_QWORD
};

static void print_registry_call_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, char const* key_name, char const* value_name, char const* value)
{
    regmon* reg = (regmon*)info->trap->data;
    gchar* escaped_pname = NULL;
    gchar* escaped_key = NULL;

    switch ( reg->format )
    {
        case OUTPUT_CSV:
            printf("regmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, info->trap->name, key_name );
            if (value_name)
                printf(",%s", value_name);
            if (value)
                printf(",\"%s\"", value);
            printf("\n");
            break;

        case OUTPUT_KV:
            printf("regmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,Key=\"%s\"",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   info->trap->name, key_name);
            if (value_name)
                printf(",ValueName=\"%s\"", value_name);
            if (value)
                printf(",Value=\"%s\"", value);
            printf("\n");
            break;

        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            escaped_key   = drakvuf_escape_str(key_name);

            printf( "{"
                    "\"Plugin\" : \"regmon\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"ProcessName\": %s,"
                    "\"UserName\": \"%s\","
                    "\"UserId\": %" PRIu64 ","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"Method\" : \"%s\","
                    "\"Key\" : %s",
                    UNPACK_TIMEVAL(info->timestamp),
                    escaped_pname,
                    USERIDSTR(drakvuf), info->proc_data.userid,
                    info->proc_data.pid, info->proc_data.ppid,
                    info->trap->name,
                    escaped_key);
            if (value_name)
            {
                gchar* escaped_vname = drakvuf_escape_str(value_name);
                printf(",\"ValueName\":%s", escaped_vname);
                g_free(escaped_vname);
            }
            if (value)
            {
                gchar* escaped_val = drakvuf_escape_str(value);
                printf(",\"Value\":%s", escaped_val);
                g_free(escaped_val);
            }

            printf("}\n");

            g_free(escaped_key);
            g_free(escaped_pname);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[REGMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ", EPROCESS:0x%" PRIx64 ", PID:%d, PPID:%d, \"%s\" %s:%" PRIi64 " %s:%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.base_addr, info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid, info->trap->name, key_name );
            if (value_name)
                printf(",%s", value_name);
            if (value)
                printf(", VALUE:\"%s\"", value);
            printf("\n");
            break;
    }
}

static event_response_t log_reg_impl( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
                                      uint64_t key_handle,
                                      char const* value_name,
                                      char const* data )
{
    if (!key_handle) return 0;

    gchar* key_path = drakvuf_reg_keyhandle_path( drakvuf, info, key_handle );

    if ( key_path )
        print_registry_call_info(drakvuf, info, key_path, value_name, data);

    g_free( key_path );

    return 0;
}

static char const* get_value_name(unicode_string_t* us)
{
    return (us && us->length > 0) ? reinterpret_cast<char const*>(us->contents) : "(Default)";
}

static event_response_t log_reg_impl( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
                                      uint64_t key_handle,
                                      addr_t value_name_addr, bool with_value_name,
                                      char const* data )
{
    unicode_string_t* value_name_us = nullptr;
    char const* value_name = nullptr;
    if (with_value_name)
    {
        value_name_us = drakvuf_read_unicode(drakvuf, info, value_name_addr);
        value_name = get_value_name(value_name_us);
    }

    auto status = log_reg_impl(drakvuf, info, key_handle, value_name, data);

    if (value_name_us) vmi_free_unicode_str(value_name_us);

    return status;
}

static event_response_t log_reg_key( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
                                     uint64_t key_handle)
{
    return log_reg_impl(drakvuf, info, key_handle, 0L, false, nullptr);
}

static event_response_t log_reg_key_value( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
        uint64_t key_handle, addr_t value_name_addr )
{
    return log_reg_impl(drakvuf, info, key_handle, value_name_addr, true, nullptr);
}

static char* get_key_path_from_attr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t attr)
{
    regmon* reg = (regmon*)info->trap->data;

    if (!attr) return nullptr;

    vmi_lock_guard vmi_lg(drakvuf);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    addr_t key_handle;
    ctx.addr = attr + reg->objattr_root;
    if ( VMI_FAILURE == vmi_read_addr(vmi_lg.vmi, &ctx, &key_handle) )
        return nullptr;

    addr_t key_name_addr;
    ctx.addr = attr + reg->objattr_name;
    if ( VMI_FAILURE == vmi_read_addr(vmi_lg.vmi, &ctx, &key_name_addr) )
        return nullptr;

    gchar* key_root_p = drakvuf_reg_keyhandle_path( drakvuf, info, key_handle );
    unicode_string_t* us = drakvuf_read_unicode( drakvuf, info, key_name_addr );
    if ( !us )
    {
        g_free(key_root_p);
        return nullptr;
    }

    char* key_path = g_strdup_printf("%s%s%s",
                                     key_root_p ?: "",
                                     key_root_p ? "\\" : "",
                                     (const char*)us->contents ?: "");
    g_free(key_root_p);
    vmi_free_unicode_str(us);

    return key_path;
}

static event_response_t log_reg_objattr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t attr)
{
    char* key_path = get_key_path_from_attr(drakvuf, info, attr);

    if (key_path)
        print_registry_call_info(drakvuf, info, key_path, nullptr, nullptr);

    g_free(key_path);

    return 0;
}

static unicode_string_t* get_data_as_string( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
        uint32_t type, addr_t data_addr, size_t data_size )
{
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = data_addr,
    };

    vmi_lock_guard vmi_lg(drakvuf);

    if ((type == REG_SZ) || (type == REG_LINK) || (type == REG_EXPAND_SZ))
        return drakvuf_read_wchar_string(vmi_lg.vmi, &ctx);

    std::vector<uint8_t> data_bytes(data_size, 0);

    size_t bytes_read = 0;
    vmi_read(vmi_lg.vmi, &ctx, data_size, data_bytes.data(), &bytes_read);

    if (bytes_read != data_size)
    {
        PRINT_DEBUG("[REGMON] Error reading data, expected %zu bytes, but actually read %zu\n", data_size, bytes_read);
        return nullptr;
    }

    std::ostringstream rs;

    if (type == REG_MULTI_SZ) // double-zero terminated Unicode strings array
    {
        ctx.addr = data_addr;
        for (size_t i = 0 ; i < data_bytes.size() ; i += 2)
        {
            uint16_t value_word = *(reinterpret_cast<uint16_t*>(&data_bytes[i]));
            uint32_t value_dword = *(reinterpret_cast<uint32_t*>(&data_bytes[i]));

            if (value_word == 0)
            {
                // Read current wchar string
                unicode_string_t* us = drakvuf_read_wchar_string(vmi_lg.vmi, &ctx);
                if (us)
                {
                    rs << "'" << us->contents << "',";
                    vmi_free_unicode_str(us);
                }
                ctx.addr = data_addr + i + 2;
            }

            if ((value_dword == 0) && ((i + 4) >= data_bytes.size()))
                break;
        }
    }
    else
    {
        for (size_t i = 0; i < data_bytes.size(); ++i)
        {
            rs << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data_bytes[i]) << ' ';
        }
    }

    std::string result = rs.str();
    if (!result.empty()) result.erase(result.size() - 1);

    unicode_string_t* data_us = (unicode_string_t*)g_try_malloc0(sizeof(unicode_string_t));
    data_us->encoding = "UTF-8";
    data_us->contents = (uint8_t*)g_strdup(result.c_str());
    data_us->length = result.size() + 1;

    return data_us;
}

static event_response_t log_reg_key_value_data( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
        uint64_t key_handle, addr_t value_name_addr,
        uint32_t type, addr_t data_addr, size_t data_size )
{
    unicode_string_t* data_us = get_data_as_string(drakvuf, info, type, data_addr, data_size);

    if ( !data_us )
        return 0;

    char const* data = (char const*)data_us->contents;
    auto status = log_reg_impl( drakvuf, info, key_handle, value_name_addr, true, data );

    free(data_us->contents);
    free(data_us);

    return status;
}

static event_response_t log_reg_key_value_entries( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
        uint64_t key_handle, addr_t value_entries_addr, size_t value_entries_count )
{
    /*
    typedef struct _KEY_VALUE_ENTRY {
      PUNICODE_STRING ValueName;
      ULONG           DataLength;
      ULONG           DataOffset;
      ULONG           Type;
    } KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;
    */

    bool is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    size_t KEY_VALUE_ENTRY_sizeof = drakvuf_get_address_width(drakvuf) + 3 * sizeof(uint32_t) + (is32bit ? 0 : 4 /*padding*/);

    std::ostringstream ss;
    for (size_t i = 0; i < value_entries_count; ++i)
    {
        vmi_lock_guard vmi_lg(drakvuf);

        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = value_entries_addr + i * KEY_VALUE_ENTRY_sizeof,
        };

        addr_t value_name_addr;
        if ( VMI_FAILURE == vmi_read_addr(vmi_lg.vmi, &ctx, &value_name_addr) )
            continue;

        unicode_string_t* value_name_us = drakvuf_read_unicode(drakvuf, info, value_name_addr);
        char const* value_name = get_value_name(value_name_us);
        ss << value_name << ",";
        if (value_name_us) vmi_free_unicode_str(value_name_us);
    }
    std::string value_names = ss.str();
    if (!value_names.empty()) value_names.erase(value_names.size() - 1);

    return log_reg_impl(drakvuf, info, key_handle, value_names.c_str(), nullptr);
}

static event_response_t delete_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwDeleteKey(
      HANDLE KeyHandle
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    return log_reg_key( drakvuf, info, key_handle );
}

static event_response_t set_value_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwSetValueKey(
      HANDLE          KeyHandle,
      PUNICODE_STRING ValueName,
      ULONG           TitleIndex,
      ULONG           Type,
      PVOID           Data,
      ULONG           DataSize
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t value_name_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    uint32_t type = drakvuf_get_function_argument(drakvuf, info, 4);
    addr_t data_addr = drakvuf_get_function_argument(drakvuf, info, 5);
    uint32_t data_size = drakvuf_get_function_argument(drakvuf, info, 6);
    return log_reg_key_value_data( drakvuf, info, key_handle, value_name_addr, type, data_addr, data_size );
}

static event_response_t delete_value_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwDeleteValueKey(
      HANDLE          KeyHandle,
      PUNICODE_STRING ValueName
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t value_name_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    return log_reg_key_value( drakvuf, info, key_handle, value_name_addr );
}

static event_response_t create_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwCreateKey(
      PHANDLE            KeyHandle,
      ACCESS_MASK        DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      ULONG              TitleIndex,
      PUNICODE_STRING    Class,
      ULONG              CreateOptions,
      PULONG             Disposition
    );
    */
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    return log_reg_objattr( drakvuf, info, objattr_addr );
}

static event_response_t create_key_transacted_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwCreateKeyTransacted(
      PHANDLE            KeyHandle,
      ACCESS_MASK        DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      ULONG              TitleIndex,
      PUNICODE_STRING    Class,
      ULONG              CreateOptions,
      HANDLE             TransactionHandle,
      PULONG             Disposition
    );
    */
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    return log_reg_objattr( drakvuf, info, objattr_addr );
}

static event_response_t enumerate_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwEnumerateKey(
      HANDLE                KeyHandle,
      ULONG                 Index,
      KEY_INFORMATION_CLASS KeyInformationClass,
      PVOID                 KeyInformation,
      ULONG                 Length,
      PULONG                ResultLength
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    return log_reg_key( drakvuf, info, key_handle );
}

static event_response_t enumerate_value_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwEnumerateValueKey(
      HANDLE                      KeyHandle,
      ULONG                       Index,
      KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
      PVOID                       KeyValueInformation,
      ULONG                       Length,
      PULONG                      ResultLength
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    return log_reg_key( drakvuf, info, key_handle );
}

static event_response_t open_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwOpenKey(
      PHANDLE            KeyHandle,
      ACCESS_MASK        DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes
    );
    */
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    return log_reg_objattr( drakvuf, info, objattr_addr );
}

static event_response_t open_key_ex_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwOpenKeyEx(
      PHANDLE            KeyHandle,
      ACCESS_MASK        DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      ULONG              OpenOptions
    );
    */
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    return log_reg_objattr( drakvuf, info, objattr_addr );
}

static event_response_t open_key_transacted_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwOpenKeyTransacted(
      PHANDLE            KeyHandle,
      ACCESS_MASK        DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      HANDLE             TransactionHandle
    );
    */
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    return log_reg_objattr( drakvuf, info, objattr_addr );
}

static event_response_t open_key_transacted_ex_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwOpenKeyTransactedEx(
      PHANDLE            KeyHandle,
      ACCESS_MASK        DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      ULONG              OpenOptions,
      HANDLE             TransactionHandle
    );
    */
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    return log_reg_objattr( drakvuf, info, objattr_addr );
}

static event_response_t query_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwQueryKey(
      HANDLE                KeyHandle,
      KEY_INFORMATION_CLASS KeyInformationClass,
      PVOID                 KeyInformation,
      ULONG                 Length,
      PULONG                ResultLength
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    return log_reg_key( drakvuf, info, key_handle );
}

static event_response_t query_multiple_value_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    __kernel_entry NTSTATUS NtQueryMultipleValueKey(
      HANDLE           KeyHandle,
      PKEY_VALUE_ENTRY ValueEntries,
      ULONG            EntryCount,
      PVOID            ValueBuffer,
      PULONG           BufferLength,
      PULONG           RequiredBufferLength
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t value_entries_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    size_t value_entries_count = drakvuf_get_function_argument(drakvuf, info, 3);
    return log_reg_key_value_entries( drakvuf, info, key_handle, value_entries_addr, value_entries_count );
}

static event_response_t query_value_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwQueryValueKey(
      HANDLE                      KeyHandle,
      PUNICODE_STRING             ValueName,
      KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
      PVOID                       KeyValueInformation,
      ULONG                       Length,
      PULONG                      ResultLength
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t value_name_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    return log_reg_key_value( drakvuf, info, key_handle, value_name_addr );
}

static void register_trap( drakvuf_t drakvuf, const char* syscall_name,
                           drakvuf_trap_t* trap,
                           event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    if ( !drakvuf_get_kernel_symbol_rva( drakvuf, syscall_name, &trap->breakpoint.rva) ) throw -1;

    trap->name = syscall_name;
    trap->cb   = hook_cb;

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}

regmon::regmon(drakvuf_t drakvuf, output_format_t output)
    : format{output}
{
    if ( !drakvuf_get_kernel_struct_member_rva(drakvuf, "_OBJECT_ATTRIBUTES", "ObjectName", &this->objattr_name) )
        throw -1;
    if ( !drakvuf_get_kernel_struct_member_rva(drakvuf, "_OBJECT_ATTRIBUTES", "RootDirectory", &this->objattr_root) )
        throw -1;

    assert(sizeof(traps) / sizeof(traps[0]) > 13);
    register_trap(drakvuf, "NtDeleteKey",            &traps[0],  delete_key_cb);
    register_trap(drakvuf, "NtSetValueKey",          &traps[1],  set_value_key_cb);
    register_trap(drakvuf, "NtDeleteValueKey",       &traps[2],  delete_value_key_cb);
    register_trap(drakvuf, "NtCreateKey",            &traps[3],  create_key_cb);
    register_trap(drakvuf, "NtCreateKeyTransacted",  &traps[4],  create_key_transacted_cb);
    register_trap(drakvuf, "NtEnumerateKey",         &traps[5],  enumerate_key_cb);
    register_trap(drakvuf, "NtEnumerateValueKey",    &traps[6],  enumerate_value_key_cb);
    register_trap(drakvuf, "NtOpenKey",              &traps[7],  open_key_cb);
    register_trap(drakvuf, "NtOpenKeyEx",            &traps[8],  open_key_ex_cb);
    register_trap(drakvuf, "NtOpenKeyTransacted",    &traps[9],  open_key_transacted_cb);
    register_trap(drakvuf, "NtOpenKeyTransactedEx",  &traps[10], open_key_transacted_ex_cb);
    register_trap(drakvuf, "NtQueryKey",             &traps[11], query_key_cb);
    register_trap(drakvuf, "NtQueryMultipleValueKey", &traps[12], query_multiple_value_key_cb);
    register_trap(drakvuf, "NtQueryValueKey",        &traps[13], query_value_key_cb);
}

regmon::~regmon(void) {}
