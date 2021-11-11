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

#include <libvmi/libvmi.h>
#include <memory>
#include <stdexcept>
#include <map>

#include "plugins/private.h"
#include <plugins/output_format.h>

#include "envmon.h"
#include "private.h"


namespace
{

struct gdeleter
{
    void operator() (gpointer p)
    {
        g_free(p);
    }
};

using gchar_ptr = std::unique_ptr<gchar, gdeleter>;

}

static const char* extended_name_formats[] =
{
    [NameUnknown]          = "NameUnknown",
    [NameFullyQualifiedDN] = "NameFullyQualifiedDN",
    [NameSamCompatible]    = "NameSamCompatible",
    [NameDisplay]          = "NameDisplay",
    [NameUniqueId]         = "NameUniqueId",
    [NameCanonical]        = "NameCanonical",
    [NameUserPrincipal]    = "NameUserPrincipal",
    [NameCanonicalEx]      = "NameCanonicalEx",
    [NameServicePrincipal] = "NameServicePrincipal",
    [NameDnsDomain]        = "NameDnsDomain",
    [NameGivenName]        = "NameGivenName",
    [NameSurname]          = "NameSurname"
};

static const char* computer_name_formats[] =
{
    [ComputerNameNetBIOS]                   = "NetBIOS",
    [ComputerNameDnsHostname]               = "DnsHostname",
    [ComputerNameDnsDomain]                 = "DnsDomain",
    [ComputerNameDnsFullyQualified]         = "DnsFullyQualified",
    [ComputerNamePhysicalNetBIOS]           = "PhysicalNetBIOS",
    [ComputerNamePhysicalDnsHostname]       = "PhysicalDnsHostname",
    [ComputerNamePhysicalDnsDomain]         = "PhysicalDnsDomain",
    [ComputerNamePhysicalDnsFullyQualified] = "PhysicalDnsFullyQualified"
};

static const std::map<uint64_t, std::string> family_name_formats
{
    { AF_UNSPEC, "AF_UNSPEC"  },
    { AF_INET,   "AF_INET"    },
    { AF_INET6,  "AF_INET6"   }
};

static const std::map<uint64_t, std::string> flags_name_formats
{
    { GAA_FLAG_SKIP_UNICAST,                "GAA_FLAG_SKIP_UNICAST"                 },
    { GAA_FLAG_SKIP_ANYCAST,                "GAA_FLAG_SKIP_ANYCAST"                 },
    { GAA_FLAG_SKIP_MULTICAST,              "GAA_FLAG_SKIP_MULTICAST"               },
    { GAA_FLAG_SKIP_DNS_SERVER,             "GAA_FLAG_SKIP_DNS_SERVER"              },
    { GAA_FLAG_INCLUDE_PREFIX,              "GAA_FLAG_INCLUDE_PREFIX"               },
    { GAA_FLAG_SKIP_FRIENDLY_NAME,          "GAA_FLAG_SKIP_FRIENDLY_NAME"           },
    { GAA_FLAG_INCLUDE_WINS_INFO,           "GAA_FLAG_INCLUDE_WINS_INFO"            },
    { GAA_FLAG_INCLUDE_GATEWAYS,            "GAA_FLAG_INCLUDE_GATEWAYS"             },
    { GAA_FLAG_INCLUDE_ALL_INTERFACES,      "GAA_FLAG_INCLUDE_ALL_INTERFACES"       },
    { GAA_FLAG_INCLUDE_ALL_COMPARTMENTS,    "GAA_FLAG_INCLUDE_ALL_COMPARTMENTS"     },
    { GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER, "GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER"  }
};

static const std::map<uint64_t, std::string> define_dos_device_flags
{
    { DDD_RAW_TARGET_PATH,       "DDD_RAW_TARGET_PATH" },
    { DDD_REMOVE_DEFINITION,     "DDD_REMOVE_DEFINITION" },
    { DDD_EXACT_MATCH_ON_REMOVE, "DDD_EXACT_MATCH_ON_REMOVE" },
    { DDD_NO_BROADCAST_SYSTEM,   "DDD_NO_BROADCAST_SYSTEM" }
};

static event_response_t trap_SspipGetUserName_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto p = get_trap_plugin<envmon>(info);

    addr_t ex_name_fmt = drakvuf_get_function_argument(drakvuf, info, 1);

    const char* ex_name_fmt_str = "<UNKNOWN>";
    if (ex_name_fmt < sizeof(extended_name_formats)/sizeof(extended_name_formats[0]) && extended_name_formats[ex_name_fmt])
        ex_name_fmt_str = extended_name_formats[ex_name_fmt];


    fmt::print(p->m_output_format, "envmon", drakvuf, info,
        keyval("ExtendedNameFormat", fmt::Nval(ex_name_fmt)),
        keyval("ExtendedNameFormatStr", fmt::Qstr(ex_name_fmt_str))
    );
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t trap_DefineDosDeviceW_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto p = get_trap_plugin<envmon>(info);

    const auto flags = print::FieldToString(define_dos_device_flags, std::bitset<64>(drakvuf_get_function_argument(drakvuf, info, 1)));
    addr_t device_name_va = drakvuf_get_function_argument(drakvuf, info, 2);
    addr_t target_path_va = drakvuf_get_function_argument(drakvuf, info, 3);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = device_name_va
    );

    vmi_lock_guard wmi_lock(drakvuf);

    auto device_name_us = drakvuf_read_wchar_string(wmi_lock, &ctx);
    const char* device_name = device_name_us ?
        reinterpret_cast<char*>(device_name_us->contents) :
        "<UNKNOWN>";

    ctx.addr = target_path_va;
    auto target_path_us = drakvuf_read_wchar_string(wmi_lock, &ctx);
    const char* target_path = target_path_us ?
        reinterpret_cast<char*>(target_path_us->contents) :
        "<UNKNOWN>";

    wmi_lock.unlock();

    fmt::print(p->m_output_format, "envmon", drakvuf, info,
        keyval("Flags", fmt::Qstr(flags)),
        keyval("DeviceName", fmt::Qstr(device_name)),
        keyval("TargetPath", fmt::Qstr(target_path))
    );

    vmi_free_unicode_str(device_name_us);
    vmi_free_unicode_str(target_path_us);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t trap_GetComputerNameW_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto p = get_trap_plugin<envmon>(info);

    fmt::print(p->m_output_format, "envmon", drakvuf, info);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t trap_IsNativeVhdBoot_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto p = get_trap_plugin<envmon>(info);

    fmt::print(p->m_output_format, "envmon", drakvuf, info);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t trap_GetComputerNameExW_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto p = get_trap_plugin<envmon>(info);

    // COMPUTER_NAME_FORMAT NameType
    addr_t name_type = drakvuf_get_function_argument(drakvuf, info, 1);

    const char* name_type_str = "<UNKNOWN>";
    if (name_type < ComputerNameMax)
        name_type_str = computer_name_formats[name_type];

    fmt::print(p->m_output_format, "envmon", drakvuf, info,
        keyval("NameType", fmt::Nval(name_type)),
        keyval("NameTypeStr", fmt::Qstr(name_type_str))
    );
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t trap_GetAdaptersAddresses_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto p = get_trap_plugin<envmon>(info);

    const auto family = print::FieldToString(family_name_formats, drakvuf_get_function_argument(drakvuf, info, 1));
    const auto flags  = print::FieldToString(flags_name_formats, std::bitset<64>(drakvuf_get_function_argument(drakvuf, info, 2)));

    if (p->m_output_format == OUTPUT_KV)
    {
        kvfmt::print("envmon", drakvuf, info,
            keyval("Family", fmt::Rstr(family)),
            fmt::Rstr(flags)
        );
    }
    else
    {
        fmt::print(p->m_output_format, "envmon", drakvuf, info,
            keyval("Family", fmt::Qstr(family)),
            keyval("Flags", fmt::Qstr(flags))
        );
    }

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t trap_WNetGetProviderNameW_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto p = get_trap_plugin<envmon>(info);

    const auto net_type = drakvuf_get_function_argument(drakvuf, info, 1);
    fmt::print(p->m_output_format, "envmon", drakvuf, info,
        keyval("NetType", fmt::Nval(net_type))
    );
    return VMI_EVENT_RESPONSE_NONE;
}

static win_ver_t get_win_ver(drakvuf_t drakvuf)
{
    vmi_lock_guard vmi(drakvuf);
    return vmi_get_winver(vmi.vmi);
}

typedef enum
{
    ARCH_X86,
    ARCH_X64,
    ARCH_INVALID,
} arch_t;

static arch_t get_arch(drakvuf_t drakvuf)
{
    switch (drakvuf_get_address_width(drakvuf))
    {
        case 8:
            return ARCH_X64;
        case 4:
            return ARCH_X86;
        default:
            return ARCH_INVALID;
    }
}

envmon::envmon(drakvuf_t drakvuf, const envmon_config* c, output_format_t output)
    : pluginex(drakvuf, output)
{
    auto winver = get_win_ver(drakvuf);
    if (!c->sspicli_profile)
    {
        PRINT_DEBUG("envmon plugin requires the JSON debug info profile for sspicli.dll!\n");
        return;
    }

    if (!c->kernel32_profile)
    {
        PRINT_DEBUG("envmon plugin requires the JSON debug ingo profile for kernel32.dll!\n");
        return;
    }

    if (!c->kernelbase_profile)
    {
        PRINT_DEBUG("envmon plugin requires the JSON debug ingo profile for KernelBase.dll!\n");
        return;
    }

    if (ARCH_X64 == get_arch(drakvuf) && !c->wow_kernel32_profile)
    {
        PRINT_DEBUG("envmon plugin requires the JSON debug ingo profile for SysWOW64/kernel32.dll!\n");
        return;
    }

    if (!c->iphlpapi_profile)
    {
        PRINT_DEBUG("envmon plugin requires the JSON debug ingo profile for iphlpapi.dll!\n");
        return;
    }

    if (!c->mpr_profile)
    {
        PRINT_DEBUG("envmon plugin requires the JSON debug ingo profile for mpr.dll!\n");
        return;
    }

    json_object* sspicli_profile = json_object_from_file(c->sspicli_profile);
    if (!sspicli_profile)
    {
        PRINT_DEBUG("envmon plugin fails to load JSON debug ingo profile for sspicli.dll\n");
        return;
    }

    PRINT_DEBUG("envmon attempt to setup a trap for \"sspicli.dll\"\n");
    {
        breakpoint_in_dll_module_searcher bp(sspicli_profile, "sspicli.dll");
        if (!register_trap(nullptr, trap_SspipGetUserName_cb, bp.for_syscall_name("SspipGetUserName")))
            throw -1;
    }
    json_object_put(sspicli_profile);

    json_object* kernelbase_profile = json_object_from_file(c->kernelbase_profile);
    if (!kernelbase_profile)
    {
        PRINT_DEBUG("envmon plugin fails to load JSON debug ingo profile for KernelBase.dll\n");
        throw -1;
    }

    PRINT_DEBUG("envmon attempt to setup a trap for \"kernelbase.dll\"\n");
    {
        breakpoint_in_dll_module_searcher bp(kernelbase_profile, "kernelbase.dll");
        if (!register_trap(nullptr, trap_GetComputerNameExW_cb, bp.for_syscall_name("GetComputerNameExW")))
            throw -1;
    }

    {
        breakpoint_in_dll_module_searcher bp(kernelbase_profile, "kernelbase.dll");
        if (!register_trap(nullptr, trap_DefineDosDeviceW_cb, bp.for_syscall_name("DefineDosDeviceW")))
            throw -1;
    }
    json_object_put(kernelbase_profile);

    json_object* kernel32_profile = json_object_from_file(c->kernel32_profile);
    if (!kernel32_profile)
    {
        PRINT_DEBUG("envmon plugin fails to load JSON debug ingo profile for kernel32.dll\n");
        throw -1;
    }

    PRINT_DEBUG("envmon attempt to setup a trap for \"kernel32.dll\"\n");
    {
        breakpoint_in_dll_module_searcher bp(kernel32_profile, "kernel32.dll");
        if (!register_trap(nullptr, trap_GetComputerNameW_cb, bp.for_syscall_name("GetComputerNameW")))
            throw -1;
    }

    if (VMI_OS_WINDOWS_7 < winver)
    {
        PRINT_DEBUG("envmon attempt to setup a trap for \"kernel32.dll\"\n");
        breakpoint_in_dll_module_searcher bp(kernel32_profile, "kernel32.dll");
        if (!register_trap(nullptr, trap_IsNativeVhdBoot_cb, bp.for_syscall_name("IsNativeVhdBoot")))
            throw -1;
    }
    json_object_put(kernel32_profile);

    if (c->wow_kernel32_profile)
    {
        json_object* wow_kernel32_profile = json_object_from_file(c->wow_kernel32_profile);
        if (!wow_kernel32_profile)
        {
            PRINT_DEBUG("envmon plugin failed to load JSON debug ingo profile for SysWOW64/kernel32.dll\n");
            throw -1;
        }

        if (VMI_OS_WINDOWS_7 < winver)
        {
            PRINT_DEBUG("envmon attempt to setup a trap for \"kernel32.dll\"\n");
            breakpoint_in_dll_module_searcher bp(wow_kernel32_profile, "kernel32.dll", true);
            if (!register_trap(nullptr, trap_IsNativeVhdBoot_cb, bp.for_syscall_name("IsNativeVhdBoot")))
                throw -1;
        }
        json_object_put(wow_kernel32_profile);
    }

    json_object* iphlpapi_profile = json_object_from_file(c->iphlpapi_profile);
    if (!iphlpapi_profile)
    {
        PRINT_DEBUG("envmon plugin fails to load JSON debug ingo profile for iphlpapi.dll\n");
        throw -1;
    }

    PRINT_DEBUG("envmon attempt to setup a trap for \"iphlpapi.dll\"\n");
    {
        breakpoint_in_dll_module_searcher bp(iphlpapi_profile, "iphlpapi.dll");
        if (!register_trap(nullptr, trap_GetAdaptersAddresses_cb, bp.for_syscall_name("GetAdaptersAddresses")))
            throw -1;

    }
    json_object_put(iphlpapi_profile);

    json_object* mpr_profile = json_object_from_file(c->mpr_profile);
    if (!mpr_profile)
    {
        PRINT_DEBUG("envmon plugin fails to load JSON debug ingo profile for mpr.dll\n");
        throw -1;
    }

    PRINT_DEBUG("envmon attempt to setup a trap for \"mpr.dll\"\n");
    {
        breakpoint_in_dll_module_searcher bp(mpr_profile, "mpr.dll");
        if (!register_trap(nullptr, trap_WNetGetProviderNameW_cb, bp.for_syscall_name("WNetGetProviderNameW")))
            throw -1;
    }

    json_object_put(mpr_profile);
}
