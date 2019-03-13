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

#include <libvmi/libvmi.h>
#include <memory>
#include <stdexcept>

#include "plugins/private.h"

#include "envmon.h"
#include "private.h"

namespace
{

typedef event_response_t(*hook_cb_t)(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

struct module_trap_context_t
{
    bool wow;
    const char* module_name;
    const char* function_name;
    addr_t function_rva;
    drakvuf_trap_t* trap;
    event_response_t(*hook_cb)(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
};

typedef enum
{
    ARCH_X86,
    ARCH_X64,
    ARCH_INVALID,
} arch_t;

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

static bool module_trap_visitor(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx)
{
    module_trap_context_t const* data = (module_trap_context_t*)visitor_ctx;

    PRINT_DEBUG("\t[ENVMON] trap_visitor: CR3[0x%lX] pid[0x%X] WoW64[%s] base_name[%s] load_address[0x%lX] full_name[%s]\n",
                module_info->dtb, module_info->pid, module_info->is_wow ? "True" : "False", module_info->base_name->contents, module_info->base_addr, module_info->full_name->contents);

    if (module_info->is_wow != data->wow)
        return false;

    data->trap->breakpoint.module = data->module_name;
    data->trap->breakpoint.pid    = module_info->pid;
    data->trap->breakpoint.addr   = module_info->base_addr + data->function_rva;

    data->trap->name = data->function_name;
    data->trap->cb   = data->hook_cb;

    return drakvuf_add_trap(drakvuf, data->trap);
}

static void register_trap(drakvuf_t drakvuf, json_object* rekall_profile, const char* function_name, bool wow, drakvuf_trap_t* trap, hook_cb_t hook_cb)
{
    module_trap_context_t visitor_ctx;

    visitor_ctx.wow = wow;
    visitor_ctx.module_name = trap->breakpoint.module;
    visitor_ctx.function_name = function_name;
    visitor_ctx.trap = trap;
    visitor_ctx.hook_cb = hook_cb;

    PRINT_DEBUG("[ENVMON] Search for %s'%s!%s'\n", wow ? "WoW64 " : "", trap->breakpoint.module, function_name);

    if (!rekall_get_function_rva(rekall_profile, function_name, &visitor_ctx.function_rva))
    {
        PRINT_DEBUG("[ENVMON] Failed to get function %s address", function_name);
        return;
    }
    if (!drakvuf_enumerate_processes_with_module(drakvuf, trap->breakpoint.module, module_trap_visitor, &visitor_ctx))
    {
        PRINT_DEBUG("[ENVMON] Failed to trap function %s!%s\n", trap->breakpoint.module, function_name);
        return;
    }
}

static event_response_t trap_SspipGetUserName_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    envmon* obj = (envmon*)(info->trap->data);
    addr_t ex_name_fmt = drakvuf_get_function_argument(drakvuf, info, 1);

    const char* ex_name_fmt_str = "<UNKNOWN>";
    if (ex_name_fmt < sizeof(extended_name_formats)/sizeof(extended_name_formats[0]) && extended_name_formats[ex_name_fmt])
        ex_name_fmt_str = extended_name_formats[ex_name_fmt];

    switch (obj->format)
    {
        case OUTPUT_CSV:
            printf("envmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->trap->name);
            printf(",%lu,\"%s\"\n", ex_name_fmt, ex_name_fmt_str);
            break;
        case OUTPUT_KV:
            printf("envmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->trap->name);
            printf(",ExtendedNameFormat=%lu,ExtendedNameFormatStr=\"%s\"\n", ex_name_fmt, ex_name_fmt_str);
            break;
        case OUTPUT_JSON:
        {
            gchar_ptr proc_name(drakvuf_escape_str(info->proc_data.name));
            printf("{"
                   "\"Plugin\" : \"envmon\","
                   "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                   "\"ProcessName\": \"%s\","
                   "\"PID\" : %d,"
                   "\"PPID\": %d,"
                   "\"Method\" : \"%s\","
                   "\"ExtendedNameFormat\" : %lu,"
                   "\"ExtendedNameFormatStr\" : \"%s\""
                   "}\n",
                   UNPACK_TIMEVAL(info->timestamp),
                   proc_name.get(),
                   info->proc_data.pid,
                   info->proc_data.ppid,
                   info->trap->name,
                   ex_name_fmt, ex_name_fmt_str);
            break;
        }
        default:
        case OUTPUT_DEFAULT:
            printf("[ENVMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\":%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->trap->name);
            printf(" EXTENDEDNAMEFORMAT:%lu EXTENDEDNAMEFORMATSTR:\"%s\"\n", ex_name_fmt, ex_name_fmt_str);
            break;
    }
    return 0;
}

static event_response_t trap_GetComputerNameW_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    envmon* obj = (envmon*)(info->trap->data);

    switch (obj->format)
    {
        case OUTPUT_CSV:
            printf("envmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->trap->name);
            break;
        case OUTPUT_KV:
            printf("envmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->trap->name);
            break;
        case OUTPUT_JSON:
        {
            gchar_ptr proc_name(drakvuf_escape_str(info->proc_data.name));
            printf("{"
                   "\"Plugin\" : \"envmon\","
                   "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                   "\"ProcessName\": \"%s\","
                   "\"PID\" : %d,"
                   "\"PPID\": %d,"
                   "\"Method\" : \"%s\""
                   "}\n",
                   UNPACK_TIMEVAL(info->timestamp),
                   proc_name.get(),
                   info->proc_data.pid,
                   info->proc_data.ppid,
                   info->trap->name);
            break;
        }
        default:
        case OUTPUT_DEFAULT:
            printf("[ENVMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\":%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->trap->name);
            break;
    }

    return 0;
}

static event_response_t trap_IsNativeVhdBoot_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    envmon* obj = (envmon*)(info->trap->data);

    switch (obj->format)
    {
        case OUTPUT_CSV:
            printf("envmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->trap->name);
            break;
        case OUTPUT_KV:
            printf("envmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->trap->name);
            break;
        case OUTPUT_JSON:
        {
            gchar_ptr proc_name(drakvuf_escape_str(info->proc_data.name));
            printf("{"
                   "\"Plugin\" : \"envmon\","
                   "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                   "\"ProcessName\": \"%s\","
                   "\"PID\" : %d,"
                   "\"PPID\": %d,"
                   "\"Method\" : \"%s\""
                   "}\n",
                   UNPACK_TIMEVAL(info->timestamp),
                   proc_name.get(),
                   info->proc_data.pid,
                   info->proc_data.ppid,
                   info->trap->name);
            break;
        }
        default:
        case OUTPUT_DEFAULT:
            printf("[ENVMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\":%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->trap->name);
            break;
    }

    return 0;
}

static event_response_t trap_GetComputerNameExW_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    envmon* obj = (envmon*)(info->trap->data);

    // COMPUTER_NAME_FORMAT NameType
    addr_t name_type = drakvuf_get_function_argument(drakvuf, info, 1);

    const char* name_type_str = "<UNKNOWN>";
    if (name_type < ComputerNameMax)
        name_type_str = computer_name_formats[name_type];

    switch (obj->format)
    {
        case OUTPUT_CSV:
            printf("envmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->trap->name);
            printf(",%lu,\"%s\"\n", name_type, name_type_str);
            break;
        case OUTPUT_KV:
            printf("envmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->trap->name);
            printf(",NameType=%lu,NameTypeStr=\"%s\"\n", name_type, name_type_str);
            break;
        case OUTPUT_JSON:
        {
            gchar_ptr proc_name(drakvuf_escape_str(info->proc_data.name));
            printf("{"
                   "\"Plugin\" : \"envmon\","
                   "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                   "\"ProcessName\": \"%s\","
                   "\"PID\" : %d,"
                   "\"PPID\": %d,"
                   "\"Method\" : \"%s\","
                   "\"NameType\" : %lu,"
                   "\"NameTypeStr\" : \"%s\""
                   "}\n",
                   UNPACK_TIMEVAL(info->timestamp),
                   proc_name.get(),
                   info->proc_data.pid,
                   info->proc_data.ppid,
                   info->trap->name,
                   name_type, name_type_str);
            break;
        }
        default:
        case OUTPUT_DEFAULT:
            printf("[ENVMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\":%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->trap->name);
            printf(" NAMETYPE:%lu NAMETYPESTR:\"%s\"\n", name_type, name_type_str);
            break;
    }
    return 0;
}

static win_ver_t get_win_ver(drakvuf_t drakvuf)
{
    vmi_lock_guard vmi(drakvuf);
    return vmi_get_winver(vmi.vmi);
}

static arch_t get_arch(drakvuf_t drakvuf)
{
    vmi_lock_guard vmi(drakvuf);
    switch (vmi_get_address_width(vmi.vmi))
    {
        case 8:
            return ARCH_X64;
        case 4:
            return ARCH_X86;
        default:
            return ARCH_INVALID;
    }
}

envmon::envmon(drakvuf_t drakvuf, const void* config, output_format_t output)
    : format(output)
{
    const envmon_config* c = (const envmon_config*)config;
    auto winver = get_win_ver(drakvuf);

    if (!c->sspicli_profile)
    {
        PRINT_DEBUG("envmon plugin requires the Rekall profile for sspicli.dll!\n");
        return;
    }
    if (!c->kernel32_profile)
    {
        PRINT_DEBUG("envmon plugin requires the Rekall profile for kernel32.dll!\n");
        return;
    }
    if (!c->kernelbase_profile)
    {
        PRINT_DEBUG("envmon plugin requires the Rekall profile for KernelBase.dll!\n");
        return;
    }
    if (ARCH_X64 == get_arch(drakvuf) && !c->wow_kernel32_profile)
    {
        PRINT_DEBUG("envmon plugin requires the Rekall profile for SysWOW64/kernel32.dll!\n");
        return;
    }

    json_object* sspicli_profile = json_object_from_file(c->sspicli_profile);
    if (!sspicli_profile)
    {
        PRINT_DEBUG("envmon plugin fails to load rekall profile for sspicli.dll\n");
        return;
    }
    register_trap(drakvuf, sspicli_profile, "SspipGetUserName", false, &traps[0], trap_SspipGetUserName_cb);
    json_object_put(sspicli_profile);

    json_object* kernelbase_profile = json_object_from_file(c->kernelbase_profile);
    if (!kernelbase_profile)
    {
        PRINT_DEBUG("envmon plugin fails to load rekall profile for KernelBase.dll\n");
        return;
    }
    register_trap(drakvuf, kernelbase_profile, "GetComputerNameExW", false, &traps[1], trap_GetComputerNameExW_cb);
    json_object_put(kernelbase_profile);

    json_object* kernel32_profile = json_object_from_file(c->kernel32_profile);
    if (!kernel32_profile)
    {
        PRINT_DEBUG("envmon plugin fails to load rekall profile for kernel32.dll\n");
        return;
    }
    register_trap(drakvuf, kernel32_profile, "GetComputerNameW", false, &traps[2], trap_GetComputerNameW_cb);
    if (VMI_OS_WINDOWS_7 < winver)
        register_trap(drakvuf, kernel32_profile, "IsNativeVhdBoot", false, &traps[3], trap_IsNativeVhdBoot_cb);

    json_object_put(kernel32_profile);

    if (c->wow_kernel32_profile)
    {
        json_object* wow_kernel32_profile = json_object_from_file(c->wow_kernel32_profile);
        if (!wow_kernel32_profile)
        {
            PRINT_DEBUG("envmon plugin failed to load rekall profile for SysWOW64/kernel32.dll\n");
            return;
        }
        if (VMI_OS_WINDOWS_7 < winver)
            register_trap(drakvuf, wow_kernel32_profile, "IsNativeVhdBoot", true, &traps[4], trap_IsNativeVhdBoot_cb);
        json_object_put(wow_kernel32_profile);
    }

    PRINT_DEBUG("[ENVMON] envmon constructor end.\n");
}
