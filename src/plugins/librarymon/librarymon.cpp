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


#include <new>
#include <libdrakvuf/libdrakvuf.h>
#include <libvmi/libvmi.h>
#include "librarymon.h"


static event_response_t load_library_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t thread = drakvuf_get_current_thread(drakvuf, info->vcpu);
    if (!thread)
        return VMI_EVENT_RESPONSE_NONE;

    auto mon = get_trap_plugin<librarymon>(info);
    if (!mon)
        return VMI_EVENT_RESPONSE_NONE;

    unicode_string_t path { 0, 0, 0 };
    unicode_string_t name { 0, 0, 0 };
    unicode_string_t* tmp = nullptr;

    if ((tmp = drakvuf_read_unicode(drakvuf, info, drakvuf_get_function_argument(drakvuf, info, 1))))
        vmi_convert_str_encoding(tmp, &path, "UTF-8");

    vmi_free_unicode_str(tmp);

    if ((tmp = drakvuf_read_unicode(drakvuf, info, drakvuf_get_function_argument(drakvuf, info, 3))))
        vmi_convert_str_encoding(tmp, &name, "UTF-8");

    vmi_free_unicode_str(tmp);
    mon->print_call_info(drakvuf, info, name, path);

    g_free(name.contents);
    g_free(path.contents);
    return VMI_EVENT_RESPONSE_NONE;
}

librarymon::librarymon(drakvuf_t drakvuf, const librarymon_config* c, output_format_t output)
: pluginex(drakvuf, output)
{
    if (!c->ntdll_profile)
    {
        PRINT_DEBUG("Librarymon plugin requires the rekall profile for ntdll.dll!\n");
        return;
    }

    json_object* ntdll_profile = json_object_from_file(c->ntdll_profile);
    if (!ntdll_profile)
    {
        PRINT_DEBUG("Librarymon plugin fails to load rekall profile for ntdll.dll\n");
        return;
    }

    PRINT_DEBUG("Librarymon attempt to setup a trap for \"LdrLoadDll\"\n");
    register_dll_trap(drakvuf, ntdll_profile, "ntdll.dll", "LdrLoadDll", load_library_cb, this);

    PRINT_DEBUG("Librarymon attempt to setup a trap for \"LdrGetDllHandle\"\n");
    register_dll_trap(drakvuf, ntdll_profile, "ntdll.dll", "LdrGetDllHandle", load_library_cb, this);

    json_object_put(ntdll_profile);
    PRINT_DEBUG("[LIBRARYMON] librarymon constructor end.\n");
}

void librarymon::print_call_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const unicode_string_t& name, const unicode_string_t& path)
{
    switch (m_output_format)
    {
        case OUTPUT_CSV:
            printf("librarymon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,\"%s\",\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid, info->trap->name,
                   (name.contents) ? (char*)name.contents : "",
                   (path.contents) ? (char*)path.contents : "");
            break;

        case OUTPUT_KV:
            printf("librarymon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\","
                   "Method=%s,ModuleName=\"%s\",ModulePath=\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   info->trap->name,
                   (name.contents) ? (char*)name.contents : "",
                   (path.contents) ? (char*)path.contents : "");
            break;

        case OUTPUT_JSON:
        {
            char* escaped_pname = drakvuf_escape_str(info->proc_data.name);
            printf( "{"
                    "\"Plugin\" : \"librarymon\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"ProcessName\": %s,"
                    "\"Method\" : \"%s\","
                    "\"ModuleName\" : \"%s\","
                    "\"ModulePath\" : \"%s\""
                    "}\n",
                    UNPACK_TIMEVAL(info->timestamp),
                    info->proc_data.pid, info->proc_data.ppid, escaped_pname, info->trap->name,
                    (name.contents) ? (char*)name.contents : "",
                   (path.contents) ? (char*)path.contents : "");
            g_free(escaped_pname);
            break;
        }
        default:
        case OUTPUT_DEFAULT:
            printf("[LIBRARYMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ", EPROCESS:0x%" PRIx64
                   ", PID:%d, PPID:%d, \"%s\" %s:%" PRIi64 " %s, MODULE_NAME:\"%s\", MODULE_PATH:\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.base_addr,
                   info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid, info->trap->name,
                   (name.contents) ? (char*)name.contents : "",
                   (path.contents) ? (char*)path.contents : "");
            break;
    }
}