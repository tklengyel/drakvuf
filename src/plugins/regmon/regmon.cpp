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


static event_response_t log_reg_hook( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
                                      addr_t key_handle_addr,
                                      addr_t value_name_addr, bool with_value_name )
{
    if ( key_handle_addr )
    {
        const char* syscall_name = info->trap->name;
        char* key_path = drakvuf_reg_keyhandle_path( drakvuf, info, key_handle_addr, 0 );

        unicode_string_t* value_name_us = drakvuf_read_unicode( drakvuf, info, value_name_addr );
        char const* value_name = (value_name_us && value_name_us->length > 0) ? reinterpret_cast<char const*>(value_name_us->contents) : "(Default)";

        if ( key_path )
        {
            regmon* reg = (regmon*)info->trap->data;

            switch ( reg->format )
            {
                case OUTPUT_CSV:
                    printf("regmon,%" PRIu32 ",0x%" PRIx64 ",%s,%" PRIi64",%s,%s",
                           info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, syscall_name, key_path );
                    if (with_value_name)
                        printf(",%s", value_name);
                    printf("\n");
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[REGMON] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ", EPROCESS:0x%" PRIx64 ", PID:%d, PPID:%d, %s %s:%" PRIi64 " %s:%s",
                           info->vcpu, info->regs->cr3, info->proc_data.base_addr, info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                           USERIDSTR(drakvuf), info->proc_data.userid, syscall_name, key_path );
                    if (with_value_name)
                        printf(",%s", value_name);
                    printf("\n");
                    break;
            }
        }

        if (value_name_us) vmi_free_unicode_str(value_name_us);
        g_free( key_path );

    }

    return 0;
}

static event_response_t log_reg_hook_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    return log_reg_hook( drakvuf, info, info->regs->rcx, 0L, false );
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

    char* key_root_p = drakvuf_reg_keyhandle_path( drakvuf, info, ctx.addr, 0 );

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
                printf("regmon,%" PRIu32 ",0x%" PRIx64 ",%s,%" PRIi64",%s,%s%s%s\n",
                       info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, syscall_name, key_root, key_sep, key_name );
                break;

            default:
            case OUTPUT_DEFAULT:
                printf("[REGMON] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ", EPROCESS:0x%" PRIx64 ", PID:%d, PPID:%d, %s %s:%" PRIi64 " %s:%s%s%s\n",
                       info->vcpu, info->regs->cr3, info->proc_data.base_addr, info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
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
    return log_reg_objattr_hook( drakvuf, info, info->regs->r8 );
}

static event_response_t log_reg_value_hook_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    return log_reg_hook( drakvuf, info, info->regs->rcx, info->regs->rdx, true );
}

static void register_trap( drakvuf_t drakvuf, const char* rekall_profile, const char* syscall_name,
                           drakvuf_trap_t* trap,
                           event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    if ( !drakvuf_get_function_rva( rekall_profile, syscall_name, &trap->breakpoint.rva) ) throw -1;

    trap->name = syscall_name;
    trap->cb   = hook_cb;

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}


regmon::regmon(drakvuf_t drakvuf, const void* config, output_format_t output)
{
    const char* rekall_profile = (const char*)config;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    this->pm = vmi_get_page_mode(vmi, 0);

    drakvuf_release_vmi(drakvuf);

    this->format = output;

    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_OBJECT_ATTRIBUTES", "ObjectName", &this->objattr_name) )
        throw -1;
    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_OBJECT_ATTRIBUTES", "RootDirectory", &this->objattr_root) )
        throw -1;

    assert(sizeof(traps) / sizeof(traps[0]) > 13);
    register_trap(drakvuf, rekall_profile, "NtDeleteKey",            &traps[0], log_reg_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtSetValueKey",          &traps[1], log_reg_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtDeleteValueKey",       &traps[2], log_reg_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtCreateKey",            &traps[3], log_reg_objattr_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtCreateKeyTransacted",  &traps[4], log_reg_objattr_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtEnumerateKey",         &traps[5], log_reg_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtEnumerateValueKey",    &traps[6], log_reg_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtOpenKey",              &traps[7], log_reg_objattr_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtOpenKeyEx",            &traps[8], log_reg_objattr_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtOpenKeyTransacted",    &traps[9], log_reg_objattr_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtOpenKeyTransactedEx",  &traps[10], log_reg_objattr_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtQueryKey",             &traps[11], log_reg_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtQueryMultipleValueKey",&traps[12], log_reg_hook_cb);
    register_trap(drakvuf, rekall_profile, "NtQueryValueKey",        &traps[13], log_reg_value_hook_cb);
}

regmon::~regmon(void) {}

