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

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>
#include "memdump.h"

#define DUMP_NAME_PLACEHOLDER "(not configured)"

// TODO move to common library, this is also used in procmon

/**
 * Dumps the memory specified by access context, from `ctx->addr` (first byte) to `ctx->addr + len_bytes - 1` (last byte).
 * File is stored in a path provided in --memdump-dir command line option and named according to the scheme:
 * <process_pid>_<base_address>_<counter>.dmp
 *
 * For some dumps, a custom structure `extras` may be optionally provided together with `printout_extras` method
 * which will enrich the default data printout.
 */
static bool dump_memory_region(
    drakvuf_t drakvuf,
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    memdump* plugin,
    access_context_t* ctx,
    size_t len_bytes,
    const char* reason,
    void* extras,
    void (*printout_extras)(drakvuf_t drakvuf, output_format_t format, void* extras))
{
    char* file = nullptr;
    const char* display_file = nullptr;
    void** access_ptrs = nullptr;
    FILE* fp = nullptr;
    bool ret = false;

    gchar* escaped_pname = nullptr;
    gchar* escaped_fname = nullptr;

    addr_t input_addr;
    addr_t aligned_addr;
    addr_t intra_page_offset;
    size_t aligned_len;
    size_t len_remainder;
    size_t num_pages;

    plugin->memdump_counter++;

    if (plugin->memdump_dir)
    {
        if (asprintf(&file, "%s/%d-0x%llx-%04d.dmp", plugin->memdump_dir, info->proc_data.pid,
                     (unsigned long long) ctx->addr, plugin->memdump_counter) < 0)
            goto done;

        display_file = (const char*)file;
    }
    else
    {
        // dry run, just print that the dump would be saved
        ret = true;
        display_file = DUMP_NAME_PLACEHOLDER;
        goto printout;
    }

    input_addr = ctx->addr;

    aligned_addr = ctx->addr & ~(VMI_PS_4KB - 1);
    intra_page_offset = ctx->addr & (VMI_PS_4KB - 1);

    aligned_len = len_bytes & ~(VMI_PS_4KB - 1);
    len_remainder = len_bytes & (VMI_PS_4KB - 1);

    if (len_remainder)
    {
        aligned_len += VMI_PS_4KB;
    }

    ctx->addr = aligned_addr;
    num_pages = aligned_len / VMI_PS_4KB;

    access_ptrs = (void**)g_malloc(num_pages * sizeof(void*));

    if (VMI_SUCCESS != vmi_mmap_guest(vmi, ctx, num_pages, access_ptrs))
    {
        PRINT_DEBUG("[MEMDUMP] Failed mmap guest\n");
        goto done;
    }

    fp = fopen(file, "w");

    if (!fp)
    {
        PRINT_DEBUG("[MEMDUMP] Failed to open file\n");
        goto done;
    }

    for (size_t i = 0; i < num_pages; i++)
    {
        // sometimes we are supposed to write less than the whole page
        size_t write_length = len_bytes >= VMI_PS_4KB ? VMI_PS_4KB : len_bytes;

        if (access_ptrs[i])
        {
            fwrite((char*)access_ptrs[i] + intra_page_offset, write_length, 1, fp);
            munmap(access_ptrs[i], VMI_PS_4KB);
        }
        else
        {
            // unaccessible page, pad with zeros to ensure proper alignment of the data
            uint8_t zeros[VMI_PS_4KB] = {};
            fwrite(zeros + intra_page_offset, write_length, 1, fp);
        }

        // this applies only to the first page
        intra_page_offset = 0;
        len_bytes -= write_length;
    }

    fclose(fp);
    ret = true;

printout:
    switch (plugin->m_output_format)
    {
        case OUTPUT_CSV:
            printf("memdump," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",\"%s\",\"%s\",%d,%" PRIx64 ",%" PRIu64 ",\"%s\"",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid, info->trap->name, reason, info->proc_data.pid, ctx->addr, len_bytes, display_file);

            if (printout_extras)
                printout_extras(drakvuf, plugin->m_output_format, extras);
            break;
        case OUTPUT_KV:
            printf("memdump Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,DumpReason=\"%s\",DumpPID=%d,DumpAddr=%" PRIx64 ",DumpSize=%" PRIu64 ",DumpFilename=\"%s\"",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   info->trap->name, reason, info->proc_data.pid, ctx->addr, len_bytes, display_file);

            if (printout_extras)
                printout_extras(drakvuf, plugin->m_output_format, extras);
            break;
        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            escaped_fname = drakvuf_escape_str(display_file);
            printf( "{"
                    "\"Plugin\": \"memdump\","
                    "\"TimeStamp\":" "\"" FORMAT_TIMEVAL "\","
                    "\"ProcessName\": %s,"
                    "\"UserName\": \"%s\","
                    "\"UserId\": %" PRIu64 ","
                    "\"PID\": %d,"
                    "\"PPID\": %d,"
                    "\"Method\": \"%s\","
                    "\"DumpReason\": \"%s\","
                    "\"DumpPID\": %d,"
                    "\"DumpAddr\": %" PRIx64 ","
                    "\"DumpSize\": %" PRIu64 ","
                    "\"DumpFilename\": %s",
                    UNPACK_TIMEVAL(info->timestamp),
                    escaped_pname,
                    USERIDSTR(drakvuf), info->proc_data.userid,
                    info->proc_data.pid, info->proc_data.ppid,
                    info->trap->name, reason, info->proc_data.pid, ctx->addr,
                    len_bytes, escaped_fname);
            if (printout_extras)
                printout_extras(drakvuf, plugin->m_output_format, extras);
            printf("}");
            g_free(escaped_fname);
            g_free(escaped_pname);
            break;
        default:
        case OUTPUT_DEFAULT:
            printf("[MEMDUMP] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64" \"%s\" Reason:\"%s\" Process:%d Base:0x%" PRIx64 " Size:%" PRIu64 " File:\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid, info->trap->name, reason, info->proc_data.pid, ctx->addr,
                   len_bytes, display_file);

            if (printout_extras)
                printout_extras(drakvuf, plugin->m_output_format, extras);
            break;
    }

    printf("\n");

done:
    free(file);
    g_free(access_ptrs);

    return ret;
}

static event_response_t free_virtual_memory_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // HANDLE ProcessHandle
    uint64_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    // OUT PVOID *BaseAddress
    addr_t mem_base_address_ptr = drakvuf_get_function_argument(drakvuf, info, 2);

    if (process_handle != 0xffffffffffffffffULL)
    {
        PRINT_DEBUG("[MEMDUMP] Process handle not pointing to self, ignore\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto plugin = get_trap_plugin<memdump>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_DTB, .dtb = info->regs->cr3 };
    ctx.addr = mem_base_address_ptr;

    addr_t mem_base_address;

    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &mem_base_address))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to read base address in NtFreeVirtualMemory\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    mmvad_info_t mmvad;

    if (VMI_SUCCESS != drakvuf_find_mmvad(drakvuf, info->proc_data.base_addr, mem_base_address, &mmvad))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to find MMVAD for memory passed to NtFreeVirtualMemory\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    ctx.addr = mem_base_address;
    uint16_t magic;
    char* magic_c = (char*)&magic;

    if (VMI_SUCCESS != vmi_read_16(vmi, &ctx, &magic))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to access memory to be used with NtFreeVirtualMemory\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (magic_c[0] == 'M' && magic_c[1] == 'Z')
    {
        ctx.addr = mmvad.starting_vpn << 12;
        size_t len_bytes = (mmvad.ending_vpn - mmvad.starting_vpn + 1) * VMI_PS_4KB;

        if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, len_bytes, "Possible binary detected", nullptr, nullptr))
        {
            PRINT_DEBUG("[MEMDUMP] Failed to store memory dump due to an internal error\n");
        }
    }

    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

typedef struct write_virtual_memory_extras
{
    vmi_pid_t target_pid;
    char* target_name;
    addr_t base_address;
} write_virtual_memory_extras_t;

static void printout_write_virtual_memory(drakvuf_t drakvuf, output_format_t format, void* extras)
{
    auto* xtr = (write_virtual_memory_extras_t*)extras;

    switch (format)
    {
        case OUTPUT_CSV:
            printf(",%d,%" PRIx64 "",
                   xtr->target_pid, xtr->base_address);
            break;
        case OUTPUT_KV:
            printf(",TargetPID=%d,WriteAddr=%" PRIx64 "",
                   xtr->target_pid, xtr->base_address);
            break;
        case OUTPUT_JSON:
            printf( ","
                    "\"TargetPID\": %d,"
                    "\"WriteAddr\": %" PRIx64,
                    xtr->target_pid, xtr->base_address);
            break;
        default:
        case OUTPUT_DEFAULT:
            printf(" TargetPID:%d WriteAddr:%" PRIx64 "",
                   xtr->target_pid, xtr->base_address);
            break;
    }
}

static event_response_t write_virtual_memory_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // IN HANDLE ProcessHandle
    addr_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);

    // IN PVOID BaseAddress
    addr_t base_address = drakvuf_get_function_argument(drakvuf, info, 2);

    // IN PVOID Buffer
    addr_t buffer_ptr = drakvuf_get_function_argument(drakvuf, info, 3);

    // IN ULONG NumberOfBytesToWrite
    addr_t buffer_size = drakvuf_get_function_argument(drakvuf, info, 4);

    auto plugin = get_trap_plugin<memdump>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_DTB, .dtb = info->regs->cr3 };
    ctx.addr = buffer_ptr;

    vmi_pid_t target_pid;
    addr_t process_addr = 0;
    char* target_name = nullptr;

    if (drakvuf_get_pid_from_handle(drakvuf, info, process_handle, &target_pid) == VMI_SUCCESS)
        if (drakvuf_find_process(drakvuf, target_pid, nullptr, &process_addr))
            target_name = drakvuf_get_process_name(drakvuf, process_addr, true);

    if (!target_name)
        target_name = g_strdup("<UNKNOWN>");

    write_virtual_memory_extras_t extras =
    {
        .target_pid = target_pid,
        .target_name = target_name,
        .base_address = base_address,
    };

    if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, buffer_size, "NtWriteVirtualMemory called", (void*)&extras, printout_write_virtual_memory))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to store memory dump due to an internal error\n");
    }

    g_free(target_name);
    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

memdump::memdump(drakvuf_t drakvuf, const memdump_config* c, output_format_t output)
    : pluginex(drakvuf, output)
{
    this->memdump_dir = c->memdump_dir;
    this->memdump_counter = 0;

    breakpoint_in_system_process_searcher bp;
    if (!register_trap<memdump>(drakvuf, nullptr, this, free_virtual_memory_hook_cb, bp.for_syscall_name("NtFreeVirtualMemory")) ||
            !register_trap<memdump>(drakvuf, nullptr, this, write_virtual_memory_hook_cb, bp.for_syscall_name("NtWriteVirtualMemory")))
    {
        throw -1;
    }
}
