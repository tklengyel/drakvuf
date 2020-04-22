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
#include <libdrakvuf/json-util.h>

#include "memdump.h"
#include "private.h"

#define DUMP_NAME_PLACEHOLDER "(not configured)"

static void save_file_metadata(const drakvuf_trap_info_t* info,
                               const char* file_path,
                               const char* data_file_name,
                               size_t dump_size,
                               addr_t dump_address,
                               const char* method,
                               const char* dump_reason,
                               extras_t* extras)
{
    char* file = NULL;
    if ( asprintf(&file, "%s.metadata", file_path) < 0 )
        return;

    FILE* fp = fopen(file, "w");
    free(file);
    if (!fp)
        return;

    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "Method", json_object_new_string(method));
    json_object_object_add(jobj, "DumpReason", json_object_new_string(dump_reason));
    json_object_object_add(jobj, "DumpAddress", json_object_new_string_fmt("0x%" PRIx64, dump_address));
    json_object_object_add(jobj, "DumpSize", json_object_new_string_fmt("0x%" PRIx64, dump_size));
    json_object_object_add(jobj, "PID", json_object_new_int(info->attached_proc_data.pid));
    json_object_object_add(jobj, "PPID", json_object_new_int(info->attached_proc_data.ppid));
    json_object_object_add(jobj, "ProcessName", json_object_new_string(info->attached_proc_data.name));

    if (extras && extras->type == WriteVirtualMemoryExtras)
    {
        json_object_object_add(jobj, "TargetPID", json_object_new_int(extras->write_virtual_memory_extras.target_pid));
        json_object_object_add(jobj, "TargetProcessName", json_object_new_string(extras->write_virtual_memory_extras.target_name));
        json_object_object_add(jobj, "TargetBaseAddress", json_object_new_string_fmt("0x%" PRIx64, extras->write_virtual_memory_extras.base_address));
    }

    json_object_object_add(jobj, "DataFileName", json_object_new_string(data_file_name));

    fprintf(fp, "%s\n", json_object_get_string(jobj));
    fclose(fp);

    json_object_put(jobj);
}

/**
 * Dumps the memory specified by access context, from `ctx->addr` (first byte) to `ctx->addr + len_bytes - 1` (last byte).
 * File is stored in a path provided in --memdump-dir command line option and named according to the scheme:
 * <process_pid>_<base_address>_<counter>.dmp
 *
 * For some dumps, a custom structure `extras` may be optionally provided together with `printout_extras` method
 * which will enrich the default data printout.
 */
bool dump_memory_region(
    drakvuf_t drakvuf,
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    memdump* plugin,
    access_context_t* ctx,
    size_t len_bytes,
    const char* reason,
    extras_t* extras,
    void (*printout_extras)(drakvuf_t drakvuf, output_format_t format, extras_t* extras))
{
    char* metafile = nullptr;
    char* file = nullptr;
    char* file_path = nullptr;
    char* tmp_file_path = nullptr;
    const char* display_file = nullptr;
    void** access_ptrs = nullptr;
    FILE* fp = nullptr;
    bool ret = false;

    gchar* escaped_pname = nullptr;
    gchar* escaped_fname = nullptr;

    const gchar* chk_str = nullptr;

    addr_t input_addr;
    addr_t aligned_addr;
    addr_t intra_page_offset;
    size_t aligned_len;
    size_t len_remainder;
    size_t num_pages;

    GChecksum* checksum = nullptr;

    size_t tmp_len_bytes = len_bytes;

    if (!plugin->memdump_dir)
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

    checksum = g_checksum_new(G_CHECKSUM_SHA256);

    if (asprintf(&tmp_file_path, "%s/dump.tmp", plugin->memdump_dir) < 0)
        goto done;

    fp = fopen(tmp_file_path, "w");

    if (!fp)
    {
        PRINT_DEBUG("[MEMDUMP] Failed to open file\n");
        goto done;
    }

    for (size_t i = 0; i < num_pages; i++)
    {
        // sometimes we are supposed to write less than the whole page
        size_t write_length = tmp_len_bytes;

        if (write_length > VMI_PS_4KB - intra_page_offset)
            write_length = VMI_PS_4KB - intra_page_offset;

        if (access_ptrs[i])
        {
            fwrite((char*)access_ptrs[i] + intra_page_offset, write_length, 1, fp);
            g_checksum_update(checksum, (const guchar*)access_ptrs[i] + intra_page_offset, write_length);
            munmap(access_ptrs[i], VMI_PS_4KB);
        }
        else
        {
            // unaccessible page, pad with zeros to ensure proper alignment of the data
            uint8_t zeros[VMI_PS_4KB] = {};
            fwrite(zeros + intra_page_offset, write_length, 1, fp);
            g_checksum_update(checksum, (const guchar*)zeros + intra_page_offset, write_length);
        }

        // this applies only to the first page
        intra_page_offset = 0;
        tmp_len_bytes -= write_length;
    }

    fclose(fp);

    chk_str = g_checksum_get_string(checksum);

    // The file name format for the memory dump file is:
    // <dump base address>_<contents hash>
    // This was set in order to satisfy the following issues:
    // * when disassembling, it is required to know the dump's image base, here it could be obtained
    //   just by looking at the file name which is handy both for humans and automated processing
    // * de-duplication - sometimes, different heuristics may want to dump the same piece of memory;
    //   unless there is a change in image base or contents, repeated memory dumps would get exactly
    //   the same file name
    if (asprintf(&file, "%llx_%.16s", (unsigned long long) ctx->addr, chk_str) < 0)
        goto done;

    if (asprintf(&file_path, "%s/%s", plugin->memdump_dir, file) < 0)
        goto done;

    display_file = (const char*)file;
    g_free((gpointer)chk_str);

    if (rename(tmp_file_path, file_path) != 0)
        goto done;

    if (asprintf(&metafile, "%s/memdump.%06d", plugin->memdump_dir, ++plugin->dumps_count) < 0)
      goto done;

    save_file_metadata(info, metafile, file, len_bytes, ctx->addr, info->trap->name, reason, extras);

    ret = true;

printout:
    switch (plugin->m_output_format)
    {
        case OUTPUT_CSV:
            printf("memdump," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",\"%s\",\"%s\",%d,%" PRIx64 ",%" PRIu64 ",\"%s\"",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->attached_proc_data.name,
                   info->attached_proc_data.userid, info->trap->name, reason, info->attached_proc_data.pid, ctx->addr, len_bytes, display_file);

            if (printout_extras)
                printout_extras(drakvuf, plugin->m_output_format, extras);
            break;
        case OUTPUT_KV:
            printf("memdump Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,DumpReason=\"%s\",DumpPID=%d,DumpAddr=%" PRIx64 ",DumpSize=%" PRIu64 ",SN=%d",
                   UNPACK_TIMEVAL(info->timestamp), info->attached_proc_data.pid, info->attached_proc_data.ppid, info->attached_proc_data.name,
                   info->trap->name, reason, info->attached_proc_data.pid, ctx->addr, len_bytes, plugin->dumps_count);

            if (printout_extras)
                printout_extras(drakvuf, plugin->m_output_format, extras);
            break;
        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->attached_proc_data.name);
            escaped_fname = drakvuf_escape_str(display_file);
            printf( "{"
                    "\"Plugin\": \"memdump\", "
                    "\"TimeStamp\":" "\"" FORMAT_TIMEVAL "\", "
                    "\"ProcessName\": %s, "
                    "\"UserName\": \"%s\", "
                    "\"UserId\": %" PRIu64 ", "
                    "\"PID\": %d, "
                    "\"PPID\": %d, "
                    "\"Method\": \"%s\", "
                    "\"DumpReason\": \"%s\", "
                    "\"DumpPID\": %d, "
                    "\"DumpAddr\": \"0x%" PRIx64 "\", "
                    "\"DumpSize\": \"0x%" PRIx64 "\", "
                    "\"DumpFilename\": %s",
                    UNPACK_TIMEVAL(info->timestamp),
                    escaped_pname,
                    USERIDSTR(drakvuf), info->attached_proc_data.userid,
                    info->attached_proc_data.pid, info->attached_proc_data.ppid,
                    info->trap->name, reason, info->attached_proc_data.pid, ctx->addr,
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
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->attached_proc_data.name,
                   USERIDSTR(drakvuf), info->attached_proc_data.userid, info->trap->name, reason, info->attached_proc_data.pid, ctx->addr,
                   len_bytes, display_file);

            if (printout_extras)
                printout_extras(drakvuf, plugin->m_output_format, extras);
            break;
    }

    printf("\n");

done:
    free(file);
    free(file_path);
    free(tmp_file_path);
    free(metafile);
    g_free(access_ptrs);

    return ret;
}

bool inspect_stack_ptr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, memdump* plugin, bool is_32bit, addr_t stack_ptr)
{
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = stack_ptr
    };

    size_t bytes_read = 0;
    uint8_t buf[512];
    // read up to 512 bytes of stack, this may fail returning a partial result
    // thus, the following for loop analyzes the buffer only up to the `bytes_read` value

    vmi_read(vmi, &ctx, 512, buf, &bytes_read);

    size_t stack_width = is_32bit ? 4 : 8;
    for (size_t i = 0; i < bytes_read; i += stack_width)
    {
        uint64_t stack_val = 0;
        memcpy(&stack_val, buf+i, stack_width);

        mmvad_info_t mmvad;
        if (!drakvuf_find_mmvad(drakvuf, info->attached_proc_data.base_addr, stack_val, &mmvad))
            continue;

        addr_t begin = mmvad.starting_vpn << 12;
        size_t len = (mmvad.ending_vpn - mmvad.starting_vpn + 1) << 12;

        page_info_t p_info = {};

        if (vmi_pagetable_lookup_extended(vmi, info->regs->cr3, stack_val, &p_info) != VMI_SUCCESS)
            continue;

        bool page_valid = (p_info.x86_ia32e.pte_value & (1UL << 0)) != 0;
        //bool page_write = (p_info.x86_ia32e.pte_value & (1UL << 1)) != 0;
        bool page_execute = (p_info.x86_ia32e.pte_value & (1UL << 63)) == 0;

        if (page_valid && page_execute && mmvad.file_name_ptr)
        {
            sptr_type_t res = check_module_linked(drakvuf, vmi, plugin, info, mmvad.starting_vpn << 12);

            if (res == ERROR)
            {
                PRINT_DEBUG("[MEMDUMP] Something is corrupted\n");
                continue;
            }

            if (res == LINKED)
            {
                PRINT_DEBUG("[MEMDUMP] Linked stack entry %llx\n", (unsigned long long) stack_val);
                continue;
            }
            else if (res == UNLINKED)
            {
                PRINT_DEBUG("[MEMDUMP] UNLINKED stack entry %llx\n", (unsigned long long) stack_val);
            }
            else if (res == MAIN)
            {
                PRINT_DEBUG("[MEMDUMP] MAIN stack entry %llx\n", (unsigned long long) stack_val);
            }
        }

        if (page_valid && page_execute)
        {
            PRINT_DEBUG("[MEMDUMP] VX stack entry %llx\n", (unsigned long long) stack_val);

            ctx.addr = begin;

            if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, len, "Stack heuristic",
                                    nullptr, nullptr))
            {
                PRINT_DEBUG("[MEMDUMP] Failed to save memory dump - internal error\n");
            }

            break;
        }
    }

    PRINT_DEBUG("[MEMDUMP] Done stack walk\n");

    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

bool dump_from_stack(drakvuf_t drakvuf, drakvuf_trap_info_t* info, memdump* plugin)
{
    bool is_32bit;
    addr_t stack_ptr;
    addr_t frame_ptr;

    if (drakvuf_get_user_stack32(drakvuf, info, &stack_ptr, &frame_ptr))
    {
        is_32bit = true;
    }
    else if (drakvuf_get_user_stack64(drakvuf, info, &stack_ptr))
    {
        is_32bit = false;
    }
    else
    {
        PRINT_DEBUG("[MEMDUMP] Failed to get stack pointer\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    PRINT_DEBUG("[MEMDUMP] Got stack pointer: %llx\n", (unsigned long long)stack_ptr);
    return inspect_stack_ptr(drakvuf, info, plugin, is_32bit, stack_ptr);
}

static event_response_t terminate_process_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // HANDLE ProcessHandle
    uint64_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);

    if (process_handle != ~0ULL)
    {
        PRINT_DEBUG("[MEMDUMP] Process handle not pointing to self, ignore\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto plugin = get_trap_plugin<memdump>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    dump_from_stack(drakvuf, info, plugin);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t free_virtual_memory_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // HANDLE ProcessHandle
    uint64_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    // OUT PVOID *BaseAddress
    addr_t mem_base_address_ptr = drakvuf_get_function_argument(drakvuf, info, 2);

    if (process_handle != ~0ULL)
    {
        PRINT_DEBUG("[MEMDUMP] Process handle not pointing to self, ignore\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto plugin = get_trap_plugin<memdump>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = mem_base_address_ptr
    };

    addr_t mem_base_address;

    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &mem_base_address))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to read base address in NtFreeVirtualMemory\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    mmvad_info_t mmvad;

    if (!drakvuf_find_mmvad(drakvuf, info->attached_proc_data.base_addr, mem_base_address, &mmvad))
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

    page_info_t p_info = {};

    if (vmi_pagetable_lookup_extended(vmi, info->regs->cr3, mem_base_address, &p_info) == VMI_SUCCESS)
    {
        bool pte_valid = (p_info.x86_ia32e.pte_value & (1UL << 0)) != 0;
        bool page_writeable = (p_info.x86_ia32e.pte_value & (1UL << 1)) != 0;
        bool page_executable = (p_info.x86_ia32e.pte_value & (1UL << 63)) == 0;

        ctx.addr = mmvad.starting_vpn << 12;
        size_t len_bytes = (mmvad.ending_vpn - mmvad.starting_vpn + 1) * VMI_PS_4KB;

        if (len_bytes > 0x1000 && pte_valid && page_writeable && page_executable)
        {
            if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, len_bytes, "Interesting RWX memory", nullptr, nullptr))
            {
                PRINT_DEBUG("[MEMDUMP] Failed to store memory dump due to an internal error\n");
            }
        }
    }

    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t protect_virtual_memory_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // HANDLE ProcessHandle
    uint64_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    // OUT PVOID *BaseAddress
    addr_t mem_base_address_ptr = drakvuf_get_function_argument(drakvuf, info, 2);

    if (process_handle != ~0ULL)
    {
        PRINT_DEBUG("[MEMDUMP] Process handle not pointing to self, ignore\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto plugin = get_trap_plugin<memdump>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = mem_base_address_ptr
    };

    addr_t mem_base_address;

    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &mem_base_address))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to read base address in NtProtectVirtualMemory\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    mmvad_info_t mmvad;

    if (!drakvuf_find_mmvad(drakvuf, info->attached_proc_data.base_addr, mem_base_address, &mmvad))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to find MMVAD for memory passed to NtProtectVirtualMemory\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    ctx.addr = mem_base_address;
    uint16_t magic;
    char* magic_c = (char*)&magic;

    if (VMI_SUCCESS != vmi_read_16(vmi, &ctx, &magic))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to access memory to be used with NtProtectVirtualMemory\n");
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

static void printout_write_virtual_memory(drakvuf_t drakvuf, output_format_t format, extras_t* xtr)
{
    switch (format)
    {
        case OUTPUT_CSV:
            printf(",%d,%" PRIx64 "",
                   xtr->write_virtual_memory_extras.target_pid, xtr->write_virtual_memory_extras.base_address);
            break;
        case OUTPUT_KV:
            printf(",TargetPID=%d,WriteAddr=%" PRIx64 "",
                   xtr->write_virtual_memory_extras.target_pid, xtr->write_virtual_memory_extras.base_address);
            break;
        case OUTPUT_JSON:
            printf( ", "
                    "\"TargetPID\": %d, "
                    "\"WriteAddr\": \"0x%" PRIx64 "\"",
                    xtr->write_virtual_memory_extras.target_pid, xtr->write_virtual_memory_extras.base_address);
            break;
        default:
        case OUTPUT_DEFAULT:
            printf(" TargetPID:%d WriteAddr:%" PRIx64 "",
                   xtr->write_virtual_memory_extras.target_pid, xtr->write_virtual_memory_extras.base_address);
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

    // don't dump self-writes
    if (process_handle == ~0ULL)
        return VMI_EVENT_RESPONSE_NONE;

    auto plugin = get_trap_plugin<memdump>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = buffer_ptr
    };

    vmi_pid_t target_pid;
    addr_t process_addr = 0;
    char* target_name = nullptr;

    if ( drakvuf_get_pid_from_handle(drakvuf, info, process_handle, &target_pid) &&
         drakvuf_find_process(drakvuf, target_pid, nullptr, &process_addr) )
    {
        target_name = drakvuf_get_process_name(drakvuf, process_addr, true);
    }

    if (!target_name)
        target_name = g_strdup("<UNKNOWN>");

    extras_t extras =
    {
        .type = WriteVirtualMemoryExtras,
        .write_virtual_memory_extras =
        {
            .target_pid = target_pid,
            .target_name = target_name,
            .base_address = base_address,
        },
    };

    if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, buffer_size, "NtWriteVirtualMemory called", &extras, printout_write_virtual_memory))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to store memory dump due to an internal error\n");
    }

    g_free(target_name);
    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

memdump::memdump(drakvuf_t drakvuf, const memdump_config* c, output_format_t output)
    : pluginex(drakvuf, output)
    , dumps_count()
{
    this->memdump_dir = c->memdump_dir;

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_LDR_DATA_TABLE_ENTRY", "DllBase", &this->dll_base_rva))
    {
        throw -1;
    }

    json_object* json_wow = drakvuf_get_json_wow(drakvuf);

    if (json_wow)
    {
        if (!json_get_struct_member_rva(drakvuf, json_wow, "_LDR_DATA_TABLE_ENTRY", "DllBase", &this->dll_base_wow_rva))
        {
            throw -1;
        }
    }
    else
    {
        PRINT_DEBUG("Memdump works better when there is a JSON profile for WoW64 NTDLL (-w)\n");
    }

    breakpoint_in_system_process_searcher bp;
    if (!register_trap<memdump>(drakvuf, nullptr, this, free_virtual_memory_hook_cb,    bp.for_syscall_name("NtFreeVirtualMemory")) ||
        !register_trap<memdump>(drakvuf, nullptr, this, protect_virtual_memory_hook_cb, bp.for_syscall_name("NtProtectVirtualMemory")) ||
        !register_trap<memdump>(drakvuf, nullptr, this, terminate_process_hook_cb,      bp.for_syscall_name("NtTerminateProcess")) ||
        !register_trap<memdump>(drakvuf, nullptr, this, write_virtual_memory_hook_cb,   bp.for_syscall_name("NtWriteVirtualMemory")))
    {
        throw -1;
    }

    this->userhook_init(drakvuf, c, output);
}

memdump::~memdump()
{
    userhook_destroy();
}
