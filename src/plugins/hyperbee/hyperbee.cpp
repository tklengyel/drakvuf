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
 ***************************************************************************
 * This plugin is part of the master's thesis of Klaus-Günther Schmidt,    *
 * student of FAU Erlangen-Nürnberg (DE) in cooperation with Politecnico   *
 * di Milano (IT) during 2020/2021.                                        *
 * The main goal of this plugin is to efficiently dump executable pages    *
 * which afterwards could be processed by analysis tools to detect         *
 * malware. The goal is reached by installing several traps:               *
 * 1. mmAccessFaultTrap: Whenever a MmAccessFault is called (to commit     *
 *    virtual memory) the regarding virtual address is saved. Additionally *
 *    the second trap is set up:                                           *
 * 2. When MmAccessFault returns to the original code it provides the      *
 *    physical address the virtual address was assigned to. This           *
 *    information is saved as well and used to set up a third trap:        *
 * 3. Whenever instructions are fetched from the physical address (frame)  *
 *    to be executed, this trap dumps the memory of the frame or even the  *
 *    whole vad node.                                                      *
 *    To be aware of further executions of this page but prevent duplicate *
 *    dumps, this execution trap is replaced by a fourth, write trap.      *
 * 4. The write trap is reacting on any writes at the monitored memory and *
 *    replaces itself with an executable trap (3). By continuously         *
 *    swapping trap 3 and 4 memory a dump of the same memory area is only  *
 *    performed, if the memory was modified in the mean time.              *
 **************************************************************************/

#include <glib.h>
#include <cinttypes>
#include <sys/stat.h>
#include <libvmi/libvmi.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>

#include <libdrakvuf/filesystem.hpp>
#include <libdrakvuf/json-util.h>
#include "hyperbee.h"
#include "plugins/output_format.h"
#include "private.h"

/**
 * Saves a pointer to the plugin and the starting virtual address of the frame.
 * This struct is passed between the different traps.
 */
struct fault_data_struct
{
    hyperbee* plugin;
    addr_t page_va;
};

/**
 * This code frees memory belonging to a certain trap.
 * It is called at the time a trap is removed. drakvuf_remove_trap will not remove a trap instantly but sort of schedules the remove.
 * Thus, if freeing the trap and trap->data instantly after drakvuf_remove_trap was called, this might lead to a use-after-free error.
 * This is why drakvuf_remove_trap has a callback option (third argument->using this callback) to set what has to be done when the trap is actually removed.
 */
static void remove_trap_cb(drakvuf_trap_t* trap)
{
    g_free(trap->data);
    g_free(trap);
}

/**
 * This is the callback of the execute trap.
 * @param drakvuf the drakvuf plugin
 * @param info information regarding the trap event
 * @return VMI_EVENT_RESPONSE_NONE, but this return information is currently not used by drakvuf.
 */
static event_response_t execute_faulted_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

/**
 * Creates an execute trap for the given (guest) frame number and passes the given fault data
 * @param gfn the (guest) frame number. If some executable instructions are fetched from this frame, the trap gets active
 * @param fault_data_old information which is required for logging. It is passed between the traps.
 * @return the execute trap that needs to be added to drakvuf
 */
drakvuf_trap_t* create_execute_trap(addr_t gfn, fault_data_struct* fault_data_old);

/**
 * Saves the metadata received during the monitoring to a logfile
 *
 * @param info the trap information
 * @param meta_file_path the path to save the metadata to
 * @param drakvuf
 * @param dump_file_name the name of the dump file
 * @param dump_size the size of the dumped file
 * @param dump_id the id of the dump
 * @param page_va the virtual address of the page where the fetch occurred
 * @param dll_name_str the name of the regarding dll
 * @param chk_str the hash
 * @param base_va the base (start) address of the VAD node, containing the dumped page
 * @param end_va the end of the VAD node, containing the dumped page
 */
static void save_file_metadata(const drakvuf_trap_info_t* info, const char* meta_file_path, drakvuf_t drakvuf,
                               const char* dump_file_name, size_t dump_size, unsigned int dump_id, addr_t page_va,
                               const char* dll_name_str, const gchar* chk_str, addr_t base_va, addr_t end_va)
{

    FILE* fp = fopen(meta_file_path, "w");
    if (!fp)
    {
        return;
    }

    json_object* json_object = json_object_new_object();
    auto timestamp = TimeVal{UNPACK_TIMEVAL(info->timestamp)};
    json_object_object_add(json_object, "TimeStamp",
                           json_object_new_string_fmt("%ld.%ld", timestamp.tv_sec, timestamp.tv_usec));
    /* Process pid */
    json_object_object_add(json_object, "PID", json_object_new_int(info->attached_proc_data.pid));
    /* Process parent pid */
    json_object_object_add(json_object, "PPID", json_object_new_int(info->attached_proc_data.ppid));
    /* Thread Id for Linux & Windows*/
    json_object_object_add(json_object, "TID", json_object_new_int(info->attached_proc_data.tid));
    /* Process SessionID/UID */
    json_object_object_add(json_object, "UserID", json_object_new_int(info->attached_proc_data.userid));
    /* Process name */
    json_object_object_add(json_object, "ProcessName", json_object_new_string(info->attached_proc_data.name));
    json_object_object_add(json_object, "EventUID", json_object_new_int64(info->event_uid));
    json_object_object_add(json_object, "CR3", json_object_new_string_fmt("0x%" PRIx64, info->regs->cr3));
    json_object_object_add(json_object, "PageVA", json_object_new_string_fmt("0x%" PRIx64, page_va));
    json_object_object_add(json_object, "VADBase", json_object_new_string_fmt("0x%" PRIx64, base_va));
    json_object_object_add(json_object, "VADEnd", json_object_new_string_fmt("0x%" PRIx64, end_va));
    json_object_object_add(json_object, "VADName", json_object_new_string(dll_name_str));
    json_object_object_add(json_object, "DumpSize", json_object_new_string_fmt("0x%" PRIx64, dump_size));
    json_object_object_add(json_object, "DumpFile", json_object_new_string(dump_file_name));
    json_object_object_add(json_object, "SHA256", json_object_new_string(chk_str));
    json_object_object_add(json_object, "DumpID", json_object_new_int(dump_id));
    json_object_object_add(json_object, "TrapPA", json_object_new_string_fmt("0x%" PRIx64, info->trap_pa));
    json_object_object_add(json_object, "GFN", json_object_new_string_fmt("0x%" PRIx64, info->trap->memaccess.gfn));
    fprintf(fp, "%s\n", json_object_get_string(json_object));
    fclose(fp);

    json_object_put(json_object);
}

/**
 * Method to get the SHA256 hash of a memory area. Similar to the dump_memory_region-code in the memdump plugin.
 */
const gchar* get_sha256_memory(
    vmi_instance_t vmi,
    access_context_t* ctx,
    size_t len_bytes)
{
    void** access_ptrs = nullptr;

    const gchar* chk_str = nullptr;
    GChecksum* checksum = nullptr;

    addr_t aligned_addr;
    addr_t intra_page_offset;
    size_t aligned_len;
    size_t len_remainder;
    size_t num_pages;
    size_t tmp_len_bytes = len_bytes;

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

    access_ptrs = (void**) g_try_malloc0(num_pages * sizeof(void*));
    if (!access_ptrs)
    {
        goto error;
    }

    if (VMI_SUCCESS != vmi_mmap_guest(vmi, ctx, num_pages, access_ptrs))
    {
        PRINT_DEBUG("[HYPERBEE] Failed mmap guest\n");
        goto error;
    }

    checksum = g_checksum_new(G_CHECKSUM_SHA256);

    for (size_t i = 0; i < num_pages; i++)
    {
        // sometimes we are supposed to write less than the whole page
        size_t write_length = tmp_len_bytes;

        if (write_length > VMI_PS_4KB - intra_page_offset)
        {
            write_length = VMI_PS_4KB - intra_page_offset;
        }

        if (access_ptrs[i])
        {
            g_checksum_update(checksum, (const guchar*) access_ptrs[i] + intra_page_offset, write_length);
            munmap(access_ptrs[i], VMI_PS_4KB);
        }
        else
        {
            // inaccessible page, pad with zeros to ensure proper alignment of the data
            uint8_t zeros[VMI_PS_4KB] = {};
            g_checksum_update(checksum, (const guchar*) zeros + intra_page_offset, write_length);
        }

        // this applies only to the first page
        intra_page_offset = 0;
        tmp_len_bytes -= write_length;
    }

    chk_str = g_checksum_get_string(checksum);
    goto done;

error:
    PRINT_DEBUG("[HYPERBEE] Failed to calculate checksum\n");

done:
    if (access_ptrs)
    {
        g_free(access_ptrs);
    }

    return chk_str;
}

/**
 * Dumps the memory specified by access context, from `ctx->addr` (first byte) to `ctx->addr + len_bytes - 1` (last byte).
 * File is stored in file_path
 *
 * Similar to the dump_memory_region-code in the memdump plugin.
 */
bool
dump_memory_region(vmi_instance_t vmi, hyperbee* plugin, access_context_t* ctx, size_t len_bytes, char* file_path)
{
    bool dump_success = false;

    void** access_ptrs = nullptr;
    FILE* fp = nullptr;

    addr_t aligned_addr;
    addr_t intra_page_offset;
    size_t aligned_len;
    size_t len_remainder;
    size_t num_pages;
    size_t tmp_len_bytes = len_bytes;

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

    access_ptrs = (void**) g_try_malloc0(num_pages * sizeof(void*));
    if (!access_ptrs)
    {
        goto error;
    }

    if (VMI_SUCCESS != vmi_mmap_guest(vmi, ctx, num_pages, access_ptrs))
    {
        PRINT_DEBUG("[HYPERBEE] Failed mmap guest\n");
        goto error;
    }

    //w just overrides the current file, if there is one.
    fp = fopen(plugin->tmp_file_path, "w");

    if (!fp)
    {
        PRINT_DEBUG("[HYPERBEE] Failed to open dump.tmp file\n");
        goto error;
    }

    for (size_t i = 0; i < num_pages; i++)
    {
        // sometimes we are supposed to write less than the whole page
        size_t write_length = tmp_len_bytes;

        if (write_length > VMI_PS_4KB - intra_page_offset)
        {
            write_length = VMI_PS_4KB - intra_page_offset;
        }

        if (access_ptrs[i])
        {
            fwrite((char*) access_ptrs[i] + intra_page_offset, write_length, 1, fp);
            munmap(access_ptrs[i], VMI_PS_4KB);
        }
        else
        {
            // inaccessible page, pad with zeros to ensure proper alignment of the data
            uint8_t zeros[VMI_PS_4KB] = {};
            fwrite(zeros + intra_page_offset, write_length, 1, fp);
        }

        // this applies only to the first page
        intra_page_offset = 0;
        tmp_len_bytes -= write_length;
    }

    fclose(fp);

    if (rename(plugin->tmp_file_path, file_path) != 0)
    {
        PRINT_DEBUG("[HYPERBEE] Failed to rename dump file\n");
        goto error;
    }

    dump_success = true;
    goto done;

error:
    PRINT_DEBUG("[HYPERBEE] Failed to dump memory\n");

done:
    if (access_ptrs)
    {
        g_free(access_ptrs);
    }

    return dump_success;
}

/**
 * Saves the virtual address where the fault occurred.
 */
struct access_fault_result_t : public call_result_t
{
    access_fault_result_t() : call_result_t(), fault_va()
    {}

    addr_t fault_va;
};

/**
 * If something was written at a monitored page this will swap the write trap to a exec trap.
 * (right away after committing the page or again after the first time it was executed)
 */
static event_response_t write_faulted_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    auto* ef_data = (struct fault_data_struct*) info->trap->data;

    if (LOG_ALWAYS)
    {
        fmt::print(ef_data->plugin->m_output_format, "hyperbee", drakvuf, info,
                   keyval("EventType", fmt::Qstr("writeframe")),
                   keyval("FrameVA", fmt::Xval(ef_data->page_va)),
                   keyval("TrapPA", fmt::Xval(info->trap_pa)),
                   keyval("CR3", fmt::Xval(info->regs->cr3)),
                   keyval("GFN", fmt::Xval(info->trap->memaccess.gfn))
                  );
    }

    drakvuf_trap* exec_trap = create_execute_trap(info->trap->memaccess.gfn, ef_data);
    if (exec_trap)
    {
        //Add and activate the exec trap
        if (drakvuf_add_trap(drakvuf, exec_trap))
        {
            //store the trap that it can be deleted in the end.
            ef_data->plugin->traps.emplace(exec_trap);

            //Removes this current execute trap and frees the memory
            ef_data->plugin->traps.erase(info->trap);
            drakvuf_remove_trap(drakvuf, info->trap, remove_trap_cb);

            PRINT_DEBUG("[HYPERBEE] Replaced write trap W on GFN 0x%lx with execute trap X\n",
                        info->trap->memaccess.gfn);
        }
        else
        {
            //If the trap was not added, keep the current write trap
            PRINT_DEBUG(
                "[HYPERBEE] Failed to add execute trap X on GFN 0x%lx. Keeping write trap W\n",
                info->trap->memaccess.gfn);
        }
    }
    else
    {
        PRINT_DEBUG(
            "[HYPERBEE] Failed to create exec trap X. Keeping write trap W on GFN 0x%lx\n",
            info->trap->memaccess.gfn);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * Creates a write trap, whose pointer is returned.
 *
 * @param info
 * @param fault_data_old
 */
drakvuf_trap_t* create_write_trap(drakvuf_trap_info_t* info, fault_data_struct* fault_data_old)
{

    //Use g_try_malloc0 to zero the alloced heap memory at first. This prevents any undefined behaviour as fields of the
    // drakvuf_trap_t remain uninitialised.
    auto* write_trap = (drakvuf_trap_t*) g_try_malloc0(sizeof(drakvuf_trap_t));
    if (!write_trap)
    {
        return nullptr;
    }

    //Create a new struct for exec_fault_data and reserve memory.
    auto* fault_data_new = (struct fault_data_struct*) g_try_malloc0(sizeof(struct fault_data_struct));
    if (!fault_data_new)
    {
        //If there is a problem with allocation of fault_data_new but write_trap was allocated successfully, free memory of write_trap.
        g_free(write_trap);
        return nullptr;
    }

    fault_data_new->plugin = fault_data_old->plugin;
    fault_data_new->page_va = fault_data_old->page_va;

    //Set the type of the trap.
    write_trap->type = MEMACCESS;
    //Guest page-frame number to set event (as defined in events.h) (This is the level 1 translation physical address of the guest. The windows used physical address).
    write_trap->memaccess.gfn = info->trap->memaccess.gfn;
    write_trap->memaccess.type = POST; //Do something after sth was written
    write_trap->memaccess.access = VMI_MEMACCESS_W; //When memory shall be written
    write_trap->data =
        fault_data_new; //Use new allocated fault_data_struct to prevent memory leaks and unexpected behaviour in case of memory corruptions

    //Cb is the asynchronous call back https://github.com/tklengyel/drakvuf/issues/1056#issuecomment-713867399
    write_trap->cb = write_faulted_cb;
    write_trap->name = "write_faulted_cb";
    return write_trap;
}

/**
 * Creates an execute trap, whose pointer is returned.
 *
 * @param info
 * @param fault_data_old
 */
drakvuf_trap_t* create_execute_trap(addr_t gfn, fault_data_struct* fault_data_old)
{

    auto* exec_trap = (drakvuf_trap_t*) g_try_malloc0(sizeof(drakvuf_trap_t));
    if (!exec_trap)
    {
        return nullptr;
    }

    //Create a new struct for exec_fault_data and reserve memory.
    auto* fault_data_new = (struct fault_data_struct*) g_try_malloc0(sizeof(struct fault_data_struct));
    if (!fault_data_new)
    {
        //If there is a problem with allocation of fault_data_new but exec_trap was allocated successfully, free memory of write_trap.
        g_free(exec_trap);
        return nullptr;
    }

    fault_data_new->plugin = fault_data_old->plugin;
    fault_data_new->page_va = fault_data_old->page_va;

    //Set the type of the trap.
    exec_trap->type = MEMACCESS;
    //Guest page-frame number to set event (as defined in events.h) (This is the level 1 translation physical address of the guest. The windows used physical address).
    exec_trap->memaccess.gfn = gfn;
    exec_trap->memaccess.type = PRE; //Do something before the access
    exec_trap->memaccess.access = VMI_MEMACCESS_X; //When memory shall be executed
    exec_trap->data =
        fault_data_new; //Use new allocated fault_data_struct to prevent memory leaks and unexpected behaviour in case of memory corruptions

    //Cb is the asynchronous call back https://github.com/tklengyel/drakvuf/issues/1056#issuecomment-713867399
    exec_trap->cb = execute_faulted_cb;
    exec_trap->name = "execute_faulted_cb";
    return exec_trap;
}

/**
 * If an instruction fetch got detected on a monitored page, this callback is executed
 *
 */
static event_response_t execute_faulted_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("[HYPERBEE] Caught X on PA 0x%lx, frame VA %llx, CR3 %lx\n", info->trap_pa,
                (unsigned long long) info->regs->rip, info->regs->cr3);

    //load the trap data
    auto* ef_data = (struct fault_data_struct*) info->trap->data;

    //Verify the program leading to the execution of this trap is the one we are filtering for (if we do).
    //The filtering could limit (and therefore focus) the monitoring and gives a speedup in such possibly uninteresting cases.
    // If it does not match the filter, delete this trap (and don't replace it)
    if (ef_data->plugin->hyperbee_filter_executable[0])
    {
        if (strcasestr(info->proc_data.name, ef_data->plugin->hyperbee_filter_executable) == NULL)
        {
            //Removes this trap and frees the memory
            ef_data->plugin->traps.erase(info->trap);
            drakvuf_remove_trap(drakvuf, info->trap, remove_trap_cb);
            PRINT_DEBUG("[HYPERBEE] Removed outdated trap for PA 0x%lx", info->trap_pa);
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    //Initialize a lot of data
    //The start of the VAD-Node. This is not necessarily the starting va of the page that is analysed.
    addr_t vad_node_base = 0;
    //The end address of the VAD-Node. The VAD-Node is not limited to a PAGE_SIZE.
    addr_t vad_node_end = 0;
    //The name of the dll
    unicode_string_t* dll_name = nullptr;
    //default name for the VAD / Dll
    char missing_data[] = "(null)";
    //default name, when the vad node represents no memory mapped file.
    char alloc_memory[] = "(no-mapped-file)";
    //The name of the application
    char* dll_name_str = missing_data;
    //The checksum of the current analyzed memory (vad or page)
    const gchar* chk_str = nullptr;

    //The size of current analyzed memory part (the amount of bytes written to disk)
    size_t memory_size = 0;
    //The whole path of the dumpfile
    char* file_path_memory_dump = nullptr;
    //The path to the file containing the metadata
    char* file_path_meta_data = nullptr;
    //The filename of which the memory dump and meta data file paths are built. it is a concatenation of the start address and the hash.
    char* file_name_stem = nullptr;
    //Is used to find a checksum in the set of already analyzed memory parts
    std::unordered_map<std::string, std::string>::iterator memory_hash_identifier;

    //initial value for malware. This can be set by an optional integrated classifier. If this is set to true (or during the execution of this method), the page dump will be stored always.
    //TODO FutureWork: if the classifier is integrated, set it to false by default, and let this be set by the classifier
    bool malware = MALWARE_DEFAULT;

    //Lock the VM
    auto vmi = vmi_lock_guard(drakvuf);

    //A struct to keep the vad node information
    mmvad_info_t mmvad;

    //Finds the correct mmvad entry by VAD-Table walk and return it within mmvad. proc_data.base_addr is the EPROCESS address and frame va the address which shall be contained within the vad entry.
    if (!drakvuf_find_mmvad(drakvuf, info->proc_data.base_addr, ef_data->page_va, &mmvad))
    {
        //If there was an error during vad search, quit but log all information
        PRINT_DEBUG("[HYPERBEE] Could not find vad information\n");
        goto log;
    }

    //Derive the vad node start and end virtual address
    vad_node_base = mmvad.starting_vpn << 12;
    vad_node_end = ((mmvad.ending_vpn + 1) << 12) - 1;

    //Read the name of the dll/binary this page belongs to
    dll_name = drakvuf_read_unicode_va(vmi, mmvad.file_name_ptr, 0);
    if (dll_name != nullptr)
    {
        dll_name_str = (char*) dll_name->contents;

        //If instructions are fetched from a System32 or SysWOW64 DLL
        if (IGNORE_SYSTEM_DLL)
        {
            //TODO FutureWork: In general it might be not secure to discard these DLLs since a malware might be able to
            // place DLLs here as well.
            if (strstr(dll_name_str, "System32") != nullptr)
            {
                PRINT_DEBUG("[HYPERBEE] Ignoring instruction fetch within System32 DLL\n");
                goto changetrap;
            }
            if (strstr(dll_name_str, "SysWOW64") != nullptr)
            {
                PRINT_DEBUG("[HYPERBEE] Ignoring instruction fetch within SysWOW64 DLL\n");
                goto changetrap;
            }
        }
    }
    else
    {
        dll_name_str = alloc_memory;
    }

    //Set the memory access context
    access_context_t ctx_memory_dump;

    //Option to dump the whole VAD node instead of just a single page
    if (DUMP_VAD)
    {
        //Prevents the dump of very big vad nodes. This might happen if a 32bit program gets executed. SYSWOW64 creates
        // a large fake vad entry to prevent the memory allocator to allocate addresses above the 32bit boundary.
        //I was told this workaround shall be corrected in further versions.
        //TODO FutureWork: Further aspects to consider: This workaround makes the DUMP_VAD mode faster, but discards also too large
        // DLLs from being dumped. Maybe some heuristics could be set up to handle this. e.g. if vad is memory mapped
        // file, monitor it at filesystem level and dump first time and later only if changed?
        if (mmvad.ending_vpn - mmvad.starting_vpn + 1 >= 1024)
        {
            PRINT_DEBUG("[HYPERBEE] Ignoring the dump of too large vad node\n");
            goto log;
        }

        //Set the area to dump for vad or page (below-else)
        ctx_memory_dump =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            //Calculate the dump_size
            .addr = mmvad.starting_vpn * VMI_PS_4KB
        };
        memory_size = (mmvad.ending_vpn - mmvad.starting_vpn + 1) * VMI_PS_4KB;
    }
    else
    {
        ctx_memory_dump =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB, /**see Libvmi.h < Translate addr via specified directory table base. */
            .dtb = info->regs->cr3, //The directory table base
            .addr = ef_data->page_va //The address to lookup.
        };
        memory_size = VMI_PS_4KB;
    }

// TODO FutureWork:
//  - Hashing of the whole VAD node is a bottleneck since it could be 1000s of pages.
//  - Combined with the aspect that a dll is not loaded at once, but partially (when needed) the hashing is not
//    useful right now. Maybe drakvuf can somehow trigger that the dll is loaded completely in one step? Or even use
//    heuristics to monitor the dll on a filesystem basis?

    //For pages this approach is good.

    //get the hash
    chk_str = get_sha256_memory(vmi, &ctx_memory_dump, memory_size);
    if (chk_str == nullptr)
    {
        PRINT_DEBUG("[HYPERBEE] Could not get SHA256 of dumpfile\n");
        goto log;
    }

    memory_hash_identifier = ef_data->plugin->hashed_dumped_data_map.find(chk_str);

    //If the checksum already exists:
    if (memory_hash_identifier != ef_data->plugin->hashed_dumped_data_map.end())
    {

        if (asprintf(&file_name_stem, "%s", memory_hash_identifier->second.c_str()) < 0)
        {
            PRINT_DEBUG("[HYPERBEE] Could not fetch base_file_name from duplicate database\n");
        }
        //using a suffix as "vad", "page" or (for the metafile) "metadata" helps to quickly select associated files
        if (DUMP_VAD)
        {
            if (asprintf(&file_path_memory_dump, "%s/%s.vad", ef_data->plugin->hyperbee_dump_dir.c_str(),
                         file_name_stem) < 0)
            {
                PRINT_DEBUG("[HYPERBEE] Could not create memory dump file name\n");
            }
        }
        else
        {
            if (asprintf(&file_path_memory_dump, "%s/%s.page", ef_data->plugin->hyperbee_dump_dir.c_str(),
                         file_name_stem) < 0)
            {
                PRINT_DEBUG("[HYPERBEE] Could not create memory dump file name\n");
            }
        }
        if (asprintf(&file_path_meta_data, "%s/%s.metafile", ef_data->plugin->hyperbee_dump_dir.c_str(),
                     file_name_stem) < 0)
        {
            PRINT_DEBUG("[HYPERBEE] Could not create meta file name\n");
        }

        //Increase the dump counter in this special case
        ++ef_data->plugin->dump_id;

        goto log;

    }

    //At this point I use a yet unpublished tool from Politecnico di Milano (IT) to analyse the accessed memory page for API calls. This information is used within a malware classifier.
    //TODO FutureWork  malware = MalwareClassifier(...)

    //If neither malware was found nor it was forced to dump or log, just change the trap for a write trap and return
    if (!malware && !DUMP_ALWAYS && !LOG_ALWAYS)
    {
        goto changetrap;
    }

    //If malware was detected or manually switched to always dump
    if (malware || DUMP_ALWAYS)
    {

        // Comment from memdump.cpp:
        // The file name format for the memory dump file is:
        // <dump base address>_<16 chars of hash>
        // This was set in order to satisfy the following issue:
        // * when disassembling, it is required to know the dump's image base, here it could be obtained
        //   just by looking at the file name which is handy both for humans and automated processing
        // * no other information was included in the file name to make it possible to reference this file in the
        //   future if the identical memory would be dumped again
        if (asprintf(&file_name_stem, "%llx_%.16s", (unsigned long long) ctx_memory_dump.addr, chk_str) < 0)
        {
            PRINT_DEBUG("[HYPERBEE] Could not create the base file path\n");
            goto log;
        }

        //dump bytes either the whole VAD or just the PAGE
        if (DUMP_VAD)
        {
            //using a suffix as "vad", "page" or (for the metafile) "metadata" helps to quickly select associated files
            if (asprintf(&file_path_memory_dump, "%s/%s.vad", ef_data->plugin->hyperbee_dump_dir.c_str(),
                         file_name_stem) < 0)
            {
                PRINT_DEBUG("[HYPERBEE] Could not create memory dump file name\n");
                goto log;
            }
        }
        else
        {
            //using a suffix as "vad", "page" or (for the metafile) "metadata" helps to quickly select associated files
            if (asprintf(&file_path_memory_dump, "%s/%s.page", ef_data->plugin->hyperbee_dump_dir.c_str(),
                         file_name_stem) < 0)
            {
                PRINT_DEBUG("[HYPERBEE] Could not create memory dump file name\n");
                goto log;
            }
        }

        //If the dump fails
        if (!dump_memory_region(vmi, ef_data->plugin, &ctx_memory_dump, memory_size, file_path_memory_dump))
        {
            PRINT_DEBUG("[HYPERBEE] Could not dump memory\n");
            file_path_memory_dump = nullptr;
            goto log;
        }

        //If the dump was successful: increase the dump counter
        ++ef_data->plugin->dump_id;

        //Add the checksum as key with the file_name_prefix (as data) to the map.
        ef_data->plugin->hashed_dumped_data_map.insert(std::pair<std::string, std::string>(chk_str, file_name_stem));

        //Create the metadata path
        if (asprintf(&file_path_meta_data, "%s/%s.metafile", ef_data->plugin->hyperbee_dump_dir.c_str(),
                     file_name_stem) < 0)
        {
            PRINT_DEBUG("[HYPERBEE] Could not create meta file name\n");
            goto log;
        }

        //If the dump of the memory was successful write all gathered data to a metadata file
        save_file_metadata(info, file_path_meta_data, drakvuf, file_path_memory_dump, memory_size,
                           ef_data->plugin->dump_id,
                           ef_data->page_va, dll_name_str, chk_str, vad_node_base, vad_node_end);
    }

log:
    //LOG the retrieved data to the console
    if (LOG_ALWAYS || malware)
    {
        char* actual_dump_file_path;
        const char* actual_checksum;
        unsigned int actual_dump_id;
        char* actual_metafile;

        //If the hash was not generated or the dump file path not set
        if ((chk_str == nullptr) || (file_path_memory_dump == nullptr))
        {
            actual_dump_file_path = missing_data;
            actual_checksum = missing_data;
            actual_dump_id = 0;
            memory_size = 0;
        }
        else
        {
            actual_dump_file_path = file_path_memory_dump;
            actual_checksum = chk_str;
            actual_dump_id = ef_data->plugin->dump_id;
        }

        //If the metadata path was not set
        if (file_path_meta_data == nullptr)
        {
            actual_metafile = missing_data;
        }
        else
        {
            actual_metafile = file_path_meta_data;
        }

        //Log everything to the screen
        fmt::print(ef_data->plugin->m_output_format, "hyperbee", drakvuf, info,
                   keyval("EventType", fmt::Qstr("execframe")),
                   keyval("CR3", fmt::Xval(info->regs->cr3)),
                   keyval("PageVA", fmt::Xval(ef_data->page_va)),
                   keyval("VADBase", fmt::Xval(vad_node_base)),
                   keyval("VADEnd", fmt::Xval(vad_node_end)),
                   keyval("VADName", fmt::Qstr(dll_name_str)),
                   keyval("DumpSize", fmt::Nval(memory_size)),
                   keyval("DumpFile", fmt::Qstr(actual_dump_file_path)),
                   keyval("SHA256", fmt::Qstr(actual_checksum)),
                   keyval("DumpID", fmt::Nval(actual_dump_id)),
                   keyval("MetaFile", fmt::Qstr(actual_metafile)),
                   keyval("TrapPA", fmt::Xval(info->trap_pa)),
                   keyval("GFN", fmt::Xval(info->trap->memaccess.gfn))
                  );
    }


    //Swap the execute for a write trap
changetrap:
    drakvuf_trap* write_trap = create_write_trap(info, ef_data);
    if (write_trap)
    {
        //Add and activate the trap
        if (drakvuf_add_trap(drakvuf, write_trap))
        {
            //store the trap that it can be deleted in the end.
            ef_data->plugin->traps.emplace(write_trap);

            //Removes this current execute trap and frees the memory
            ef_data->plugin->traps.erase(info->trap);
            drakvuf_remove_trap(drakvuf, info->trap, remove_trap_cb);

            PRINT_DEBUG("[HYPERBEE] Replaced execute trap X on GFN 0x%lx with write trap W\n",
                        info->trap->memaccess.gfn);
        }
        else
        {
            //If the trap was not added, keep the current exec trap
            PRINT_DEBUG(
                "[HYPERBEE] Failed to add write trap W on GFN 0x%lx. Keeping execute trap X\n",
                info->trap->memaccess.gfn);
        }
    }
    else
    {
        PRINT_DEBUG(
            "[HYPERBEE] Failed to create write trap W. Keeping execute trap X on GFN 0x%lx\n",
            info->trap->memaccess.gfn);
    }

    //Frees memory
    if (file_name_stem)
    {
        free(file_name_stem);
    }
    if (file_path_memory_dump)
    {
        free(file_path_memory_dump);
    }
    if (file_path_meta_data)
    {
        free(file_path_meta_data);
    }
    if (dll_name)
    {
        vmi_free_unicode_str(dll_name);
    }
    g_free((gpointer) chk_str);

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * This method is called when the mmAccessFault handler returns, right before the actual code execution continues.
 * It is used to grab the physical address, that got assigned to the virtual
 * This method is based on the code of the IPT plugin
 */
static event_response_t mm_access_fault_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    //Loads a pointer to the plugin, which is responsible for the trap (in this case -> hyperbee2)
    auto plugin = get_trap_plugin<hyperbee>(info);

    //get_trap_params reinterprets the pointer of info->trap->data as a pointer to access_fault_result_t
    auto params = get_trap_params<access_fault_result_t>(info);

    //Verifies that the params we got above (preset by the previous trap) match the trap_information this cb got called with.
    //This is used, if the trap (e.g. a shared dll) is risen by another process which fetches accidentally instructions from this page as well
    if (!params->verify_result_call_params(drakvuf, info))
    {
        PRINT_DEBUG("[HYPERBEE] info & thread parameters did not match\n");
        return VMI_EVENT_RESPONSE_NONE;
    }


    //Calculate the frame's starting virtual address from the fault_va by clearing the lower 12 bits.
    addr_t page_va = ((params->fault_va >> 12) << 12);

    //Create an identifier for each monitored memory part. That is a combination of the CR3 register and the page_va.
    //As the exec trap will be replaced by a write trap and vice-versa (and not be removed once hit to keep focus on that page) it is required to prevent adding multiple traps for the same memory areas.
    //Even page_va and gfn relate the page_va is used as identifier, since the gfn would require an additional translation from va to pa, which would cost additional time.
    std::pair<addr_t, addr_t> monitored_page_identifier(info->regs->cr3, page_va);

    //Try to find the current trap identifier in the set of existing traps.
    auto it = plugin->monitored_pages.find(monitored_page_identifier);

    //If the memory area is not monitored yet: Create a new trap for that.
    if (it == plugin->monitored_pages.end())
    {
        //page_info_t is a type of type page_info https://stackoverflow.com/a/30370413
        page_info_t p_info = {};
        {
            auto vmi = vmi_lock_guard(drakvuf);

            // According to http://libvmi.com/api/ Gets the physical address that the VA got assigned to (and its page size) as well as the addresses of other paging related structures depending on the page mode of the VM.
            //Translates the virtual address to the direct physical address (not only the frame physical address)
            //cr3 is the address of the relevant page directory base
            //fault_va is the virtual address to translate to a physical one via dtb
            //&p_info is the address of a struct to save the information to.
            //Page info has a vaddr, that is taken from the param. the dtb equals the cr3 and the paddr is grabbed, as it is now assigned.
            if (VMI_SUCCESS != vmi_pagetable_lookup_extended(vmi, info->regs->cr3, params->fault_va, &p_info))
            {
                PRINT_DEBUG("[HYPERBEE] failed to lookup page info\n");
                plugin->destroy_trap(info->trap);
                return VMI_EVENT_RESPONSE_NONE;
            }
        }

        //Print out all previous gathered information.
        if (LOG_ALWAYS)
        {
            fmt::print(plugin->m_output_format, "hyperbee", drakvuf, info,
                       keyval("EventType", fmt::Qstr("pagefault")),
                       keyval("CR3", fmt::Xval(info->regs->cr3)),
                       keyval("VA", fmt::Xval(params->fault_va)),
                       keyval("PA", fmt::Xval(p_info.paddr))
                      );
        }

        //Create a new struct for exec_fault_data and reserve memory.
        auto* ef_data = (struct fault_data_struct*) g_try_malloc0(sizeof(struct fault_data_struct));
        if (ef_data)
        {
            //Reference the plugin there.
            ef_data->plugin = plugin;

            ef_data->page_va = page_va;

            drakvuf_trap* exec_trap = create_execute_trap(p_info.paddr >> 12, ef_data);
            //Free ef_data as it is not used anymore
            g_free(ef_data);

            if (exec_trap)
            {
                //Add and activate the trap
                if (drakvuf_add_trap(drakvuf, exec_trap))
                {
                    //store the trap to be deleted in the end.
                    plugin->traps.emplace(exec_trap);
                    plugin->monitored_pages.insert(monitored_page_identifier);
                    PRINT_DEBUG("[HYPERBEE] Set up execute trap X on GFN 0x%lx\n", info->trap->memaccess.gfn);
                }
                else
                {
                    //If the trap was not added successfully
                    //Can't keep trap since it is specific for the RIP
                    PRINT_DEBUG(
                        "[HYPERBEE] Failed to add execute trap X on GFN 0x%lx. Deleting mmAccessFault Return Trap\n",
                        info->trap->memaccess.gfn);
                }
            }
            else
            {
                PRINT_DEBUG(
                    "[HYPERBEE] Failed to create execute trap X. Not monitoring GFN 0x%lx\n",
                    info->trap->memaccess.gfn);
            }
        }
        else
        {
            PRINT_DEBUG(
                "[HYPERBEE] Failed to allocate memory for fault_data. Not monitoring GFN 0x%lx\n",
                info->trap->memaccess.gfn);
        }

    }

    //Destroys this return trap, because it is specific for the RIP and not usable anymore. This was the trap being called when the physical address got computed.
    //Deletes this trap from the list of existing traps traps
    //Additionally removes the trap and frees the memory
    plugin->destroy_trap(info->trap);

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * This method is the callback of a trap which was added in the last lines of the constructor through register_trap
 * It is called at the entry of MmAccessFault right before the first instruction of the access fault handler is executed.
 * At that point we just know the faulting virtual address, which is the second parameter -> rdx.
 * At that moment the fault handler was still not executed, so this Virtual Address is still not mapped to anywhere. Thus we create another breakpoint, which causes that mm_access_fault_return_hook_cb will be called one MmAccessFault function is done and returns.
 * We also need to pass fault_va to the next breakpoint as it will be impossible to determine what it was after the function is executed.
 * MmAccessFault is called if a allocated page is used for the first time.
 * This method is based on some ideas of the IPT plugin

 */
static event_response_t mm_access_fault_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    //Load the plugin object.
    auto plugin = get_trap_plugin<hyperbee>(info);

    //Checks if a filter was set and applies it:
    //This applies only to the trap set up. If the program dies in the meantime, the trap continues and might rise the
    // callback even if another program is triggering it, since all depends only on the guest frame number.
    if (plugin->hyperbee_filter_executable[0])
    {
        //Use NULL when calling C functions.
        if (strcasestr(info->proc_data.name, plugin->hyperbee_filter_executable) == NULL)
        {
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    //The first argument is the FaultStatus, and the second (rdx) the VirtualAddress which caused the fault.
    addr_t fault_va = drakvuf_get_function_argument(drakvuf, info, 2);
    PRINT_DEBUG("[HYPERBEE] Caught MmAccessFault(%d, %lx)\n", info->proc_data.pid, fault_va);

    //The kernel space starts with 0xFFFF... and higher.  User space is within 0x0000F... and below. If the trap was created by a kernel module we don't mind as we assume the integrity of the kernel.
    //https://www.codemachine.com/article_x64kvas.html: The upper 16 bits of virtual addresses are always set to 0x0 for user mode addresses and to 0xF for kernel mode addresses
    //Checks if the highest bit (bit 64) = 1000...000 is one or not. If it is one, this must be part of the kernel, since it would has to be 0 for the user mode.
    if (fault_va & (1ULL << 63))
    {
        PRINT_DEBUG("[HYPERBEE] Don't trap in kernel %d %lx\n", info->proc_data.pid, fault_va);
        return VMI_EVENT_RESPONSE_NONE;
    }

    //Since plugin is a pointer, we access its components with ->. Here we register an additional trap.
    //Right now we are at the beginning of the MmAccessFault method. We get the fault_va which can be received (as above) from reading it from the stack as seconds element.
    //But we also want to know the physical address it is assigned to, which is the return of the MmAccessFault method.
    //Since we are not able to determine the return address of the MmAccessFault, we need to extract it somehow.
    //This can be done right here at the entry of MmAccessFault, since the RIP is the top stack element right now and the esp points to it. So by breakpoint_by_pid_searcher we retrieve this return address and set a hook to it (the address where the execution continues after returning from MmAccessFault).

    //Adds a return hook, a hook which will be called after function completes and returns.
    //Each time registers a trap, which is just for the process at the current step -> specific for the RIP
    auto trap = plugin->register_trap<access_fault_result_t>(
                    info,
                    mm_access_fault_return_hook_cb,
                    breakpoint_by_pid_searcher());

    //If trap creation failed
    if (!trap)
    {
        PRINT_DEBUG("[HYPERBEE] Could not create accessFaultReturnTrap\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    //After the trap got constructed, enrich its details already with some information we already (and just) know here (at this point).

    //access_fault_result_t extends from call_result_t which extends from plugin_params
    //get_trap_params reinterprets the pointer of trap->data as a pointer to access_fault_result_t
    //Load the information that is saved by hitting the first trap.
    //With params we can preset the params that the newly risen second breakpoint will receive.
    auto params = get_trap_params<access_fault_result_t>(trap);

    //Save the address of the target thread, address of the rsp (this was the rip-address, which we used for construction) and the value of the CR3 register to the params.
    params->set_result_call_params(info);

    //enrich the params of the new/next trap with the information which fault virtual address resulted in the fault. This information is used later.
    params->fault_va = fault_va;

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * This is the constructor of the plugin.
 */
hyperbee::hyperbee(drakvuf_t drakvuf, const hyperbee_config_struct* c, output_format_t output)
    : pluginex(drakvuf, output)
{

    //Check if the dump directory parameter was provided
    if (!c->hyperbee_dump_dir)
    {
        PRINT_DEBUG("[HYPERBEE] Output directory for dumps not provided, not activating hyperbee plugin\n");
        return;
    }

    //Load the filter if existing
    if (c->hyperbee_filter_executable)
    {
        this->hyperbee_filter_executable = c->hyperbee_filter_executable;
    }

    //get the output dir from the config arguments
    this->hyperbee_dump_dir = c->hyperbee_dump_dir;

    //Check if the dump directory exists
    if (!std::filesystem::exists(this->hyperbee_dump_dir))
    {
        PRINT_DEBUG("[HYPERBEE] The output directory is no valid/existing path, not activating hyperbee plugin\n");
        return;
    }

    //Construct the full frame dump directory by appending /dumps/ and create the folder if not yet existing.
    this->hyperbee_dump_dir /= "dumps";

    //Creates the dump folder
    int res = mkdir(this->hyperbee_dump_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (res != 0 && errno != EEXIST)
    {
        PRINT_DEBUG("[HYPERBEE] Failed to create dump directory %s\n", this->hyperbee_dump_dir.c_str());
        return;
    }

    //Create the default dump file name
    if (asprintf(&this->tmp_file_path, "%s/dump.tmp", this->hyperbee_dump_dir.c_str()) < 0)
    {
        PRINT_DEBUG("[HYPERBEE] Failed to build the string containing the temp_file_path\n");
        return;
    }

    //Looks up the relative virtual address of a syscall method
    breakpoint_in_system_process_searcher bp;

    //This code adds a trap to mmAccessFault: whenever MmAccessFault is called, it calls back to mm_access_fault_hook_cb.
    //This trap is general for MmAccessFault and is just created one time and used over and over again.
    if (!register_trap(nullptr, mm_access_fault_hook_cb, bp.for_syscall_name("MmAccessFault"),
                       "mmAccessFaultTrap"))
    {
        throw -1;
    }
}

//Is called after shutting down.
hyperbee::~hyperbee()
{
    for (const auto trap: traps)
    {
        g_free(trap->data);
        g_free(trap);
    }
    free(this->tmp_file_path);
}
