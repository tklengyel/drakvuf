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
 * The main goal of this plugin is to efficiently monitor machine code,    *
 * resulting in the name [Machine] Code Mon[itor]. Following the rules     *
 * below it dumps executable pages which afterwards could be processed by  *
 * analysis tools to detect malware. The goal is reached by installing     *
 * several traps:                                                          *
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

#include <plugins/filesystem.hpp>
#include <libdrakvuf/json-util.h>
#include "codemon.h"
#include "plugins/output_format.h"
#include "private.h"

/**
 * The default string, for incomplete entries.
 */
static char missing_data[] = "(null)";
/**
 * The string used for vad nodes, that don't belong to mapped files, but to dynamically allocated memory
 */
static char alloc_memory[] = "(no-mapped-file)";

//See codemon.h -> codemon_config_struct
static bool log_everything = false;
static bool dump_vad = false;
static bool analyse_system_dll_vad = false;
static bool default_benign = false;

/**
 * Saves the metadata received during the monitoring to a logfile
 *
 * @param trap_info the trap information
 * @param dump_metadata data to be logged gathered during the analysis
 * @param fault_data the struct with the fault data
 */
static void save_file_metadata(const drakvuf_trap_info_t* trap_info,
                               const dump_metadata_struct* dump_metadata,
                               const fault_data_struct* fault_data)
{

    //Opens the meta file
    FILE* fp = fopen(dump_metadata->meta_file, "w");
    if (!fp)
    {
        return;
    }

    //Determines the string that shall be printed as vad_name
    char* actual_vad_name;
    if (dump_metadata->vad_name == nullptr)
    {
        actual_vad_name = alloc_memory;
    }
    else
    {
        actual_vad_name = (char*) dump_metadata->vad_name->contents;
    }

    json_object* json_object = json_object_new_object();
    auto timestamp = TimeVal{UNPACK_TIMEVAL(trap_info->timestamp)};
    json_object_object_add(json_object, "TimeStamp",
                           json_object_new_string_fmt("%ld.%ld", timestamp.tv_sec, timestamp.tv_usec));
    /* Process pid */
    json_object_object_add(json_object, "PID", json_object_new_int(trap_info->attached_proc_data.pid));
    /* Process parent pid */
    json_object_object_add(json_object, "PPID", json_object_new_int(trap_info->attached_proc_data.ppid));
    /* Thread Id for Linux & Windows*/
    json_object_object_add(json_object, "TID", json_object_new_int(trap_info->attached_proc_data.tid));
    /* Process SessionID/UID */
    json_object_object_add(json_object, "UserID", json_object_new_int(trap_info->attached_proc_data.userid));
    /* Process name */
    json_object_object_add(json_object, "ProcessName", json_object_new_string(trap_info->attached_proc_data.name));
    json_object_object_add(json_object, "EventUID", json_object_new_int64(trap_info->event_uid));
    json_object_object_add(json_object, "CR3", json_object_new_string_fmt("0x%" PRIx64, trap_info->regs->cr3));
    json_object_object_add(json_object, "PageVA", json_object_new_string_fmt("0x%" PRIx64, fault_data->page_va));
    json_object_object_add(json_object,
                           "VADBase",
                           json_object_new_string_fmt("0x%" PRIx64, dump_metadata->vad_node_base));
    json_object_object_add(json_object,
                           "VADEnd",
                           json_object_new_string_fmt("0x%" PRIx64, dump_metadata->vad_node_end));
    json_object_object_add(json_object, "VADName", json_object_new_string(actual_vad_name));
    json_object_object_add(json_object,
                           "DumpSize",
                           json_object_new_string_fmt("0x%" PRIx64, dump_metadata->dump_size));
    json_object_object_add(json_object, "DumpFile", json_object_new_string(dump_metadata->dump_file));
    json_object_object_add(json_object, "SHA256", json_object_new_string(dump_metadata->sha256sum));
    json_object_object_add(json_object, "DumpID", json_object_new_int(fault_data->plugin->dump_id));
    json_object_object_add(json_object, "TrapPA", json_object_new_string_fmt("0x%" PRIx64, trap_info->trap_pa));
    json_object_object_add(json_object,
                           "GFN",
                           json_object_new_string_fmt("0x%" PRIx64, trap_info->trap->memaccess.gfn));
    fprintf(fp, "%s\n", json_object_get_string(json_object));
    fclose(fp);

    json_object_put(json_object);
}

/**
 * Prints all information of a dump to the console
 * @param drakvuf the current drakvuf instance
 * @param trap_info contains information regarding the current activation of the trap like register values, timestamps, ...
 * @param dump_metadata the struct containing the dump metadata
 * @param fault_data the struct with the fault data
 */
void log_all_to_console(drakvuf_t drakvuf,
                        drakvuf_trap_info* trap_info,
                        dump_metadata_struct* dump_metadata,
                        fault_data_struct* fault_data)
{

    unsigned int actual_dump_id;
    int actual_dump_size;
    const char* actual_checksum;
    char* actual_dump_file_path;
    char* actual_metafile;
    char* actual_vad_name;

    //If the memory was not dumped some values should be reset as they would not make sense.
    if (dump_metadata->dump_file == nullptr)
    {
        actual_dump_id = 0;
        actual_dump_size = 0;
        actual_checksum = missing_data;
        actual_dump_file_path = missing_data;
        actual_metafile = missing_data;
    }
    else
    {
        actual_dump_id = fault_data->plugin->dump_id;
        actual_dump_size = dump_metadata->dump_size;
        actual_checksum = dump_metadata->sha256sum;
        actual_dump_file_path = dump_metadata->dump_file;
        actual_metafile = dump_metadata->meta_file;
    }

    //Determines the string that shall be printed as vad_name
    if (dump_metadata->vad_name == nullptr)
    {
        actual_vad_name = alloc_memory;
    }
    else
    {
        actual_vad_name = (char*) dump_metadata->vad_name->contents;
    }

    //Log everything to the screen
    fmt::print(fault_data->plugin->m_output_format, "codemon", drakvuf, trap_info,
               keyval("EventType", fmt::Qstr("execframe")),
               keyval("CR3", fmt::Xval(trap_info->regs->cr3)),
               keyval("PageVA", fmt::Xval(fault_data->page_va)),
               keyval("VADBase", fmt::Xval(dump_metadata->vad_node_base)),
               keyval("VADEnd", fmt::Xval(dump_metadata->vad_node_end)),
               keyval("VADName", fmt::Qstr(actual_vad_name)),
               keyval("DumpSize", fmt::Nval(actual_dump_size)),
               keyval("DumpFile", fmt::Qstr(actual_dump_file_path)),
               keyval("SHA256", fmt::Qstr(actual_checksum)),
               keyval("DumpID", fmt::Nval(actual_dump_id)),
               keyval("MetaFile", fmt::Qstr(actual_metafile)),
               keyval("TrapPA", fmt::Xval(trap_info->trap_pa)),
               keyval("GFN", fmt::Xval(trap_info->trap->memaccess.gfn))
              );
}

/**
 * Frees all elements of the dump_metadata that are stored at the heap.
 * @param dump_metadata the metadata which elements shall be freed.
 */
void free_all(dump_metadata_struct* dump_metadata)
{
    if (dump_metadata->file_stem)
    {
        free(dump_metadata->file_stem);
    }
    if (dump_metadata->dump_file)
    {
        free(dump_metadata->dump_file);
    }
    if (dump_metadata->meta_file)
    {
        free(dump_metadata->meta_file);
    }
    if (dump_metadata->vad_name)
    {
        vmi_free_unicode_str(dump_metadata->vad_name);
    }
    g_free((gpointer) dump_metadata->sha256sum);
    g_free(dump_metadata);
}

/**
 * Dumps the memory specified by access context, from `ctx->addr` (first byte) to `ctx->addr + len_bytes - 1` (last byte).
 * Code is based on memdump.cpp
 *
 * Similar to the dump_memory_region-code in the memdump plugin.
 * @param vmi the current vmi instance for accessing the guest
 * @param plugin
 * @param ctx the memory access context
 * @param dump_metadata containing the dump size and the dump file path
 * @return if the dump was successful or not
 */
bool
dump_memory_region(vmi_instance_t vmi, codemon* plugin, access_context_t* ctx, dump_metadata_struct* dump_metadata)
{
    bool dump_success = false;

    void** access_ptrs = nullptr;
    FILE* fp = nullptr;

    addr_t aligned_addr;
    addr_t intra_page_offset;
    size_t aligned_len;
    size_t len_remainder;
    size_t num_pages;
    size_t tmp_len_bytes = dump_metadata->dump_size;

    aligned_addr = ctx->addr & ~(VMI_PS_4KB - 1);
    intra_page_offset = ctx->addr & (VMI_PS_4KB - 1);

    aligned_len = dump_metadata->dump_size & ~(VMI_PS_4KB - 1);
    len_remainder = dump_metadata->dump_size & (VMI_PS_4KB - 1);

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
        PRINT_DEBUG("[CODEMON] Failed mmap guest\n");
        goto error;
    }

    //w just overrides the current file, if there is one.
    fp = fopen(plugin->tmp_file_path, "w");

    if (!fp)
    {
        PRINT_DEBUG("[CODEMON] Failed to open dump.tmp file\n");
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

    if (rename(plugin->tmp_file_path, dump_metadata->dump_file) != 0)
    {
        PRINT_DEBUG("[CODEMON] Failed to rename dump file\n");
        goto error;
    }

    dump_success = true;
    goto done;

error:
    PRINT_DEBUG("[CODEMON] Failed to dump memory\n");

done:
    if (access_ptrs)
    {
        g_free(access_ptrs);
    }

    return dump_success;
}

/**
 * Constructs the paths of the dump_file and meta_file
 * @param dump_dir the directory to save the files to.
 * @param dump_metadata the struct containing the file_stem
 * @return if the creation was successful
 */
bool set_dump_paths(const char* dump_dir, dump_metadata_struct* dump_metadata)
{
    //using a suffix as "vad", "page" or (for the metafile) "metadata" helps to quickly select associated files
    if (asprintf(&dump_metadata->meta_file, "%s/%s.metafile", dump_dir, dump_metadata->file_stem) < 0)
    {
        PRINT_DEBUG("[CODEMON] Could not create meta file name\n");
        return false;
    }
    auto file_extension = dump_vad ? "vad" : "page";
    if (asprintf(&dump_metadata->dump_file, "%s/%s.%s", dump_dir, dump_metadata->file_stem, file_extension)
        < 0)
    {
        PRINT_DEBUG("[CODEMON] Could not create memory dump file name\n");
        return false;
    }
    return true;
}

/**
 * Method to get the sha256 hash of a memory area. Similar to the dump_memory_region-code in the memdump.cpp plugin.
 * @param vmi the current vmi instance for the guest access
 * @param ctx the memory access context
 * @param dump_metadata containing the dump size and the dump file path
 */
void get_sha256_memory(
    vmi_instance_t vmi,
    access_context_t* ctx,
    dump_metadata_struct* dump_metadata)
{
    void** access_ptrs = nullptr;

    const gchar* sha256sum = nullptr;
    GChecksum* checksum = nullptr;

    addr_t aligned_addr;
    addr_t intra_page_offset;
    size_t aligned_len;
    size_t len_remainder;
    size_t num_pages;
    size_t tmp_len_bytes = dump_metadata->dump_size;

    aligned_addr = ctx->addr & ~(VMI_PS_4KB - 1);
    intra_page_offset = ctx->addr & (VMI_PS_4KB - 1);

    aligned_len = dump_metadata->dump_size & ~(VMI_PS_4KB - 1);
    len_remainder = dump_metadata->dump_size & (VMI_PS_4KB - 1);

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
        PRINT_DEBUG("[CODEMON] Failed mmap guest\n");
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

    //The returned string is owned by the checksum and should not be modified or freed. (glib-Data-Checksums @ gnome.org)
    sha256sum = g_checksum_get_string(checksum);
    goto done;

error:
    PRINT_DEBUG("[CODEMON] Failed to calculate checksum\n");

done:
    //The returned string should be freed with g_free() when no longer needed.(glib-String-Utility-Functions @ gnome.org)
    //If chk_str is null, it also returns null
    dump_metadata->sha256sum = g_strdup(sha256sum);

    g_checksum_free(checksum);

    //If the gpointer is null, it just returns.
    g_free(access_ptrs);
}

/**
 * This sets up the access_context which is used to dump/access memory of the guest. It can differ between vad and page mode.
 * @param mmvad the obtained mmvad information
 * @param cr3 the value of the cr3 register
 * @param page_va the current used page va
 * @param dump_metadata required to store the memory dump size
 * @param ctx_memory_dump the created object used for dumping
 * @return false, if the context was not generated as the vad node was too big.
 */
bool setup_dump_context(mmvad_info_t mmvad,
                        uint64_t cr3,
                        addr_t page_va,
                        dump_metadata_struct* dump_metadata,
                        access_context_t* ctx_memory_dump)
{
    //Translate addr via specified directory table base.
    ctx_memory_dump->translate_mechanism = VMI_TM_PROCESS_DTB;
    //The CR3 reg stores the address to the directory table base
    ctx_memory_dump->dtb = cr3;
    //Required to be set to "null"
    ctx_memory_dump->ksym = nullptr;
    ctx_memory_dump->pid = 0;

    //Option to dump the whole VAD node instead of just a single page
    if (dump_vad)
    {
        //Prevents the dump of very big vad nodes. This might happen if a 32bit program gets executed. SYSWOW64 creates
        // a large fake vad entry to prevent the memory allocator to allocate addresses above the 32bit boundary.
        //I was told this workaround shall be corrected in further versions.
        //TODO FutureWork: Further aspects to consider: This workaround makes the DUMP_VAD mode faster, but discards also too large
        // DLLs from being dumped. Maybe some heuristics could be set up to handle this. e.g. if vad is memory mapped
        // file, monitor it at filesystem level and dump first time and later only if changed?
        if (mmvad.ending_vpn - mmvad.starting_vpn + 1 >= 1024)
        {
            PRINT_DEBUG("[CODEMON] Ignoring the dump of too large vad node\n");
            return false;
        }

        //Set the area to dump for vad or page (below-else)
        ctx_memory_dump->addr = mmvad.starting_vpn * VMI_PS_4KB; //Calculate the dump_size
        dump_metadata->dump_size = (mmvad.ending_vpn - mmvad.starting_vpn + 1) * VMI_PS_4KB;
    }
    else
    {
        ctx_memory_dump->addr = page_va; //The page va to lookup.
        dump_metadata->dump_size = VMI_PS_4KB;
    }
    return true;
}

/**
 * Extracts the name of the current analysed vad node.
 * - Commonly this is some mapped file, like a dll. If no name was extracted leave it as nullptr
 * @param vmi the current vmi instance for the guest access
 * @param file_name_ptr the pointer of the filename which is contained in a mmvad struct
 * @param dump_metadata storing the vad node name
 * @return if the extraction was successful or not
 */
bool retrieve_and_filter_vad_name(const vmi_lock_guard& vmi, addr_t file_name_ptr, dump_metadata_struct* dump_metadata)
{
    //Read the name of the dll/binary this node belongs to
    dump_metadata->vad_name = drakvuf_read_unicode_va(vmi, file_name_ptr, 0);

    if (dump_metadata->vad_name != nullptr)
    {
        //If we don't want to analyse the vad belonging to system files:
        if (!analyse_system_dll_vad)
        {
            //Exclude current memory area from analysis, if instructions are fetched from a System32 or SysWOW64 DLL

            //TODO FutureWork: In general it might be not secure to discard these DLLs since a malware might be able to
            // place DLLs here as well.
            if (strstr((char*) dump_metadata->vad_name->contents, "System32") != nullptr)
            {
                PRINT_DEBUG("[CODEMON] Ignoring instruction fetch within System32 DLL\n");
                return false;
            }
            if (strstr((char*) dump_metadata->vad_name->contents, "SysWOW64") != nullptr)
            {
                PRINT_DEBUG("[CODEMON] Ignoring instruction fetch within SysWOW64 DLL\n");
                return false;
            }
        }
    }

    return true;
}

/**
 * Uses information from the current trap data to determine which memory area to analyse.
 * Depending of the settings, this memory is dumped and could be analysed for malware.
 *
 * @param drakvuf the current drakvuf instance
 * @param vmi the current vmi instance for the guest access
 * @param trap_info contains information regarding the current activation of the trap like register values, timestamps, ...
 * @param fault_data the struct with the fault data
 * @param dump_metadata storing all extracted data
 * @return if malware was detected or not. this is currently a not included feature, but part of future work (or could be implemented by oneself)
 */
bool analyse_memory(drakvuf_t drakvuf,
                    const vmi_lock_guard& vmi,
                    const drakvuf_trap_info_t* trap_info,
                    const fault_data_struct* fault_data,
                    dump_metadata_struct* dump_metadata)
{
    //A struct to keep the vad node information
    mmvad_info_t mmvad;

    //initial value for malware. This can be set by an optional integrated classifier. If this is set to true (or during the execution of this method), the page dump will be stored always.
    //TODO FutureWork: if the classifier is integrated, set it to false by default, and let this be set by the classifier
    bool malware = !default_benign;

    //Finds the correct mmvad entry by VAD-Table walk and return it within mmvad. proc_data.base_addr is the EPROCESS address and frame va the address which shall be contained within the vad entry.
    if (!drakvuf_find_mmvad(drakvuf, trap_info->proc_data.base_addr, fault_data->page_va, &mmvad))
    {
        //If there was an error during vad search, quit but log all information
        PRINT_DEBUG("[CODEMON] Could not find vad information\n");
        return false;
    }

    //Derive the vad node start and end virtual address
    dump_metadata->vad_node_base = mmvad.starting_vpn << 12;
    dump_metadata->vad_node_end = ((mmvad.ending_vpn + 1) << 12) - 1;

    bool is_interesting_node = retrieve_and_filter_vad_name(vmi, mmvad.file_name_ptr, dump_metadata);
    if (!is_interesting_node)
    {
        //debug message within retrieve_and_filter_vad_name
        //Don't load further information, but output the already extracted data.
        return malware;
    }

    //Set the memory access context
    access_context_t ctx_memory_dump;
    bool dump_ctx_valid =
        setup_dump_context(mmvad, trap_info->regs->cr3, fault_data->page_va, dump_metadata, &ctx_memory_dump);

    if (!dump_ctx_valid)
    {
        //debug message within retrieve_and_filter_vad_name
        return malware;
    }

    // TODO FutureWork:
    //  - Hashing of the whole VAD node is a bottleneck since it could be 1000s of pages.
    //  - Combined with the aspect that a dll is not loaded at once, but partially (when needed) the hashing is not
    //    useful right now. Maybe drakvuf can somehow trigger that the dll is loaded completely in one step? Or even use
    //    heuristics to monitor the dll on a filesystem basis?

    //For pages this approach is good.

    //get the hash
    //    The checksum of the current analyzed memory (vad or page)
    get_sha256_memory(vmi, &ctx_memory_dump, dump_metadata);
    if (dump_metadata->sha256sum == nullptr)
    {
        PRINT_DEBUG("[CODEMON] Could not get SHA256 of dumpfile\n");
        return malware;
    }

    //Generate the file stem
    if (asprintf(&dump_metadata->file_stem,
                 "%llx_%.16s",
                 (unsigned long long) ctx_memory_dump.addr,
                 dump_metadata->sha256sum)
        < 0)
    {
        PRINT_DEBUG("[CODEMON] Could not create the file stem\n");
        return malware;
    }

    //Set the metadata and dumpfile path
    if (!set_dump_paths(fault_data->plugin->dump_dir.c_str(),
                        dump_metadata))
    {
        //debug message within set_dump_paths
        return malware;
    }

    //Is used to find a checksum in the set of already analyzed memory parts
    auto memory_hash_identifier = fault_data->plugin->dumped_memory_map.find(dump_metadata->sha256sum);

    //If the checksum already exists:
    if (memory_hash_identifier != fault_data->plugin->dumped_memory_map.end())
    {
        //Make sure the two file stems match
        if (strcmp(memory_hash_identifier->second.c_str(), dump_metadata->file_stem) == 0)
        {
            //Increase the dump counter in this special case
            ++fault_data->plugin->dump_id;
            return malware;
        }
        else
        {
            //since there were problems with the file stem, continue to dump all data again
            PRINT_DEBUG("[CODEMON] Could not reuse data from previously saved data, dumping again\n");
        }

        //If the flow continues here, there was an or with the stored data. Dump the data again.
    }

    //At this point I use a yet unpublished tool from Politecnico di Milano (IT) to analyse the accessed memory page for API calls. This information is used within a malware classifier.
    //TODO FutureWork  malware = malware_classifier(...)

    //If malware was detected or manually switched to always dump
    if (malware)
    {
        // Comment from memdump.cpp:
        // The file name format for the memory dump file is:
        // <dump base address>_<16 chars of hash>
        // This was set in order to satisfy the following issue:
        // * when disassembling, it is required to know the dump's image base, here it could be obtained
        //   just by looking at the file name which is handy both for humans and automated processing
        // * no other information was included in the file name to make it possible to reference this file in the
        //   future if the identical memory would be dumped again

        //If the dump fails
        if (!dump_memory_region(vmi,
                                fault_data->plugin,
                                &ctx_memory_dump,
                                dump_metadata))
        {
            PRINT_DEBUG("[CODEMON] Could not dump memory\n");
            if (dump_metadata->dump_file)
            {
                g_free(dump_metadata->dump_file);
                dump_metadata->dump_file = nullptr;
            }
            return malware;
        }

        //If the dump was successful: increase the dump counter
        ++fault_data->plugin->dump_id;

        //Add the checksum as key with the file_name_prefix (as data) to the map.
        fault_data->plugin->dumped_memory_map.insert(std::make_pair(dump_metadata->sha256sum,
                dump_metadata->file_stem));


        //If the dump of the memory was successful write all gathered data to a metadata file
        save_file_metadata(trap_info, dump_metadata, fault_data);
    }
    return malware;
}

/**
 * This code frees memory belonging to a certain trap.
 * It is called at the time a trap is removed. drakvuf_remove_trap will not remove a trap instantly but sort of schedules the remove.
 * Thus, if freeing the trap and trap->data instantly after drakvuf_remove_trap was called, this might lead to a use-after-free error.
 * This is why drakvuf_remove_trap has a callback option (third argument->using this callback) to set what has to be done when the trap is actually removed.
 *
 * @param trap the trap which memory shall be freed
 */
static void remove_trap_cb(drakvuf_trap_t* trap)
{
    g_free(trap->data);
    g_free(trap);
}

void swap_traps(drakvuf_t drakvuf,
                drakvuf_trap_info* trap_info,
                fault_data_struct* fault_data)
{
    drakvuf_trap* write_trap = create_write_trap(trap_info, fault_data);
    if (write_trap)
    {
        //Add and activate the trap
        if (drakvuf_add_trap(drakvuf, write_trap))
        {
            //store the trap that it can be deleted in the end.
            fault_data->plugin->traps.emplace(write_trap);

            //Removes this current execute trap and frees the memory
            fault_data->plugin->traps.erase(trap_info->trap);
            drakvuf_remove_trap(drakvuf, trap_info->trap, remove_trap_cb);

            PRINT_DEBUG("[CODEMON] Replaced execute trap X on GFN 0x%lx with write trap W\n",
                        trap_info->trap->memaccess.gfn);
        }
        else
        {
            //If the trap was not added, keep the current exec trap
            PRINT_DEBUG(
                "[CODEMON] Failed to add write trap W on GFN 0x%lx. Keeping execute trap X\n",
                trap_info->trap->memaccess.gfn);
        }
    }
    else
    {
        PRINT_DEBUG(
            "[CODEMON] Failed to create write trap W. Keeping execute trap X on GFN 0x%lx\n",
            trap_info->trap->memaccess.gfn);
    }
}

/**
* This is the callback of the write trap. If an instruction write got detected on a monitored page, this callback is executed
* @param drakvuf the drakvuf plugin
* @param trap_info information regarding the trap event
* @return VMI_EVENT_RESPONSE_NONE, but this return information is currently not used by drakvuf.
*/
static event_response_t write_faulted_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info)
{
    //load the passed fault data from the trap information
    auto* fault_data = (struct fault_data_struct*) trap_info->trap->data;

    if (log_everything)
    {
        fmt::print(fault_data->plugin->m_output_format, "codemon", drakvuf, trap_info,
                   keyval("EventType", fmt::Qstr("writefault")),
                   keyval("FrameVA", fmt::Xval(fault_data->page_va)),
                   keyval("TrapPA", fmt::Xval(trap_info->trap_pa)),
                   keyval("CR3", fmt::Xval(trap_info->regs->cr3)),
                   keyval("GFN", fmt::Xval(trap_info->trap->memaccess.gfn))
                  );
    }

    //Create the new exec trap
    drakvuf_trap* exec_trap = create_execute_trap(trap_info->trap->memaccess.gfn, fault_data);
    if (exec_trap)
    {
        //Add and activate the exec trap
        if (drakvuf_add_trap(drakvuf, exec_trap))
        {
            //store the trap that it can be deleted in the end.
            fault_data->plugin->traps.emplace(exec_trap);

            //Removes this current execute trap and frees the memory
            fault_data->plugin->traps.erase(trap_info->trap);
            drakvuf_remove_trap(drakvuf, trap_info->trap, remove_trap_cb);

            PRINT_DEBUG("[CODEMON] Replaced write trap W on GFN 0x%lx with execute trap X\n",
                        trap_info->trap->memaccess.gfn);
        }
        else
        {
            //If the trap was not added, keep the current write trap
            PRINT_DEBUG(
                "[CODEMON] Failed to add execute trap X on GFN 0x%lx. Keeping write trap W\n",
                trap_info->trap->memaccess.gfn);
        }
    }
    else
    {
        PRINT_DEBUG(
            "[CODEMON] Failed to create exec trap X. Keeping write trap W on GFN 0x%lx\n",
            trap_info->trap->memaccess.gfn);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * Creates a write trap, whose pointer is returned.
 *
 * @param trap_info
 * @param fault_data_old
 */
drakvuf_trap_t* create_write_trap(drakvuf_trap_info_t* trap_info, fault_data_struct* fault_data_old)
{

    //Use g_try_malloc0 to zero the allocated heap memory at first. This prevents any undefined behaviour as fields of the
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
    write_trap->memaccess.gfn = trap_info->trap->memaccess.gfn;
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
* This is the callback of the execute trap. If an instruction fetch got detected on a monitored page, this callback is executed
* @param drakvuf the drakvuf plugin
* @param trap_info information regarding the trap event
* @return VMI_EVENT_RESPONSE_NONE, but this return information is currently not used by drakvuf.
*/
static event_response_t execute_faulted_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info)
{
    PRINT_DEBUG("[CODEMON] Caught X on PA 0x%lx, frame VA %llx, CR3 %lx\n", trap_info->trap_pa,
                (unsigned long long) trap_info->regs->rip, trap_info->regs->cr3);

    //load the trap data
    auto* fault_data = (struct fault_data_struct*) trap_info->trap->data;

    //Verify the program leading to the execution of this trap is the one we are filtering for (if we do).
    //The filtering could limit (and therefore focus) the monitoring and gives a speedup in such possibly uninteresting cases.
    // If it does not match the filter, delete this trap (and don't replace it)
    if (fault_data->plugin->filter_executable[0])
    {
        if (strcasestr(trap_info->proc_data.name, fault_data->plugin->filter_executable) == NULL)
        {
            //Removes this trap and frees the memory
            fault_data->plugin->traps.erase(trap_info->trap);
            drakvuf_remove_trap(drakvuf, trap_info->trap, remove_trap_cb);
            PRINT_DEBUG("[CODEMON] Removed filtered trap for PA 0x%lx", trap_info->trap_pa);
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    //Allocate memory on the heap for a struct to store all dump relevant information
    auto* dump_metadata = (struct dump_metadata_struct*) g_try_malloc0(sizeof(struct dump_metadata_struct));
    if (dump_metadata)
    {
        //Lock the VM
        auto vmi = vmi_lock_guard(drakvuf);

        //Dump memory and check for malware
        bool malware = analyse_memory(drakvuf, vmi, trap_info, fault_data, dump_metadata);

        //Log information if required
        if (log_everything || malware)
        {
            log_all_to_console(drakvuf, trap_info, dump_metadata, fault_data);
        }
        swap_traps(drakvuf, trap_info, fault_data);
        free_all(dump_metadata);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * Creates an execute trap for the given (guest) frame number and passes the given fault data
 * @param gfn the (guest) frame number. If some executable instructions are fetched from this frame, the trap gets active
 * @param fault_data_old information which is required for logging. It is passed between the traps.
 * @return the execute trap that needs to be added to drakvuf
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
 * This method is called when the mmAccessFault handler returns, right before the actual code execution continues.
 * It is used to grab the physical address, that got assigned to the virtual
 * This method is based on the code of the IPT plugin
 */
static event_response_t mm_access_fault_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info)
{
    //Loads a pointer to the plugin, which is responsible for the trap (in this case -> codemon2)
    auto plugin = get_trap_plugin<codemon>(trap_info);

    //get_trap_params reinterprets the pointer of info->trap->data as a pointer to access_fault_result_t
    auto params = get_trap_params<access_fault_result_t>(trap_info);

    //Verifies that the params we got above (preset by the previous trap) match the trap_information this cb got called with.
    //This is used, if the trap (e.g. a shared dll) is risen by another process which fetches accidentally instructions from this page as well
    if (!params->verify_result_call_params(drakvuf, trap_info))
    {
        PRINT_DEBUG("[CODEMON] info & thread parameters did not match\n");
        return VMI_EVENT_RESPONSE_NONE;
    }


    //Calculate the frame's starting virtual address from the fault_va by clearing the lower 12 bits.
    addr_t page_va = ((params->fault_va >> 12) << 12);

    //Create an identifier for each monitored memory part. That is a combination of the CR3 register and the page_va.
    //As the exec trap will be replaced by a write trap and vice-versa (and not be removed once hit to keep focus on that page) it is required to prevent adding multiple traps for the same memory areas.
    //Even page_va and gfn relate the page_va is used as identifier, since the gfn would require an additional translation from va to pa, which would cost additional time.
    std::pair<addr_t, addr_t> monitored_page_identifier(trap_info->regs->cr3, page_va);

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
            if (VMI_SUCCESS != vmi_pagetable_lookup_extended(vmi, trap_info->regs->cr3, params->fault_va, &p_info))
            {
                PRINT_DEBUG("[CODEMON] failed to lookup page info\n");
                plugin->destroy_trap(trap_info->trap);
                return VMI_EVENT_RESPONSE_NONE;
            }
        }

        //Print out all previous gathered information.
        if (log_everything)
        {
            fmt::print(plugin->m_output_format, "codemon", drakvuf, trap_info,
                       keyval("EventType", fmt::Qstr("pagefault")),
                       keyval("CR3", fmt::Xval(trap_info->regs->cr3)),
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
                    PRINT_DEBUG("[CODEMON] Set up execute trap X on GFN 0x%lx\n", trap_info->trap->memaccess.gfn);
                }
                else
                {
                    //If the trap was not added successfully
                    //Can't keep trap since it is specific for the RIP
                    PRINT_DEBUG(
                        "[CODEMON] Failed to add execute trap X on GFN 0x%lx. Deleting mmAccessFault Return Trap\n",
                        trap_info->trap->memaccess.gfn);
                }
            }
            else
            {
                PRINT_DEBUG(
                    "[CODEMON] Failed to create execute trap X. Not monitoring GFN 0x%lx\n",
                    trap_info->trap->memaccess.gfn);
            }
        }
        else
        {
            PRINT_DEBUG(
                "[CODEMON] Failed to allocate memory for fault_data. Not monitoring GFN 0x%lx\n",
                trap_info->trap->memaccess.gfn);
        }

    }

    //Destroys this return trap, because it is specific for the RIP and not usable anymore. This was the trap being called when the physical address got computed.
    //Deletes this trap from the list of existing traps traps
    //Additionally removes the trap and frees the memory
    plugin->destroy_trap(trap_info->trap);

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
static event_response_t mm_access_fault_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info)
{

    //Load the plugin object.
    auto plugin = get_trap_plugin<codemon>(trap_info);

    //Checks if a filter was set and applies it:
    //This applies only to the trap set up. If the program dies in the meantime, the trap continues and might rise the
    // callback even if another program is triggering it, since all depends only on the guest frame number.
    if (plugin->filter_executable)
    {
        //Use NULL when calling C functions.
        if (strcasestr(trap_info->proc_data.name, plugin->filter_executable) == NULL)
        {
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    //The first argument is the FaultStatus, and the second (rdx) the VirtualAddress which caused the fault.
    addr_t fault_va = drakvuf_get_function_argument(drakvuf, trap_info, 2);
    PRINT_DEBUG("[CODEMON] Caught MmAccessFault(%d, %lx)\n", trap_info->proc_data.pid, fault_va);

    //The kernel space starts with 0xFFFF... and higher.  User space is within 0x0000F... and below. If the trap was created by a kernel module we don't mind as we assume the integrity of the kernel.
    //https://www.codemachine.com/article_x64kvas.html: The upper 16 bits of virtual addresses are always set to 0x0 for user mode addresses and to 0xF for kernel mode addresses
    //Checks if the highest bit (bit 64) = 1000...000 is one or not. If it is one, this must be part of the kernel, since it would has to be 0 for the user mode.
    if (fault_va & (1ULL << 63))
    {
        PRINT_DEBUG("[CODEMON] Don't trap in kernel %d %lx\n", trap_info->proc_data.pid, fault_va);
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
                    trap_info,
                    mm_access_fault_return_hook_cb,
                    breakpoint_by_pid_searcher());

    //If trap creation failed
    if (!trap)
    {
        PRINT_DEBUG("[CODEMON] Could not create accessFaultReturnTrap\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    //After the trap got constructed, enrich its details already with some information we already (and just) know here (at this point).

    //access_fault_result_t extends from call_result_t which extends from plugin_params
    //get_trap_params reinterprets the pointer of trap->data as a pointer to access_fault_result_t
    //Load the information that is saved by hitting the first trap.
    //With params we can preset the params that the newly risen second breakpoint will receive.
    auto params = get_trap_params<access_fault_result_t>(trap);

    //Save the address of the target thread, address of the rsp (this was the rip-address, which we used for construction) and the value of the CR3 register to the params.
    params->set_result_call_params(trap_info);

    //enrich the params of the new/next trap with the information which fault virtual address resulted in the fault. This information is used later.
    params->fault_va = fault_va;

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * This is the constructor of the plugin.
 */
codemon::codemon(drakvuf_t
                           drakvuf,
                           const codemon_config_struct* c, output_format_t
                           output)
    : pluginex(drakvuf, output)
{

    //Check if the dump directory parameter was provided
    if (!c->codemon_dump_dir)
    {
        PRINT_DEBUG("[CODEMON] Output directory for dumps not provided, not activating codemon plugin\n");
        return;
    }

    //Load the filter if existing
    if (c->codemon_filter_executable)
    {
        this->filter_executable = c->codemon_filter_executable;
    }

    //get the output dir from the config arguments
    this->dump_dir = c->codemon_dump_dir;

    //Check if the dump directory exists
    if (!std::filesystem::exists(this->dump_dir))
    {
        PRINT_DEBUG("[CODEMON] The output directory is no valid/existing path, not activating codemon plugin\n");
        return;
    }

    //Construct the full frame dump directory by appending /dumps/ and create the folder if not yet existing.
    this->dump_dir /= "dumps";

    //Creates the dump folder
    int res = mkdir(this->dump_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (res != 0 && errno != EEXIST)
    {
        PRINT_DEBUG("[CODEMON] Failed to create dump directory %s\n", this->dump_dir.c_str());
        return;
    }

    //Create the default dump file name
    if (asprintf(&this->tmp_file_path, "%s/dump.tmp", this->dump_dir.c_str()) < 0)
    {
        PRINT_DEBUG("[CODEMON] Failed to build the string containing the temp_file_path\n");
        return;
    }

    //Load argument settings
    log_everything = c->codemon_log_everything;
    dump_vad = c->codemon_dump_vad;
    analyse_system_dll_vad = c->codemon_analyse_system_dll_vad;
    default_benign = c->codemon_default_benign;

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
codemon::~codemon()
{
    for (const auto trap: traps)
    {
        g_free(trap->data);
        g_free(trap);
    }
    free(this->tmp_file_path);
}
