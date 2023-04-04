/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2023 Tamas K Lengyel.                                  *
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

#include <cinttypes>
#include <sys/stat.h>
#include <libvmi/libvmi.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <fstream>

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

// See codemon.h -> codemon_config_struct
static bool log_everything = false;
static bool dump_vad = false;
static bool analyse_system_dll_vad = false;
static bool default_benign = false;

/**
 * Saves the metadata received during the monitoring to a logfile
 *
 * @param trap_info the trap information
 * @param dump_metadata data to be logged gathered during the analysis
 * @param page_va virtual address of page
 */
void codemon::save_file_metadata(const drakvuf_trap_info_t* trap_info, const dump_metadata_struct* dump_metadata, addr_t page_va)
{
    auto output_file = std::ofstream{dump_metadata->meta_file};
    if (!output_file)
    {
        PRINT_DEBUG("[CODEMON] ERROR: failed to open metadata file (%s), this shouldn't happen!\n", dump_metadata->meta_file);
        return;
    }

    //Determines the string that shall be printed as vad_name
    char* actual_vad_name;
    if (dump_metadata->vad_name == nullptr)
        actual_vad_name = alloc_memory;
    else
        actual_vad_name = (char*) dump_metadata->vad_name->contents;

    json_object* json_object = json_object_new_object();
    auto timestamp = TimeVal{UNPACK_TIMEVAL(trap_info->timestamp)};
    json_object_object_add(json_object, "TimeStamp", json_object_new_string_fmt("%ld.%ld", timestamp.tv_sec, timestamp.tv_usec));
    json_object_object_add(json_object, "PID", json_object_new_int(trap_info->attached_proc_data.pid));
    json_object_object_add(json_object, "PPID", json_object_new_int(trap_info->attached_proc_data.ppid));
    json_object_object_add(json_object, "TID", json_object_new_int(trap_info->attached_proc_data.tid));
    json_object_object_add(json_object, "UserID", json_object_new_int(trap_info->attached_proc_data.userid));
    json_object_object_add(json_object, "ProcessName", json_object_new_string(trap_info->attached_proc_data.name));
    json_object_object_add(json_object, "EventUID", json_object_new_int64(trap_info->event_uid));
    json_object_object_add(json_object, "CR3", json_object_new_string_fmt("0x%" PRIx64, trap_info->regs->cr3));
    json_object_object_add(json_object, "PageVA", json_object_new_string_fmt("0x%" PRIx64, page_va));
    json_object_object_add(json_object, "VADBase", json_object_new_string_fmt("0x%" PRIx64, dump_metadata->vad_node_base));
    json_object_object_add(json_object, "VADEnd", json_object_new_string_fmt("0x%" PRIx64, dump_metadata->vad_node_end));
    json_object_object_add(json_object, "VADName", json_object_new_string(actual_vad_name));
    json_object_object_add(json_object, "DumpSize", json_object_new_string_fmt("0x%" PRIx64, dump_metadata->dump_size));
    json_object_object_add(json_object, "DumpFile", json_object_new_string(dump_metadata->dump_file));
    json_object_object_add(json_object, "SHA256", json_object_new_string(dump_metadata->sha256sum));
    json_object_object_add(json_object, "DumpID", json_object_new_int(this->dump_id));
    json_object_object_add(json_object, "TrapPA", json_object_new_string_fmt("0x%" PRIx64, trap_info->trap_pa));
    json_object_object_add(json_object, "GFN", json_object_new_string_fmt("0x%" PRIx64, trap_info->trap->memaccess.gfn));

    output_file << json_object_get_string(json_object);
    json_object_put(json_object);
}

/**
 * Prints all information of a dump to the console
 * @param trap_info contains information regarding the current activation of the trap like register values, timestamps, ...
 * @param dump_metadata the struct containing the dump metadata
 * @param page_va virtual address of page
 */
void codemon::log_all_to_console(const drakvuf_trap_info* trap_info, dump_metadata_struct* dump_metadata, addr_t page_va)
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
        actual_dump_id = this->dump_id;
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
    fmt::print(this->m_output_format, "codemon", this->drakvuf, trap_info,
        keyval("EventType", fmt::Qstr("execframe")),
        keyval("CR3", fmt::Xval(trap_info->regs->cr3)),
        keyval("PageVA", fmt::Xval(page_va)),
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
bool dump_memory_region(vmi_instance_t vmi, codemon* plugin, access_context_t* ctx, dump_metadata_struct* dump_metadata)
{
    bool dump_success = false;

    void** access_ptrs = nullptr;

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

    {
        // add scope to close file, since we want to rename it
        auto output_file = std::ofstream{plugin->tmp_file_path.c_str()};
        if (!output_file)
        {
            PRINT_DEBUG("[CODEMON] ERROR: Failed to open tmp dump file (%s), this shouldn't happen!\n", plugin->tmp_file_path.c_str());
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
                output_file.write((char*) access_ptrs[i] + intra_page_offset, write_length);
                munmap(access_ptrs[i], VMI_PS_4KB);
            }
            else
            {
                // inaccessible page, pad with zeros to ensure proper alignment of the data
                uint8_t zeros[VMI_PS_4KB] = {};
                output_file.write((char*) zeros + intra_page_offset, write_length);
            }

            // this applies only to the first page
            intra_page_offset = 0;
            tmp_len_bytes -= write_length;
        }
    }

    if (rename(plugin->tmp_file_path.c_str(), dump_metadata->dump_file) != 0)
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
    if (asprintf(&dump_metadata->dump_file, "%s/%s.%s", dump_dir, dump_metadata->file_stem, file_extension) < 0)
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
void get_sha256_memory(vmi_instance_t vmi, access_context_t* ctx, dump_metadata_struct* dump_metadata)
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
 * @param drakvuf the current drakvuf instance for the guest access
 * @param file_name_ptr the pointer of the filename which is contained in a mmvad struct
 * @param dump_metadata storing the vad node name
 * @return if the extraction was successful or not
 */
bool retrieve_and_filter_vad_name(drakvuf_t drakvuf, addr_t file_name_ptr, dump_metadata_struct* dump_metadata)
{
    //Read the name of the dll/binary this node belongs to
    dump_metadata->vad_name = drakvuf_read_unicode_va(drakvuf, file_name_ptr, 0);

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
 * @param trap_info contains information regarding the current activation of the trap like register values, timestamps, ...
 * @param dump_metadata storing all extracted data
 * @param page_va virtual address of page
 * @return if malware was detected or not. this is currently a not included feature, but part of future work (or could be implemented by oneself)
 */
bool codemon::analyse_memory(const drakvuf_trap_info_t* trap_info, dump_metadata_struct* dump_metadata, addr_t page_va)
{
    auto vmi = vmi_lock_guard(this->drakvuf);

    //A struct to keep the vad node information
    mmvad_info_t mmvad;

    //initial value for malware. This can be set by an optional integrated classifier. If this is set to true (or during the execution of this method), the page dump will be stored always.
    //TODO FutureWork: if the classifier is integrated, set it to false by default, and let this be set by the classifier
    bool malware = !default_benign;

    //Finds the correct mmvad entry by VAD-Table walk and return it within mmvad. proc_data.base_addr is the EPROCESS address and frame va the address which shall be contained within the vad entry.
    if (!drakvuf_find_mmvad(drakvuf, trap_info->proc_data.base_addr, page_va, &mmvad))
    {
        //If there was an error during vad search, quit but log all information
        PRINT_DEBUG("[CODEMON] Could not find vad information\n");
        return false;
    }

    //Derive the vad node start and end virtual address
    dump_metadata->vad_node_base = mmvad.starting_vpn << 12;
    dump_metadata->vad_node_end = ((mmvad.ending_vpn + 1) << 12) - 1;

    bool is_interesting_node = retrieve_and_filter_vad_name(this->drakvuf, mmvad.file_name_ptr, dump_metadata);
    if (!is_interesting_node)
    {
        //debug message within retrieve_and_filter_vad_name
        //Don't load further information, but output the already extracted data.
        return malware;
    }

    //Set the memory access context
    ACCESS_CONTEXT(ctx_memory_dump);
    bool dump_ctx_valid = setup_dump_context(mmvad, trap_info->regs->cr3, page_va, dump_metadata, &ctx_memory_dump);

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
    if (!set_dump_paths(this->dump_dir.c_str(), dump_metadata))
    {
        //debug message within set_dump_paths
        return malware;
    }

    //Is used to find a checksum in the set of already analyzed memory parts
    auto memory_hash_identifier = this->dumped_memory_map.find(dump_metadata->sha256sum);

    //If the checksum already exists:
    if (memory_hash_identifier != this->dumped_memory_map.end())
    {
        //Make sure the two file stems match
        if (strcmp(memory_hash_identifier->second.c_str(), dump_metadata->file_stem) == 0)
        {
            PRINT_DEBUG("[CODEMON] Skipping dump as it %llx_%s exists\n", (unsigned long long) ctx_memory_dump.addr, dump_metadata->file_stem);
            //Increase the dump counter in this special case
            ++this->dump_id;
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
        PRINT_DEBUG("[CODEMON] dumping memory to %llx_%s\n", (unsigned long long) ctx_memory_dump.addr, dump_metadata->file_stem);

        // Comment from memdump.cpp:
        // The file name format for the memory dump file is:
        // <dump base address>_<16 chars of hash>
        // This was set in order to satisfy the following issue:
        // * when disassembling, it is required to know the dump's image base, here it could be obtained
        //   just by looking at the file name which is handy both for humans and automated processing
        // * no other information was included in the file name to make it possible to reference this file in the
        //   future if the identical memory would be dumped again

        //If the dump fails
        if (!dump_memory_region(vmi, this, &ctx_memory_dump, dump_metadata))
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
        ++this->dump_id;

        //Add the checksum as key with the file_name_prefix (as data) to the map.
        this->dumped_memory_map.insert(std::make_pair(dump_metadata->sha256sum, dump_metadata->file_stem));

        //If the dump of the memory was successful write all gathered data to a metadata file
        this->save_file_metadata(trap_info, dump_metadata, page_va);
    }
    else
    {
        PRINT_DEBUG("[CODEMON] not dumping from %llx as it's not considered as malware\n", (unsigned long long) ctx_memory_dump.addr);
    }

    return malware;
}

/**
* This is the callback of the write trap. If an instruction write got detected on a monitored page, this callback is executed
*/
event_response_t codemon::write_faulted_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info)
{
    auto params = libhook::GetTrapParams<AccessFaultResult>(trap_info);
    if (log_everything)
    {
        fmt::print(this->m_output_format, "codemon", drakvuf, trap_info,
            keyval("EventType", fmt::Qstr("writefault")),
            keyval("FrameVA", fmt::Xval(params->page_va)),
            keyval("TrapPA", fmt::Xval(trap_info->trap_pa)),
            keyval("CR3", fmt::Xval(trap_info->regs->cr3)),
            keyval("GFN", fmt::Xval(trap_info->trap->memaccess.gfn))
        );
    }

    //Create the new exec trap
    auto exec_hook = createMemAccessHook<AccessFaultResult>(&codemon::execute_faulted_cb, trap_info->trap->memaccess.gfn, PRE, VMI_MEMACCESS_X);
    if (!exec_hook)
    {
        PRINT_DEBUG("[CODEMON] Failed to create exec hook X. Keeping write trap W on GFN 0x%lx\n", trap_info->trap->memaccess.gfn);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto exec_hook_params = libhook::GetTrapParams<AccessFaultResult>(exec_hook->trap_);
    exec_hook_params->page_va = params->page_va;

    this->remove_memaccess_hook(trap_info);
    this->memaccess_hooks.insert(std::move(exec_hook));

    PRINT_DEBUG("[CODEMON] Replaced write hook on GFN 0x%lx with execute hook\n", trap_info->trap->memaccess.gfn);
    return VMI_EVENT_RESPONSE_NONE;
}

void codemon::remove_memaccess_hook(drakvuf_trap_info_t* trap_info)
{
    for (auto it = this->memaccess_hooks.begin(); it != this->memaccess_hooks.end(); ++it)
    {
        if ((*it)->trap_ == trap_info->trap)
        {
            // this is ok to erase element, while iterating over, since we instantly return and stop iteration
            this->memaccess_hooks.erase(it);
            return;
        }
    }

    PRINT_DEBUG("[CODEMON] attempted to remove a hook which doesn't exist, this should never happen\n");
    throw -1;
}

/**
* This is the callback of the execute trap. If an instruction fetch got detected on a monitored page, this callback is executed
* @param drakvuf the drakvuf plugin
* @param trap_info information regarding the trap event
* @return VMI_EVENT_RESPONSE_NONE
*/
event_response_t codemon::execute_faulted_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info)
{
    auto params = libhook::GetTrapParams<AccessFaultResult>(trap_info);
    PRINT_DEBUG("[CODEMON] Caught X on PA 0x%lx, frame VA 0x%lx, CR3 0x%lx\n", trap_info->trap_pa, trap_info->regs->rip, trap_info->regs->cr3);

    // Verify the program leading to the execution of this trap is the one we are filtering for (if we do).
    // The filtering could limit (and therefore focus) the monitoring and gives a speedup in such possibly uninteresting cases.
    // If it does not match the filter, delete this trap (and don't replace it)
    if (this->filter_executable)
    {
        if (strcasestr(trap_info->proc_data.name, (*this->filter_executable).c_str()) == NULL)
        {
            this->remove_memaccess_hook(trap_info);
            PRINT_DEBUG("[CODEMON] Removed filtered hook for PA 0x%lx", trap_info->trap_pa);
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    //Allocate memory on the heap for a struct to store all dump relevant information
    auto dump_metadata = std::make_unique<dump_metadata_struct>();
    if (!dump_metadata)
    {
        PRINT_DEBUG("[CODEMON] failed to allocate dump_metadata_struct, unhooking\n");
        this->remove_memaccess_hook(trap_info);
        return VMI_EVENT_RESPONSE_NONE;
    }

    bool malware = this->analyse_memory(trap_info, dump_metadata.get(), params->page_va);

    //Log information if required
    if (log_everything || malware)
        log_all_to_console(trap_info, dump_metadata.get(), params->page_va);

    auto write_hook = createMemAccessHook<AccessFaultResult>(&codemon::write_faulted_cb, trap_info->trap->memaccess.gfn, POST, VMI_MEMACCESS_W);
    if (!write_hook)
    {
        PRINT_DEBUG("[CODEMON] Failed to create write hook. Keeping execute hook on GFN 0x%lx\n", trap_info->trap->memaccess.gfn);
        free_all(dump_metadata.get());
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto write_hook_params = libhook::GetTrapParams<AccessFaultResult>(write_hook->trap_);
    write_hook_params->page_va = params->page_va;

    // Replace current execute hook with write hook
    this->memaccess_hooks.insert(std::move(write_hook));
    this->remove_memaccess_hook(trap_info);

    PRINT_DEBUG("[CODEMON] Replaced execute hook X on GFN 0x%lx with write hook W\n", trap_info->trap->memaccess.gfn);
    free_all(dump_metadata.get());

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * This method is called when the mmAccessFault handler returns, right before the actual code execution continues.
 * It is used to grab the physical address, that got assigned to the virtual
 */
event_response_t codemon::mm_access_fault_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info)
{
    auto params = libhook::GetTrapParams<AccessFaultResult>(trap_info);
    if (!params->verifyResultCallParams(drakvuf, trap_info))
        return VMI_EVENT_RESPONSE_NONE;

    // Calculate the frame's starting virtual address from the page_va by clearing the lower 12 bits.
    addr_t page_va = ((params->page_va >> 12) << 12);

    //Create an identifier for each monitored memory part.
    //As the exec trap will be replaced by a write trap and vice-versa (and not be removed once hit to keep focus on that page) it is required to prevent adding multiple traps for the same memory areas.
    //Even page_va and gfn relate the page_va is used as identifier, since the gfn would require an additional translation from va to pa, which would cost additional time.
    std::pair<addr_t, addr_t> monitored_page_identifier(trap_info->regs->cr3, page_va);

    //Try to find the current trap identifier in the set of existing traps.
    auto it = this->monitored_pages.find(monitored_page_identifier);

    //If the memory area is not monitored yet: Create a new trap for that.
    if (it == this->monitored_pages.end())
    {
        page_info_t p_info = {};
        {
            auto vmi = vmi_lock_guard(drakvuf);

            // Translates the virtual address to the direct physical address (not only the frame physical address)
            if (VMI_SUCCESS != vmi_pagetable_lookup_extended(vmi, trap_info->regs->cr3, params->page_va, &p_info))
            {
                // If we're in here that means we can't access page
                // check if this is the first time we're here for this address
                bool first_try = this->pf_in_progress.find(std::make_pair(params->target_pid, params->target_tid)) == this->pf_in_progress.end();

                if (!first_try)
                {
                    // if this isn't the first time, then we've already tried page faulting and it didn't help
                    PRINT_DEBUG("[CODEMON] Failed to load page via page fault, CR3=0x%lx, Addr=0x%lx\n", trap_info->regs->cr3, params->page_va);
                    this->pf_in_progress.erase(std::make_pair(params->target_pid, params->target_tid));
                    this->mmAccessFaultReturnHook.reset();
                    return VMI_EVENT_RESPONSE_NONE;
                }

                // this is our first try, so we page fault
                if (vmi_request_page_fault(vmi, trap_info->vcpu, params->page_va, 0) == VMI_SUCCESS)
                {
                    PRINT_DEBUG("[CODEMON] Failed to request page, performing page fault for CR3=0x%lx, Addr=0x%lx\n", trap_info->regs->cr3, params->page_va);
                    this->pf_in_progress.insert(std::make_pair(params->target_pid, params->target_tid));
                    return VMI_EVENT_RESPONSE_NONE;
                }
                else
                {
                    PRINT_DEBUG("[CODEMON] Failed to request page fault for CR3=0x%lx, Addr=0x%lx\n", trap_info->regs->cr3, params->page_va);
                    this->mmAccessFaultReturnHook.reset();
                    return VMI_EVENT_RESPONSE_NONE;
                }
            }
        }

        this->pf_in_progress.erase(std::make_pair(params->target_pid, params->target_tid));

        if (log_everything)
        {
            fmt::print(this->m_output_format, "codemon", drakvuf, trap_info,
                keyval("EventType", fmt::Qstr("pagefault")),
                keyval("CR3", fmt::Xval(trap_info->regs->cr3)),
                keyval("VA", fmt::Xval(params->page_va)),
                keyval("PA", fmt::Xval(p_info.paddr))
            );
        }

        const auto gfn = p_info.paddr >> 12;
        auto exec_hook = createMemAccessHook<AccessFaultResult>(&codemon::execute_faulted_cb, gfn, PRE, VMI_MEMACCESS_X);
        if (!exec_hook)
        {
            PRINT_DEBUG("[CODEMON] Failed to create execute trap X. Not monitoring GFN 0x%lx\n", gfn);
            this->mmAccessFaultReturnHook.reset();
            return VMI_EVENT_RESPONSE_NONE;
        }

        auto exec_hook_params = libhook::GetTrapParams<AccessFaultResult>(exec_hook->trap_);
        exec_hook_params->page_va = page_va;

        this->memaccess_hooks.insert(std::move(exec_hook));
        this->monitored_pages.insert(monitored_page_identifier);
        PRINT_DEBUG("[CODEMON] Set up execute trap X on GFN 0x%lx\n", gfn);
    }

    // Destroys this return trap, because it is specific for specific page_va.
    // This was the trap being called when the physical address got computed.
    this->mmAccessFaultReturnHook.reset();
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
event_response_t codemon::mm_access_fault_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info)
{
    //Checks if a filter was set and applies it:
    //This applies only to the trap set up. If the program dies in the meantime, the trap continues and might rise the
    //callback even if another program is triggering it, since all depends only on the guest frame number.
    if (this->filter_executable)
    {
        if (*this->filter_executable != trap_info->proc_data.name)
            return VMI_EVENT_RESPONSE_NONE;
    }

    const auto pid = trap_info->proc_data.pid;

    //The first argument is the FaultStatus, and the second (rdx) the VirtualAddress which caused the fault.
    addr_t fault_va = drakvuf_get_function_argument(drakvuf, trap_info, 2);
    PRINT_DEBUG("[CODEMON] Caught MmAccessFault(%d, 0x%lx)\n", pid, fault_va);

    //The kernel space starts with 0xFFFF... and higher.  User space is within 0x0000F... and below. If the trap was created by a kernel module we don't mind as we assume the integrity of the kernel.
    //https://www.codemachine.com/article_x64kvas.html: The upper 16 bits of virtual addresses are always set to 0x0 for user mode addresses and to 0xF for kernel mode addresses
    //Checks if the highest bit (bit 64) = 1000...000 is one or not. If it is one, this must be part of the kernel, since it would has to be 0 for the user mode.
    if (fault_va & (1ULL << 63))
    {
        PRINT_DEBUG("[CODEMON] Don't trap in kernel %d 0x%lx\n", pid, fault_va);
        return VMI_EVENT_RESPONSE_NONE;
    }

    //Right now we are at the beginning of the MmAccessFault method. We get the fault_va which can be received (as above) from reading it from the stack as seconds element.
    //But we also want to know the physical address it is assigned to, which is the return of the MmAccessFault method.
    //Since we are not able to determine the return address of the MmAccessFault, we need to extract it somehow.
    //This can be done right here at the entry of MmAccessFault, since the RIP is the top stack element right now and the esp points to it. So by breakpoint_by_pid_searcher we retrieve this return address and set a hook to it (the address where the execution continues after returning from MmAccessFault).

    // Adds a return hook, a hook which will be called after function completes and returns.
    this->mmAccessFaultReturnHook = createReturnHook<AccessFaultResult>(trap_info, &codemon::mm_access_fault_return_hook_cb);
    if (!this->mmAccessFaultReturnHook)
    {
        PRINT_DEBUG("[CODEMON] Could not create accessFaultReturnTrap\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto params = libhook::GetTrapParams<AccessFaultResult>(this->mmAccessFaultReturnHook->trap_);
    params->setResultCallParams(trap_info);
    params->page_va = fault_va;

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * As we may accidentally trigger an exception in the kernel by using vmi_request_page_fault,
 * we hook KiSystemServiceHandler to account for that situation. Inside this hook,
 * we check if it was "our fault" and if so, we forcefully return EXCEPTION_CONTINUE_EXECUTION.
 * In any other case, we just pass the control to the original exception handler.
 *
 * This part is shamelessly stolen from libusermode.
 */
event_response_t codemon::ki_system_service_handler_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("[CODEMON] Entered system service handler\n");
    proc_data_t proc_data = info->attached_proc_data;
    if (!proc_data.tid)
    {
        PRINT_DEBUG("[CODEMON] Failed to get thread id in system service handler!\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    bool our_fault = this->pf_in_progress.find(std::make_pair(proc_data.pid, proc_data.tid)) != this->pf_in_progress.end();
    if (!our_fault)
    {
        PRINT_DEBUG("[CODEMON] Not suppressing service exception - not our fault\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // emulate `ret` instruction
    addr_t saved_rip = drakvuf_get_function_return_address(drakvuf, info);
    if (!saved_rip)
    {
        PRINT_DEBUG("[CODEMON] Error while reading the saved RIP in system service handler\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    page_mode_t pm = drakvuf_get_page_mode(drakvuf);
    bool is32 = (pm != VMI_PM_IA32E);

    constexpr int EXCEPTION_CONTINUE_EXECUTION = 0;
    info->regs->rip = saved_rip;
    info->regs->rsp += (is32 ? 4 : 8);
    info->regs->rax = EXCEPTION_CONTINUE_EXECUTION;
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

codemon::codemon(drakvuf_t drakvuf, const codemon_config_struct* config, output_format_t output)
    : pluginex(drakvuf, output)
{
    //Check if the dump directory parameter was provided
    if (!config->dump_dir)
    {
        PRINT_DEBUG("[CODEMON] Output directory for dumps not provided, not activating codemon plugin\n");
        return;
    }

    this->dump_dir = std::filesystem::path(config->dump_dir);
    if (!std::filesystem::is_directory(this->dump_dir))
    {
        PRINT_DEBUG("[CODEMON] Output directory doesn't exist. Creating...\n");
        if (!std::filesystem::create_directory(this->dump_dir))
        {
            PRINT_DEBUG("[CODEMON] Failed to create output directory %s\n", this->dump_dir.c_str());
            throw -1;
        }
    }

    // Construct the full frame dump directory by appending /dumps/ and create the folder if not yet existing.
    this->dump_dir /= "dumps";

    //Creates the dump folder
    if (!std::filesystem::is_directory(this->dump_dir))
    {
        PRINT_DEBUG("[CODEMON] Dumps directory doesn't exist. Creating...\n");
        if (!std::filesystem::create_directory(this->dump_dir))
        {
            PRINT_DEBUG("[CODEMON] Failed to create dump directory %s\n", this->dump_dir.c_str());
            throw -1;
        }
    }

    //Create the default dump file name
    this->tmp_file_path = this->dump_dir / "/dump.tmp";

    // Load argument settings
    log_everything = config->log_everything;
    dump_vad = config->dump_vad;
    analyse_system_dll_vad = config->analyse_system_dll_vad;
    default_benign = config->default_benign;
    if (config->filter_executable)
        this->filter_executable = config->filter_executable;

    this->mmAccessFaultHook = createSyscallHook("MmAccessFault", &codemon::mm_access_fault_hook_cb);
    if (!this->mmAccessFaultHook)
        throw -1;

    this->kiSystemServiceHandlerHook = createSyscallHook("KiSystemServiceHandler", &codemon::ki_system_service_handler_cb);
    if (!this->kiSystemServiceHandlerHook)
        throw -1;
}
