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

#include <glib.h>
#include <config.h>
#include <inttypes.h>
#include <libvmi/x86.h>
#include <cassert>
#include <sstream>
#include <string>

#include "../plugins.h"
#include "../plugin_utils.h"
#include "filedelete.h"
#include "plugins/output_format.h"
#include "private.h"

#include <libinjector/libinjector.h>
#include <libdrakvuf/json-util.h>

using std::ostringstream;
using std::string;

const char* offset_names[__OFFSET_MAX][2] =
{
    [FILE_OBJECT_TYPE] = {"_FILE_OBJECT", "Type"},
    [FILE_OBJECT_FLAGS] = {"_FILE_OBJECT", "Flags"},
    [FILE_OBJECT_FILENAME] = {"_FILE_OBJECT", "FileName"},
    [FILE_OBJECT_SECTIONOBJECTPOINTER] = {"_FILE_OBJECT", "SectionObjectPointer"},
    [SECTIONOBJECTPOINTER_DATASECTIONOBJECT] = {"_SECTION_OBJECT_POINTERS", "DataSectionObject"},
    [SECTIONOBJECTPOINTER_SHAREDCACHEMAP] = {"_SECTION_OBJECT_POINTERS", "SharedCacheMap"},
    [SECTIONOBJECTPOINTER_IMAGESECTIONOBJECT] = {"_SECTION_OBJECT_POINTERS", "ImageSectionObject"},
    [CONTROL_AREA_SEGMENT] = {"_CONTROL_AREA", "Segment"},
    [SEGMENT_CONTROLAREA] = {"_SEGMENT", "ControlArea"},
    [SEGMENT_SIZEOFSEGMENT] = {"_SEGMENT", "SizeOfSegment"},
    [SEGMENT_TOTALNUMBEROFPTES] = {"_SEGMENT", "TotalNumberOfPtes"},
    [SUBSECTION_NEXTSUBSECTION] = {"_SUBSECTION", "NextSubsection"},
    [SUBSECTION_SUBSECTIONBASE] = {"_SUBSECTION", "SubsectionBase"},
    [SUBSECTION_PTESINSUBSECTION] = {"_SUBSECTION", "PtesInSubsection"},
    [SUBSECTION_CONTROLAREA] = {"_SUBSECTION", "ControlArea"},
    [SUBSECTION_STARTINGSECTOR] = {"_SUBSECTION", "StartingSector"},
    [OBJECT_HEADER_BODY] = { "_OBJECT_HEADER", "Body" },
    [OBJECT_HEADER_HANDLE_COUNT] = { "_OBJECT_HEADER", "HandleCount" },
};

static const flags_str_t fo_flags_map =
{
    REGISTER_FLAG(FO_FILE_OPEN),
    REGISTER_FLAG(FO_SYNCHRONOUS_IO),
    REGISTER_FLAG(FO_ALERTABLE_IO),
    REGISTER_FLAG(FO_NO_INTERMEDIATE_BUFFERING),
    REGISTER_FLAG(FO_WRITE_THROUGH),
    REGISTER_FLAG(FO_SEQUENTIAL_ONLY),
    REGISTER_FLAG(FO_CACHE_SUPPORTED),
    REGISTER_FLAG(FO_NAMED_PIPE),
    REGISTER_FLAG(FO_STREAM_FILE),
    REGISTER_FLAG(FO_MAILSLOT),
    REGISTER_FLAG(FO_GENERATE_AUDIT_ON_CLOSE),
    REGISTER_FLAG(FO_DIRECT_DEVICE_OPEN),
    REGISTER_FLAG(FO_FILE_MODIFIED),
    REGISTER_FLAG(FO_FILE_SIZE_CHANGED),
    REGISTER_FLAG(FO_CLEANUP_COMPLETE),
    REGISTER_FLAG(FO_TEMPORARY_FILE),
    REGISTER_FLAG(FO_DELETE_ON_CLOSE),
    REGISTER_FLAG(FO_OPENED_CASE_SENSITIVE),
    REGISTER_FLAG(FO_HANDLE_CREATED),
    REGISTER_FLAG(FO_FILE_FAST_IO_READ),
    REGISTER_FLAG(FO_RANDOM_ACCESS),
    REGISTER_FLAG(FO_FILE_OPEN_CANCELLED),
    REGISTER_FLAG(FO_VOLUME_OPEN),
    REGISTER_FLAG(FO_REMOTE_ORIGIN),
    REGISTER_FLAG(FO_DISALLOW_EXCLUSIVE),
    REGISTER_FLAG(FO_SKIP_SET_EVENT),
    REGISTER_FLAG(FO_SKIP_SET_FAST_IO),
    REGISTER_FLAG(FO_INDIRECT_WAIT_OBJECT),
    REGISTER_FLAG(FO_SECTION_MINSTORE_TREATMENT),
};

static bool get_file_object_handle_count(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, filedelete* f, handle_t handle, uint64_t* handle_count)
{
    if (!handle_count)
        return false;

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, info->attached_proc_data.base_addr, handle);
    if (!obj)
        return false; // Break operatioin to not crash VM

    addr_t handles = obj + f->offsets[OBJECT_HEADER_HANDLE_COUNT];

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.addr = handles;
    ctx.dtb = info->regs->cr3;

    bool is32bit = (f->pm != VMI_PM_IA32E);
    uint64_t handles_value = 0;
    bool success = false;
    if (is32bit)
        success = (VMI_SUCCESS == vmi_read_32(vmi, &ctx, (uint32_t*)&handles_value));
    else
        success = (VMI_SUCCESS == vmi_read_64(vmi, &ctx, &handles_value));
    if (success)
        *handle_count = handles_value;

    return success;
}

static bool get_file_object_flags(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, filedelete* f, handle_t handle, uint64_t* flags)
{
    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, info->attached_proc_data.base_addr, handle);
    if (!obj)
        return false; // Break operatioin to not crash VM

    addr_t file = obj + f->offsets[OBJECT_HEADER_BODY];
    addr_t fileflags = file + f->offsets[FILE_OBJECT_FLAGS];

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.addr = fileflags;
    ctx.dtb = info->regs->cr3;

    uint32_t flags_value;
    bool success = (VMI_SUCCESS == vmi_read_32(vmi, &ctx, &flags_value));
    if (success && flags) *flags = flags_value;
    return success;
}

static std::string get_file_name(filedelete* f, drakvuf_t drakvuf, vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    addr_t handle,
    addr_t* out_file, addr_t* out_filetype)
{
    // TODO: verify that the dtb in the _EPROCESS is the same as the cr3?

    if (!info->attached_proc_data.base_addr)
        return {};

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, info->attached_proc_data.base_addr, handle);

    if (!obj)
        return {};

    addr_t file = obj + f->offsets[OBJECT_HEADER_BODY];
    addr_t filename = file + f->offsets[FILE_OBJECT_FILENAME];
    addr_t filetype = file + f->offsets[FILE_OBJECT_TYPE];

    if (out_file)
        *out_file = file;

    if (out_filetype)
        *out_filetype = filetype;

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.addr = filetype;
    ctx.dtb = info->regs->cr3;

    uint8_t type = 0;
    if (VMI_FAILURE == vmi_read_8(vmi, &ctx, &type))
        return {};

    if (type != 5)
        return {};

    unicode_string_t* filename_us = drakvuf_read_unicode(drakvuf, info, filename);
    if (!filename_us) return {};
    std::string ret = {(const char*)filename_us->contents};
    vmi_free_unicode_str(filename_us);
    return ret;
}

static void print_filedelete_information(filedelete* f, drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    const char* filename,
    file_extraction_reason_t reason,
    size_t bytes_read, uint64_t fo_flags,
    int seq_number)
{
    std::string flags = parse_flags(fo_flags, fo_flags_map, f->format);
    std::string r;
    switch (reason)
    {
        case FILEEXTR_WRITE:
            r = "WriteFile";
            break;
        case FILEEXTR_DELETE:
            r = "DeleteFile";
            break;
        default:
            r = "Unknown";
            break;
    }

    if (f->format == OUTPUT_KV)
    {
        kvfmt::print("fileextractor", drakvuf, info,
            keyval("FileName", fmt::Qstr(filename)),
            keyval("Size", fmt::Nval(bytes_read)),
            keyval("Flags", fmt::Xval(fo_flags)),
            fmt::Rstr(flags),
            keyval("SeqNum", fmt::Nval(seq_number)),
            keyval("Reason", fmt::Qstr(r))
        );
    }
    else
    {
        fmt::print(f->format, "fileextractor", drakvuf, info,
            keyval("FileName", fmt::Qstr(filename)),
            keyval("Size", fmt::Nval(bytes_read)),
            keyval("Flags", fmt::Xval(fo_flags)),
            keyval("FlagsExpanded", fmt::Qstr(flags)),
            keyval("SeqNum", fmt::Nval(seq_number)),
            keyval("Reason", fmt::Qstr(r))
        );
    }
}

static void print_extraction_failure(filedelete* f, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const string& filename, const string& message)
{
    fmt::print(f->format, "fileextractor_fail", drakvuf, info,
        keyval("FileName", fmt::Qstr(filename)),
        keyval("Message", fmt::Qstr(message))
    );
}

static void save_file_metadata(filedelete* f,
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    int sequence_number,
    addr_t control_area,
    const char* filename,
    file_extraction_reason_t reason,
    size_t file_size,
    uint64_t fo_flags,
    uint32_t ntstatus = 0)
{
    char* file = NULL;
    if ( asprintf(&file, "%s/file.%06d.metadata", f->dump_folder, sequence_number) < 0 )
        return;

    FILE* fp = fopen(file, "w");
    free(file);
    if (!fp)
        return;

    json_object* jobj = json_object_new_object();
    if (!jobj)
    {
        fclose(fp);
        return;
    }

    filename = filename ?: "<UNKNOWN>";
    json_object_object_add(jobj, "FileName", json_object_new_string(filename));
    json_object_object_add(jobj, "FileSize", json_object_new_int64(file_size));
    json_object_object_add(jobj, "FileFlags", json_object_new_string_fmt("0x%lx (%s)", fo_flags, parse_flags(fo_flags, fo_flags_map, OUTPUT_DEFAULT, "0").c_str()));
    json_object_object_add(jobj, "SequenceNumber", json_object_new_int(sequence_number));
    json_object_object_add(jobj, "ControlArea", json_object_new_string_fmt("0x%lx", control_area));
    json_object_object_add(jobj, "PID", json_object_new_int64(static_cast<uint64_t>(info->attached_proc_data.pid)));
    json_object_object_add(jobj, "PPID", json_object_new_int64(static_cast<uint64_t>(info->attached_proc_data.ppid)));
    json_object_object_add(jobj, "ProcessName", json_object_new_string(info->attached_proc_data.name));

    if (!ntstatus)
    {
        json_object_object_add(jobj, "FullReadSuccess", json_object_new_boolean(TRUE));
    }
    else
    {
        json_object_object_add(jobj, "FullReadSuccess", json_object_new_boolean(FALSE));
        // if the file have been read partially, also note what was the NTSTATUS of failing operation
        json_object_object_add(jobj, "ReadNTStatus", json_object_new_int(ntstatus));
    }

    fprintf(fp, "%s\n", json_object_get_string(jobj));
    fclose(fp);

    json_object_put(jobj);
    print_filedelete_information(f, drakvuf, info, filename, reason,
        file_size, fo_flags, sequence_number);
}

static void extract_ca_file(filedelete* f,
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    addr_t control_area,
    access_context_t* ctx,
    const char* filename,
    uint64_t fo_flags,
    file_extraction_reason_t reason)
{
    addr_t subsection = control_area + f->control_area_size;
    addr_t segment = 0;
    addr_t test = 0;
    addr_t test2 = 0;
    size_t filesize = 0;

    /* Check whether subsection points back to the control area */
    ctx->addr = control_area + f->offsets[CONTROL_AREA_SEGMENT];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &segment) )
        return;

    ctx->addr = segment + f->offsets[SEGMENT_CONTROLAREA];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &test) || test != control_area )
        return;

    ctx->addr = segment + f->offsets[SEGMENT_SIZEOFSEGMENT];
    if ( VMI_FAILURE == vmi_read_64(vmi, ctx, &test) )
        return;

    ctx->addr = segment + f->offsets[SEGMENT_TOTALNUMBEROFPTES];
    if ( VMI_FAILURE == vmi_read_32(vmi, ctx, (uint32_t*)&test2) )
        return;

    if ( test != (test2 * 4096) )
        return;

    const int curr_sequence_number = ++f->sequence_number;

    char* file = NULL;
    if ( asprintf(&file, "%s/file.%06d.mm", f->dump_folder, curr_sequence_number) < 0 )
        return;

    FILE* fp = fopen(file, "w");
    free(file);
    if (!fp)
        return;

    while (subsection)
    {
        /* Check whether subsection points back to the control area */
        ctx->addr = subsection + f->offsets[SUBSECTION_CONTROLAREA];
        if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &test) || test != control_area )
            break;

        addr_t base = 0;
        addr_t start = 0;
        uint32_t ptes = 0;

        ctx->addr = subsection + f->offsets[SUBSECTION_SUBSECTIONBASE];
        if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &base) )
            break;

        ctx->addr = subsection + f->offsets[SUBSECTION_PTESINSUBSECTION];
        if ( VMI_FAILURE == vmi_read_32(vmi, ctx, &ptes) )
            break;

        ctx->addr = subsection + f->offsets[SUBSECTION_STARTINGSECTOR];
        if ( VMI_FAILURE == vmi_read_32(vmi, ctx, (uint32_t*)&start) )
            break;

        /*
         * The offset into the file is stored implicitely
         * based on the PTE's location within the Subsection.
         */
        addr_t subsection_offset = start * 0x200;
        addr_t ptecount;
        for (ptecount=0; ptecount < ptes; ptecount++)
        {
            addr_t pteoffset = base + f->mmpte_size * ptecount;
            addr_t fileoffset = subsection_offset + ptecount * 0x1000;

            addr_t pte = 0;
            ctx->addr = pteoffset;
            if ( VMI_FAILURE == vmi_read(vmi, ctx, f->mmpte_size, &pte, NULL) )
                break;

            if ( ENTRY_PRESENT(1, pte) )
            {
                uint8_t page[4096];

                if ( VMI_FAILURE == vmi_read_pa(vmi, VMI_BIT_MASK(12, 48) & pte, 4096, &page, NULL) )
                    continue;

                if ( !fseek ( fp, fileoffset, SEEK_SET ) )
                {
                    if ( fwrite(page, 4096, 1, fp) )
                        filesize = MAX(filesize, fileoffset + 4096);
                }
            }
        }

        ctx->addr = subsection + f->offsets[SUBSECTION_NEXTSUBSECTION];
        if ( !vmi_read_addr(vmi, ctx, &subsection) )
            break;
    }

    fclose(fp);

    save_file_metadata(f, drakvuf, info, curr_sequence_number, control_area, filename, reason, filesize, fo_flags);
}

static void extract_file(filedelete* f,
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    addr_t file_pa,
    access_context_t* ctx,
    const char* filename,
    uint64_t fo_flags,
    file_extraction_reason_t reason)
{
    addr_t sop = 0;
    addr_t datasection = 0;
    addr_t sharedcachemap = 0;
    addr_t imagesection = 0;

    ctx->addr = file_pa + f->offsets[FILE_OBJECT_SECTIONOBJECTPOINTER];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &sop) )
        return;

    ctx->addr = sop + f->offsets[SECTIONOBJECTPOINTER_DATASECTIONOBJECT];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &datasection) )
        return;

    if ( datasection )
        extract_ca_file(f, drakvuf, info, vmi, datasection, ctx, filename, fo_flags, reason);

    ctx->addr = sop + f->offsets[SECTIONOBJECTPOINTER_SHAREDCACHEMAP];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &sharedcachemap) )
        return;

    // TODO: extraction from sharedcachemap

    ctx->addr = sop + f->offsets[SECTIONOBJECTPOINTER_IMAGESECTIONOBJECT];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &imagesection) )
        return;

    if ( imagesection != datasection )
        extract_ca_file(f, drakvuf, info, vmi, imagesection, ctx, filename, fo_flags, reason);
}

/*
 * The approach where the system process list es enumerated looking for
 * the matching cr3 value in each _EPROCESS struct is not going to work
 * if a DKOM attack unhooks the _EPROCESS struct.
 *
 * We can access the _EPROCESS structure by reading the FS_BASE register on x86
 * or the GS_BASE register on x64, which contains the _KPCR.
 *
 * FS/GS -> _KPCR._KPRCB.CurrentThread -> _ETHREAD._KTHREAD.Process = _EPROCESS
 *
 * Also see: http://www.csee.umbc.edu/~stephens/SECURITY/491M/HiddenProcesses.ppt
 */
static void grab_file_by_handle(filedelete* f, drakvuf_t drakvuf,
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info, addr_t handle,
    file_extraction_reason_t reason)
{
    addr_t file = 0;
    addr_t filetype = 0;
    std::string filename = get_file_name(f, drakvuf, vmi, info, handle, &file, &filetype);
    if (filename.empty()) return;

    uint64_t fo_flags = 0;
    get_file_object_flags(drakvuf, info, vmi, f, handle, &fo_flags);

    if (f->dump_folder)
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .addr = filetype,
            .dtb = info->regs->cr3,
        );
        extract_file(f, drakvuf, info, vmi, file, &ctx, filename.c_str(), fo_flags, reason);
        return;
    }

    print_filedelete_information(f, drakvuf, info, filename.c_str(), reason, 0, 0, 0);
}

static bool save_file_chunk(filedelete* f, int file_sequence_number, void* buffer, size_t size)
{
    char* file = nullptr;
    if ( asprintf(&file, "%s/file.%06d.mm", f->dump_folder, file_sequence_number) < 0 )
        return false;

    FILE* fp = fopen(file, "a");
    free(file);
    if (!fp) return false;

    bool success = (fwrite(buffer, size, 1, fp) == 1);
    fclose(fp);

    return success;
}

// TODO Replace `is_success` with `injector->finish_status`
static event_response_t finish_readfile(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, bool is_success)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;
    filedelete* f = injector->f;
    auto thread = std::make_pair(info->attached_proc_data.pid, info->attached_proc_data.tid);

    auto filename = f->files[ {info->attached_proc_data.pid, injector->handle}].first;
    auto reason = f->files[ {info->attached_proc_data.pid, injector->handle}].second;

    if (!is_success)
        grab_file_by_handle(f, drakvuf, vmi, info, injector->handle, reason);

    f->closing_handles[thread] = true;

    free_resources(drakvuf, info);
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

event_response_t memcpy_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;
    filedelete* f = injector->f;

    if (!drakvuf_check_return_context(drakvuf, info, injector->target_pid, injector->target_tid, injector->target_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    injector->target_rsp = 0;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = injector->pool
    );

    auto vmi = vmi_lock_guard(drakvuf);

    if (injector->curr_sequence_number < 0) injector->curr_sequence_number = ++f->sequence_number;
    const int curr_sequence_number = injector->curr_sequence_number;

    if (VMI_SUCCESS == vmi_read(vmi, &ctx, injector->bytes_to_read, injector->buffer, NULL) &&
        save_file_chunk(f, curr_sequence_number, injector->buffer, injector->bytes_to_read))
    {
        injector->file_offset += injector->bytes_to_read;
        if (injector->file_offset >= injector->file_size)
        {
            auto filename = f->files[ {info->attached_proc_data.pid, injector->handle}].first;
            auto reason = f->files[ {info->attached_proc_data.pid, injector->handle}].second;
            save_file_metadata(f, drakvuf, info, curr_sequence_number, 0, filename.c_str(), reason, injector->file_offset, injector->fo_flags);

            injector->finish_status = true;
        }
    }
    else
    {
        PRINT_DEBUG("[FILEDELETE2] [RtlCopyMemory] Error. Stop processing (PID %d, TID %d, FileName '%s', status 0x%lx).\n",
            info->attached_proc_data.pid, info->attached_proc_data.tid, f->files[ {info->attached_proc_data.pid, injector->handle}].first.c_str(), info->regs->rax);
    }

    if (inject_unmapview(drakvuf, info, vmi, injector))
    {
        injector->target_rsp = info->regs->rsp;
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    return finish_readfile(drakvuf, info, vmi, injector->finish_status);
}

event_response_t close_handle_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;

    if (!drakvuf_check_return_context(drakvuf, info, injector->target_pid, injector->target_tid, injector->target_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    injector->target_rsp = 0;

    auto vmi = vmi_lock_guard(drakvuf);
    return finish_readfile(drakvuf, info, vmi, injector->finish_status);
}

event_response_t unmapview_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;

    if (!drakvuf_check_return_context(drakvuf, info, injector->target_pid, injector->target_tid, injector->target_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    injector->target_rsp = 0;

    auto vmi = vmi_lock_guard(drakvuf);
    if (injector->file_offset < injector->file_size)
    {
        if (inject_mapview(drakvuf, info, vmi, injector))
        {
            injector->target_rsp = info->regs->rsp;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
    }

    if (inject_close_handle(drakvuf, info, vmi, injector))
    {
        injector->target_rsp = info->regs->rsp;
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    return finish_readfile(drakvuf, info, vmi, injector->finish_status);
}

event_response_t mapview_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;

    if (!drakvuf_check_return_context(drakvuf, info, injector->target_pid, injector->target_tid, injector->target_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    injector->target_rsp = 0;

    auto vmi = vmi_lock_guard(drakvuf);

    if (info->regs->rax)
    {
        auto filename = injector->f->files[ {info->attached_proc_data.pid, injector->handle}].first;
        ostringstream msg;
        msg << "ZwMapViewOfSection failed with status 0x" << std::hex << info->regs->rax;
        print_extraction_failure(injector->f, drakvuf, info, filename,
            msg.str());
    }
    else
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = injector->mapview.base
        );

        if ((VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(injector->view_base), &injector->view_base, NULL)))
        {
            PRINT_DEBUG("[FILEDELETE2] [ZwMapViewOfSection] Failed to read view base\n");
            goto err;
        }

        ctx.addr = injector->mapview.size;
        uint64_t view_size = 0;
        if ((VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(view_size), &view_size, NULL)))
        {
            PRINT_DEBUG("[FILEDELETE2] [ZwMapViewOfSection] Failed to read view size\n");
            goto err;
        }

        addr_t pool = find_pool(injector->f->pools);
        if (!pool)
        {
            if (inject_allocate_pool(drakvuf, info, vmi, injector))
            {
                injector->target_rsp = info->regs->rsp;
                return VMI_EVENT_RESPONSE_SET_REGISTERS;
            }
        }
        else
        {
            injector->pool = pool;
            if (inject_memcpy(drakvuf, info, vmi, injector))
            {
                injector->target_rsp = info->regs->rsp;
                return VMI_EVENT_RESPONSE_SET_REGISTERS;
            }
        }
    }

err:
    PRINT_DEBUG("[FILEDELETE2] [ZwMapViewOfSection] Error. Stop processing (PID %d, TID %d).\n",
        info->attached_proc_data.pid, info->attached_proc_data.tid);

    return finish_readfile(drakvuf, info, vmi, false);
}

event_response_t injected_createsection_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;

    if (!drakvuf_check_return_context(drakvuf, info, injector->target_pid, injector->target_tid, injector->target_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    injector->target_rsp = 0;

    auto vmi = vmi_lock_guard(drakvuf);

    if (info->regs->rax)
    {
        auto filename = injector->f->files[ {info->attached_proc_data.pid, injector->handle}].first;
        ostringstream msg;
        msg << "ZwCreateSection failed with status 0x" << std::hex << info->regs->rax;
        print_extraction_failure(injector->f, drakvuf, info, filename,
            msg.str());
    }
    else
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = injector->createsection.handle,
        );

        if ((VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(injector->section_handle), &injector->section_handle, NULL)))
        {
            PRINT_DEBUG("[FILEDELETE2] [ZwCreateSection] Failed to read section handle\n");
            goto err;
        }

        if (inject_mapview(drakvuf, info, vmi, injector))
        {
            injector->target_rsp = info->regs->rsp;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
    }

err:
    PRINT_DEBUG("[FILEDELETE2] [ZwCreateSection] Error. Stop processing (PID %d, TID %d).\n",
        info->attached_proc_data.pid, info->attached_proc_data.tid);

    return finish_readfile(drakvuf, info, vmi, false);
}

event_response_t exallocatepool_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;

    if (!drakvuf_check_return_context(drakvuf, info, injector->target_pid, injector->target_tid, injector->target_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    injector->target_rsp = 0;

    auto vmi = vmi_lock_guard(drakvuf);

    if (info->regs->rax)
    {
        injector->f->pools[info->regs->rax] = true;

        injector->pool = info->regs->rax;
        if (inject_unmapview(drakvuf, info, vmi, injector))
        {
            injector->target_rsp = info->regs->rsp;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        else
        {
            goto err;
        }
    }
    else
    {
        auto filename = injector->f->files[ {info->attached_proc_data.pid, injector->handle}].first;
        print_extraction_failure(injector->f, drakvuf, info, filename,
            "ExAllocatePoolWithTag failed to allocate pool");
    }

err:
    PRINT_DEBUG("[FILEDELETE2] [ExAllocatePoolWithTag] Error. Stop processing (PID %d, TID %d).\n",
        info->attached_proc_data.pid, info->attached_proc_data.tid);

    return finish_readfile(drakvuf, info, vmi, false);
}

event_response_t queryvolumeinfo_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;

    if (!drakvuf_check_return_context(drakvuf, info, injector->target_pid, injector->target_tid, injector->target_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    injector->target_rsp = 0;

    auto vmi = vmi_lock_guard(drakvuf);

    if (info->regs->rax)
    {
        auto filename = injector->f->files[ {info->attached_proc_data.pid, injector->handle}].first;
        ostringstream msg;
        msg << "ZwQueryVolumeInformationFile failed with status 0x" << std::hex << info->regs->rax;

        print_extraction_failure(injector->f, drakvuf, info, filename, msg.str());

        goto handled;
    }
    else
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = injector->queryvolumeinfo.out,
        );

        struct FILE_FS_DEVICE_INFORMATION dev_info = {};
        if ((VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct FILE_FS_DEVICE_INFORMATION), &dev_info, NULL)))
        {
            PRINT_DEBUG("[FILEDELETE2] [ZwQueryVolumeInformationFile] Failed to read FsDeviceInformation\n");
            goto err;
        }

        if (7 != dev_info.device_type) // FILE_DEVICE_DISK
        {
            auto filename = injector->f->files[ {info->attached_proc_data.pid, injector->handle}].first;
            ostringstream msg;
            msg << "ZwQueryVolumeInformationFile stop processing device type " << dev_info.device_type;

            print_extraction_failure(injector->f, drakvuf, info, filename, msg.str());
            goto handled;
        }

        injector->readfile.bytes_read = 0UL;
        if (inject_queryinfo(drakvuf, info, vmi, injector))
        {
            injector->target_rsp = info->regs->rsp;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
    }

err:
    PRINT_DEBUG("[FILEDELETE2] [ZwQueryVolumeInformationFile] Error. Stop processing (PID %d, TID %d).\n",
        info->attached_proc_data.pid, info->attached_proc_data.tid);

handled:
    return finish_readfile(drakvuf, info, vmi, false);
}

event_response_t queryinfo_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;

    if (!drakvuf_check_return_context(drakvuf, info, injector->target_pid, injector->target_tid, injector->target_rsp))
        return VMI_EVENT_RESPONSE_NONE;
    injector->target_rsp = 0;

    auto vmi = vmi_lock_guard(drakvuf);

    if (info->regs->rax)
    {
        auto filename = injector->f->files[ {info->attached_proc_data.pid, injector->handle}].first;
        ostringstream msg;
        msg << "ZwQueryInformationFile failed with status 0x" << std::hex << info->regs->rax;

        print_extraction_failure(injector->f, drakvuf, info, filename, msg.str());

        goto handled;
    }
    else
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = injector->queryvolumeinfo.out
        );

        struct FILE_STANDARD_INFORMATION dev_info = {};
        if ((VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(dev_info), &dev_info, NULL)))
        {
            PRINT_DEBUG("[FILEDELETE2] [ZwQueryInformationFile] Failed to read FsDeviceInformation\n");
            goto err;
        }

        if (0 == dev_info.end_of_file)
        {
            auto filename = injector->f->files[ {info->attached_proc_data.pid, injector->handle}].first;
            print_extraction_failure(injector->f, drakvuf, info, filename, "Zero size file");
            goto handled;
        }

        injector->readfile.bytes_read = 0UL;
        injector->file_size = dev_info.end_of_file;

        auto filename = injector->f->files[ {info->attached_proc_data.pid, injector->handle}].first;

        if (inject_createsection(drakvuf, info, vmi, injector))
        {
            injector->target_rsp = info->regs->rsp;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
    }

err:
    PRINT_DEBUG("[FILEDELETE2] [ZwQueryInformationFile] Error. Stop processing (PID %d, TID %d).\n",
        info->attached_proc_data.pid, info->attached_proc_data.tid);

handled:
    return finish_readfile(drakvuf, info, vmi, false);
}

typedef enum
{
    START_READFILE_INVALID,
    START_READFILE_ERROR,
    START_READFILE_SUCCEED
} start_readfile_t;

/*
 * Drakvuf must be locked/unlocked in the caller
 */
static start_readfile_t start_readfile(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, handle_t handle, const char* filename, event_response_t* response)
{
    *response = VMI_EVENT_RESPONSE_NONE;
    filedelete* f = (filedelete*)info->trap->data;
    uint64_t fo_flags = 0;

    if ( 0 == info->attached_proc_data.base_addr )
    {
        PRINT_DEBUG("[FILEDELETE2] Failed to get process base on vCPU 0x%d\n",
            info->vcpu);
        return START_READFILE_ERROR;
    }

    /*
     * Check if process/thread is being processed. If so skip it. Add it into
     * regestry otherwise.
     */
    auto thread = std::make_pair(info->attached_proc_data.pid, info->attached_proc_data.tid);
    auto thread_it = f->closing_handles.find(thread);
    auto map_end = f->closing_handles.end();
    if (map_end != thread_it)
    {
        bool handled = thread_it->second;
        if (handled)
        {
            f->files.erase({info->attached_proc_data.pid, handle});
            f->closing_handles.erase(thread);
        }

        return START_READFILE_SUCCEED;
    }
    else
    {
        // do not start dumping new file
        if (f->is_stopping())
            return START_READFILE_SUCCEED;

        if (!get_file_object_flags(drakvuf, info, vmi, f, handle, &fo_flags))
            return START_READFILE_ERROR;

        f->closing_handles[thread] = false;
    }

    /*
     * Real function body.
     *
     * Now we are sure this is new call to NtClose (not result of function injection) and
     * the Handle have been modified in NtWriteFile. So we should save it on the host.
     */
    wrapper_t* injector = (wrapper_t*)g_try_malloc0(sizeof(wrapper_t));
    if (!injector)
        return START_READFILE_ERROR;

    injector->bp = (drakvuf_trap_t*)g_try_malloc0(sizeof(drakvuf_trap_t));
    if (!injector->bp)
    {
        g_free(injector);
        return START_READFILE_ERROR;
    }

    injector->buffer = g_try_malloc0(BYTES_TO_READ);
    if (!injector->buffer)
    {
        g_free(injector->bp);
        g_free(injector);
        return START_READFILE_ERROR;
    }

    injector->f = f;
    injector->bp->name = info->trap->name;
    injector->handle = handle;
    injector->fo_flags = fo_flags;
    injector->is32bit = (f->pm != VMI_PM_IA32E);
    injector->curr_sequence_number = -1;
    injector->eprocess_base = info->attached_proc_data.base_addr;
    injector->target_pid = info->attached_proc_data.pid;
    injector->target_tid = info->attached_proc_data.tid;
    injector->finish_status = false;

    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

    if (inject_queryvolumeinfo(drakvuf, info, vmi, injector))
    {
        injector->target_rsp = info->regs->rsp;
        *response = VMI_EVENT_RESPONSE_SET_REGISTERS;
        return START_READFILE_SUCCEED;
    }

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    return START_READFILE_ERROR;
}

static event_response_t createfile_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if (!info->attached_proc_data.pid)
    {
        PRINT_DEBUG("[FILEDELETE2] [PID:%d] [TID:%d] Error: Failed to get "
            "attached process\n",
            info->attached_proc_data.pid, info->attached_proc_data.tid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto w = (struct createfile_ret_info*)info->trap->data;

    if (!drakvuf_check_return_context(drakvuf, info, w->pid, w->tid, w->rsp))
        return VMI_EVENT_RESPONSE_NONE;

    // Return if NtCreateFile/NtOpenFile failed
    if (info->regs->rax)
        return VMI_EVENT_RESPONSE_NONE;

    uint32_t handle = 0;
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = w->handle
    );

    vmi_lock_guard vmi_lg(drakvuf);
    if (VMI_SUCCESS != vmi_read_32(vmi_lg.vmi, &ctx, &handle))
        PRINT_DEBUG("[FILEDELETE2] Failed to read pHandle at 0x%lx (PID %d, TID %d)\n", w->handle, w->pid, w->tid);

    if (handle)
    {
        auto filename = get_file_name(w->f, drakvuf, vmi_lg.vmi, info, handle, nullptr, nullptr);
        if (filename.empty()) filename = "<UNKNOWN>";

        w->f->files[ {info->attached_proc_data.pid, handle}] = {filename, FILEEXTR_DELETE};
    }

    delete w;
    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)g_free);

    return VMI_EVENT_RESPONSE_NONE;
}

static void createfile_cb_impl(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle)
{
    if (!info->attached_proc_data.pid)
    {
        PRINT_DEBUG("[FILEDELETE2] [PID:%d] [TID:%d] Error: Failed to get "
            "attached process\n",
            info->attached_proc_data.pid, info->attached_proc_data.tid);
        return;
    }

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);

    auto w = new createfile_ret_info;
    w->pid = info->attached_proc_data.pid;
    w->tid = info->attached_proc_data.tid;
    w->rsp = info->regs->rsp;
    w->handle = handle;
    w->f = (filedelete*)info->trap->data;

    drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
    trap->breakpoint.lookup_type = LOOKUP_KERNEL;
    trap->breakpoint.addr_type = ADDR_VA;
    trap->breakpoint.addr = ret_addr;
    trap->type = BREAKPOINT;
    trap->name = info->trap->name;
    trap->data = w;
    trap->cb = createfile_ret_cb;
    trap->ttl = drakvuf_get_limited_traps_ttl(drakvuf);

    if ( !drakvuf_add_trap(drakvuf, trap) )
    {
        printf("Failed to trap return at 0x%lx\n", ret_addr);
        delete w;
        g_free(trap);
    }
}

static event_response_t openfile_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t create_options = drakvuf_get_function_argument(drakvuf, info, 6);

    if (create_options & FILE_DELETE_ON_CLOSE)
        createfile_cb_impl(drakvuf, info, handle);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t createfile_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t create_options = drakvuf_get_function_argument(drakvuf, info, 9);

    if (create_options & FILE_DELETE_ON_CLOSE)
        createfile_cb_impl(drakvuf, info, handle);

    return VMI_EVENT_RESPONSE_NONE;
}

/*
 * NTSTATUS ZwSetInformationFile(
 *  HANDLE                 FileHandle,
 *  PIO_STATUS_BLOCK       IoStatusBlock,
 *  PVOID                  FileInformation,
 *  ULONG                  Length,
 *  FILE_INFORMATION_CLASS FileInformationClass
 * );
 *
 * When FileInformationClass is FileDispositionInformation then FileInformation points to
 * struct _FILE_DISPOSITION_INFORMATION {
 *  BOOLEAN DeleteFile;
 * }
 */
static event_response_t setinformation_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if (!info->attached_proc_data.pid)
    {
        PRINT_DEBUG("[FILEDELETE2] [PID:%d] [TID:%d] Error: Failed to get "
            "attached process\n",
            info->attached_proc_data.pid, info->attached_proc_data.tid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    filedelete* f = (filedelete*)info->trap->data;

    if (f->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t fileinfo = drakvuf_get_function_argument(drakvuf, info, 3);
    uint32_t fileinfoclass = drakvuf_get_function_argument(drakvuf, info, 5);

    event_response_t response = 0;
    if (fileinfoclass == FILE_DISPOSITION_INFORMATION)
    {
        uint8_t del = 0;
        ACCESS_CONTEXT(ctx);
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = fileinfo;

        if ( VMI_FAILURE == vmi_read_8(vmi, &ctx, &del) )
            goto done;

        if (del)
        {
            auto filename = get_file_name(f, drakvuf, vmi, info, handle, nullptr, nullptr);
            if (filename.empty()) filename = "<UNKNOWN>";

            f->files[ {info->attached_proc_data.pid, handle}] = {filename, FILEEXTR_DELETE};
        }
    }

done:
    drakvuf_release_vmi(drakvuf);
    return response;
}

static event_response_t writefile_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if (!info->attached_proc_data.pid)
    {
        PRINT_DEBUG("[FILEDELETE2] [PID:%d] [TID:%d] Error: Failed to get "
            "attached process\n",
            info->attached_proc_data.pid, info->attached_proc_data.tid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    filedelete* f = (filedelete*)info->trap->data;

    if (f->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);

    auto filename = get_file_name(f, drakvuf, vmi, info, handle, nullptr, nullptr);
    if (filename.empty()) filename = "<UNKNOWN>";

    f->files[ {info->attached_proc_data.pid, handle}] = {filename, FILEEXTR_WRITE};

    drakvuf_release_vmi(drakvuf);
    return 0;
}

/*
 * Intercept all handles close and filter file handles.
 *
 * The main difficulty is that this handler intercepts not only CloseHandle()
 * calls but returns from injected functions. To distinguish such situations
 * we use the regestry of processes/threads being processed.
 */
static event_response_t close_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if (!info->attached_proc_data.pid)
    {
        PRINT_DEBUG("[FILEDELETE2] [PID:%d] [TID:%d] Error: Failed to get "
            "attached process\n",
            info->attached_proc_data.pid, info->attached_proc_data.tid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    filedelete* f = (filedelete*)info->trap->data;
    vmi_lock_guard vmi(drakvuf);

    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);

    auto file_info = f->files.find({info->attached_proc_data.pid, handle});
    const auto reason = file_info->second.second;

    if ( f->files.end() == file_info )
        return VMI_EVENT_RESPONSE_NONE;

    uint64_t handle_count = 1;
    if (get_file_object_handle_count(drakvuf, info, vmi.vmi, f, handle, &handle_count))
    {
        if (handle_count > 1) return VMI_EVENT_RESPONSE_NONE;
    }

    event_response_t response = 0;
    if (f->use_injector)
    {
        /*
         * Check if closing handle have been changed with NtWriteFile
         */
        auto filename = file_info->second.first;
        if (filename.empty())
            goto done;

        if ( START_READFILE_SUCCEED == start_readfile(drakvuf, info, vmi.vmi, handle, filename.c_str(), &response) )
            goto done;
    }

    if (f->files.erase({info->attached_proc_data.pid, handle}) > 0)
    {
        if (f->is_stopping())
            return VMI_EVENT_RESPONSE_NONE;

        // We detect the fact of closing of the previously modified file.
        grab_file_by_handle(f, drakvuf, vmi.vmi, info, handle, reason);
    }

done:
    return response;
}

static event_response_t createsection_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if (!info->attached_proc_data.pid)
    {
        PRINT_DEBUG("[FILEDELETE2] [PID:%d] [TID:%d] Error: Failed to get "
            "attached process\n",
            info->attached_proc_data.pid, info->attached_proc_data.tid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    filedelete* f = (filedelete*)info->trap->data;

    if (f->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    handle_t handle = drakvuf_get_function_argument(drakvuf, info, 7);
    uint32_t access_mask = drakvuf_get_function_argument(drakvuf, info, 2);
    std::string filename;

    // Filter out system handles: those having high bits rised
    // WARNING Without this target VM could freeze or crash!
    if (static_cast<int64_t>(handle) < 0LL)
        goto done;

    if ( !(0x2 & access_mask) ) // SECTION_MAP_WRITE
        goto done;

    filename = get_file_name(f, drakvuf, vmi, info, handle, nullptr, nullptr);
    if (filename.empty()) filename = "<UNKNOWN>";

    f->files[ {info->attached_proc_data.pid, handle}] = {filename, FILEEXTR_WRITE};

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}


static void register_trap( drakvuf_t drakvuf, const char* syscall_name,
    drakvuf_trap_t* trap,
    event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    if ( !drakvuf_get_kernel_symbol_rva( drakvuf, syscall_name, &trap->breakpoint.rva) ) throw -1;

    trap->name = syscall_name;
    trap->cb   = hook_cb;
    trap->ttl  = drakvuf_get_limited_traps_ttl(drakvuf);

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}

static addr_t get_function_va(drakvuf_t drakvuf, const char* lib, const char* func_name)
{
    addr_t rva;
    if ( !drakvuf_get_kernel_symbol_rva( drakvuf, func_name, &rva) )
    {
        PRINT_DEBUG("[FILEDELETE2] [Init] Failed to get RVA of %s\n", func_name);
        throw -1;
    }

    addr_t va = drakvuf_exportksym_to_va(drakvuf, 4, nullptr, lib, rva);
    if (!va)
    {
        PRINT_DEBUG("[FILEDELETE2] [Init] Failed to get VA of %s\n", func_name);
        throw -1;
    }

    return va;
}

filedelete::filedelete(drakvuf_t drakvuf, const filedelete_config* c, output_format_t output)
    : drakvuf(drakvuf)
    , offsets(new size_t[__OFFSET_MAX])
    , dump_folder(c->dump_folder)
    , pm(drakvuf_get_page_mode(drakvuf))
    , format(output)
    , use_injector(c->filedelete_use_injector)
    , sequence_number()
{
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->domid = vmi_get_vmid(vmi);
    drakvuf_release_vmi(drakvuf);

    if (!this->use_injector)
    {
        assert(sizeof(traps)/sizeof(traps[0]) > 2);
        register_trap(drakvuf, "NtSetInformationFile", &traps[0], setinformation_cb);
        register_trap(drakvuf, "NtWriteFile",          &traps[1], writefile_cb);
        register_trap(drakvuf, "NtClose",              &traps[2], close_cb);
        /* TODO
        register_trap(drakvuf, "NtDeleteFile",            &traps[3], deletefile_cb);
        register_trap(drakvuf, "ZwDeleteFile",            &traps[4], deletefile_cb); */
    }
    else
    {
        this->queryvolumeinfo_va = get_function_va(drakvuf, "ntoskrnl.exe", "ZwQueryVolumeInformationFile");
        this->queryinfo_va = get_function_va(drakvuf, "ntoskrnl.exe", "ZwQueryInformationFile");
        this->createsection_va = get_function_va(drakvuf, "ntoskrnl.exe", "ZwCreateSection");
        this->close_handle_va = get_function_va(drakvuf, "ntoskrnl.exe", "ZwClose");
        this->mapview_va = get_function_va(drakvuf, "ntoskrnl.exe", "ZwMapViewOfSection");
        this->unmapview_va = get_function_va(drakvuf, "ntoskrnl.exe", "ZwUnmapViewOfSection");
        this->readfile_va = get_function_va(drakvuf, "ntoskrnl.exe", "ZwReadFile");
        this->waitobject_va = get_function_va(drakvuf, "ntoskrnl.exe", "ZwWaitForSingleObject");
        this->exallocatepool_va = get_function_va(drakvuf, "ntoskrnl.exe", "ExAllocatePoolWithTag");
        this->exfreepool_va = get_function_va(drakvuf, "ntoskrnl.exe", "ExFreePoolWithTag");
        this->memcpy_va = get_function_va(drakvuf, "ntoskrnl.exe", "RtlCopyMemoryNonTemporal");

        assert(sizeof(traps)/sizeof(traps[0]) > 3);
        register_trap(drakvuf, "NtSetInformationFile", &traps[0], setinformation_cb);
        register_trap(drakvuf, "NtWriteFile",          &traps[1], writefile_cb);
        register_trap(drakvuf, "NtClose",              &traps[2], close_cb);
        register_trap(drakvuf, "ZwCreateSection",      &traps[3], createsection_cb);
        register_trap(drakvuf, "NtCreateFile",         &traps[4], createfile_cb);
        register_trap(drakvuf, "NtOpenFile",           &traps[5], openfile_cb);
    }

    if ( !drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, __OFFSET_MAX, this->offsets) )
        throw -1;

    if ( !drakvuf_get_kernel_struct_size(drakvuf, "_CONTROL_AREA", &this->control_area_size) )
        throw -1;

    if ( VMI_PM_LEGACY == this->pm )
        this->mmpte_size = 4;
    else
        this->mmpte_size = 8;
}

filedelete::~filedelete()
{
    if (!m_is_stopping)
        stop();
    delete[] offsets;
}

bool filedelete::stop()
{
    for (unsigned long i = 0; i < sizeof(traps)/sizeof(traps[0]); ++i)
        drakvuf_remove_trap(drakvuf, &traps[i], nullptr);
    m_is_stopping = true;
    return closing_handles.empty();
}
