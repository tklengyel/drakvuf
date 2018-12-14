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
#include <cassert>

#include "../plugins.h"
#include "filedelete.h"
#include "private.h"

#include <libinjector/libinjector.h>

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
};

static std::string fo_flag_to_string(std::string flag, output_format_t format)
{
    switch (format)
    {
        case OUTPUT_KV:
            return flag + "=true,";
        default:
            return flag + " | ";
    }
}

static std::string fo_flags_to_string(uint64_t fo_flags, output_format_t format = OUTPUT_DEFAULT)
{
    std::string str("");

    if (FO_FILE_OPEN & fo_flags)
        str += fo_flag_to_string("FO_FILE_OPEN", format);

    if (FO_SYNCHRONOUS_IO & fo_flags)
        str += fo_flag_to_string("FO_SYNCHRONOUS_IO", format);

    if (FO_ALERTABLE_IO & fo_flags)
        str += fo_flag_to_string("FO_ALERTABLE_IO", format);

    if (FO_NO_INTERMEDIATE_BUFFERING & fo_flags)
        str += fo_flag_to_string("FO_NO_INTERMEDIATE_BUFFERING", format);

    if (FO_WRITE_THROUGH & fo_flags)
        str += fo_flag_to_string("FO_WRITE_THROUGH", format);

    if (FO_SEQUENTIAL_ONLY & fo_flags)
        str += fo_flag_to_string("FO_SEQUENTIAL_ONLY", format);

    if (FO_CACHE_SUPPORTED & fo_flags)
        str += fo_flag_to_string("FO_CACHE_SUPPORTED", format);

    if (FO_NAMED_PIPE & fo_flags)
        str += fo_flag_to_string("FO_NAMED_PIPE", format);

    if (FO_STREAM_FILE & fo_flags)
        str += fo_flag_to_string("FO_STREAM_FILE", format);

    if (FO_MAILSLOT & fo_flags)
        str += fo_flag_to_string("FO_MAILSLOT", format);

    if (FO_GENERATE_AUDIT_ON_CLOSE & fo_flags)
        str += fo_flag_to_string("FO_GENERATE_AUDIT_ON_CLOSE", format);

    if (FO_DIRECT_DEVICE_OPEN & fo_flags)
        str += fo_flag_to_string("FO_DIRECT_DEVICE_OPEN", format);

    if (FO_FILE_MODIFIED & fo_flags)
        str += fo_flag_to_string("FO_FILE_MODIFIED", format);

    if (FO_FILE_SIZE_CHANGED & fo_flags)
        str += fo_flag_to_string("FO_FILE_SIZE_CHANGED", format);

    if (FO_CLEANUP_COMPLETE & fo_flags)
        str += fo_flag_to_string("FO_CLEANUP_COMPLETE", format);

    if (FO_TEMPORARY_FILE & fo_flags)
        str += fo_flag_to_string("FO_TEMPORARY_FILE", format);

    if (FO_DELETE_ON_CLOSE & fo_flags)
        str += fo_flag_to_string("FO_DELETE_ON_CLOSE", format);

    if (FO_OPENED_CASE_SENSITIVE & fo_flags)
        str += fo_flag_to_string("FO_OPENED_CASE_SENSITIVE", format);

    if (FO_HANDLE_CREATED & fo_flags)
        str += fo_flag_to_string("FO_HANDLE_CREATED", format);

    if (FO_FILE_FAST_IO_READ & fo_flags)
        str += fo_flag_to_string("FO_FILE_FAST_IO_READ", format);

    if (FO_RANDOM_ACCESS & fo_flags)
        str += fo_flag_to_string("FO_RANDOM_ACCESS", format);

    if (FO_FILE_OPEN_CANCELLED & fo_flags)
        str += fo_flag_to_string("FO_FILE_OPEN_CANCELLED", format);

    if (FO_VOLUME_OPEN & fo_flags)
        str += fo_flag_to_string("FO_VOLUME_OPEN", format);

    if (FO_REMOTE_ORIGIN & fo_flags)
        str += fo_flag_to_string("FO_REMOTE_ORIGIN", format);

    if (FO_DISALLOW_EXCLUSIVE & fo_flags)
        str += fo_flag_to_string("FO_DISALLOW_EXCLUSIVE", format);

    if (FO_SKIP_SET_EVENT & fo_flags)
        str += fo_flag_to_string("FO_SKIP_SET_EVENT", format);

    if (FO_SKIP_SET_FAST_IO & fo_flags)
        str += fo_flag_to_string("FO_SKIP_SET_FAST_IO", format);

    if (FO_INDIRECT_WAIT_OBJECT & fo_flags)
        str += fo_flag_to_string("FO_INDIRECT_WAIT_OBJECT", format);

    if (FO_SECTION_MINSTORE_TREATMENT & fo_flags)
        str += fo_flag_to_string("FO_SECTION_MINSTORE_TREATMENT", format);

    if (!str.empty())
        switch (format)
        {
            case OUTPUT_KV:
                str.resize(str.size() - 1);
                break;
            default:
                str.resize(str.size() - 3);
                break;
        }

    return str;
}

static bool get_file_object_flags(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, filedelete* f, handle_t handle, uint64_t* flags)
{
    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, info->proc_data.base_addr, handle);
    if (!obj)
        return false; // Break operatioin to not crash VM

    addr_t file = obj + f->offsets[OBJECT_HEADER_BODY];
    addr_t fileflags = file + f->offsets[FILE_OBJECT_FLAGS];

    access_context_t ctx;
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

    if (!info->proc_data.base_addr)
        return {};

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, info->proc_data.base_addr, handle);

    if (!obj)
        return {};

    addr_t file = obj + f->offsets[OBJECT_HEADER_BODY];
    addr_t filename = file + f->offsets[FILE_OBJECT_FILENAME];
    addr_t filetype = file + f->offsets[FILE_OBJECT_TYPE];

    if (out_file)
        *out_file = file;

    if (out_filetype)
        *out_filetype = filetype;

    access_context_t ctx;
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

static void save_file_metadata(filedelete* f,
                               const drakvuf_trap_info_t* info,
                               int sequence_number,
                               addr_t control_area,
                               const char* filename,
                               size_t file_size,
                               uint64_t fo_flags)
{
    char* file = NULL;
    if ( asprintf(&file, "%s/file.%06d.metadata", f->dump_folder, sequence_number) < 0 )
        return;

    FILE* fp = fopen(file, "w");
    free(file);
    if (!fp)
        return;

    fprintf(fp, "FileName: \"%s\"\n", filename ?: "<UNKNOWN>");
    fprintf(fp, "FileSize: %zu\n", file_size);
    fprintf(fp, "FileFlags: 0x%lx (%s)\n", fo_flags, fo_flags_to_string(fo_flags).c_str());
    fprintf(fp, "SequenceNumber: %d\n", sequence_number);
    fprintf(fp, "ControlArea: 0x%lx\n", control_area);
    fprintf(fp, "PID: %" PRIu64 "\n", static_cast<uint64_t>(info->proc_data.pid));
    fprintf(fp, "PPID: %" PRIu64 "\n", static_cast<uint64_t>(info->proc_data.ppid));
    fprintf(fp, "ProcessName: \"%s\"\n", info->proc_data.name);

    fclose(fp);
}

static void extract_ca_file(filedelete* f,
                            drakvuf_t drakvuf,
                            const drakvuf_trap_info_t* info,
                            vmi_instance_t vmi,
                            addr_t control_area,
                            access_context_t* ctx,
                            const char* filename,
                            uint64_t fo_flags)
{
    addr_t subsection = control_area + f->control_area_size;
    addr_t segment = 0, test = 0, test2 = 0;
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

        addr_t base = 0, start = 0;
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

                if ( VMI_FAILURE == vmi_read_pa(vmi, VMI_BIT_MASK(12,48) & pte, 4096, &page, NULL) )
                    continue;

                if ( !fseek ( fp, fileoffset, SEEK_SET ) )
                {
                    if ( fwrite(page, 4096, 1, fp) )
                        filesize = fileoffset + 4096;
                }
            }
        }

        ctx->addr = subsection + f->offsets[SUBSECTION_NEXTSUBSECTION];
        if ( !vmi_read_addr(vmi, ctx, &subsection) )
            break;
    }

    fclose(fp);

    save_file_metadata(f, info, curr_sequence_number, control_area, filename, filesize, fo_flags);
}

static void extract_file(filedelete* f,
                         drakvuf_t drakvuf,
                         const drakvuf_trap_info_t* info,
                         vmi_instance_t vmi,
                         addr_t file_pa,
                         access_context_t* ctx,
                         const char* filename,
                         uint64_t fo_flags)
{
    addr_t sop = 0;
    addr_t datasection = 0, sharedcachemap = 0, imagesection = 0;

    ctx->addr = file_pa + f->offsets[FILE_OBJECT_SECTIONOBJECTPOINTER];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &sop) )
        return;

    ctx->addr = sop + f->offsets[SECTIONOBJECTPOINTER_DATASECTIONOBJECT];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &datasection) )
        return;

    if ( datasection )
        extract_ca_file(f, drakvuf, info, vmi, datasection, ctx, filename, fo_flags);

    ctx->addr = sop + f->offsets[SECTIONOBJECTPOINTER_SHAREDCACHEMAP];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &sharedcachemap) )
        return;

    // TODO: extraction from sharedcachemap

    ctx->addr = sop + f->offsets[SECTIONOBJECTPOINTER_IMAGESECTIONOBJECT];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &imagesection) )
        return;

    if ( imagesection != datasection )
        extract_ca_file(f, drakvuf, info, vmi, imagesection, ctx, filename, fo_flags);
}

static void print_filedelete_information(filedelete* f, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const char* filename, size_t bytes_read = 0, uint64_t fo_flags = 0)
{
    std::string flags = fo_flags_to_string(fo_flags, f->format);
    switch (f->format)
    {
        case OUTPUT_CSV:
            printf("filedelete," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",\"%s\",%" PRIu64 ",0x%" PRIx64 "(%s)\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid, filename, bytes_read, fo_flags, flags.c_str());
            break;
        case OUTPUT_KV:
            if (!flags.empty())
                flags = "," + flags;
            printf("filedelete Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,FileName=\"%s\",Size=%ld%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   info->trap->name, filename, bytes_read, flags.c_str());
            break;
        default:
        case OUTPUT_DEFAULT:
            printf("[FILEDELETE] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64" \"%s\" SIZE:%" PRIu64 " FO_FLAGS:0x%" PRIx64 "(%s)\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid, filename, bytes_read, fo_flags, flags.c_str());
            break;
    }
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
                                drakvuf_trap_info_t* info, addr_t handle)
{
    addr_t file = 0;
    addr_t filetype = 0;
    std::string filename = get_file_name(f, drakvuf, vmi, info, handle, &file, &filetype);
    if (filename.empty()) return;

    uint64_t fo_flags = 0;
    get_file_object_flags(drakvuf, info, vmi, f, handle, &fo_flags);

    print_filedelete_information(f, drakvuf, info, filename.c_str(), 0, fo_flags);

    if (f->dump_folder)
    {
        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .addr = filetype,
            .dtb = info->regs->cr3,
        };
        extract_file(f, drakvuf, info, vmi, file, &ctx, filename.c_str(), fo_flags);
    }
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

static event_response_t finish_readfile(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, bool is_success = false)
{
    if (!is_success)
    {
        wrapper_t* injector = (wrapper_t*)info->trap->data;
        filedelete* f = injector->f;

        grab_file_by_handle(f, drakvuf, vmi, info, injector->handle);
    }

    wrapper_t* injector = (wrapper_t*)info->trap->data;
    filedelete* f = injector->f;
    auto filename = f->files[std::make_pair(info->proc_data.pid, injector->handle)];
    print_filedelete_information(f, drakvuf, info, filename.c_str(), injector->ntreadfile_info.bytes_read, injector->fo_flags);

    free_resources(drakvuf, info);
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

event_response_t readfile_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;
    filedelete* f = injector->f;

    if (info->regs->cr3 != injector->target_cr3)
        return 0;

    uint32_t thread_id = 0;
    if (!drakvuf_get_current_thread_id(drakvuf, info->vcpu, &thread_id))
        return 0;

    if (thread_id != injector->target_thread_id)
        return 0;

    auto response = 0;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = injector->ntreadfile_info.io_status_block,
    };

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    const uint32_t status = info->regs->rax;
    uint32_t isb_status = 0; // `isb` is `IO_STATUS_BLOCK`
    size_t isb_size = 0;
    bool is_success = false;

    if (injector->is32bit)
    {
        struct IO_STATUS_BLOCK_32 io_status_block;
        if ((VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(io_status_block), &io_status_block, NULL)))
            goto err;

        isb_status = io_status_block.status;
        isb_size = io_status_block.info;
    }
    else
    {
        struct IO_STATUS_BLOCK_64 io_status_block;
        if ((VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(io_status_block), &io_status_block, NULL)))
            goto err;

        isb_status = io_status_block.status;
        isb_size = io_status_block.info;
    }

    if ( STATUS_SUCCESS == status && isb_size )
    {
        if (injector->curr_sequence_number < 0) injector->curr_sequence_number = ++f->sequence_number;
        const int curr_sequence_number = injector->curr_sequence_number;

        void* buffer = g_malloc0(isb_size);

        ctx.addr = injector->ntreadfile_info.out;
        if (VMI_FAILURE == vmi_read(vmi, &ctx, isb_size, buffer, NULL))
        {
            g_free(buffer);
            goto err;
        }

        bool success = save_file_chunk(f, curr_sequence_number, buffer, isb_size);
        g_free(buffer);
        if (!success)
            goto err;

        injector->ntreadfile_info.bytes_read += isb_size;

        if (BYTES_TO_READ == isb_size)
        {
            if (inject_readfile(drakvuf, info, vmi, injector))
            {
                response = VMI_EVENT_RESPONSE_SET_REGISTERS;
                goto done;
            }
            else
            {
                goto err;
            }
        }
        else
        {
            auto filename = f->files[std::make_pair(info->proc_data.pid, injector->handle)];
            save_file_metadata(f, info, curr_sequence_number, 0, filename.c_str(), injector->ntreadfile_info.bytes_read, injector->fo_flags);

        }
    }
    else
    {
        PRINT_DEBUG("[FILEDELETE2] [ReadFile] Failed to read %s with status 0x%lx and IO_STATUS_BLOCK = { Status 0x%x; Size 0x%lx} .\n",
                    f->files[std::make_pair(info->proc_data.pid, injector->handle)].c_str(), info->regs->rax, isb_status, isb_size);
        goto err;
    }

    is_success = true;
    goto handled;

err:
    PRINT_DEBUG("[FILEDELETE2] [ReadFile] Error. Stop processing (CR3 0x%lx, TID %d, FileName '%s', status 0x%lx).\n",
                info->regs->cr3, thread_id, f->files[std::make_pair(info->proc_data.pid, injector->handle)].c_str(), info->regs->rax);

handled:
    response = finish_readfile(drakvuf, info, vmi, is_success);

done:
    drakvuf_release_vmi(drakvuf);

    return response;
}

event_response_t exallocatepool_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    wrapper_t* injector = (wrapper_t*)info->trap->data;

    auto response = 0;
    uint32_t thread_id = 0;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if (info->regs->cr3 != injector->target_cr3)
        goto done;

    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &thread_id) ||
            !injector->target_thread_id || thread_id != injector->target_thread_id )
        goto done;

    if (info->regs->rax)
    {
        injector->f->pools[info->regs->rax] = true;

        injector->pool = info->regs->rax;
        if (inject_readfile(drakvuf, info, vmi, injector))
        {
            response = VMI_EVENT_RESPONSE_SET_REGISTERS;
            goto done;
        }
        else
        {
            goto err;
        }
    }

err:
    PRINT_DEBUG("[FILEDELETE2] [ExAllocatePoolWithTag] Error. Stop processing (CR3 0x%lx, TID %d).\n",
                info->regs->cr3, thread_id);

    response = finish_readfile(drakvuf, info, vmi);

done:
    drakvuf_release_vmi(drakvuf);

    return response;
}

event_response_t queryobject_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;

    auto response = 0;
    uint32_t thread_id = 0;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if (info->regs->cr3 != injector->target_cr3)
        goto done;

    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &thread_id) ||
            !injector->target_thread_id || thread_id != injector->target_thread_id )
        goto done;

    if (info->regs->rax)
        goto handled;
    else
    {
        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = injector->ntqueryobject_info.out,
        };

        struct FILE_FS_DEVICE_INFORMATION dev_info = { 0 };
        if ((VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct FILE_FS_DEVICE_INFORMATION), &dev_info, NULL)))
        {
            PRINT_DEBUG("[FILEDELETE2] [QueryObject] Failed to read FsDeviceInformation\n");
            goto err;
        }

        if (7 != dev_info.device_type) // FILE_DEVICE_DISK
            goto handled;

        injector->ntreadfile_info.bytes_read = 0UL;

        addr_t pool = find_pool(injector->f->pools);
        if (!pool)
        {
            if (inject_allocate_pool(drakvuf, info, vmi, injector))
            {
                response = VMI_EVENT_RESPONSE_SET_REGISTERS;
                goto done;
            }
        }
        else
        {
            injector->pool = pool;
            if (inject_readfile(drakvuf, info, vmi, injector))
            {
                response = VMI_EVENT_RESPONSE_SET_REGISTERS;
                goto done;
            }
        }
    }

err:
    PRINT_DEBUG("[FILEDELETE2] [QueryObject] Error. Stop processing (CR3 0x%lx, TID %d).\n",
                info->regs->cr3, thread_id);

handled:
    response = finish_readfile(drakvuf, info, vmi);

done:
    drakvuf_release_vmi(drakvuf);

    return response;
}

/*
 * Drakvuf must be locked/unlocked in the caller
 */
static event_response_t start_readfile(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, handle_t handle, const char* filename)
{
    filedelete* f = (filedelete*)info->trap->data;

    uint64_t fo_flags = 0;
    if (!get_file_object_flags(drakvuf, info, vmi, f, handle, &fo_flags))
        return 0;

    bool is_synchronous = (fo_flags & FO_SYNCHRONOUS_IO);
    if (!is_synchronous)
        return 0;

    if ( 0 == info->proc_data.base_addr )
    {
        PRINT_DEBUG("[FILEDELETE2] Failed to get process base on vCPU 0x%d\n",
                    info->vcpu);
        return 0;
    }

    uint32_t target_thread_id = 0;
    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &target_thread_id) ||
            !target_thread_id )
    {
        PRINT_DEBUG("[FILEDELETE2] Failed to get Thread ID\n");
        return 0;
    }

    /*
     * Check if process/thread is being processed. If so skip it. Add it into
     * regestry otherwise.
     */
    auto thread = std::make_pair(info->regs->cr3, target_thread_id);
    auto thread_it = f->closing_handles.find(thread);
    auto map_end = f->closing_handles.end();
    if (map_end != thread_it)
    {
        bool handled = thread_it->second;
        if (handled)
        {
            f->files.erase(std::make_pair(info->proc_data.pid, handle));
            f->closing_handles.erase(thread);
        }

        return 0;
    }
    else
        f->closing_handles[thread] = false;

    /*
     * Real function body.
     *
     * Now we are sure this is new call to NtClose (not result of function injection) and
     * the Handle have been modified in NtWriteFile. So we should save it on the host.
     */
    wrapper_t* injector = (wrapper_t*)g_malloc0(sizeof(wrapper_t));
    if (!injector)
        return 0;

    injector->bp = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
    if (!injector->bp)
    {
        g_free(injector);
        return 0;
    }

    injector->f = f;
    injector->bp->name = info->trap->name;
    injector->handle = handle;
    injector->fo_flags = fo_flags;
    injector->is32bit = (f->pm != VMI_PM_IA32E);
    injector->target_cr3 = info->regs->cr3;
    injector->curr_sequence_number = -1;
    injector->eprocess_base = info->proc_data.base_addr;
    injector->target_thread_id = target_thread_id;

    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

    if (inject_queryobject(drakvuf, info, vmi, injector))
        return VMI_EVENT_RESPONSE_SET_REGISTERS;

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    return 0;
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
    filedelete* f = (filedelete*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t fileinfo = drakvuf_get_function_argument(drakvuf, info, 3);
    uint32_t fileinfoclass = drakvuf_get_function_argument(drakvuf, info, 5);

    event_response_t response = 0;
    if (fileinfoclass == FILE_DISPOSITION_INFORMATION)
    {
        uint8_t del = 0;
        access_context_t ctx;
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = fileinfo;
        if ( VMI_FAILURE == vmi_read_8(vmi, &ctx, &del) )
            goto done;

        if (del)
        {
            if (f->use_injector)
            {
                auto filename = get_file_name(f, drakvuf, vmi, info, handle, nullptr, nullptr);
                if (filename.empty()) filename = "<UNKNOWN>";

                f->files[std::make_pair(info->proc_data.pid, handle)] = filename;

                response = start_readfile(drakvuf, info, vmi, handle, filename.c_str());
            }
            else
            {
                grab_file_by_handle(f, drakvuf, vmi, info, handle);
            }
        }
    }

done:
    drakvuf_release_vmi(drakvuf);
    return response;
}

static event_response_t writefile_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    filedelete* f = (filedelete*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);

    auto filename = get_file_name(f, drakvuf, vmi, info, handle, nullptr, nullptr);
    if (filename.empty()) filename = "<UNKNOWN>";

    f->files[std::make_pair(info->proc_data.pid, handle)] = filename;

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
    filedelete* f = (filedelete*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);

    auto response = 0;
    if (f->use_injector)
    {
        /*
         * Check if closing handle have been changed with NtWriteFile
         */
        auto filename = f->files[std::make_pair(info->proc_data.pid, handle)];
        if (filename.empty())
            goto err;

        response = start_readfile(drakvuf, info, vmi, handle, filename.c_str());
    }
    else
    {
        if (f->files.erase(std::make_pair(info->proc_data.pid, handle)) > 0)
        {
            // We detect the fact of closing of the previously modified file.
            grab_file_by_handle(f, drakvuf, vmi, info, handle);
        }
    }

err:
    drakvuf_release_vmi(drakvuf);
    return response;
}

static event_response_t createsection_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    filedelete* f = (filedelete*)info->trap->data;
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

    f->files[std::make_pair(info->proc_data.pid, handle)] = filename;

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}


static void register_trap( drakvuf_t drakvuf, const char* syscall_name,
                           drakvuf_trap_t* trap,
                           event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    if ( !drakvuf_get_function_rva( drakvuf, syscall_name, &trap->breakpoint.rva) ) throw -1;

    trap->name = syscall_name;
    trap->cb   = hook_cb;

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}

static addr_t get_function_va(drakvuf_t drakvuf, const char* lib, const char* func_name)
{
    addr_t rva;
    if ( !drakvuf_get_function_rva( drakvuf, func_name, &rva) )
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

filedelete::filedelete(drakvuf_t drakvuf, const void* config, output_format_t output)
    : sequence_number()
{
    const struct filedelete_config* c = (const struct filedelete_config*)config;
    this->pm = drakvuf_get_page_mode(drakvuf);

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->domid = vmi_get_vmid(vmi);
    drakvuf_release_vmi(drakvuf);

    this->dump_folder = c->dump_folder;
    this->format = output;
    this->use_injector = c->filedelete_use_injector;

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
        this->queryobject_va = get_function_va(drakvuf, "ntoskrnl.exe", "ZwQueryVolumeInformationFile");
        this->readfile_va = get_function_va(drakvuf, "ntoskrnl.exe", "ZwReadFile");
        this->waitobject_va = get_function_va(drakvuf, "ntoskrnl.exe", "ZwWaitForSingleObject");
        this->exallocatepool_va = get_function_va(drakvuf, "ntoskrnl.exe", "ExAllocatePoolWithTag");
        this->exfreepool_va = get_function_va(drakvuf, "ntoskrnl.exe", "ExFreePoolWithTag");

        assert(sizeof(traps)/sizeof(traps[0]) > 3);
        register_trap(drakvuf, "NtSetInformationFile", &traps[0], setinformation_cb);
        register_trap(drakvuf, "NtWriteFile",          &traps[1], writefile_cb);
        register_trap(drakvuf, "NtClose",              &traps[2], close_cb);
        register_trap(drakvuf, "ZwCreateSection",      &traps[3], createsection_cb);
    }

    this->offsets = (size_t*)malloc(sizeof(size_t)*__OFFSET_MAX);

    if ( !drakvuf_get_struct_members_array_rva(drakvuf, offset_names, __OFFSET_MAX, this->offsets) )
        throw -1;

    if ( !drakvuf_get_struct_size(drakvuf, "_CONTROL_AREA", &this->control_area_size) )
        throw -1;

    if ( VMI_PM_LEGACY == this->pm )
        this->mmpte_size = 4;
    else
        this->mmpte_size = 8;
}

filedelete::~filedelete()
{
    free(this->offsets);
}
