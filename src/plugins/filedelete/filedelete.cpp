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

#include "../plugins.h"
#include "filedelete.h"

#define FILE_DISPOSITION_INFORMATION 13

enum offset {
    FILE_OBJECT_TYPE,
    FILE_OBJECT_FILENAME,
    FILE_OBJECT_SIZE,
    FILE_OBJECT_SECTIONOBJECTPOINTER,
    SECTIONOBJECTPOINTER_DATASECTIONOBJECT,
    SECTIONOBJECTPOINTER_SHAREDCACHEMAP,
    SECTIONOBJECTPOINTER_IMAGESECTIONOBJECT,
    CONTROL_AREA_SEGMENT,
    SEGMENT_CONTROLAREA,
    SEGMENT_SIZEOFSEGMENT,
    SEGMENT_TOTALNUMBEROFPTES,
    SUBSECTION_NEXTSUBSECTION,
    SUBSECTION_SUBSECTIONBASE,
    SUBSECTION_PTESINSUBSECTION,
    SUBSECTION_CONTROLAREA,
    SUBSECTION_STARTINGSECTOR,
    OBJECT_HEADER_BODY,
    UNICODE_STRING_LENGTH,
    UNICODE_STRING_BUFFER,
    __OFFSET_MAX
};

static const char *offset_names[__OFFSET_MAX][2] = {
    [FILE_OBJECT_TYPE] = {"_FILE_OBJECT", "Type"},
    [FILE_OBJECT_FILENAME] = {"_FILE_OBJECT", "FileName"},
    [FILE_OBJECT_SIZE] = {"_FILE_OBJECT", "Size"},
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
    [UNICODE_STRING_LENGTH] = {"_UNICODE_STRING", "Length" },
    [UNICODE_STRING_BUFFER] = {"_UNICODE_STRING", "Buffer" },
};

static void extract_ca_file(filedelete *f, drakvuf_t drakvuf, vmi_instance_t vmi, addr_t control_area, access_context_t *ctx)
{
    addr_t subsection = control_area + f->control_area_size;
    addr_t segment = 0, test = 0, test2 = 0;

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

    char *file = NULL;
    if ( asprintf(&file, "%s/file.0x%lx.mm", f->dump_folder, control_area) < 0 )
        return;

    FILE *fp = fopen(file, "w");

    while(subsection)
    {
        /* Check whether subsection points back to the control area */
        ctx->addr = subsection + f->offsets[SUBSECTION_CONTROLAREA];
        if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &test) || test != control_area )
            break;

        addr_t base;
        uint32_t ptes, start;

        ctx->addr = subsection + f->offsets[SUBSECTION_SUBSECTIONBASE];
        if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &base) )
            break;

        if ( !(base & VMI_BIT_MASK(0,11)) )
            break;

        ctx->addr = subsection + f->offsets[SUBSECTION_PTESINSUBSECTION];
        if ( VMI_FAILURE == vmi_read_32(vmi, ctx, &ptes) )
            break;

        ctx->addr = subsection + f->offsets[SUBSECTION_STARTINGSECTOR];
        if ( VMI_FAILURE == vmi_read_32(vmi, ctx, &start) )
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
            if ( f->mmpte_size != vmi_read(vmi, ctx, &pte, f->mmpte_size) )
                break;

            if ( ENTRY_PRESENT(1, pte) )
            {
                uint8_t page[4096];

                if ( 4096 != vmi_read_pa(vmi, VMI_BIT_MASK(12,48) & pte, page, 4096) )
                    continue;

                fseek ( fp , fileoffset , SEEK_SET );
                fwrite(page, 4096, 1, fp);
            }
        }

        ctx->addr = subsection + f->offsets[SUBSECTION_NEXTSUBSECTION];
        if ( !vmi_read_addr(vmi, ctx, &subsection) )
            break;
    };

    fclose(fp);
    free(file);
}

static void extract_file(filedelete *f,
                         drakvuf_t drakvuf,
                         vmi_instance_t vmi,
                         addr_t file_pa,
                         access_context_t *ctx)
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
        extract_ca_file(f, drakvuf, vmi, datasection, ctx);

    ctx->addr = sop + f->offsets[SECTIONOBJECTPOINTER_SHAREDCACHEMAP];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &sharedcachemap) )
        return;

    // TODO: extraction from sharedcachemap

    ctx->addr = sop + f->offsets[SECTIONOBJECTPOINTER_IMAGESECTIONOBJECT];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &imagesection) )
        return;

    if ( imagesection != datasection )
        extract_ca_file(f, drakvuf, vmi, imagesection, ctx);
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
static void grab_file_by_handle(filedelete *f, drakvuf_t drakvuf,
                                vmi_instance_t vmi,
                                drakvuf_trap_info_t *info, addr_t handle)
{
    uint8_t type = 0;
    addr_t process=drakvuf_get_current_process(drakvuf, info->vcpu);

    // TODO: verify that the dtb in the _EPROCESS is the same as the cr3?

    if (!process)
        return;

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, process, handle);

    if (!obj)
        return;

    addr_t file = obj + f->offsets[OBJECT_HEADER_BODY];
    addr_t filename = file + f->offsets[FILE_OBJECT_FILENAME];
    addr_t filetype = file + f->offsets[FILE_OBJECT_TYPE];

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.addr = filetype;
    ctx.dtb = info->regs->cr3;

    if (VMI_FAILURE == vmi_read_8(vmi, &ctx, &type))
        return;

    if (type != 5)
        return;

    uint16_t length = 0, size = 0;
    addr_t buffer = 0;

    ctx.addr = filename + f->offsets[FILE_OBJECT_SIZE];
    if ( VMI_FAILURE == vmi_read_16(vmi, &ctx, &size) )
        return;

    ctx.addr = filename + f->offsets[UNICODE_STRING_BUFFER];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &buffer) )
        return;

    ctx.addr = filename + f->offsets[UNICODE_STRING_LENGTH];
    if ( VMI_FAILURE == vmi_read_16(vmi, &ctx, &length) )
        return;

    if (length && buffer) {
        unicode_string_t str;
        str.length = length;
        str.encoding = "UTF-16";
        str.contents = (unsigned char *)g_malloc0(length);

        ctx.addr = buffer;
        if ( length != vmi_read(vmi, &ctx, str.contents, length) )
            return;

        unicode_string_t str2 = { .contents = NULL };
        if ( vmi_convert_str_encoding(&str, &str2, "UTF-8") == VMI_SUCCESS )
        {
            switch(f->format) {
            case OUTPUT_CSV:
                printf("filedelete,%" PRIu32 ",0x%" PRIx64 ",%s,%" PRIi64 ",\"%s\"\n",
                       info->vcpu, info->regs->cr3, info->procname, info->userid, str2.contents);
                break;
            default:
            case OUTPUT_DEFAULT:
                printf("[FILEDELETE] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s:%" PRIi64" \"%s\"\n",
                       info->vcpu, info->regs->cr3, info->procname,
                       USERIDSTR(drakvuf), info->userid, str2.contents);
                break;
            };

            if (f->dump_folder)
                extract_file(f, drakvuf, vmi, file, &ctx);

            free(str2.contents);
        }
        g_free(str.contents);
    }
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
static event_response_t setinformation(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {

    filedelete *f = (filedelete *)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    uint32_t fileinfoclass = 0;
    reg_t handle = 0, fileinfo = 0;

    if (f->pm == VMI_PM_IA32E) {
        handle = info->regs->rcx;
        fileinfo = info->regs->r8;

        ctx.addr = info->regs->rsp + 5 * sizeof(addr_t); // addr of fileinfoclass
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &fileinfoclass) )
            goto done;
    } else {
        ctx.addr = info->regs->rsp + sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &handle) )
            goto done;
        ctx.addr += 2 * sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &fileinfo) )
            goto done;
        ctx.addr += 2 * sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &fileinfoclass) )
            goto done;
    }

    if (fileinfoclass == FILE_DISPOSITION_INFORMATION) {
        uint8_t del = 0;
        ctx.addr = fileinfo;
        if ( VMI_FAILURE == vmi_read_8(vmi, &ctx, &del) )
            goto done;

        if (del)
            grab_file_by_handle(f, drakvuf, vmi, info, handle);
    }

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}

filedelete::filedelete(drakvuf_t drakvuf, const void *config, output_format_t output)
{
    const struct filedelete_config *c = (const struct filedelete_config *)config;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->pm = vmi_get_page_mode(vmi, 0);
    this->domid = vmi_get_vmid(vmi);
    drakvuf_release_vmi(drakvuf);

    this->dump_folder = c->dump_folder;
    this->format = output;

    if( !drakvuf_get_function_rva(c->rekall_profile, "NtSetInformationFile", &this->traps[0].breakpoint.rva) )
        throw -1;
    if( !drakvuf_get_function_rva(c->rekall_profile, "ZwSetInformationFile", &this->traps[1].breakpoint.rva) )
        throw -1;

    this->traps[0].name = "NtSetInformationFile";
    this->traps[0].cb = setinformation;
    this->traps[1].name = "ZwSetInformationFile";
    this->traps[1].cb = setinformation;
    /* TODO
    traps[2].u2.rva = drakvuf_get_function_rva(c->rekall_profile, "NtDeleteFile");
    traps[2].name = "NtDeleteFile";
    traps[3].u2.rva = drakvuf_get_function_rva(c->rekall_profile, "ZwDeleteFile");
    traps[3].name = "ZwDeleteFile";*/

    this->offsets = (size_t*)malloc(sizeof(size_t)*__OFFSET_MAX);

    int i;
    for(i=0;i<__OFFSET_MAX;i++) {
        if( !drakvuf_get_struct_member_rva(c->rekall_profile, offset_names[i][0], offset_names[i][1], &this->offsets[i]))
            throw -1;
    }

    if ( !drakvuf_get_struct_size(c->rekall_profile, "_CONTROL_AREA", &this->control_area_size) )
        throw -1;

    if ( VMI_PM_LEGACY == this->pm )
        this->mmpte_size = 4;
    else
        this->mmpte_size = 8;

    if ( !drakvuf_add_trap(drakvuf, &traps[0]) )
        throw -1;
    //drakvuf_add_trap(drakvuf, &traps[1]);
    //drakvuf_add_trap(drakvuf, &traps[2]);
    //drakvuf_add_trap(drakvuf, &traps[3]);
}

filedelete::~filedelete() {
    free(this->offsets);
}
