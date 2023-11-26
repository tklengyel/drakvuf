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
 ***************************************************************************/

#include "plugins/output_format.h"
#include <libdrakvuf/libdrakvuf.h>

#include "procdump_linux.h"
#include "private.h"

using namespace std::string_literals;
using namespace procdump_linux_ns;

static void process_visitor(drakvuf_t drakvuf, addr_t process, void* visitor_ctx)
{
    auto ctx = reinterpret_cast<std::vector<vmi_pid_t>*>(visitor_ctx);

    vmi_pid_t pid = 0;
    if (!drakvuf_get_process_pid(drakvuf, process, &pid))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to get PID of process 0x%" PRIx64 "\n", process);
        return;
    }

    ctx->push_back(pid);
}

std::vector<vmi_pid_t> procdump_linux::get_running_processes()
{
    std::vector<vmi_pid_t> pids;
    drakvuf_enumerate_processes(drakvuf, process_visitor, &pids);
    return pids;
}

void procdump_linux::save_file_metadata(std::shared_ptr<linux_procdump_task_t> task)
{
    FILE* fp = fopen((procdump_dir / (task->data_file_name + ".metadata"s)).c_str(), "w");
    if (!fp)
    {
        PRINT_DEBUG("[PROCDUMP] [%d:%d] Failed to open metadata file\n", task->process_data.pid, task->process_data.tid);
        return;
    }

    json_object* jobj = json_object_new_object();
    json_object_object_add(jobj, "DumpSize", json_object_new_string_fmt("0x%" PRIx64, task->dump_size));
    json_object_object_add(jobj, "PID", json_object_new_int(task->process_data.pid));
    json_object_object_add(jobj, "PPID", json_object_new_int(task->process_data.ppid));
    json_object_object_add(jobj, "ProcessName", json_object_new_string(task->process_data.name));
    json_object_object_add(jobj, "TargetPID", json_object_new_int(task->process_data.pid));
    json_object_object_add(jobj, "TargetName", json_object_new_string(task->process_data.name));
    json_object_object_add(jobj, "Compression", json_object_new_string(use_compression ? "gzip" : "none"));
    json_object_object_add(jobj, "Status", json_object_new_string("Success"));
    json_object_object_add(jobj, "DataFileName", json_object_new_string(task->data_file_name.data()));
    json_object_object_add(jobj, "SequenceNumber", json_object_new_int(task->idx));

    fprintf(fp, "%s\n", json_object_get_string(jobj));
    fclose(fp);

    json_object_put(jobj);
}

void procdump_linux::dump_zero_page(std::shared_ptr<linux_procdump_task_t> task)
{
    uint8_t zeros[VMI_PS_4KB] = {};
    task->writer->append(zeros, VMI_PS_4KB);
}

void procdump_linux::read_vm(drakvuf_t drakvuf, vmi_instance_t vmi, vm_area_info vm_area, std::shared_ptr<linux_procdump_task_t> task)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = task->process_data.pid,
        .addr = vm_area.vm_start);

    addr_t aligned_size = (vm_area.size) & ~(VMI_PS_4KB - 1);
    auto intra_page_offset = vm_area.vm_start & (VMI_PS_4KB - 1);
    if (vm_area.size & (VMI_PS_4KB - 1))
        aligned_size += VMI_PS_4KB;

    if (vm_area.size + intra_page_offset > aligned_size)
        aligned_size += VMI_PS_4KB;

    auto num_pages = aligned_size / VMI_PS_4KB ;

    std::vector<void*> access_ptrs(num_pages, nullptr);

    if (VMI_SUCCESS == vmi_mmap_guest(vmi, &ctx, num_pages, PROT_READ, access_ptrs.data()))
    {
        for (size_t i = 0; i < num_pages; ++i)
        {
            if (access_ptrs[i])
            {
                task->writer->append(static_cast<uint8_t*>(access_ptrs[i]), VMI_PS_4KB);
                munmap(access_ptrs[i], VMI_PS_4KB);
            }
            else
                dump_zero_page(task);
        }
    }
    else
    {
        // unaccessible page, pad with zeros to ensure proper alignment of the data
        for (size_t i = 0; i < num_pages; ++i)
            dump_zero_page(task);
    }
}

void procdump_linux::write_program_headers(std::shared_ptr<linux_procdump_task_t> task, std::vector<vm_area_info> vma_list)
{
    //add PT_NOTE program header for notes
    struct elf64_program_header note_program_header(PT_NOTE, 0, task->note_offset, 0, 0, task->note_aligned, 0);
    task->writer->append((const uint8_t*)&note_program_header, sizeof(struct elf64_program_header));

    //add program header for each memory region
    for (uint64_t i = 0; i < vma_list.size(); i++)
    {
        struct elf64_program_header pr_header(PT_LOAD, vma_list[i].segment_flags, vma_list[i].file_offset, vma_list[i].vm_start, 0, vma_list[i].size, vma_list[i].size);
        task->writer->append((const uint8_t*)&pr_header, sizeof(struct elf64_program_header));
    }
}

void procdump_linux::write_section_headers(std::shared_ptr<linux_procdump_task_t> task, std::vector<vm_area_info> vma_list)
{
    //add STRTAB section into dump file. it contains the names of all sections
    //String Table format: https://refspecs.linuxbase.org/elf/elf.pdf#page=31
    task->writer->append((const uint8_t*)&string_table_section, sizeof(string_table_section));

    //add null section (only it's header). Some unpackers need it to work properly
    struct elf64_section_header null_section_header(NULL_INDEX, SHT_NULL, 0, 0, 0, 0, 0);
    task->writer->append((const uint8_t*)&null_section_header, sizeof(struct elf64_section_header));

    //add SHT_NOTE section header for notes
    struct elf64_section_header note_section_header(NOTE0_INDEX, SHT_NOTE, 0, 0, task->note_offset, task->note_aligned, 1);
    task->writer->append((const uint8_t*)&note_section_header, sizeof(struct elf64_section_header));

    //add section header for each memory region
    for (uint64_t i = 0; i < vma_list.size(); i++)
    {
        struct elf64_section_header sc_header(LOAD_INDEX, SHT_PROGBITS, vma_list[i].section_flags, vma_list[i].vm_start, vma_list[i].file_offset, vma_list[i].size, 1);
        task->writer->append((const uint8_t*)&sc_header, sizeof(struct elf64_section_header));
    }

    //add STRTAB section header
    uint64_t strtab_offset = task->note_offset + task->note_aligned;
    struct elf64_section_header string_table_section_header(SHSTRTAB_INDEX, SHT_STRTAB, 0, 0, strtab_offset, sizeof(string_table_section), 1);
    task->writer->append((const uint8_t*)&string_table_section_header, sizeof(struct elf64_section_header));
}

void procdump_linux::calc_note_size_and_count(std::vector<vm_area_info> vma_list, uint64_t* note_size, uint64_t* note_count)
{
    //for now notes contain only NT_FILE with mapped filenames
    *note_size += sizeof(struct elf64_note_header);
    *note_size += sizeof(struct elf64_nt_file_header);

    for (uint64_t i = 0; i < vma_list.size(); i++)
    {
        if (!vma_list[i].filename.empty())
        {
            *note_size += sizeof(struct elf64_nt_file_entry) + vma_list[i].filename.size() + 1;
            *note_count += 1;
        }
    }
}

void procdump_linux::write_notes(std::shared_ptr<linux_procdump_task_t> task, std::vector<vm_area_info> vma_list)
{
    //all notes header
    struct elf64_note_header note_header(task->note_size - sizeof(struct elf64_note_header));
    task->writer->append((const uint8_t*)&note_header, sizeof(struct elf64_note_header));

    //NT_FILE header
    struct elf64_nt_file_header nt_file_header(task->note_count, address_width);
    task->writer->append((const uint8_t*)&nt_file_header, sizeof(struct elf64_nt_file_header));

    // File associations (NT_FILE) described here : https://www.gabriel.urdhr.fr/2015/05/29/core-file/
    for (uint64_t i = 0; i < vma_list.size(); i++)
    {
        if (!vma_list[i].filename.empty())
        {
            struct elf64_nt_file_entry nt(vma_list[i].vm_start, vma_list[i].vm_end, vma_list[i].vm_pgoff * VMI_PS_4KB);
            task->writer->append((const uint8_t*)&nt, sizeof(struct elf64_nt_file_entry));
        }
    }

    for (uint64_t i = 0; i < vma_list.size(); i++)
    {
        if (!vma_list[i].filename.empty())
        {
            task->writer->append((const uint8_t*)vma_list[i].filename.c_str(), vma_list[i].filename.size() + 1);
        }
    }

    //4-byte alignment for notes. readelf can't read them without memory alignment
    uint8_t null = '\0';
    for (uint64_t i = 0; i < task->note_aligned - task->note_size; i++)
        task->writer->append((const uint8_t*)&null, sizeof(uint8_t));
}

void procdump_linux::start_copy_memory(drakvuf_t drakvuf, vmi_instance_t vmi, std::shared_ptr<linux_procdump_task_t> task, std::vector<vm_area_info> vma_list)
{
    calc_note_size_and_count(vma_list, &task->note_size, &task->note_count);

    task->note_aligned = task->note_size;
    if (task->note_size % 4)
        task->note_aligned += 4 - (task->note_size % 4);

    auto elf_header =  elf64_header(sizeof(struct elf64_header),
            task->note_offset + task->note_aligned + sizeof(string_table_section),
            vma_list.size() + 1,  // All memory regions + PT_NOTE
            vma_list.size() + 3,  // All memory regions + SHT_NULL + SHT_NOTE + SHT_STRTAB
            vma_list.size() + 2); // Section header string table index. It is last section, but counting starts from 0

    task->writer->append((const uint8_t*)&elf_header, sizeof(struct elf64_header));

    write_program_headers(task, vma_list);

    for (uint64_t i = 0; i < vma_list.size(); i++)
    {
        read_vm(drakvuf, vmi, vma_list[i], task);
    }

    write_notes(task, vma_list);
    write_section_headers(task, vma_list);
    task->writer->finish();
    task->dump_size = task->writer->data_size();
}

void procdump_linux::print_dump_exclusion(drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("[PROCDUMP] Skip excluded process %d (%s)\n"
        , info->proc_data.pid
        , info->proc_data.name
    );
    fmt::print(m_output_format, "procdump_skip", drakvuf, info,
        keyval("Message", fmt::Rstr("Excluded by filter"))
    );
}

void procdump_linux::print_dump_failure(addr_t process_base, const std::string& message)
{
    //fill some data for output message
    drakvuf_trap_info_t info = {};
    drakvuf_trap_t trap = {};

    if (!drakvuf_get_process_data(drakvuf, process_base, &info.proc_data))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to get data of process 0x%" PRIx64 "\n", process_base);
        return;
    }

    addr_t cr3;
    drakvuf_get_process_dtb(drakvuf, process_base, &cr3);
    x86_registers_t regs
    {
        .cr3 = cr3
    };

    info.regs = &regs;
    info.timestamp = g_get_real_time();
    info.trap = &trap;

    PRINT_DEBUG("[PROCDUMP] Failed to dump process %d (%s)\n"
        , info.proc_data.pid
        , info.proc_data.name
    );
    fmt::print(m_output_format, "procdump_fail", drakvuf, &info,
        keyval("Message", fmt::Rstr(message))
    );

    g_free(const_cast<char*>(info.proc_data.name));
}

void procdump_linux::print_dump_info(std::shared_ptr<linux_procdump_task_t> task)
{
    //fill some data for output message
    drakvuf_trap_info_t info = {};
    drakvuf_trap_t trap = {};

    addr_t cr3;
    drakvuf_get_process_dtb(drakvuf, task->process_base, &cr3);
    x86_registers_t regs
    {
        .cr3 = cr3
    };

    info.regs = &regs;
    info.timestamp = g_get_real_time();
    info.trap = &trap;
    info.proc_data = task->process_data;

    fmt::print(m_output_format, "procdump", drakvuf, &info,
        keyval("TargetPID", fmt::Nval(task->process_data.pid)),
        keyval("TargetName", fmt::Estr(task->process_data.name)),
        keyval("DumpReason", task->reason ? fmt::Estr("TerminateProcess") : fmt::Estr("FinishAnalysis")),
        keyval("DumpSize", fmt::Nval(task->dump_size)),
        keyval("SN", fmt::Nval(task->idx)),
        keyval("Status", fmt::Estr("Success"))
    );

    g_free(const_cast<char*>(info.proc_data.name));
}

// https://elixir.bootlin.com/linux/latest/source/lib/maple_tree.c#L208
static uint64_t node_type(addr_t node_addr)
{
    return (node_addr >> MAPLE_NODE_TYPE_SHIFT) & MAPLE_NODE_TYPE_MASK;
}

static void convert_flags(vm_area_info& info, uint32_t flags)
{
    if (flags & VM_READ)
    {
        info.segment_flags += PF_R;
        info.section_flags += SHF_ALLOC;
    }
    if (flags & VM_WRITE)
    {
        info.segment_flags += PF_W;
        info.section_flags += SHF_WRITE;
    }
    if (flags & VM_EXEC)
    {
        info.segment_flags += PF_X;
        info.section_flags += SHF_EXECINSTR;
    }
}

// read vm_area_info from given address
void procdump_linux::read_vma_info(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t vm_area, proc_data_t const& process_data, std::vector<vm_area_info>& vma_list)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = process_data.pid,
        .addr = vm_area + this->offsets[VM_AREA_STRUCT_VM_START]);

    vm_area_info info = {};
    addr_t vm_file = 0;
    addr_t dentry_addr = 0;
    uint32_t flags = 0;

    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &info.vm_start))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to read vm_start\n");
        return;
    }

    ctx.addr = vm_area + this->offsets[VM_AREA_STRUCT_VM_END];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &info.vm_end))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to read vm_end\n");
        return;
    }

    info.size = info.vm_end - info.vm_start;

    ctx.addr = vm_area + this->offsets[VM_AREA_STRUCT_VM_FLAGS];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &flags))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to read flags\n");
        return;
    }

    convert_flags(info, flags);

    if (!info.segment_flags)
        return;

    ctx.addr = vm_area + this->offsets[VM_AREA_STRUCT_VM_FILE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &vm_file))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to read vm_file\n");
        return;
    }

    ctx.addr = vm_file + this->offsets[_FILE_F_PATH] + this->offsets[_PATH_DENTRY];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &dentry_addr))
    {
        dentry_addr = 0;
    }

    //get mapped filename if file has been mapped
    char* tmp = drakvuf_get_filepath_from_dentry(drakvuf, dentry_addr);
    info.filename = tmp ?: "";
    g_free(tmp);

    if (!info.filename.empty())
    {
        ctx.addr = vm_area + this->offsets[VM_AREA_STRUCT_VM_PGOFF];
        if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &info.vm_pgoff))
        {
            PRINT_DEBUG("[PROCDUMP] Failed to read next vm_pgoff\n");
            return;
        }
    }

    vma_list.push_back(info);
}

// leafes stored in maple_range_64, but slots are pointers to vm_area_struct
void procdump_linux::read_range_leafes(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t node_addr, proc_data_t const& process_data, std::vector<vm_area_info>& vma_list)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = process_data.pid,
        .addr = (node_addr & ~MAPLE_NODE_MASK) + this->tree_offsets[MAPLE_RANGE_SLOT]);

    addr_t slot = 0;

    for (int i = 0; i < MAPLE_RANGE64_SLOTS; i++)
    {
        slot = 0;
        if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &slot))
        {
            PRINT_DEBUG("[PROCDUMP] Failed to read slot\n");
        }
        // some slots may be set to 0
        // last slot sometimes filled with used slot counter
        if (slot > MAPLE_RANGE64_SLOTS)
        {
            read_vma_info(drakvuf, vmi, slot, process_data, vma_list);
        }
        ctx.addr += 8;
    }
}

void procdump_linux::read_range_node_impl(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t node_addr, proc_data_t const& process_data, std::vector<vm_area_info>& vma_list, int count, uint64_t offset)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = process_data.pid,
        .addr = (node_addr & ~MAPLE_NODE_MASK) + offset);

    addr_t slot = 0;

    // get all non-zero slots
    for (int i = 0; i < count; i++)
    {
        slot = 0;
        if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &slot))
        {
            PRINT_DEBUG("[PROCDUMP] Failed to read slot\n");
            return;
        }
        if (slot)
        {
            switch (node_type(slot))
            {
                case MAPLE_ARANGE_64:
                    read_arange_node(drakvuf, vmi, slot, process_data, vma_list);
                    break;
                case MAPLE_RANGE_64:
                    read_range_node(drakvuf, vmi, slot, process_data, vma_list);
                    break;
                case MAPLE_LEAF_64:
                    read_range_leafes(drakvuf, vmi, slot, process_data, vma_list);
                    break;
                default:
                    PRINT_DEBUG("[PROCDUMP] Unsupported node type\n");
                    break;
            }
        }
        ctx.addr += 8;
    }
}

// Read range node and go deeper into the tree
void procdump_linux::read_range_node(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t node_addr, proc_data_t const& process_data, std::vector<vm_area_info>& vma_list)
{
    read_range_node_impl(drakvuf, vmi, node_addr, process_data, vma_list, MAPLE_RANGE64_SLOTS, this->tree_offsets[MAPLE_RANGE_SLOT]);
}

// Read arange node and go deeper into the tree
void procdump_linux::read_arange_node(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t node_addr, proc_data_t const& process_data, std::vector<vm_area_info>& vma_list)
{
    read_range_node_impl(drakvuf, vmi, node_addr, process_data, vma_list, MAPLE_ARANGE64_SLOTS, this->tree_offsets[MAPLE_ARANGE_SLOT]);
}

/* Non-leaf nodes store the type of the node pointed to (enum maple_type in bits 3-6)
    https://elixir.bootlin.com/linux/v6.6.1/source/include/linux/maple_tree.h#L93

    That's why we need to trim the lower bits of the address with MAPLE_NODE_MASK,
    otherwise they will point to incorrect data.
*/

std::vector<vm_area_info> procdump_linux::get_vmas_from_maple_tree(drakvuf_t drakvuf, vmi_instance_t vmi, proc_data_t const& process_data)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = process_data.pid,
        .addr = process_data.base_addr + this->offsets[TASK_STRUCT_ACTIVE_MM]);

    uint32_t map_count = 0;
    addr_t active_mm = 0;
    addr_t ma_root = 0;

    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &active_mm))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to read active_mm\n");
        return {};
    }

    ctx.addr = active_mm + this->offsets[MM_STRUCT_MAP_COUNT];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &map_count))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to read map_count\n");
        return {};
    }

    ctx.addr = active_mm + this->tree_offsets[MM_STRUCT_MM_MT] + this->tree_offsets[MAPLE_TREE_MA_ROOT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ma_root))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to read ma_root\n");
        return {};
    }

    std::vector<vm_area_info> vma_list;
    vma_list.reserve(map_count);

    // Start VMA search from maple tree root
    switch (node_type(ma_root))
    {
        case MAPLE_ARANGE_64:
            read_arange_node(drakvuf, vmi, ma_root, process_data, vma_list);
            break;
        case MAPLE_RANGE_64:
            read_range_node(drakvuf, vmi, ma_root, process_data, vma_list);
            break;
        case MAPLE_LEAF_64:
            read_range_leafes(drakvuf, vmi, ma_root, process_data, vma_list);
            break;
        default:
            PRINT_DEBUG("[PROCDUMP] Unsupported root type\n");
            return {};
    }

    return vma_list;
}

//get important information for every memory region from task_struct
std::vector<vm_area_info> procdump_linux::get_vmas_from_list(drakvuf_t drakvuf, vmi_instance_t vmi, proc_data_t const& process_data)
{
    uint32_t map_count = 0;
    addr_t active_mm = 0;
    addr_t vm_area = 0;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = process_data.pid,
        .addr = process_data.base_addr + this->offsets[TASK_STRUCT_ACTIVE_MM]);

    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &active_mm))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to read active_mm\n");
        return {};
    }

    ctx.addr = active_mm + this->offsets[MM_STRUCT_MAP_COUNT];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &map_count))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to read map_count\n");
        return {};
    }

    ctx.addr = active_mm + this->list_offsets[MM_STRUCT_MMAP];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &vm_area))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to read mmap\n");
        return {};
    }

    std::vector<vm_area_info> vma_list;
    vma_list.reserve(map_count);

    for (uint32_t i = 0; i < map_count; i++ )
    {
        read_vma_info(drakvuf, vmi, vm_area, process_data, vma_list);

        ctx.addr = vm_area + this->list_offsets[VM_AREA_STRUCT_VM_NEXT];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &vm_area))
        {
            PRINT_DEBUG("[PROCDUMP] Failed to read next vm_area\n");
            return {};
        }
    }

    return vma_list;
}

static void calculate_offset(std::vector<vm_area_info> &vma_list, uint64_t* file_offset)
{
    uint64_t headers_size = sizeof(struct elf64_header) + sizeof(struct elf64_program_header) * (vma_list.size() + 1);
    *file_offset += headers_size;

    for(uint64_t i = 0; i < vma_list.size(); i++)
    {
        vma_list[i].file_offset = *file_offset;
        *file_offset += vma_list[i].size;
    }
}

void procdump_linux::dump_process(drakvuf_t drakvuf, std::shared_ptr<linux_procdump_task_t> task)
{
    if (!drakvuf_get_process_data(drakvuf, task->process_base, &task->process_data))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to get data of process 0x%" PRIx64 "\n", task->process_base);
        return;
    }

    auto vmi = vmi_lock_guard(drakvuf);
    std::vector<vm_area_info> vma_list;

    if (use_maple_tree)
        vma_list = get_vmas_from_maple_tree(drakvuf, vmi, task->process_data);
    else
        vma_list = get_vmas_from_list(drakvuf, vmi, task->process_data);

    calculate_offset(vma_list, &task->note_offset);

    if (vma_list.empty())
    {
        print_dump_failure(task->process_base, "Failed to read process memory");
        //task->writer->finish();
        return;
    }

    start_copy_memory(drakvuf, vmi, task, vma_list);
    save_file_metadata(task);
    print_dump_info(task);
    this->finished.insert(task->process_data.pid);
}

void procdump_linux::start_dump_process(vmi_pid_t pid, bool reason)
{
    addr_t process_base = 0;
    if (!drakvuf_get_process_by_pid(drakvuf, pid, &process_base, nullptr))
        return;

    auto proc_name = drakvuf_get_process_name(drakvuf, process_base, true);
    if (proc_name && exclude.match(proc_name))
    {
        //fill some data for output message
        drakvuf_trap_info_t info = {};
        drakvuf_trap_t trap = {};

        g_free(proc_name);

        addr_t cr3;
        drakvuf_get_process_dtb(drakvuf, process_base, &cr3);
        x86_registers_t regs
        {
            .cr3 = cr3
        };

        info.regs = &regs;
        info.timestamp = g_get_real_time();
        info.trap = &trap;

        if (!drakvuf_get_process_data(drakvuf, process_base, &info.proc_data))
        {
            PRINT_DEBUG("[PROCDUMP] Failed to get data of process 0x%" PRIx64 "\n", process_base);
            return;
        }

        print_dump_exclusion(&info);

        g_free(const_cast<char*>(info.proc_data.name));
        return;
    }

    if (begin_stop_at && timeout && g_get_real_time() / G_USEC_PER_SEC - begin_stop_at > timeout)
    {
        print_dump_failure(process_base, "Timeout");
        return;
    }

    auto task = std::make_shared<linux_procdump_task_t>(
            process_base, procdump_dir.string(),
            procdumps_count++,
            use_compression,
            reason);

    g_free(proc_name);
    dump_process(drakvuf, task);
}

bool procdump_linux::is_process_handled(vmi_pid_t pid)
{
    return this->finished.find(pid) != this->finished.end();
}

event_response_t procdump_linux::do_exit_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    if (!is_process_handled(info->proc_data.pid))
        start_dump_process(info->proc_data.pid, 1);

    return VMI_EVENT_RESPONSE_NONE;
}

procdump_linux::procdump_linux(drakvuf_t drakvuf, const procdump_linux_config* config, output_format_t output)
    : pluginex(drakvuf, output)
    , timeout{config->timeout}
    , dump_new_processes_on_finish(config->dump_new_processes_on_finish)
    , procdump_dir{config->procdump_dir ?: ""}
    , use_compression{config->compress_procdumps}
    , use_maple_tree{config->use_maple_tree}
    , exclude{config->exclude_file, "[PROCDUMP]"}
{
    if (procdump_dir.empty())
    {
        PRINT_DEBUG("[PROCDUMP] No dump folder specified\n");
        return;
    }
    if (address_width != 64)
    {
        PRINT_DEBUG("[PROCDUMP] Plugin works only on x64\n");
        throw -1;
    }

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_offset_names, this->offsets.size(), this->offsets.data()))
    {
        PRINT_DEBUG("[PROCDUMP] Failed to get some offsets\n");
        throw -1;
    }
    if (use_maple_tree)
    {
        if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, tree_offset_names, this->tree_offsets.size(), this->tree_offsets.data()))
        {
            PRINT_DEBUG("[PROCDUMP] Failed to get maple tree offsets\n");
            throw -1;
        }
    }
    else
    {
        if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, list_offset_names, this->list_offsets.size(), this->list_offsets.data()))
        {
            PRINT_DEBUG("[PROCDUMP] Failed to get list offsets\n");
            throw -1;
        }
    }

    exit_hook = createSyscallHook("do_exit", &procdump_linux::do_exit_cb);
    if (nullptr == exit_hook)
    {
        PRINT_DEBUG("[PROCDUMP] Method do_exit not found.\n");
        throw -1;
    }
}

bool procdump_linux::stop_impl()
{
    if (procdump_dir.empty())
        return true;

    if (!begin_stop_at)
        begin_stop_at = g_get_real_time() / G_USEC_PER_SEC;

    if (dump_new_processes_on_finish)
    {
        auto running_processes = get_running_processes();
        for (auto pid : running_processes)
            start_dump_process(pid, 0);
    }

    return true;
}