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

#ifndef PROCDUMP_LINUX_H
#define PROCDUMP_LINUX_H

#include "plugins/plugins_ex.h"
#include "helpers/exclude_matcher.h"
#include "private.h"
#include "coredump.h"
#include <filesystem>

using namespace procdump_linux_ns;

struct procdump_linux_config
{
    uint32_t timeout;
    bool dump_new_processes_on_finish;
    const char* procdump_dir;
    const char* exclude_file;
    bool compress_procdumps;
    bool use_maple_tree;
};

class procdump_linux: public pluginex
{
public:
    procdump_linux(drakvuf_t drakvuf, const procdump_linux_config* config, output_format_t output);
    ~procdump_linux() = default;
    virtual bool stop_impl() override;

private:
    std::array<size_t, procdump_linux_ns::__LINUX_OFFSET_MAX> offsets;
    std::array<size_t, procdump_linux_ns::__LIST_OFFSET_MAX> list_offsets;
    std::array<size_t, procdump_linux_ns::__TREE_OFFSET_MAX> tree_offsets;

    std::unique_ptr<libhook::SyscallHook> exit_hook;

    uint64_t procdumps_count{0};
    std::set<vmi_pid_t> finished;

    uint32_t timeout{0};
    bool dump_new_processes_on_finish{0};
    const std::filesystem::path procdump_dir;
    bool const use_compression{false};
    bool const use_maple_tree{false};
    const exclude_matcher exclude;
    int address_width = drakvuf_get_address_width(drakvuf) * 8;
    uint32_t begin_stop_at{0};

    void read_vma_info(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t leaf_addr, proc_data_t const& process_data, std::vector<vm_area_info>& vma_list);
    void read_range_node_impl(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t node_addr, proc_data_t const& process_data, std::vector<vm_area_info>& vma_list, int count, uint64_t offset);
    void read_range_node(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t node_addr, proc_data_t const& process_data, std::vector<vm_area_info>& vma_list);
    void read_range_leafes(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t node_addr, proc_data_t const& process_data, std::vector<vm_area_info>& vma_list);
    void read_arange_node(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t node_addr, proc_data_t const& process_data, std::vector<vm_area_info>& vma_list);
    std::vector<vm_area_info> get_vmas_from_maple_tree(drakvuf_t drakvuf, vmi_instance_t vmi, proc_data_t const& process_data);
    std::vector<vm_area_info> get_vmas_from_list(drakvuf_t drakvuf, vmi_instance_t vmi, proc_data_t const& process_data);

    void start_copy_memory(drakvuf_t drakvuf, vmi_instance_t vmi, std::shared_ptr<linux_procdump_task_t> task, std::vector<vm_area_info> vma_list);
    void start_dump_process(vmi_pid_t pid, bool reason);

    bool is_process_handled(vmi_pid_t pid);
    void dump_zero_page(std::shared_ptr<linux_procdump_task_t> task);
    void read_vm(drakvuf_t drakvuf, vmi_instance_t vmi, vm_area_info vm_area, std::shared_ptr<linux_procdump_task_t> task);
    void dump_process(drakvuf_t drakvuf, std::shared_ptr<linux_procdump_task_t> task);

    void write_program_headers(std::shared_ptr<linux_procdump_task_t> task, std::vector<vm_area_info> vma_list);
    void write_section_headers(std::shared_ptr<linux_procdump_task_t> task, std::vector<vm_area_info> vma_list);
    void calc_note_size_and_count(std::vector<vm_area_info> vma_list, uint64_t* note_size, uint64_t* note_count);
    void write_notes(std::shared_ptr<linux_procdump_task_t> task, std::vector<vm_area_info> vma_list);

    void print_dump_exclusion(drakvuf_trap_info_t* info);
    void print_dump_failure(addr_t process_base, const std::string& message);
    void print_dump_info(std::shared_ptr<linux_procdump_task_t> task);
    void save_file_metadata(std::shared_ptr<linux_procdump_task_t> task);
    std::vector<vmi_pid_t> get_running_processes();

    event_response_t do_exit_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
};

#endif