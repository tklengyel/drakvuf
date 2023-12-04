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

#ifndef LINUX_PROCDUMP_PRIVATE_H
#define LINUX_PROCDUMP_PRIVATE_H

#include <string>
#include <set>
#include "writer.h"

using namespace std::string_literals;

namespace procdump2_ns
{

//https://elixir.bootlin.com/linux/v4.8/source/include/linux/mm.h
#define VM_NONE		    0x00000000

#define VM_READ		    0x00000001	/* currently active flags */
#define VM_WRITE	    0x00000002
#define VM_EXEC		    0x00000004
#define VM_SHARED	    0x00000008

/* mprotect() hardcodes VM_MAYREAD >> 4 == VM_READ, and so for r/w/x bits. */
#define VM_MAYREAD	    0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	    0x00000020
#define VM_MAYEXEC	    0x00000040
#define VM_MAYSHARE	    0x00000080

#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
#define VM_UFFD_MISSING	0x00000200	/* missing pages tracking */
#define VM_PFNMAP	    0x00000400	/* Page-ranges managed without "struct page", just pure PFN */
#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */
#define VM_UFFD_WP	    0x00001000	/* wrprotect pages tracking */

#define VM_LOCKED	    0x00002000
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */

/* Used by sys_madvise() */
#define VM_SEQ_READ	    0x00008000	/* App will access data sequentially */
#define VM_RAND_READ	0x00010000	/* App will not benefit from clustered reads */

#define VM_DONTCOPY	    0x00020000      /* Do not copy this vma on fork */
#define VM_DONTEXPAND	0x00040000	/* Cannot expand with mremap() */
#define VM_LOCKONFAULT	0x00080000	/* Lock the pages covered when they are faulted in */
#define VM_ACCOUNT	    0x00100000	/* Is a VM accounted object */
#define VM_NORESERVE	0x00200000	/* should the VM suppress accounting */
#define VM_HUGETLB	    0x00400000	/* Huge TLB Page VM */
#define VM_ARCH_1	    0x01000000	/* Architecture-specific flag */
#define VM_ARCH_2	    0x02000000
#define VM_DONTDUMP	    0x04000000	/* Do not include in the core dump */

#define NULL_INDEX 0
#define SHSTRTAB_INDEX 1
#define NOTE0_INDEX 11
#define LOAD_INDEX 17
static const char string_table_section[] = {'\0', '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', '\0', 'n', 'o', 't', 'e', '0', '\0', 'l', 'o', 'a', 'd', '\0'};

struct linux_procdump_task_t
{
    std::string data_file_name;
    addr_t process_base;
    const uint64_t idx = 0;
    bool reason = 0;
    std::unique_ptr<ProcdumpWriter> writer;

    proc_data_t process_data = {};
    uint64_t dump_size = 0;
    uint64_t mapped_files_count = 0;
    uint64_t note_offset = 0;
    uint64_t note_size = 0;
    uint64_t note_aligned = 0;
    uint64_t note_count = 0;

    linux_procdump_task_t(addr_t process_base,
        std::string procdump_dir,
        uint64_t idx,
        bool use_compression,
        bool reason)
        : process_base(process_base)
        , idx(idx)
        , reason(reason)
    {
        data_file_name = "procdump."s + std::to_string(idx);
        writer = ProcdumpWriterFactory::build(
                procdump_dir + "/"s + data_file_name,
                use_compression);
    }
};

struct vm_area_info
{
    uint32_t segment_flags;
    uint32_t section_flags;
    addr_t vm_start;
    addr_t vm_end;
    uint32_t vm_pgoff;

    uint64_t size;
    std::string filename;
    uint64_t file_offset;
};

struct dump_offsets
{
    uint64_t curr_program_offset;
    uint64_t curr_section_offset;
    uint64_t curr_write_offset;
};


//https://elixir.bootlin.com/linux/v6.6.1/source/include/linux/maple_tree.h#L41
#define MAPLE_NODE_MASK	255UL

#define MAPLE_NODE_TYPE_MASK	0x0F
#define MAPLE_NODE_TYPE_SHIFT	0x03

enum maple_type
{
    MAPLE_DENSE,
    MAPLE_LEAF_64,
    MAPLE_RANGE_64,
    MAPLE_ARANGE_64,
};

// may differ from version to version
#define MAPLE_RANGE64_SLOTS	16
#define MAPLE_ARANGE64_SLOTS 10

enum
{
    TASK_STRUCT_MM,
    TASK_STRUCT_ACTIVE_MM,
    MM_STRUCT_MAP_COUNT,
    VM_AREA_STRUCT_VM_START,
    VM_AREA_STRUCT_VM_END,
    VM_AREA_STRUCT_VM_FLAGS,
    VM_AREA_STRUCT_VM_FILE,
    VM_AREA_STRUCT_VM_PGOFF,
    _FILE_F_PATH,
    _PATH_DENTRY,
    __LINUX_OFFSET_MAX,
};

// Linux Offsets
static const char* linux_offset_names[__LINUX_OFFSET_MAX][2] =
{
    [TASK_STRUCT_MM] = {"task_struct", "mm"},
    [TASK_STRUCT_ACTIVE_MM] = {"task_struct", "active_mm"},
    [MM_STRUCT_MAP_COUNT] = {"mm_struct", "map_count"},
    [VM_AREA_STRUCT_VM_START] = {"vm_area_struct", "vm_start"},
    [VM_AREA_STRUCT_VM_END] = {"vm_area_struct", "vm_end"},
    [VM_AREA_STRUCT_VM_FLAGS] = {"vm_area_struct", "vm_flags"},
    [VM_AREA_STRUCT_VM_FILE] = {"vm_area_struct", "vm_file"},
    [VM_AREA_STRUCT_VM_PGOFF] = {"vm_area_struct", "vm_pgoff"},
    [_FILE_F_PATH] = {"file", "f_path"},
    [_PATH_DENTRY] = {"path", "dentry"},
};

enum
{
    MM_STRUCT_MMAP,
    VM_AREA_STRUCT_VM_NEXT,
    __LIST_OFFSET_MAX,
};

// VMA list Offsets
static const char* list_offset_names[__LIST_OFFSET_MAX][2] =
{
    [MM_STRUCT_MMAP] = {"mm_struct", "mmap"},
    [VM_AREA_STRUCT_VM_NEXT] = {"vm_area_struct", "vm_next"},
};

// Kernel version 6.2+
enum
{
    MM_STRUCT_MM_MT,
    MAPLE_TREE_MA_ROOT,
    MAPLE_ARANGE_SLOT,
    MAPLE_RANGE_SLOT,
    __TREE_OFFSET_MAX,
};

// Maple tree Offsets
static const char* tree_offset_names[__TREE_OFFSET_MAX][2] =
{
    [MM_STRUCT_MM_MT] = {"mm_struct", "mm_mt"},
    [MAPLE_TREE_MA_ROOT] = {"maple_tree", "ma_root"},
    [MAPLE_ARANGE_SLOT] = {"maple_arange_64", "slot"},
    [MAPLE_RANGE_SLOT] = {"maple_range_64", "slot"},
};

}
#endif