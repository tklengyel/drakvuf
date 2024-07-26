/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
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

#ifndef LIBFS_EXT4
#define LIBFS_EXT4

#include <libfs/base.hpp>
#include <libfs/ext4/private.hpp>

#include <stddef.h>
#include <stdint.h>
#include <variant>
#include <fstream>
#include <tuple>

namespace libfs
{

enum
{
    EXTENT_STATUS_RB_NODE,
    EXTENT_STATUS_ES_LBLK,
    EXTENT_STATUS_ES_LEN,
    EXTENT_STATUS_ES_PBLK,
    RB_ROOT_RB_NODE,
    RB_NODE_RB_LEFT,
    RB_NODE_RB_RIGHT,
    RB_NODE___RB_PARENT_COLOR,
    __LINUX_EXT4_OFFSET_MAX,
};

static const char* linux_offset_names[__LINUX_EXT4_OFFSET_MAX][2] =
{
    [EXTENT_STATUS_RB_NODE] = {"extent_status", "rb_node"},
    [EXTENT_STATUS_ES_LBLK] = {"extent_status", "es_lblk"},
    [EXTENT_STATUS_ES_LEN] = {"extent_status", "es_len"},
    [EXTENT_STATUS_ES_PBLK] = {"extent_status", "es_pblk"},
    [RB_NODE___RB_PARENT_COLOR] = {"rb_node", "__rb_parent_color"},
    [RB_NODE_RB_RIGHT] = {"rb_node", "rb_right"},
    [RB_NODE_RB_LEFT] = {"rb_node", "rb_left"},
    [RB_ROOT_RB_NODE] = {"rb_root", "rb_node"},
};

class Ext4Filesystem : public BaseFilesystem
{
private:
    /* offsets for parsing kernel structures */
    std::array<size_t, __LINUX_EXT4_OFFSET_MAX> offsets;

    /* because we can't use directly drakvuf_->kpgd store in this variable */
    addr_t dtb_;

    /* config provided */
    uint64_t extract_size;

    /* fs specific variables */
    std::unique_ptr<ext4_super_block> super_block;

    /* fs initialization */
    void init_super_block();

    /* save file helpers */
    struct write_file_data
    {
        std::ofstream outfile;
        uint64_t filesize;
        uint64_t offset = 0;
    };

    /* work with inode */
    std::unique_ptr<ext4_inode> get_inode(uint64_t inode_number);
    std::unique_ptr<ext4_inode> read_inode_from_disk(uint64_t inode_number);

    /* work with extents */
    std::vector<uint8_t> get_data_from_extent(std::unique_ptr<write_file_data>& config, ext4_extent& extent);
    void save_data_from_leaf(std::unique_ptr<write_file_data>& outfile, std::unique_ptr<ext4_extent_header>& extent_header, std::vector<ext4_extent_union>& extents);
    void traverse_extents(std::unique_ptr<write_file_data>& config, std::unique_ptr<ext4_extent_header>& extent_header, std::vector<ext4_extent_union>& extents);

    // todo
    std::vector<ext4_dir_entry_generic_t> get_inode_dir_entries(std::unique_ptr<ext4_inode>& inode);

    /* helper functions */
    bool save_file_by_inode(const std::string& output_file, uint64_t inode_number, std::unique_ptr<ext4_inode>& inode, uint64_t inode_size, std::unique_ptr<ext4_extent_header>& extent_header, std::vector<ext4_extent_union>& extents);

    /* rb helpers */
    addr_t rb_first(addr_t root);
    addr_t rb_next(addr_t node);
    std::vector<ext4_extent> get_extents_from_tree(addr_t i_es_tree);
public:
    Ext4Filesystem(drakvuf_t drakvuf, uint64_t extract_size);

    bool save_file_by_inode(const std::string& output_file, uint64_t inode_number, addr_t dtb);
    bool save_file_by_tree(const std::string& output_file, uint64_t i_size, addr_t i_es_tree, addr_t dtb);
};

} // end namespace

#endif
