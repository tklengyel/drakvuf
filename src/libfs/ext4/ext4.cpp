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

#include <cassert>
#include <iostream>
#include <filesystem>

#include <libvmi/libvmi.h>
#include <libfs/ext4/ext4.hpp>

namespace libfs
{

addr_t Ext4Filesystem::rb_first(addr_t root)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = this->dtb_,
        .addr = root + this->offsets[RB_ROOT_RB_NODE]
    );

    auto vmi = vmi_lock_guard(drakvuf_);
    addr_t n;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &n) || !n)
        return 0;

    ctx.addr = n + this->offsets[RB_NODE_RB_LEFT];
    addr_t rb_left = 0;
    addr_t tmp = 0;
    while (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &tmp) && tmp)
    {
        rb_left = tmp;
        ctx.addr = rb_left + this->offsets[RB_NODE_RB_LEFT];
    }

    return rb_left;
}

addr_t Ext4Filesystem::rb_next(addr_t node)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = this->dtb_,
        .addr = node + this->offsets[RB_NODE___RB_PARENT_COLOR]
    );

    auto vmi = vmi_lock_guard(drakvuf_);
    addr_t empty_node = 0;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &empty_node) || empty_node == node)
        return 0;

    /* If we have a right-hand child, go down and then left as far as we can. */
    addr_t rb_right = 0;
    ctx.addr = node + this->offsets[RB_NODE_RB_RIGHT];
    if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &rb_right) && rb_right)
    {
        node = rb_right;

        addr_t rb_left = 0;
        ctx.addr = node + this->offsets[RB_NODE_RB_LEFT];
        while (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &rb_left) && rb_left)
        {
            // important: don't place assignment in loop it's break logic
            node = rb_left;
            ctx.addr = node + this->offsets[RB_NODE_RB_LEFT];
        }

        return node;
    }

    addr_t tmp = 0;
    addr_t parent = 0;
    ctx.addr = node + this->offsets[RB_NODE___RB_PARENT_COLOR];
    while (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &tmp))
    {
        parent = tmp & ~3;
        if (!parent)
            break;

        ctx.addr = parent + this->offsets[RB_NODE_RB_RIGHT];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &rb_right) || node != rb_right)
            break;

        node = parent;
        ctx.addr = node + this->offsets[RB_NODE___RB_PARENT_COLOR];
    }

    return parent;
}

std::vector<ext4_extent> Ext4Filesystem::get_extents_from_tree(addr_t i_es_tree)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = this->dtb_,
    );
    auto vmi = vmi_lock_guard(drakvuf_);

    addr_t node = rb_first(i_es_tree);

    std::vector<libfs::ext4_extent> extents = {};
    if (!node)
        goto out;

    while (node)
    {
        addr_t es = node - this->offsets[EXTENT_STATUS_RB_NODE];

        uint32_t es_lblk, es_len = 0;
        uint64_t es_pblk = 0;

        ctx.addr = es + this->offsets[EXTENT_STATUS_ES_LBLK];
        if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &es_lblk))
            goto out;

        ctx.addr = es + this->offsets[EXTENT_STATUS_ES_LEN];
        if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &es_len))
            goto out;

        ctx.addr = es + this->offsets[EXTENT_STATUS_ES_PBLK];
        if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &es_pblk))
            goto out;

        ext4_extent extent =
        {
            .ee_block = es_lblk,
            .ee_len = static_cast<uint16_t>(es_len & 0xffff),
            .ee_start_hi = static_cast<uint16_t>((es_pblk >> 32) & 0xffff),
            .ee_start_lo = static_cast<uint32_t>(es_pblk & 0xffffffff)
        };
        extents.emplace_back(extent);

        node = rb_next(node);
    }

    // drop last empty node from list
    if (!extents.empty())
        extents.pop_back();

out:
    return extents;
}

std::vector<uint8_t> Ext4Filesystem::get_data_from_extent(std::unique_ptr<write_file_data>& config, ext4_extent& extent)
{
    /* extents can be unitialized */
    if (extent.ee_len > EXT_INIT_MAX_LEN)
        return {};

    uint64_t offset = extent.get_start() * super_block->get_block_size();
    uint64_t length = (uint64_t)extent.ee_len * (uint64_t)super_block->get_block_size();

    uint64_t rest = config->filesize - config->offset;
    /* truncate last extent by actual filesize */
    if (length > rest)
        length = rest;

    /* ignoring empty extents */
    if (0 == length)
        return {};

    std::vector<uint8_t> extent_data(length);
    if (VMI_FAILURE == get_raw_from_fs(offset, length, extent_data.data()))
    {
        PRINT_ERROR("[ext4] failed to read extent data\n");
        throw -1;
    }

    return extent_data;
}

void Ext4Filesystem::save_data_from_leaf(std::unique_ptr<write_file_data>& config, std::unique_ptr<ext4_extent_header>& extent_header, std::vector<ext4_extent_union>& extents)
{
    if (extent_header->eh_depth)
    {
        PRINT_ERROR("[ext4] can't read data from non-leaf node\n");
        return;
    }

    for (uint16_t idx = 0; idx < extent_header->eh_entries; idx++)
    {
        auto extent = extents[idx].extent;
        auto data = get_data_from_extent(config, extent);

        if (data.empty())
            continue;

        uint64_t bytes_to_write = data.size();

        if (config->offset + bytes_to_write > config->filesize)
            bytes_to_write = config->filesize - config->offset;

        config->outfile.write(reinterpret_cast<const char*>(data.data()), bytes_to_write);
        config->offset += bytes_to_write;
    }
}

void Ext4Filesystem::traverse_extents(std::unique_ptr<write_file_data>& config, std::unique_ptr<ext4_extent_header>& extent_header, std::vector<ext4_extent_union>& extents)
{
    if (extent_header->eh_depth == 0)
        return save_data_from_leaf(config, extent_header, extents);

    for (uint16_t idx = 0; idx < extent_header->eh_entries; idx++)
    {
        auto extent = extents[idx].extent_idx;

        uint64_t offset = super_block->get_block_size() * extent.get_leaf();
        auto new_extent_header = get_struct_from_fs<ext4_extent_header>(offset);
        auto new_extents_vector = get_array_of_structs_from_fs<ext4_extent_union>(offset + sizeof(ext4_extent_header), new_extent_header->eh_entries);

        /*
         * performance hint
         * if the file is smaller than 175GB, we do not need an additional recursive call and we work as with a normal loop.
         */
        if (new_extent_header->eh_depth == 0)
            save_data_from_leaf(config, new_extent_header, new_extents_vector);
        else
            traverse_extents(config, new_extent_header, new_extents_vector);
    }
}

std::unique_ptr<ext4_inode> Ext4Filesystem::read_inode_from_disk(uint64_t inode_number)
{
    uint64_t blockgroup_number = (inode_number - 1 ) / super_block->s_inodes_per_group;
    uint64_t offset = super_block->get_block_size() + blockgroup_number * sizeof(ext4_group_desc);

#ifdef DRAKVUF_DEBUG
    PRINT_DEBUG("[ext4-dbg] get_inode: inode_number: %lu\n", inode_number);
    PRINT_DEBUG("[ext4-dbg] get_inode: blockgroup_number: 0x%lx\n", blockgroup_number);
    PRINT_DEBUG("[ext4-dbg] get_inode: offset: 0x%lx\n", offset);
#endif

    auto group_desc = get_struct_from_fs<ext4_group_desc>(offset);

    uint64_t table_offset = group_desc->get_inode_table() * super_block->get_block_size();
    uint64_t idx_in_table = (inode_number - 1) % super_block->s_inodes_per_group;
    uint64_t inode_offset = table_offset + super_block->s_inode_size * idx_in_table;

#ifdef DRAKVUF_DEBUG
    PRINT_DEBUG("[ext4-dbg] get_inode: table_offset: 0x%lx\n", table_offset);
    PRINT_DEBUG("[ext4-dbg] get_inode: idx_in_table: 0x%lx\n", idx_in_table);
    PRINT_DEBUG("[ext4-dbg] get_inode: inode_offset: 0x%lx\n", inode_offset);
#endif

    auto inode = get_struct_from_fs<ext4_inode>(inode_offset);

#ifdef DRAKVUF_DEBUG
    PRINT_DEBUG("[ext4] inode->i_mode: %o\n", inode->i_mode);
    PRINT_DEBUG("[ext4] inode->blocks_count: %lu\n", inode->get_blocks_count());
    PRINT_DEBUG("[ext4] inode->inode_size: %lu\n", inode->get_inode_size());
#endif

    return inode;
}

std::unique_ptr<ext4_inode> Ext4Filesystem::get_inode(uint64_t inode_number)
{
    if (inode_number <= 0 || inode_number > super_block->s_inodes_count)
    {
        PRINT_ERROR("[ext4] incorrect inode number: %lu\n", inode_number);
        return {};
    }

    auto inode = read_inode_from_disk(inode_number);

    if (inode->get_inode_size() > extract_size)
    {
        PRINT_DEBUG("[ext4] unsupported filesize\n");
        return {};
    }

    return inode;
}

bool Ext4Filesystem::save_file_by_inode(const std::string& output_filename, uint64_t inode_number, std::unique_ptr<ext4_inode>& inode, uint64_t inode_size, std::unique_ptr<ext4_extent_header>& extent_header, std::vector<ext4_extent_union>& extents)
{
    /* prepare config for writing file */
    auto config = std::make_unique<write_file_data>();

    config->filesize = inode_size;
    config->outfile = std::ofstream(output_filename, std::ios::out | std::ios::binary);

    try
    {
        traverse_extents(config, extent_header, extents);
    }
    catch (int)
    {
        return false;
    }

    /* in case there is an uninitialized extent, we add zeros, as the kernel does (for file integrity) */
    if (config->filesize != config->offset)
    {
        uint64_t size = config->filesize - config->offset;
        char* array = static_cast<char*>(std::calloc(size, sizeof(char)));
        if (array)
        {
            config->outfile.write(array, size);
            std::free(array);
        }
    }

    return true;
}

/*
 * Saving a file by inode that has been completely written to disk and is not in the cache.
 * For example, if i_state == I_DIRTY, then the file is in the cache and you need to use the save_file_by_tree function.
 *
 * It's probably better to use save_file_by_tree, but we'll leave it for now, because the files were extracted earlier like this
 *
 * @param output_file the name of the extracted file
 * @param inode_number inode in filesystem
 * @return if the file is saved successfully, then true is returned, otherwise false
 */
bool Ext4Filesystem::save_file_by_inode(const std::string& output_file, uint64_t inode_number, addr_t dtb)
{
    this->dtb_ = dtb;

    auto inode = get_inode(inode_number);
    if (nullptr == inode)
        return {};

    uint64_t inode_size = inode->get_inode_size();

    /* in this function we can only work with real files on disk (without caches) */
    if (inode_size <= 0)
        return {};

    /* init first chunk iteration */
    auto extent_header = inode->get_extent_header();
    std::vector<ext4_extent_union> extents(extent_header->eh_entries);
    std::memcpy(extents.data(), inode->i_block + sizeof(ext4_extent_header), sizeof(ext4_extent_union) * extent_header->eh_entries);

    return save_file_by_inode(output_file, inode_number, inode, inode_size, extent_header, extents);
}

/*
 * Saving a file from a red-black tree obtained from kernel memory.
 * Unlike save_file_by_inode, it works in all scenarios, because it receives information about extents directly from memory
 *
 * @param output_file the name of the extracted file
 * @param i_size inode size (filesize)
 * @param i_es_tree red black tree (https://elixir.bootlin.com/linux/v6.4/source/fs/ext4/ext4.h#L1040)
 * @return if the file is saved successfully, then true is returned, otherwise false
 */
bool Ext4Filesystem::save_file_by_tree(const std::string& output_file, uint64_t i_size, addr_t i_es_tree, addr_t dtb)
{
    this->dtb_ = dtb;

    /* prepare config for writing file */
    auto config = std::make_unique<write_file_data>();

    config->filesize = i_size;
    config->outfile = std::ofstream(output_file, std::ios::out | std::ios::binary);

    auto extents = get_extents_from_tree(i_es_tree);
    for (auto& extent : extents)
    {
        auto data = get_data_from_extent(config, extent);
        if (data.empty())
            continue;

        uint64_t bytes_to_write = data.size();

        if (config->offset + bytes_to_write > config->filesize)
            bytes_to_write = config->filesize - config->offset;

        config->outfile.write(reinterpret_cast<const char*>(data.data()), bytes_to_write);
        config->offset += bytes_to_write;
    }

    /* in case there is an uninitialized extent, we add zeros, as the kernel does (for file integrity) */
    if (config->filesize != config->offset)
    {
        uint64_t size = config->filesize - config->offset;
        char* array = static_cast<char*>(std::calloc(size, sizeof(char)));
        if (array)
        {
            config->outfile.write(array, size);
            std::free(array);
        }
    }

    return true;
}

void Ext4Filesystem::init_super_block()
{
    super_block = get_struct_from_fs<ext4_super_block>(GROUP_0_PADDING);

#ifdef DRAKVUF_DEBUG
    PRINT_DEBUG("[ext4-dbg] super_block: total inode count: %d\n", super_block->s_inodes_count);
    PRINT_DEBUG("[ext4-dbg] super_block: total block count: %lu\n", super_block->get_block_count());
    PRINT_DEBUG("[ext4-dbg] super_block: reserved block count: %lu\n", super_block->get_reservered_block_count());
    PRINT_DEBUG("[ext4-dbg] super_block: free block count: %lu\n", super_block->get_free_block_count());
    PRINT_DEBUG("[ext4-dbg] super_block: volume name: %s\n", super_block->s_volume_name);
    PRINT_DEBUG("[ext4-dbg] super_block: last mounted: %s\n", super_block->s_last_mounted);
    PRINT_DEBUG("[ext4-dbg] super_block: checksum: 0x%x\n", super_block->s_checksum);
    PRINT_DEBUG("[ext4-dbg] super_block: s_feature_compat: %s\n", super_block->get_features_compat().c_str());
    PRINT_DEBUG("[ext4-dbg] super_block: s_feature_incompat: %s\n", super_block->get_features_incompat().c_str());
    PRINT_DEBUG("[ext4-dbg] super_block: groups_per_flex: %lu\n", super_block->get_groups_per_flex());
    PRINT_DEBUG("[ext4-dbg] super_block: block_size: %d\n", super_block->get_block_size());
#endif

    assert(super_block->s_magic == EXT4_MAGIC);
}

/*
 * initialization for parsing ext4 filesystem
 * @param drakvuf instanse of drakvuf
 * @param extract_size maximum size of file to extraction
 */
Ext4Filesystem::Ext4Filesystem(drakvuf_t drakvuf, uint64_t extract_size) : BaseFilesystem(drakvuf),
    extract_size(extract_size)
{
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_offset_names, this->offsets.size(), this->offsets.data()))
    {
        PRINT_ERROR("[ext4] failed to get some offsets\n");
        return;
    }
    init_super_block();
}

} // namespace libfs
