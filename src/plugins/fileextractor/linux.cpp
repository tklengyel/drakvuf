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

#include "private.h"
#include "linux.h"
#include <filesystem>
#include <sys/types.h>
#include <sys/stat.h>

#define VM_WRITE 0x00000002

using namespace fileextractor_ns;

static std::string get_dump_filename(std::string dump_folder, int task_idx, std::string ext)
{
    std::stringstream file;
    file << dump_folder << "/file." << std::setw(6) << std::setfill('0') << task_idx << "." << ext;
    return file.str();
}

static std::string get_data_filename(std::string dump_folder, int task_idx)
{
    return get_dump_filename(dump_folder, task_idx, "mm");
}

static std::string get_metadata_filename(std::string dump_folder, int task_idx)
{
    return get_dump_filename(dump_folder, task_idx, "metadata");
}

void linux_fileextractor::print_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, std::unique_ptr<extract_result>& result)
{
    std::optional<fmt::Qstr<std::string>> file_sha256;
    if (!result->filehash.empty())
        file_sha256 = result->filehash;

    fmt::print(m_output_format, "fileextractor", drakvuf, info,
        keyval("FileName", fmt::Estr(result->filename)),
        keyval("Inode", fmt::Nval(result->file_info->inode_number)),
        keyval("Reason", fmt::Estr(extract_reason[result->reason])),
        keyval("Size", fmt::Nval(result->file_info->filesize)),
        keyval("AccessTime", fmt::Nval(result->file_info->access_time)),
        keyval("ModifyTime", fmt::Nval(result->file_info->modify_time)),
        keyval("ChangeTime", fmt::Nval(result->file_info->change_time)),
        keyval("SeqNum", fmt::Nval(result->seq_num)),
        keyval("FileHash", file_sha256)
    );
}

void linux_fileextractor::print_extraction_failure(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const std::string& filename, const std::string& message)
{
    fmt::print(m_output_format, "fileextractor_fail", drakvuf, info,
        keyval("FileName", fmt::Estr(filename)),
        keyval("Message", fmt::Estr(message))
    );
}

void linux_fileextractor::print_extraction_exclusion(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const std::string& filename)
{
    fmt::print(m_output_format, "fileextractor_skip", drakvuf, info,
        keyval("FileName", fmt::Estr(filename)),
        keyval("Message", fmt::Rstr("Excluded by filter"))
    );
}

void linux_fileextractor::save_file_metadata(const std::string& file, drakvuf_trap_info_t* info, const extract_result& result)
{
    using json_object_uptr = std::unique_ptr<json_object, decltype(&json_object_put)>;
    json_object_uptr jobj(json_object_new_object(), json_object_put);
    if (!jobj)
        return;

    auto out = std::ofstream(file, std::ios::out);
    if (!out.is_open())
        return;

    json_object_object_add(
        jobj.get(),
        "FileName",
        json_object_new_string(result.filename.data())
    );

    json_object_object_add(
        jobj.get(),
        "FileSize",
        json_object_new_int64(result.file_info->filesize)
    );

    json_object_object_add(
        jobj.get(),
        "SequenceNumber",
        json_object_new_int64(result.seq_num)
    );

    json_object_object_add(
        jobj.get(),
        "PID",
        json_object_new_int64(static_cast<uint64_t>(info->proc_data.pid))
    );

    json_object_object_add(
        jobj.get(),
        "PPID",
        json_object_new_int64(static_cast<uint64_t>(info->proc_data.ppid))
    );

    json_object_object_add(
        jobj.get(),
        "ProcessName",
        json_object_new_string(info->proc_data.name)
    );

    out << json_object_get_string(jobj.get());
}

std::string linux_fileextractor::get_filename(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t file_addr)
{
    if (!file_addr)
        return nullptr;

    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = file_addr + this->offsets[_FILE_F_PATH] + this->offsets[_PATH_DENTRY]);

    addr_t dentry_addr = 0;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &dentry_addr))
        return nullptr;

    char* tmp = drakvuf_get_filepath_from_dentry(drakvuf, dentry_addr);
    if (!tmp)
        return {};

    std::string filename(tmp);
    g_free(tmp);
    return filename;
}

std::string linux_fileextractor::calculate_hash(std::string& filename, uint64_t filesize)
{
    if (hash_size && (filesize > hash_size))
        return {};

    std::ifstream file(filename, std::ios::binary);
    if (!file)
        return {};

    GChecksum* checksum = g_checksum_new(G_CHECKSUM_SHA256);
    std::array<unsigned char, 4096> buffer;

    while (!file.eof())
    {
        int n = file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()).gcount();
        g_checksum_update(checksum, buffer.data(), n);
    }

    std::string hash(g_checksum_get_string(checksum));
    g_checksum_free(checksum);

    return hash;
}

std::unique_ptr<libfs::file_info> linux_fileextractor::get_file_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t inode)
{
    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    uint32_t uid, gid, access_time, modify_time, change_time = 0;
    uint64_t filesize, i_ino = 0;
    uint16_t i_mode = 0;

    ctx.addr = inode + this->offsets[_INODE_I_INO];
    if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &i_ino))
        return {};

    ctx.addr = inode + this->offsets[_INODE_I_UID];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &uid))
        return {};

    ctx.addr = inode + this->offsets[_INODE_I_GID];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &gid))
        return {};

    ctx.addr = inode + this->offsets[_INODE_I_SIZE];
    if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &filesize))
        return {};

    ctx.addr = inode + this->offsets[_INODE_I_ATIME];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &access_time))
        return {};

    ctx.addr = inode + this->offsets[_INODE_I_MTIME];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &modify_time))
        return {};

    ctx.addr = inode + this->offsets[_INODE_I_CTIME];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &change_time))
        return {};

    ctx.addr = inode + this->offsets[_INODE_I_MODE];
    if (VMI_FAILURE == vmi_read_16(vmi, &ctx, &i_mode))
        return {};

    return std::make_unique<libfs::file_info>(
            i_ino,
            uid,
            gid,
            filesize,
            access_time,
            modify_time,
            change_time,
            i_mode
        );
}

std::unique_ptr<linux_fileextractor::extract_result> linux_fileextractor::extract_file(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t inode, std::string& filename)
{
    if (exclude.match(filename))
    {
        print_extraction_exclusion(drakvuf, info, filename);
        return {};
    }

    auto seq_num = ++this->sequence_number;
    auto output_filename = get_data_filename(this->dump_folder, seq_num);
    auto metadata_filename = get_metadata_filename(this->dump_folder, seq_num);

    auto result = std::make_unique<extract_result>();
    /*
     * magic kernel convertion from one struct to another
     * src: https://elixir.bootlin.com/linux/v6.4/source/fs/ext4/ext4.h#L1684
     */
    addr_t ext4_inode_info = inode - this->offsets[_EXT4_INODE_INFO_VFS_INODE];
    addr_t i_es_tree = ext4_inode_info + this->offsets[_EXT4_INODE_INFO_I_ES_TREE];

    result->file_info = get_file_info(drakvuf, info, inode);
    if (!result->file_info)
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to get information about file: %s\n", filename.c_str());
        return {};
    }

    umask(S_IWGRP|S_IWOTH);
    try
    {
        if (!ext4->save_file_by_tree(output_filename, result->file_info->filesize, i_es_tree, info->regs->cr3))
            result->file_info = {};
    }
    catch (int)
    {
        std::error_code ec;
        std::filesystem::remove(output_filename, ec);
        result->file_info = {};
    }

    if (!result->file_info)
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to extract file: %s\n", filename.c_str());
        print_extraction_failure(drakvuf, info, filename, "Exception on extract");
        return {};
    }

    result->filename = filename;
    result->seq_num = seq_num;
    result->filehash = calculate_hash(output_filename, result->file_info->filesize);

    save_file_metadata(metadata_filename, info, *result);

    return result;
}

task_id linux_fileextractor::make_task_id(uint64_t inode)
{
    return (task_id)inode;
}

/*
 * To bypass the caches of the file system, the O_SYNC flag is forcibly set
 * Performance is slightly reduced, but not critical
 */
event_response_t linux_fileextractor::openat_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    static long do_sys_openat2(
        int dfd,
        const char __user *filename,
        struct open_how *how
    )
     */

    addr_t name = drakvuf_get_function_argument(drakvuf, info, 2);
    addr_t how = drakvuf_get_function_argument(drakvuf, info, 3);

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = name
    );

    char* tmp = vmi_read_str(vmi, &ctx);
    if (tmp)
    {
        std::string filename(tmp);
        g_free(tmp);

        // no need to modify flags if file is excluded
        if (exclude.match(filename))
            return VMI_EVENT_RESPONSE_NONE;
    }

    ctx.addr = how + this->offsets[_OPEN_HOW_FLAGS];

    uint64_t flags;
    if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &flags))
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to read open_how->flags\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // files with O_PATH are not actually opened, so there is no need to modify the flags
    if (!(flags & FLAG_O_PATH))
    {
        // modification
        flags |= FLAG_O_SYNC | FLAG_O_DSYNC;

        if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &flags))
        {
            PRINT_DEBUG("[FILEEXTRACTOR] failed to wirte open_how->flags\n");
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_fileextractor::write_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    static ssize_t ext4_write_file_iter(
        struct kiocb *iocb,
        struct iov_iter *from
    )
     */
    addr_t iocb = drakvuf_get_function_argument(drakvuf, info, 1);

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    addr_t filp;
    ctx.addr = iocb + this->offsets[_KIOCB_KI_FILP];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &filp))
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to read kiocb->ki_filp\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto filename = get_filename(drakvuf, info, filp);
    if (filename.empty())
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to get filename\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t f_inode;
    ctx.addr = filp + this->offsets[_FILE_F_INODE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &f_inode))
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to read file->f_inode\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t i_ino;
    ctx.addr = f_inode + this->offsets[_INODE_I_INO];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &i_ino))
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to read inode->i_ino\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto id = make_task_id(i_ino);
    auto task = tasks.find(id);
    if (task != tasks.end())
        task->second->filename = filename;
    else
        tasks[id] = std::make_unique<linux_task_t>(i_ino, filename);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_fileextractor::close_file_cb(drakvuf_t dravkuf, drakvuf_trap_info_t* info)
{
    /*
    static int ext4_release_file(
        struct inode *inode,
        struct file *filp
    )
     */

    addr_t filp = drakvuf_get_function_argument(drakvuf, info, 2);

    auto filename = get_filename(drakvuf, info, filp);
    if (filename.empty())
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to get filename\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    addr_t f_inode;
    ctx.addr = filp + this->offsets[_FILE_F_INODE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &f_inode))
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to read file->f_inode\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t i_ino;
    ctx.addr = f_inode + this->offsets[_INODE_I_INO];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &i_ino))
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to read inode->i_ino\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto id = make_task_id(i_ino);
    auto task = tasks.find(id);
    if (task != tasks.end())
    {
        auto result = extract_file(drakvuf, info, f_inode, filename);
        if (!result)
            return VMI_EVENT_RESPONSE_NONE;

        task->second->extracted = true;

        result->reason = REASON_CLOSE;
        print_info(drakvuf, info, result);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_fileextractor::mmap_write_cb(drakvuf_t dravkuf, drakvuf_trap_info_t* info)
{
    /*
    vm_fault_t ext4_page_mkwrite(
        struct vm_fault *vmf
    )
    static vm_fault_t ext4_dax_huge_fault(
        struct vm_fault *vmf,
        enum page_entry_size pe_size
    )
     */

    addr_t vmf = drakvuf_get_function_argument(drakvuf, info, 1);

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    addr_t vma;
    ctx.addr = vmf + this->offsets[_VM_FAULT_VMA];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &vma))
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to read vm_fault->vma\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t vm_file;
    ctx.addr = vma + this->offsets[_VM_AREA_STRUCT_VM_FILE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &vm_file))
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to read vm_area_struct->vm_file\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto filename = get_filename(drakvuf, info, vm_file);
    if (filename.empty())
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to get filename\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t f_inode;
    ctx.addr = vm_file + this->offsets[_FILE_F_INODE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &f_inode))
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to read file->f_inode\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t i_ino;
    ctx.addr = f_inode + this->offsets[_INODE_I_INO];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &i_ino))
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to read inode->i_ino\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto id = make_task_id(i_ino);
    auto task = tasks.find(id);
    if (task != tasks.end())
        task->second->filename = filename;
    else
        tasks[id] = std::make_unique<linux_task_t>(i_ino, filename);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_fileextractor::unlink_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    static int ext4_unlink(
        struct inode *dir,
        struct dentry *dentry
    )
     */

    addr_t dentry = drakvuf_get_function_argument(drakvuf, info, 2);

    char* tmp = drakvuf_get_filepath_from_dentry(drakvuf, dentry);
    if (!tmp)
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to get filename\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    std::string filename(tmp);
    g_free(tmp);

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    addr_t dentry_d_inode;
    ctx.addr = dentry + this->offsets[_DENTRY_D_INODE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &dentry_d_inode))
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to read dentry->d_inode\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t i_ino;
    ctx.addr = dentry_d_inode + this->offsets[_INODE_I_INO];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &i_ino))
    {
        PRINT_DEBUG("[FILEEXTRACTOR] failed to read inode->i_ino\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto id = make_task_id(i_ino);
    auto task = tasks.find(id);
    if (task != tasks.end())
    {
        auto result = extract_file(drakvuf, info, dentry_d_inode, filename);
        if (!result)
            return VMI_EVENT_RESPONSE_NONE;

        task->second->extracted = true;

        result->reason = REASON_DELETE;
        print_info(drakvuf, info, result);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

linux_fileextractor::linux_fileextractor(drakvuf_t drakvuf, const fileextractor_config* config, output_format_t output)
    : pluginex(drakvuf, output)
    , ext4{std::make_unique<libfs::Ext4Filesystem>(drakvuf, config->extract_size * 1024 * 1024)}
    , exclude(config->exclude_file, "[FILEEXTRACTOR]")
    , hash_size(config->hash_size * 1024 * 1024)
    , dump_folder(config->dump_folder ?: "")
{
    if (!config->dump_folder)
    {
        PRINT_DEBUG("[FILEEXTRACTOR] No dump folder specified\n");
        return;
    }

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_offset_names, this->offsets.size(), this->offsets.data()))
    {
        PRINT_ERROR("[FILEEXTRACTOR] failed to get some offsets\n");
        return;
    }

    // currently drakvuf support only ext4 filesystem
    this->ext4_unlink_hook = createSyscallHook("ext4_unlink", &linux_fileextractor::unlink_file_cb, "vfs_unlink");
    this->ext4_release_file_hook = createSyscallHook("ext4_release_file", &linux_fileextractor::close_file_cb);
    this->ext4_file_write_iter_hook = createSyscallHook("ext4_file_write_iter", &linux_fileextractor::write_file_cb);
    this->ext4_page_mkwrite_hook = createSyscallHook("ext4_page_mkwrite", &linux_fileextractor::mmap_write_cb);
    this->ext4_dax_huge_fault_hook = createSyscallHook("ext4_dax_huge_fault", &linux_fileextractor::mmap_write_cb);
    this->do_sys_openat2_hook = createSyscallHook("do_sys_openat2", &linux_fileextractor::openat_cb);
}
