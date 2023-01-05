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

#include <libvmi/libvmi.h>
#include <map>
#include <string>
#include <glib.h>

#include "private.h"
#include "linux.h"
#include "plugins/output_format.h"

using namespace filetracer_ns;

/* -------------------HELPER FUNCTIONS------------------ */

#define VERSION_GE(ver, x, y) \
    ((ver) && ((ver)->major > (x) || ((ver)->major == (x) && (ver)->minor >= (y))))

static std::string to_oct_str(uint64_t n)
{
    std::stringstream ss;
    ss << std::oct << n;
    return ss.str();
}

uint64_t linux_filetracer::make_hook_id(drakvuf_trap_info_t* info)
{
    uint64_t u64_pid = info->proc_data.pid;
    uint64_t u64_tid = info->proc_data.tid;
    return (u64_pid << 32) | u64_tid;
}

/* -----------------FILE INFO PARSING------------------ */

bool linux_filetracer::get_file_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, linux_data* params, addr_t file_addr)
{
    if (!file_addr)
        return false;

    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = file_addr + this->offsets[_FILE_F_PATH] + this->offsets[_PATH_DENTRY]);

    addr_t dentry_addr = 0;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &dentry_addr))
        return false;

    return get_dentry_info(drakvuf, info, params, dentry_addr);
}

bool linux_filetracer::get_path_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, linux_data* params, addr_t path_addr)
{
    if (!path_addr)
        return false;

    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = path_addr + this->offsets[_PATH_DENTRY]);

    addr_t dentry_addr = 0;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &dentry_addr))
        return false;

    return get_dentry_info(drakvuf, info, params, dentry_addr);
}

bool linux_filetracer::get_dentry_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, linux_data* params, addr_t dentry_addr)
{
    if (!dentry_addr)
        return false;

    char* tmp = drakvuf_get_filepath_from_dentry(drakvuf, dentry_addr);
    params->filename = tmp ?: "";
    g_free(tmp);

    if (params->filename.empty())
        return false;

    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3);

    addr_t inode;
    ctx.addr = dentry_addr + this->offsets[_DENTRY_D_INODE];
    if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &inode) && inode)
    {
        uint16_t mode;
        ctx.addr = inode + this->offsets[_INODE_I_MODE];
        if (VMI_SUCCESS == vmi_read_16(vmi, &ctx, &mode) && mode)
        {
            params->permissions = mode & 0xfff;
            params->modes = parse_flags(mode, linux_file_modes, this->m_output_format);
        }

        uint32_t flags;
        ctx.addr = inode + this->offsets[_INODE_I_FLAGS];
        if (VMI_SUCCESS == vmi_read_32(vmi, &ctx, &flags) && flags)
            params->modes = parse_flags(flags, linux_inode_flags, this->m_output_format);

        uint32_t uid;
        ctx.addr = inode + this->offsets[_INODE_I_UID];
        if (VMI_SUCCESS == vmi_read_32(vmi, &ctx, &uid) && uid)
            params->uid = uid;

        uint32_t gid;
        ctx.addr = inode + this->offsets[_INODE_I_GID];
        if (VMI_SUCCESS == vmi_read_32(vmi, &ctx, &gid) && gid)
            params->gid = gid;
    }

    return true;
}

void linux_filetracer::print_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, linux_data* params)
{
    std::vector<std::pair<std::string, fmt::Aarg>> extra_args;
    extra_args.emplace_back(keyval("FileName", fmt::Estr(params->filename)));
    if (!params->modes.empty())
        extra_args.emplace_back(keyval("Mode", fmt::Rstr(params->modes)));
    if (!params->flags.empty())
        extra_args.emplace_back(keyval("Flag", fmt::Rstr(params->flags)));
    if (params->uid)
        extra_args.emplace_back(keyval("UID", fmt::Rstr(std::to_string(*(params->uid)))));
    if (params->gid)
        extra_args.emplace_back(keyval("GID", fmt::Rstr(std::to_string(*(params->gid)))));
    for (auto& arg : params->args)
        extra_args.emplace_back(std::make_pair(arg.first, fmt::Rstr(arg.second)));

    addr_t current_process = drakvuf_get_current_process(drakvuf, info);
    const char* thread_name = drakvuf_get_process_name(drakvuf, current_process, false);

    fmt::print(this->m_output_format, "filetracer", drakvuf, info,
        keyval("Permissions", fmt::Rstr(to_oct_str(params->permissions))),
        keyval("ThreadName", fmt::Rstr(thread_name)),
        extra_args);

    g_free(const_cast<char*>(thread_name));
}

char* linux_filetracer::read_filename(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t fileaddr)
{
    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = fileaddr);

    return vmi_read_str(vmi, &ctx);
}

/* ---------------FILE OPERATIONS CALLBACK-------------- */

event_response_t linux_filetracer::open_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<linux_data>(info);
    if (!drakvuf_check_return_context(drakvuf, info, params->pid, params->tid, params->rsp))
        return VMI_EVENT_RESPONSE_NONE;

    addr_t file_struct = info->regs->rax;

    if (file_struct && file_struct != ~0ul && file_struct != ~1ul)
        if (get_file_info(drakvuf, info, params, file_struct))
            print_info(drakvuf, info, params);

    uint64_t hookID = make_hook_id(info);
    this->ret_hooks.erase(hookID);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::open_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    struct file *do_filp_open(
        int dfd,
        struct filename *pathname,
        const struct open_flags *op
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s \n", info->trap->name);
    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    if (!ret_addr)
        return VMI_EVENT_RESPONSE_NONE;

    // Create new trap for return callback
    uint64_t hookID = make_hook_id(info);
    auto hook = this->createReturnHook<linux_data>(info, &linux_filetracer::open_file_ret_cb);
    auto params = libhook::GetTrapParams<linux_data>(hook->trap_);

    // Save data
    params->pid = info->proc_data.pid;
    params->tid = info->proc_data.tid;
    params->rsp = ret_addr;

    hook->trap_->name = info->trap->name;
    this->ret_hooks[hookID] = std::move(hook);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::read_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    ssize_t vfs_read(
        struct file *file,
        char __user *buf,
        size_t count,
        loff_t *pos
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t file_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    uint64_t count = drakvuf_get_function_argument(drakvuf, info, 3);
    int64_t pos = drakvuf_get_function_argument(drakvuf, info, 4);

    linux_data params;
    params.args["count"] = std::to_string(count);
    params.args["pos"] = std::to_string(pos);

    if (get_file_info(drakvuf, info, &params, file_struct))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::write_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    ssize_t vfs_write(
        struct file *file,
        const char __user *buf,
        size_t count,
        loff_t *pos
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t file_struct = drakvuf_get_function_argument(drakvuf, info, 1);

    linux_data params;
    if (get_file_info(drakvuf, info, &params, file_struct))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::close_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int filp_close(
        struct file *filp,
        fl_owner_t id
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t file_struct = drakvuf_get_function_argument(drakvuf, info, 1);

    linux_data params;
    if (get_file_info(drakvuf, info, &params, file_struct))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::llseek_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    loff_t vfs_llseek(
        struct file *file,
        loff_t offset,
        int whence
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t file_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    int64_t offset = drakvuf_get_function_argument(drakvuf, info, 2);
    int whence = drakvuf_get_function_argument(drakvuf, info, 3);

    linux_data params;
    params.args["offset"] = std::to_string(offset);
    params.args["whence"] = parse_flags(whence, linux_lseek_whence, this->m_output_format);
    if (get_file_info(drakvuf, info, &params, file_struct))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::memfd_create_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // int __x64_sys_memfd_create (
    //     const char __user *uname,
    //     unsigned int flags
    // )
    //

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    auto vmi = vmi_lock_guard(drakvuf);
    addr_t pt_regs = drakvuf_get_function_argument(drakvuf, info, 1);

    addr_t file_name_addr;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, pt_regs + this->regs[PT_REGS_RDI], 0, &file_name_addr))
    {
        PRINT_DEBUG("[FILETRACER] Failed to read uname from memfd_create\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    uint32_t flags;
    if (VMI_FAILURE == vmi_read_32_va(vmi, pt_regs + this->regs[PT_REGS_RSI], 0, &flags))
    {
        PRINT_DEBUG("[FILETRACER] Failed to read uname from memfd_create\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    linux_data params;
    char* tmp = read_filename(drakvuf, info, file_name_addr);
    params.filename = tmp ?: "";
    g_free(tmp);
    params.flags = parse_flags(flags, linux_memfd_flags, this->m_output_format);

    if (!params.filename.empty())
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::mknod_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_mknod(
        struct inode *dir,
        struct dentry *dentry,
        umode_t mode,
        dev_t dev
    )

    in 5.12+:
    int vfs_mknod(
        struct user_namespace *mnt_userns,
        struct inode *dir,
        struct dentry *dentry,
        umode_t mode,
        dev_t dev
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    auto ver = drakvuf_get_kernel_version(drakvuf, info);
    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, VERSION_GE(ver, 5, 12) ? 3 : 2);

    linux_data params;
    if (get_dentry_info(drakvuf, info, &params, dentry_addr))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::rename_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_rename(
        struct inode *old_dir,
        struct dentry *old_dentry,
        struct inode *new_dir,
        struct dentry *new_dentry,
        struct inode **delegated_inode,
        unsigned int flags
    )

    in 5.12:
    int vfs_rename(
        struct renamedata *rd
    )
    struct renamedata {
        struct user_namespace *old_mnt_userns;
        struct inode *old_dir;
        struct dentry *old_dentry;
        struct user_namespace *new_mnt_userns;
        struct inode *new_dir;
        struct dentry *new_dentry;
        struct inode **delegated_inode;
        unsigned int flags;
    } __randomize_layout;
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t old_dentry_addr;
    addr_t new_dentry_addr;

    auto ver = drakvuf_get_kernel_version(drakvuf, info);
    if (VERSION_GE(ver, 5, 12))
    {
        addr_t struct_addr = drakvuf_get_function_argument(drakvuf, info, 1);

        auto vmi = vmi_lock_guard(drakvuf);

        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3);

        ctx.addr = struct_addr + this->offsets[_RENAMEDATA_OLD_DENTRY];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &old_dentry_addr))
            return VMI_EVENT_RESPONSE_NONE;

        ctx.addr = struct_addr + this->offsets[_RENAMEDATA_NEW_DENTRY];
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &new_dentry_addr))
            return VMI_EVENT_RESPONSE_NONE;
    }
    else
    {
        old_dentry_addr = drakvuf_get_function_argument(drakvuf, info, 2);
        new_dentry_addr = drakvuf_get_function_argument(drakvuf, info, 4);
    }

    char* tmp = drakvuf_get_filepath_from_dentry(drakvuf, old_dentry_addr);
    std::string old_name = tmp ?: "";
    g_free(tmp);

    if (old_name.empty())
        return VMI_EVENT_RESPONSE_NONE;

    linux_data params;
    params.args["old_name"] = old_name;
    if (get_dentry_info(drakvuf, info, &params, new_dentry_addr))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::truncate_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    long vfs_truncate(
        const struct path *path,
        loff_t length
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t path_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    uint64_t length = drakvuf_get_function_argument(drakvuf, info, 2);

    linux_data params;
    params.args["length"] = std::to_string(length);

    if (get_path_info(drakvuf, info, &params, path_struct))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::allocate_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_fallocate(
        struct file *file,
        int mode,
        loff_t offset,
        loff_t len
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t file_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    int64_t offset = drakvuf_get_function_argument(drakvuf, info, 3);
    int64_t length = drakvuf_get_function_argument(drakvuf, info, 4);

    linux_data params;
    params.args["offset"] = std::to_string(offset);
    params.args["length"] = std::to_string(length);
    if (get_file_info(drakvuf, info, &params, file_struct))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

/* ---------------FILE ATTRIBUTES CHANGE CALLBACK------- */

event_response_t linux_filetracer::chmod_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    static int chmod_common(
        const struct path *path,
        umode_t mode
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t path_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    int64_t new_mode = drakvuf_get_function_argument(drakvuf, info, 2);

    linux_data params;
    params.args["new_permissions"] = to_oct_str(new_mode & 0xfff);
    params.args["new_mode"] = parse_flags(new_mode, linux_file_modes, this->m_output_format);
    if (get_path_info(drakvuf, info, &params, path_struct))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::chown_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    static int chown_common(
        const struct path *path,
        uid_t user,
        gid_t group
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t path_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    uint64_t new_uid = drakvuf_get_function_argument(drakvuf, info, 2);
    uint64_t new_gid = drakvuf_get_function_argument(drakvuf, info, 3);

    linux_data params;
    params.args["new_uid"] = std::to_string(new_uid);
    params.args["new_gid"] = std::to_string(new_gid);
    if (get_path_info(drakvuf, info, &params, path_struct))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::utimes_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /* int vfs_utimes(
        const struct path *path,
        struct timespec64 *times
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t path_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t struct_timespec64 = drakvuf_get_function_argument(drakvuf, info, 2);

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = struct_timespec64 + this->offsets[_TIMESPEC64_TV_SEC]);

    uint64_t time_sec = 0;
    if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &time_sec))
    {
        PRINT_DEBUG("[FILETRACER] Failed to read timespec64\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    linux_data params;
    if (time_sec)
        params.args["time_sec"] = std::to_string(time_sec);

    if (get_path_info(drakvuf, info, &params, path_struct))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::access_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // static long do_faccessat(
    //     int dfd,
    //     const char __user *filename,
    //     int mode,
    //     int flags
    // )

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t file_name_addr = drakvuf_get_function_argument(drakvuf, info, 2);

    linux_data params;
    char* tmp = read_filename(drakvuf, info, file_name_addr);
    params.filename = tmp ?: "";
    g_free(tmp);

    if (!params.filename.empty())
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

/* ---------------DIRECTORY OPERATIONS CALLBACK--------- */

event_response_t linux_filetracer::mkdir_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_mkdir(
        struct inode *dir,
        struct dentry *dentry,
        umode_t mode
    )

    in 5.12+:
    int vfs_mkdir(
        struct user_namespace *mnt_userns,
        struct inode *dir,
        struct dentry *dentry,
        umode_t mode
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    auto ver = drakvuf_get_kernel_version(drakvuf, info);
    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, VERSION_GE(ver, 5, 12) ? 3 : 2);
    int64_t new_mode = drakvuf_get_function_argument(drakvuf, info, VERSION_GE(ver, 5, 12) ? 4 : 3);

    linux_data params;
    params.args["new_permissions"] = to_oct_str(new_mode & 0xfff);
    params.args["new_mode"] = parse_flags(new_mode, linux_file_modes, this->m_output_format);

    if (get_dentry_info(drakvuf, info, &params, dentry_addr))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::rmdir_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_rmdir(
        struct inode *dir,
        struct dentry *dentry
    )

    in 5.12+:
    int vfs_rmdir(
        struct user_namespace *mnt_userns,
        struct inode *dir,
        struct dentry *dentry
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    auto ver = drakvuf_get_kernel_version(drakvuf, info);
    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, VERSION_GE(ver, 5, 12) ? 3 : 2);

    linux_data params;
    if (get_dentry_info(drakvuf, info, &params, dentry_addr))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::chdir_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    void set_fs_pwd(
        struct fs_struct *fs,
        const struct path *path
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t path_struct = drakvuf_get_function_argument(drakvuf, info, 2);

    linux_data params;
    if (get_path_info(drakvuf, info, &params, path_struct))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::chroot_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    void set_fs_root(
        struct fs_struct *fs,
        const struct path *path
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t path_struct = drakvuf_get_function_argument(drakvuf, info, 2);

    linux_data params;
    if (get_path_info(drakvuf, info, &params, path_struct))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

/* ---------------LINK OPEARTIONS CALLBACK-------------- */

event_response_t linux_filetracer::link_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_link(
        struct dentry *old_dentry,
        struct inode *dir,
        struct dentry *new_dentry,
        struct inode **delegated_inode
    )

    in 5.12+:
    int vfs_link(
        struct dentry *old_dentry,
        struct user_namespace *mnt_userns,
        struct inode *dir,
        struct dentry *new_dentry,
        struct inode **delegated_inode
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    auto ver = drakvuf_get_kernel_version(drakvuf, info);
    addr_t old_dentry_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t new_dentry_addr = drakvuf_get_function_argument(drakvuf, info, VERSION_GE(ver, 5, 12) ? 4 : 3);

    char* tmp = drakvuf_get_filepath_from_dentry(drakvuf, new_dentry_addr);
    std::string link_name = tmp ?: "";
    g_free(tmp);
    if (link_name.empty())
        return VMI_EVENT_RESPONSE_NONE;

    linux_data params;
    params.args["link_name"] = link_name;
    if (get_dentry_info(drakvuf, info, &params, old_dentry_addr))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::unlink_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_unlink(
        struct inode *dir,
        struct dentry *dentry,
        struct inode **delegated_inode
    )

    in 5.12+:
    int vfs_unlink(
        struct user_namespace *mnt_userns,
        struct inode *dir,
        struct dentry *dentry,
        struct inode **delegated_inode
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    auto ver = drakvuf_get_kernel_version(drakvuf, info);
    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, VERSION_GE(ver, 5, 12) ? 3 : 2);

    linux_data params;
    if (get_dentry_info(drakvuf, info, &params, dentry_addr))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::symbolic_link_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_symlink(
        struct inode *dir,
        struct dentry *dentry,
        const char *oldname
    )

    in 5.12+:
    int vfs_symlink(
        struct user_namespace *mnt_userns,
        struct inode *dir,
        struct dentry *dentry,
        const char *oldname
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    auto ver = drakvuf_get_kernel_version(drakvuf, info);
    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, VERSION_GE(ver, 5, 12) ? 3 : 2);
    addr_t oldname_addr = drakvuf_get_function_argument(drakvuf, info, VERSION_GE(ver, 5, 12) ? 4 : 3);

    linux_data params;
    char* tmp = read_filename(drakvuf, info, oldname_addr);
    params.args["oldname"] = tmp ?: "";
    g_free(tmp);
    if (get_dentry_info(drakvuf, info, &params, dentry_addr))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_filetracer::read_link_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // int vfs_readlink(
    //     struct dentry *dentry,
    //     char __user *buffer,
    //     int buflen
    // )

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    uint64_t buflen = drakvuf_get_function_argument(drakvuf, info, 3);

    linux_data params;
    params.args["buflen"] = std::to_string(buflen);

    if (get_dentry_info(drakvuf, info, &params, dentry_addr))
        print_info(drakvuf, info, &params);

    return VMI_EVENT_RESPONSE_NONE;
}

linux_filetracer::linux_filetracer(drakvuf_t drakvuf, output_format_t output) : pluginex(drakvuf, output)
{
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_offset_names, this->offsets.size(), this->offsets.data()))
    {
        PRINT_DEBUG("[FILETRACER] Failed to get some offsets\n");
    }

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_pt_regs_offsets_name, this->regs.size(), this->regs.data()))
    {
        PRINT_DEBUG("[FILETRACER] Failed to get regs offsets\n");
        return;
    }

    // File operations hooks
    open_file_hook = createSyscallHook("do_filp_open", &linux_filetracer::open_file_cb);
    read_file_hook = createSyscallHook("vfs_read", &linux_filetracer::read_file_cb);
    write_file_hook = createSyscallHook("vfs_write", &linux_filetracer::write_file_cb);
    close_file_hook = createSyscallHook("filp_close", &linux_filetracer::close_file_cb);
    llseek_file_hook = createSyscallHook("vfs_llseek", &linux_filetracer::llseek_file_cb);
    memfd_create_file_hook = createSyscallHook("__x64_sys_memfd_create", &linux_filetracer::memfd_create_file_cb, "memfd_create");
    mknod_file_hook = createSyscallHook("vfs_mknod", &linux_filetracer::mknod_file_cb);
    rename_file_hook = createSyscallHook("vfs_rename", &linux_filetracer::rename_file_cb);
    truncate_file_hook = createSyscallHook("do_truncate", &linux_filetracer::truncate_file_cb);
    allocate_file_hook = createSyscallHook("vfs_allocate", &linux_filetracer::allocate_file_cb);

    // File attributes change hooks
    chmod_file_hook = createSyscallHook("chmod_common", &linux_filetracer::chmod_file_cb);
    chown_file_hook = createSyscallHook("chown_common", &linux_filetracer::chown_file_cb);
    utimes_file_hook = createSyscallHook("vfs_utimes", &linux_filetracer::utimes_file_cb);
    access_file_hook = createSyscallHook("do_faccessat", &linux_filetracer::access_file_cb);

    // Directory operations hooks
    mkdir_hook = createSyscallHook("vfs_mkdir", &linux_filetracer::mkdir_cb);
    rmdir_hook = createSyscallHook("vfs_rmdir", &linux_filetracer::rmdir_cb);
    chdir_hook = createSyscallHook("set_fs_pwd", &linux_filetracer::chdir_cb);
    chroot_hook = createSyscallHook("set_fs_root", &linux_filetracer::chroot_cb);

    // Link operations hooks
    link_file_hook = createSyscallHook("vfs_link", &linux_filetracer::link_file_cb);
    unlink_file_hook = createSyscallHook("vfs_unlink", &linux_filetracer::unlink_file_cb);
    symbolic_link_file_hook = createSyscallHook("vfs_symlink", &linux_filetracer::symbolic_link_file_cb);
    read_link_hook = createSyscallHook("vfs_readlink", &linux_filetracer::read_link_cb);
}
