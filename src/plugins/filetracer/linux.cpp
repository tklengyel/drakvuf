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
    if (params->file_handle)
        extra_args.emplace_back(keyval("FileHandle", fmt::Rstr(std::to_string(params->file_handle))));
    for (auto& arg : params->args)
        extra_args.emplace_back(std::make_pair(arg.first, fmt::Rstr(arg.second)));

    addr_t current_process = drakvuf_get_current_process(drakvuf, info);
    const char* thread_name = drakvuf_get_process_name(drakvuf, current_process, false);

    fmt::print(
        this->m_output_format,
        "filetracer",
        drakvuf,
        info,
        keyval("Permissions", fmt::Rstr(to_oct_str(params->permissions))),
        keyval("ThreadName", fmt::Rstr(thread_name)),
        std::move(extra_args)
    );

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
    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    addr_t file_struct = info->regs->rax;

    if (file_struct && file_struct != ~0ul && file_struct != ~1ul)
        if (get_file_info(drakvuf, info, params, file_struct))
            print_info(drakvuf, info, params);

    auto hookID = make_hook_id(info, params->target_rsp);
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
    auto hook = this->createReturnHook<linux_data>(info, &linux_filetracer::open_file_ret_cb, info->trap->name);
    auto params = libhook::GetTrapParams<linux_data>(hook->trap_);

    // Save data
    params->setResultCallParams(drakvuf, info);

    auto hookID = make_hook_id(info, params->target_rsp);
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
    // OR for ksys_read:
    // ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    addr_t file_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    uint64_t count = drakvuf_get_function_argument(drakvuf, info, 3);
    addr_t ppos = drakvuf_get_function_argument(drakvuf, info, 4);
    int64_t pos = 0;

    if (ppos)
    {
        auto vmi = vmi_lock_guard(drakvuf);

        ACCESS_CONTEXT(ctx, .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3, .addr = ppos);

        if (VMI_FAILURE == vmi_read_64(vmi, &ctx, (uint64_t*)&pos))
            pos = 0;
    }

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
    // OR for ksys_write:
    // ssize_t ksys_write(unsigned int fd, const char __user *buf, size_t count)
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

event_response_t linux_filetracer::memfd_create_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<linux_data>(info);
    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    params->file_handle = info->regs->rax;

    if (params->file_handle > -1 && !params->filename.empty())
        print_info(drakvuf, info, params);

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks.erase(hookID);
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

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    if (!ret_addr)
        return VMI_EVENT_RESPONSE_NONE;


    // Create new trap for return callback
    auto hook = this->createReturnHook<linux_data>(info, &linux_filetracer::memfd_create_file_ret_cb, info->trap->name);
    auto params = libhook::GetTrapParams<linux_data>(hook->trap_);

    // Save data
    params->setResultCallParams(drakvuf, info);

    char* tmp = read_filename(drakvuf, info, file_name_addr);
    params->filename = tmp ?: "";
    g_free(tmp);

    params->flags = parse_flags(flags, linux_memfd_flags, this->m_output_format);

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks[hookID] = std::move(hook);

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
    int do_truncate(
        struct dentry *dentry,
        loff_t length,
        unsigned int time_attrs,
        struct file *filp
    )

    in 5.12+:
    int do_truncate(
        struct user_namespace *mnt_userns,
        struct dentry *dentry,
        loff_t length,
        unsigned int time_attrs,
        struct file *filp
    )
    */

    PRINT_DEBUG("[FILETRACER] Callback : %s\n", info->trap->name);

    auto ver = drakvuf_get_kernel_version(drakvuf, info);
    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, VERSION_GE(ver, 5, 12) ? 2 : 1);
    uint64_t length = drakvuf_get_function_argument(drakvuf, info, VERSION_GE(ver, 5, 12) ? 3 : 2);

    linux_data params;
    params.args["length"] = std::to_string(length);

    if (get_dentry_info(drakvuf, info, &params, dentry_addr))
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

/* ---------------SYSCALL-BASED FILE TRACING (Modern kernels 6.x+)-------------- */

// Linux x64 syscall numbers for file operations
enum linux_file_syscalls
{
    __NR_read = 0,
    __NR_write = 1,
    __NR_open = 2,
    __NR_close = 3,
    __NR_stat = 4,
    __NR_fstat = 5,
    __NR_lstat = 6,
    __NR_lseek = 8,
    __NR_pread64 = 17,
    __NR_pwrite64 = 18,
    __NR_access = 21,
    __NR_dup = 32,
    __NR_dup2 = 33,
    __NR_sendfile = 40,
    __NR_fcntl = 72,
    __NR_flock = 73,
    __NR_fsync = 74,
    __NR_fdatasync = 75,
    __NR_truncate = 76,
    __NR_ftruncate = 77,
    __NR_getdents = 78,
    __NR_getcwd = 79,
    __NR_chdir = 80,
    __NR_fchdir = 81,
    __NR_rename = 82,
    __NR_mkdir = 83,
    __NR_rmdir = 84,
    __NR_creat = 85,
    __NR_link = 86,
    __NR_unlink = 87,
    __NR_symlink = 88,
    __NR_readlink = 89,
    __NR_chmod = 90,
    __NR_fchmod = 91,
    __NR_chown = 92,
    __NR_fchown = 93,
    __NR_lchown = 94,
    __NR_getdents64 = 217,
    __NR_openat = 257,
    __NR_mkdirat = 258,
    __NR_mknodat = 259,
    __NR_fchownat = 260,
    __NR_unlinkat = 263,
    __NR_renameat = 264,
    __NR_linkat = 265,
    __NR_symlinkat = 266,
    __NR_readlinkat = 267,
    __NR_fchmodat = 268,
    __NR_faccessat = 269,
    __NR_renameat2 = 316,
    __NR_memfd_create = 319,
    __NR_openat2 = 437,
};

static const char* get_syscall_name(uint64_t nr)
{
    switch (nr)
    {
        case __NR_read:
            return "read";
        case __NR_write:
            return "write";
        case __NR_open:
            return "open";
        case __NR_close:
            return "close";
        case __NR_stat:
            return "stat";
        case __NR_fstat:
            return "fstat";
        case __NR_lstat:
            return "lstat";
        case __NR_lseek:
            return "lseek";
        case __NR_pread64:
            return "pread64";
        case __NR_pwrite64:
            return "pwrite64";
        case __NR_access:
            return "access";
        case __NR_dup:
            return "dup";
        case __NR_dup2:
            return "dup2";
        case __NR_sendfile:
            return "sendfile";
        case __NR_truncate:
            return "truncate";
        case __NR_ftruncate:
            return "ftruncate";
        case __NR_getcwd:
            return "getcwd";
        case __NR_chdir:
            return "chdir";
        case __NR_fchdir:
            return "fchdir";
        case __NR_rename:
            return "rename";
        case __NR_mkdir:
            return "mkdir";
        case __NR_rmdir:
            return "rmdir";
        case __NR_creat:
            return "creat";
        case __NR_link:
            return "link";
        case __NR_unlink:
            return "unlink";
        case __NR_symlink:
            return "symlink";
        case __NR_readlink:
            return "readlink";
        case __NR_chmod:
            return "chmod";
        case __NR_fchmod:
            return "fchmod";
        case __NR_chown:
            return "chown";
        case __NR_fchown:
            return "fchown";
        case __NR_lchown:
            return "lchown";
        case __NR_getdents64:
            return "getdents64";
        case __NR_openat:
            return "openat";
        case __NR_mkdirat:
            return "mkdirat";
        case __NR_mknodat:
            return "mknodat";
        case __NR_fchownat:
            return "fchownat";
        case __NR_unlinkat:
            return "unlinkat";
        case __NR_renameat:
            return "renameat";
        case __NR_linkat:
            return "linkat";
        case __NR_symlinkat:
            return "symlinkat";
        case __NR_readlinkat:
            return "readlinkat";
        case __NR_fchmodat:
            return "fchmodat";
        case __NR_faccessat:
            return "faccessat";
        case __NR_renameat2:
            return "renameat2";
        case __NR_memfd_create:
            return "memfd_create";
        case __NR_openat2:
            return "openat2";
        default:
            return nullptr;
    }
}

static bool is_file_syscall(uint64_t nr)
{
    return get_syscall_name(nr) != nullptr;
}

bool linux_filetracer::get_pt_regs_and_nr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* pt_regs_addr, uint64_t* nr)
{
    /*
     * For x64_sys_call: long x64_sys_call(struct pt_regs *regs, unsigned int nr)
     *   - rdi = pt_regs* (kernel address, bit 47 set)
     *   - esi = syscall number (32-bit)
     */
    if (VMI_GET_BIT(info->regs->rdi, 47))
    {
        *pt_regs_addr = info->regs->rdi;
        uint32_t nr_32 = (uint32_t)(info->regs->rsi & 0xFFFFFFFF);
        if (nr_32 < 0x1000)
        {
            *nr = nr_32;
            return true;
        }

        // Fallback: read orig_rax from pt_regs
        auto vmi = vmi_lock_guard(drakvuf);
        return VMI_SUCCESS == vmi_read_addr_va(vmi, *pt_regs_addr + this->regs[PT_REGS_ORIG_RAX], 0, nr);
    }

    // Newer kernel style: do_syscall_64(unsigned long nr, struct pt_regs *regs)
    *nr = info->regs->rdi;
    *pt_regs_addr = info->regs->rsi;
    return true;
}

bool linux_filetracer::read_pt_regs_arg(drakvuf_t drakvuf, addr_t pt_regs_addr, int arg_index, uint64_t* value)
{
    // x64 syscall args in pt_regs: rdi, rsi, rdx, r10, r8, r9
    static const int arg_offsets[] =
    {
        PT_REGS_RDI, PT_REGS_RSI, PT_REGS_RDX, PT_REGS_R10, PT_REGS_R8, PT_REGS_R9
    };

    if (arg_index < 0 || arg_index >= 6)
        return false;

    auto vmi = vmi_lock_guard(drakvuf);
    return VMI_SUCCESS == vmi_read_addr_va(vmi, pt_regs_addr + this->regs[arg_offsets[arg_index]], 0, value);
}

char* linux_filetracer::read_user_string(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t user_addr)
{
    if (!user_addr)
        return nullptr;

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = user_addr);

    return vmi_read_str(vmi, &ctx);
}

std::string linux_filetracer::get_filename_from_fd(drakvuf_t drakvuf, drakvuf_trap_info_t* info, int fd)
{
    if (fd < 0)
        return "";

    // Get current task's files_struct
    addr_t task = drakvuf_get_current_process(drakvuf, info);
    if (!task)
        return "";

    auto vmi = vmi_lock_guard(drakvuf);

    // task_struct->files (struct files_struct *)
    addr_t files_struct;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, task + this->offsets[_TASK_STRUCT_FILES], 0, &files_struct) || !files_struct)
        return "";

    // files_struct->fdt (struct fdtable *)
    addr_t fdtable;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, files_struct + this->offsets[_FILES_STRUCT_FDT], 0, &fdtable) || !fdtable)
        return "";

    // fdtable->fd (struct file **fd)
    addr_t fd_array;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, fdtable + this->offsets[_FDTABLE_FD], 0, &fd_array) || !fd_array)
        return "";

    // fd_array[fd] -> struct file *
    addr_t file_struct;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, fd_array + fd * sizeof(addr_t), 0, &file_struct) || !file_struct)
        return "";

    // file->f_path.dentry
    addr_t dentry;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, file_struct + this->offsets[_FILE_F_PATH] + this->offsets[_PATH_DENTRY], 0, &dentry) || !dentry)
        return "";

    // Use drakvuf helper to get full path from dentry
    char* path = drakvuf_get_filepath_from_dentry(drakvuf, dentry);
    if (!path)
        return "";

    std::string result(path);
    g_free(path);
    return result;
}

void linux_filetracer::print_syscall_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const char* syscall_name, linux_data* params)
{
    std::vector<std::pair<std::string, fmt::Aarg>> extra_args;

    if (!params->filename.empty())
        extra_args.emplace_back(keyval("FileName", fmt::Estr(params->filename)));
    if (params->file_handle)
        extra_args.emplace_back(keyval("FileHandle", fmt::Nval(static_cast<uint64_t>(params->file_handle))));
    for (auto& arg : params->args)
        extra_args.emplace_back(std::make_pair(arg.first, fmt::Rstr(arg.second)));

    addr_t current_process = drakvuf_get_current_process(drakvuf, info);
    const char* thread_name = drakvuf_get_process_name(drakvuf, current_process, false);

    fmt::print(
        this->m_output_format,
        "filetracer",
        drakvuf,
        info,
        keyval("Syscall", fmt::Qstr(syscall_name)),
        keyval("ThreadName", fmt::Rstr(thread_name)),
        std::move(extra_args)
    );

    g_free(const_cast<char*>(thread_name));
}

event_response_t linux_filetracer::syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t pt_regs_addr = 0;
    uint64_t nr = 0;

    if (!get_pt_regs_and_nr(drakvuf, info, &pt_regs_addr, &nr))
        return VMI_EVENT_RESPONSE_NONE;

    // Filter for file-related syscalls only
    if (!is_file_syscall(nr))
        return VMI_EVENT_RESPONSE_NONE;

    const char* syscall_name = get_syscall_name(nr);
    linux_data params;

    // Read syscall arguments from pt_regs
    uint64_t arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0;
    read_pt_regs_arg(drakvuf, pt_regs_addr, 0, &arg0);
    read_pt_regs_arg(drakvuf, pt_regs_addr, 1, &arg1);
    read_pt_regs_arg(drakvuf, pt_regs_addr, 2, &arg2);
    read_pt_regs_arg(drakvuf, pt_regs_addr, 3, &arg3);

    // Extract file information based on syscall type
    switch (nr)
    {
        case __NR_read:
        case __NR_write:
        {
            // ssize_t read/write(int fd, void *buf, size_t count)
            int fd = (int)arg0;
            params.file_handle = fd;
            params.args["count"] = std::to_string(arg2);
            params.filename = get_filename_from_fd(drakvuf, info, fd);
            break;
        }

        case __NR_pread64:
        case __NR_pwrite64:
        {
            // ssize_t pread64/pwrite64(int fd, void *buf, size_t count, off_t offset)
            int fd = (int)arg0;
            params.file_handle = fd;
            params.args["count"] = std::to_string(arg2);
            params.args["offset"] = std::to_string(arg3);
            params.filename = get_filename_from_fd(drakvuf, info, fd);
            break;
        }

        case __NR_open:
        case __NR_creat:
        {
            // int open(const char *pathname, int flags, mode_t mode)
            char* pathname = read_user_string(drakvuf, info, arg0);
            if (pathname)
            {
                params.filename = pathname;
                g_free(pathname);
            }
            params.args["flags"] = std::to_string(arg1);
            params.args["mode"] = std::to_string(arg2);
            break;
        }

        case __NR_openat:
        case __NR_openat2:
        {
            // int openat(int dirfd, const char *pathname, int flags, mode_t mode)
            params.args["dirfd"] = std::to_string((int)arg0);
            char* pathname = read_user_string(drakvuf, info, arg1);
            if (pathname)
            {
                params.filename = pathname;
                g_free(pathname);
            }
            params.args["flags"] = std::to_string(arg2);
            break;
        }

        case __NR_close:
        {
            // int close(int fd)
            int fd = (int)arg0;
            params.file_handle = fd;
            params.filename = get_filename_from_fd(drakvuf, info, fd);
            break;
        }

        case __NR_lseek:
        {
            // off_t lseek(int fd, off_t offset, int whence)
            int fd = (int)arg0;
            params.file_handle = fd;
            params.args["offset"] = std::to_string((int64_t)arg1);
            params.args["whence"] = std::to_string(arg2);
            params.filename = get_filename_from_fd(drakvuf, info, fd);
            break;
        }

        case __NR_stat:
        case __NR_lstat:
        case __NR_access:
        case __NR_truncate:
        case __NR_unlink:
        case __NR_rmdir:
        case __NR_mkdir:
        case __NR_chmod:
        case __NR_readlink:
        case __NR_chdir:
        {
            // syscalls with (const char *pathname, ...)
            char* pathname = read_user_string(drakvuf, info, arg0);
            if (pathname)
            {
                params.filename = pathname;
                g_free(pathname);
            }
            break;
        }

        case __NR_fstat:
        case __NR_ftruncate:
        case __NR_fchmod:
        case __NR_fchown:
        case __NR_fchdir:
        case __NR_dup:
        {
            // syscalls with (int fd, ...)
            int fd = (int)arg0;
            params.file_handle = fd;
            params.filename = get_filename_from_fd(drakvuf, info, fd);
            break;
        }

        case __NR_rename:
        case __NR_link:
        case __NR_symlink:
        {
            // syscalls with (const char *oldpath, const char *newpath)
            char* oldpath = read_user_string(drakvuf, info, arg0);
            char* newpath = read_user_string(drakvuf, info, arg1);
            if (oldpath)
            {
                params.filename = oldpath;
                g_free(oldpath);
            }
            if (newpath)
            {
                params.args["newpath"] = newpath;
                g_free(newpath);
            }
            break;
        }

        case __NR_unlinkat:
        case __NR_mkdirat:
        case __NR_fchmodat:
        case __NR_faccessat:
        case __NR_readlinkat:
        {
            // syscalls with (int dirfd, const char *pathname, ...)
            params.args["dirfd"] = std::to_string((int)arg0);
            char* pathname = read_user_string(drakvuf, info, arg1);
            if (pathname)
            {
                params.filename = pathname;
                g_free(pathname);
            }
            break;
        }

        case __NR_renameat:
        case __NR_renameat2:
        case __NR_linkat:
        case __NR_symlinkat:
        {
            // syscalls with (int olddirfd, const char *oldpath, int newdirfd, const char *newpath, ...)
            params.args["olddirfd"] = std::to_string((int)arg0);
            char* oldpath = read_user_string(drakvuf, info, arg1);
            if (oldpath)
            {
                params.filename = oldpath;
                g_free(oldpath);
            }
            params.args["newdirfd"] = std::to_string((int)arg2);
            char* newpath = read_user_string(drakvuf, info, arg3);
            if (newpath)
            {
                params.args["newpath"] = newpath;
                g_free(newpath);
            }
            break;
        }

        case __NR_memfd_create:
        {
            // int memfd_create(const char *name, unsigned int flags)
            char* name = read_user_string(drakvuf, info, arg0);
            if (name)
            {
                params.filename = name;
                g_free(name);
            }
            params.args["flags"] = std::to_string(arg1);
            break;
        }

        case __NR_sendfile:
        {
            // ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
            params.args["out_fd"] = std::to_string((int)arg0);
            params.args["in_fd"] = std::to_string((int)arg1);
            params.file_handle = (int)arg1;
            params.args["count"] = std::to_string(arg3);
            params.filename = get_filename_from_fd(drakvuf, info, (int)arg1);
            break;
        }

        case __NR_dup2:
        {
            // int dup2(int oldfd, int newfd)
            params.args["oldfd"] = std::to_string((int)arg0);
            params.args["newfd"] = std::to_string((int)arg1);
            params.file_handle = (int)arg0;
            params.filename = get_filename_from_fd(drakvuf, info, (int)arg0);
            break;
        }

        default:
            // For other file syscalls, just log the syscall name
            break;
    }

    print_syscall_info(drakvuf, info, syscall_name, &params);
    return VMI_EVENT_RESPONSE_NONE;
}

/* ---------------CONSTRUCTOR-------------- */

linux_filetracer::linux_filetracer(drakvuf_t drakvuf, output_format_t output) : pluginex(drakvuf, output)
{
    PRINT_DEBUG("[FILETRACER] Initializing Linux filetracer\n");

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_offset_names, this->offsets.size(), this->offsets.data()))
    {
        PRINT_DEBUG("[FILETRACER] Warning: Failed to get some offsets\n");
    }

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_pt_regs_offsets_name, this->regs.size(), this->regs.data()))
    {
        PRINT_DEBUG("[FILETRACER] Failed to get regs offsets\n");
        return;
    }

    // Try modern kernel hook (x64_sys_call) first - works on kernel 6.x+
    syscall_hook = createSyscallHook("x64_sys_call", &linux_filetracer::syscall_cb, "x64_sys_call");
    if (syscall_hook)
    {
        PRINT_DEBUG("[FILETRACER] Using x64_sys_call hook for modern kernel\n");
        return;  // Success - no need for legacy hooks
    }

    // Fallback to legacy VFS hooks (older kernels)
    PRINT_DEBUG("[FILETRACER] x64_sys_call not available, using legacy VFS hooks\n");

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
