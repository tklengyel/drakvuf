/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  *
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dirent.h>
#include <glib.h>
#include <err.h>
#include <algorithm>
#include <assert.h>
#include <sstream>
#include <map>

#include <libvmi/libvmi.h>
#include "linux.h"
#include "filetracer.h"
#include "private.h"

void free_gstrings(struct linux_wrapper* lw)
{

    g_string_free(lw->filename, TRUE);
    g_string_free(lw->flags, TRUE);
    g_string_free(lw->modes, TRUE);
    g_string_free(lw->uid, TRUE);
    g_string_free(lw->gid, TRUE);
    for (auto arg : lw->args)
    {
        g_string_free(arg.second, TRUE);
    }
}

void print_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, linux_wrapper* lw)
{
    linux_filetracer* f = (linux_filetracer*)info->trap->data;
    gchar* escaped_pname = NULL;
    gchar* escaped_fname = NULL;

    switch (f->format)
    {
        case OUTPUT_CSV:
            printf("filetracer," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,%s",
                UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, info->trap->name, lw->filename->str);
            if (lw->modes->len)
                printf(",\"%s\"", lw->modes->str);
            if (lw->flags->len)
                printf(",\"%s\"", lw->flags->str);
            if (lw->uid->len)
                printf(",%s", lw->uid->str);
            if (lw->gid->len)
                printf(",%s", lw->gid->str);
            for (auto arg : lw->args)
            {
                if (arg.second->len)
                    printf(",%s", arg.second->str);
            }
            printf("\n");
            break;

        case OUTPUT_KV:
            printf("filetracer Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,File=\"%s\"",
                UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                info->trap->name, lw->filename->str);
            if (lw->modes->len)
                printf(",Modes=%s", lw->modes->str);
            if (lw->flags->len)
                printf(",Flags=%s", lw->flags->str);
            if (lw->uid->len)
                printf(",UID=%s", lw->uid->str);
            if (lw->gid->len)
                printf(",GID=%s", lw->gid->str);
            for (auto arg : lw->args)
            {
                if (arg.second->len)
                    printf(",%s=%s", arg.first.c_str(), arg.second->str);
            }
            printf("\n");
            break;

        case OUTPUT_JSON:
            escaped_fname = drakvuf_escape_str(lw->filename->str);
            escaped_pname = drakvuf_escape_str(info->proc_data.name);

            printf("{"
                "\"Plugin\" : \"filetracer\","
                "\"TimeStamp\" :"
                "\"" FORMAT_TIMEVAL "\","
                "\"ProcessName\": %s,"
                "\"UserName\": \"%s\","
                "\"UserId\": %" PRIu64 ","
                "\"PID\" : %d,"
                "\"PPID\": %d,"
                "\"TID\": %d,"
                "\"Method\": \"%s\","
                "\"FileName\": \"%s\",",
                UNPACK_TIMEVAL(info->timestamp),
                escaped_pname,
                USERIDSTR(drakvuf), info->proc_data.userid,
                info->proc_data.pid, info->proc_data.ppid, info->proc_data.tid,
                info->trap->name, escaped_fname);
            if (lw->permissions)
                printf("\"Permissions\": %o,", lw->permissions);
            if (lw->modes->len)
                printf("\"Mode\": \"%s\",", lw->modes->str);
            if (lw->flags->len)
                printf("\"Flag\": \"%s\",", lw->flags->str);
            if (lw->uid->len)
                printf("\"UID\": %s,", lw->uid->str);
            if (lw->gid->len)
                printf("\"GID\": %s,", lw->gid->str);
            for (auto arg : lw->args)
            {
                if (arg.second->len)
                    printf("\"%s\" : \"%s\",", arg.first.c_str(), arg.second->str);
            }

            printf("}\n");
            g_free(escaped_fname);
            g_free(escaped_pname);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[FILETRACER] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " %s,%s",
                UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                USERIDSTR(drakvuf), info->proc_data.userid, info->trap->name, lw->filename->str);

            if (lw->permissions)
                printf(",\"Permissions:%o\"", lw->permissions);
            if (lw->modes->len)
                printf(",\"Mode:%s\"", lw->modes->str);
            if (lw->flags->len)
                printf(",\"Flag:%s\"", lw->flags->str);
            if (lw->uid->len)
                printf(",UID:%s", lw->uid->str);
            if (lw->gid->len)
                printf(",GID:%s", lw->gid->str);
            for (auto arg : lw->args)
            {
                if (arg.second->len)
                    printf(",%s:%s", arg.first.c_str(), arg.second->str);
            }
            printf("\n");
            break;
    }
}

GString* get_filepath(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, addr_t dentry_addr)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    linux_filetracer* f = (linux_filetracer*)info->trap->data;

    ctx.addr = dentry_addr + f->offsets[_DENTRY_D_NAME] + f->offsets[_QSTR_NAME] + 16;
    GString* path_name = g_string_new(NULL);
    gchar* p = vmi_read_str(vmi, &ctx);
    if (p == NULL)
        return g_string_assign(path_name, "");
    g_string_assign(path_name, p);
    g_free(p);

    if (path_name->str[0] != '[' && g_strcmp0(path_name->str, "") != 0)
    {
        addr_t d_parent = 0;
        ctx.addr = dentry_addr + 24;
        GString* dirname = g_string_new(NULL);
        GString* prev_dirname = g_string_new(path_name->str);

        while (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &d_parent) && d_parent)
        {
            ctx.addr = d_parent + f->offsets[_DENTRY_D_NAME] + f->offsets[_QSTR_NAME] + 16;
            gchar* temp = vmi_read_str(vmi, &ctx);
            if (temp == NULL)
                break;
            dirname = g_string_assign(dirname, temp);
            g_free(temp);

            if (g_strcmp0(dirname->str, "/") == 0 || g_strcmp0(dirname->str, "") == 0 || g_strcmp0(dirname->str, prev_dirname->str) == 0)
                break;

            ctx.addr = d_parent + 24;
            g_string_assign(prev_dirname, dirname->str);
            g_string_append(dirname, "/");
            g_string_append(dirname, path_name->str);
            g_string_assign(path_name, dirname->str);
        }
        g_string_prepend(path_name, "/");
        g_string_free (prev_dirname, TRUE);
        g_string_free (dirname, TRUE);
    }
    else
        return g_string_assign(path_name, "");

    return path_name;
}

int get_file_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, linux_wrapper* lw, addr_t struct_addr = 0, std::string struct_name = "")
{
    if (!struct_addr || struct_name == "")
        return 0;

    linux_filetracer* f = (linux_filetracer*)info->trap->data;

    vmi_lock_guard vmi_lg(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    addr_t dentry_addr = 0;
    if (struct_name == "file")
    {
        ctx.addr = struct_addr + f->offsets[_FILE_F_PATH] + f->offsets[_PATH_DENTRY];
        if (VMI_FAILURE == vmi_read_addr(vmi_lg.vmi, &ctx, &dentry_addr))
            return 0;
    }
    else if (struct_name == "path")
    {
        ctx.addr = struct_addr + f->offsets[_PATH_DENTRY];
        if (VMI_FAILURE == vmi_read_addr(vmi_lg.vmi, &ctx, &dentry_addr))
            return 0;
    }
    else if (struct_name == "dentry")
        dentry_addr = struct_addr;
    else
        return 0;

    if (!dentry_addr)
        return 0;

    GString* filepath = get_filepath(drakvuf, info, vmi_lg.vmi, dentry_addr);
    if (filepath->str != NULL)
        g_string_assign(lw->filename, filepath->str);
    g_string_free(filepath, TRUE);

    if (g_strcmp0(lw->filename->str, "") == 0)
    {
        return 0;
    }

    addr_t inode;
    ctx.addr = dentry_addr + f->offsets[_DENTRY_D_INODE];
    if (VMI_SUCCESS == vmi_read_addr(vmi_lg.vmi, &ctx, &inode) && inode)
    {
        uint16_t mode;
        ctx.addr = inode + f->offsets[_INODE_I_MODE];
        if (VMI_SUCCESS == vmi_read_16(vmi_lg.vmi, &ctx, &mode) && mode)
        {
            lw->permissions = mode & 0xfff;
            g_string_assign(lw->modes, parse_flags(mode, linux_file_modes, f->format).c_str());
        }

        uint32_t flags;
        ctx.addr = inode + f->offsets[_INODE_I_FLAGS];
        if (VMI_SUCCESS == vmi_read_32(vmi_lg.vmi, &ctx, &flags) && flags)
        {
            g_string_assign(lw->flags, parse_flags(flags, linux_inode_flags, f->format).c_str());
        }

        uint32_t uid;
        ctx.addr = inode + f->offsets[_INODE_I_UID];
        if (VMI_SUCCESS == vmi_read_32(vmi_lg.vmi, &ctx, &uid) && uid)
            g_string_printf(lw->uid, "%u", uid);

        uint32_t gid;
        ctx.addr = inode + f->offsets[_INODE_I_GID];
        if (VMI_SUCCESS == vmi_read_32(vmi_lg.vmi, &ctx, &gid) && gid)
            g_string_printf(lw->gid, "%u", gid);
    }
    return 1;
}

char* read_filename(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t fileaddr)
{
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = fileaddr
    );

    char* filename = vmi_read_str(vmi, &ctx);
    drakvuf_release_vmi(drakvuf);
    return filename;
}

/* ---------------FILE OPERATIONS CALLBACK-------------- */

static event_response_t open_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct linux_wrapper* lw = (struct linux_wrapper*)info->trap->data;
    addr_t file_struct = 0;

    if (!drakvuf_check_return_context(drakvuf, info, lw->pid, lw->tid, lw->rsp))
        return VMI_EVENT_RESPONSE_NONE;

    file_struct = info->regs->rax;

    if (!file_struct || file_struct == ~0ul || file_struct == ~1ul)
        goto finish;

    info->trap->data = lw->f;
    if (get_file_info(drakvuf, info, lw, file_struct, "file"))
        print_info(drakvuf, info, lw);

finish:
    lw->f->traps_to_free = g_slist_remove(lw->f->traps_to_free, info->trap);
    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)g_free);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t open_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    struct file *do_filp_open(
        int dfd,
        struct filename *pathname,
        const struct open_flags *op
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    linux_filetracer* f = (linux_filetracer*)info->trap->data;
    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    if (!ret_addr)
        return VMI_EVENT_RESPONSE_NONE;

    struct linux_wrapper* lw = new (std::nothrow) linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;

    lw->f = f;
    lw->pid = info->proc_data.pid;
    lw->tid = info->proc_data.tid;
    lw->rsp = ret_addr;

    drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
    trap->breakpoint.lookup_type = LOOKUP_PID;
    trap->breakpoint.pid = 0;
    trap->breakpoint.addr_type = ADDR_VA;
    trap->breakpoint.addr = ret_addr;
    trap->breakpoint.module = "linux";
    trap->type = BREAKPOINT;
    trap->name = info->trap->name;
    trap->data = lw;
    trap->cb = open_file_ret_cb;

    if (!drakvuf_add_trap(drakvuf, trap))
    {
        printf("Failed to trap return at 0x%lx\n", ret_addr);
        free_gstrings(lw);
        delete lw;
        g_free(trap);
    }
    else
        f->traps_to_free = g_slist_prepend(f->traps_to_free, trap);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t read_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    ssize_t vfs_read(
        struct file *file,
        char __user *buf,
        size_t count,
        loff_t *pos
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t file_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    lw->args["count"] = g_string_new(NULL);
    g_string_printf(lw->args["count"], "%lu", drakvuf_get_function_argument(drakvuf, info, 3));
    int64_t pos = drakvuf_get_function_argument(drakvuf, info, 4);
    lw->args["pos"] = g_string_new(NULL);
    g_string_printf(lw->args["pos"], "%lx", pos);
    if (get_file_info(drakvuf, info, lw, file_struct, "file"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}


static event_response_t write_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    ssize_t vfs_write(
        struct file *file,
        const char __user *buf,
        size_t count,
        loff_t *pos
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t file_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    if (get_file_info(drakvuf, info, lw, file_struct, "file"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t close_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int filp_close(
        struct file *filp,
        fl_owner_t id
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t file_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    if (get_file_info(drakvuf, info, lw, file_struct, "file"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t llseek_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    loff_t vfs_llseek(
        struct file *file,
        loff_t offset,
        int whence
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t file_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    int64_t offset_ = drakvuf_get_function_argument(drakvuf, info, 2);
    int whence = drakvuf_get_function_argument(drakvuf, info, 3);
    linux_filetracer* f = (linux_filetracer*)info->trap->data;
    lw->args["offset"] = g_string_new(NULL);
    g_string_printf(lw->args["offset"], "%ld", offset_);
    lw->args["whence"] = g_string_new(NULL);
    g_string_printf(lw->args["whence"], "%s", parse_flags(whence, linux_lseek_whence, f->format).c_str());
    if (get_file_info(drakvuf, info, lw, file_struct, "file"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

/*
static event_response_t memfd_create_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    // int memfd_create(
    //     const char __user *uname,
    //     unsigned int flags
    // )

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t file_name_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    g_string_printf(lw->filename, "%s", read_filename(drakvuf, info, file_name_addr));
    if (lw->filename->str != NULL  && g_strcmp0(lw->filename->str, "") != 0)
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}
*/

static event_response_t mknod_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_mknod(
        struct inode *dir,
        struct dentry *dentry,
        umode_t mode,
        dev_t dev
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    if (get_file_info(drakvuf, info, lw, dentry_addr, "dentry"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t rename_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
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
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    lw->args["old_name"] = get_filepath(drakvuf, info, vmi, dentry_addr);
    drakvuf_release_vmi(drakvuf);

    if (g_strcmp0(lw->args["old_name"]->str, "") == 0)
    {
        free_gstrings(lw);
        delete lw;
        return VMI_EVENT_RESPONSE_NONE;
    }

    dentry_addr = drakvuf_get_function_argument(drakvuf, info, 4);
    if (get_file_info(drakvuf, info, lw, dentry_addr, "dentry"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t truncate_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    long vfs_truncate(
        const struct path *path,
        loff_t length
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t path_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    uint64_t length = drakvuf_get_function_argument(drakvuf, info, 2);
    lw->args["length"] = g_string_new(NULL);
    g_string_printf(lw->args["length"], "%ld", length);
    if (get_file_info(drakvuf, info, lw, path_struct, "path"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t allocate_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_fallocate(
        struct file *file,
        int mode,
        loff_t offset,
        loff_t len
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t file_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    int64_t offset = drakvuf_get_function_argument(drakvuf, info, 3);
    lw->args["offset"] = g_string_new(NULL);
    g_string_printf(lw->args["offset"], "%ld", offset);
    int64_t length = drakvuf_get_function_argument(drakvuf, info, 4);
    lw->args["length"] = g_string_new(NULL);
    g_string_printf(lw->args["length"], "%ld", length);
    if (get_file_info(drakvuf, info, lw, file_struct, "file"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

/* ---------------FILE ATTRIBUTES CHANGE CALLBACK------- */

static event_response_t chmod_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    static int chmod_common(
        const struct path *path,
        umode_t mode
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    linux_filetracer* f = (linux_filetracer*)info->trap->data;
    addr_t path_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    int64_t new_mode = drakvuf_get_function_argument(drakvuf, info, 2);
    lw->args["new_permissions"] = g_string_new(NULL);
    g_string_printf(lw->args["new_permissions"], "%lo", new_mode & 0xfff);
    lw->args["new_mode"] = g_string_new(NULL);
    g_string_printf(lw->args["new_mode"], "%s", parse_flags(new_mode, linux_file_modes, f->format).c_str());
    if (get_file_info(drakvuf, info, lw, path_struct, "path"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t chown_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    static int chown_common(
        const struct path *path,
        uid_t user,
        gid_t group
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t path_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    uint64_t new_uid = drakvuf_get_function_argument(drakvuf, info, 2);
    lw->args["new_uid"] = g_string_new(NULL);
    g_string_printf(lw->args["new_uid"], "%ld", new_uid);
    uint64_t new_gid = drakvuf_get_function_argument(drakvuf, info, 3);
    lw->args["new_gid"] = g_string_new(NULL);
    g_string_printf(lw->args["new_gid"], "%ld", new_gid);
    if (get_file_info(drakvuf, info, lw, path_struct, "path"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

/*
Commented as kernel symbol varies with distros.
static event_response_t utimes_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // static int utimes_common(
    //     const struct path *path,
    //     struct timespec64 *times
    // )

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    linux_filetracer* f = (linux_filetracer*)info->trap->data;
    uint64_t time_sec = 0;
    addr_t path_struct = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t struct_timespec64 = drakvuf_get_function_argument(drakvuf, info, 2);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = struct_timespec64 + f->offsets[_TIMESPEC64_TV_SEC],
    };

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    vmi_read_64(vmi, &ctx, &time_sec);
    drakvuf_release_vmi(drakvuf);
    if (time_sec) {
        lw->args["time_sec"] = g_string_new(NULL);
        g_string_printf(lw->args["time_sec"], "%ld", time_sec);
    }

    if (get_file_info(drakvuf, info, lw, path_struct, "path"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}


static event_response_t access_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    // long do_faccessat(
    //     int dfd,
    //     const char __user *filename,
    //     int mode
    // )

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t file_name_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    g_string_printf(lw->filename, "%s", read_filename(drakvuf, info, file_name_addr));
    if (lw->filename->str != NULL && g_strcmp0(lw->filename->str, "") != 0)
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}
*/

/* ---------------DIRECTORY OPERATIONS CALLBACK--------- */

static event_response_t mkdir_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_mkdir(
        struct inode *dir,
        struct dentry *dentry,
        umode_t mode
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;

    linux_filetracer* f = (linux_filetracer*)info->trap->data;
    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    int64_t new_mode = drakvuf_get_function_argument(drakvuf, info, 3);
    lw->args["new_permissions"] = g_string_new(NULL);
    g_string_printf(lw->args["new_permissions"], "%lo", new_mode & 0xfff);
    lw->args["new_mode"] = g_string_new(NULL);
    g_string_printf(lw->args["new_mode"], "%s", parse_flags(new_mode, linux_file_modes, f->format).c_str());
    if (get_file_info(drakvuf, info, lw, dentry_addr, "dentry"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t rmdir_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_rmdir(
        struct inode *dir,
        struct dentry *dentry
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    if (get_file_info(drakvuf, info, lw, dentry_addr, "dentry"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t chdir_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    void set_fs_pwd(
        struct fs_struct *fs,
        const struct path *path
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t path_struct = drakvuf_get_function_argument(drakvuf, info, 2);
    if (get_file_info(drakvuf, info, lw, path_struct, "path"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t chroot_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    void set_fs_root(
        struct fs_struct *fs,
        const struct path *path
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t path_struct = drakvuf_get_function_argument(drakvuf, info, 2);
    if (get_file_info(drakvuf, info, lw, path_struct, "path"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

/* ---------------LINK OPEARTIONS CALLBACK-------------- */

static event_response_t link_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_link(
        struct dentry *old_dentry,
        struct inode *dir,
        truct dentry *new_dentry,
        struct inode **delegated_inode
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    lw->args["link_name"] = get_filepath(drakvuf, info, vmi, dentry_addr);
    drakvuf_release_vmi(drakvuf);

    if (g_strcmp0(lw->args["link_name"]->str, "") == 0)
    {
        free_gstrings(lw);
        delete lw;
        return VMI_EVENT_RESPONSE_NONE;
    }

    dentry_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    if (get_file_info(drakvuf, info, lw, dentry_addr, "dentry"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t unlink_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_unlink(
        struct inode *dir,
        struct dentry *dentry,
        struct inode **delegated_inode
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    if (get_file_info(drakvuf, info, lw, dentry_addr, "dentry"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t symbolic_link_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int vfs_symlink(
        struct inode *dir,
        struct dentry *dentry,
        const char *oldname
    )
    */

    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    addr_t oldname_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    if (oldname_addr)
    {
        gchar* fn = read_filename(drakvuf, info, oldname_addr);
        lw->args["oldname"] = g_string_new(NULL);
        if (fn != NULL)
        {
            g_string_printf(lw->args["oldname"], "%s", fn);
        }
        g_free(fn);
    }
    if (get_file_info(drakvuf, info, lw, dentry_addr, "dentry"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}

/*
static event_response_t read_link_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    // int vfs_readlink(
    //     struct dentry *dentry,
    //     char __user *buffer,
    //     int buflen
    // )


    PRINT_DEBUG("Filetracer Callback : %s \n", info->trap->name);
    struct linux_wrapper* lw = new linux_wrapper;
    if (!lw)
        return VMI_EVENT_RESPONSE_NONE;
    addr_t dentry_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    uint64_t buflen = drakvuf_get_function_argument(drakvuf, info, 3);
    lw->args["buflen"] = g_string_new(NULL);
    g_string_printf(lw->args["buflen"], "%ld", buflen);
    if (get_file_info(drakvuf, info, lw, dentry_addr, "dentry"))
        print_info(drakvuf, info, lw);
    free_gstrings(lw);
    delete lw;
    return VMI_EVENT_RESPONSE_NONE;
}
*/

/* ----------------------------------------------------- */

static void register_trap(drakvuf_t drakvuf, const char* syscall_name,
    drakvuf_trap_t* trap,
    event_response_t (*hook_cb)(drakvuf_t drakvuf, drakvuf_trap_info_t* info))
{
    addr_t syscall_addr;
    if (!drakvuf_get_kernel_symbol_rva(drakvuf, syscall_name, &syscall_addr))
        throw - 1;

    trap->breakpoint.addr += syscall_addr;
    trap->name = syscall_name;
    trap->cb = hook_cb;
    trap->ttl = drakvuf_get_limited_traps_ttl(drakvuf);
    trap->ah_cb = nullptr;

    if (!drakvuf_add_trap(drakvuf, trap))
        throw - 1;
}

linux_filetracer::linux_filetracer(drakvuf_t drakvuf, output_format_t output)
    : format{output}, traps_to_free(NULL)
{
    this->offsets = new size_t[__LINUX_OFFSET_MAX];

    addr_t _text;
    if (!drakvuf_get_kernel_symbol_rva(drakvuf, "_text", &_text))
        throw - 1;

    addr_t kernel_base = drakvuf_get_kernel_base(drakvuf);
    this->kaslr = kernel_base - _text;

    for (int i = 0; i < 22; i++)
        this->trap[i].breakpoint.addr = this->kaslr;

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_offset_names, __LINUX_OFFSET_MAX, this->offsets))
        throw - 1;

    assert(sizeof(trap) / sizeof(trap[0]) > 21);

    // File operations
    register_trap(drakvuf, "do_filp_open", &trap[0], open_file_cb);
    register_trap(drakvuf, "vfs_read", &trap[1], read_file_cb);
    register_trap(drakvuf, "vfs_write", &trap[2], write_file_cb);
    register_trap(drakvuf, "filp_close", &trap[3], close_file_cb);
    register_trap(drakvuf, "vfs_llseek", &trap[4], llseek_file_cb);
    // register_trap(drakvuf, "__x64_sys_memfd_create", &trap[5], memfd_create_file_cb);
    register_trap(drakvuf, "vfs_mknod", &trap[6], mknod_file_cb);
    register_trap(drakvuf, "vfs_rename", &trap[7], rename_file_cb);
    register_trap(drakvuf, "do_truncate", &trap[8], truncate_file_cb);
    register_trap(drakvuf, "vfs_fallocate", &trap[9], allocate_file_cb);

    // File Attributes
    register_trap(drakvuf, "chmod_common", &trap[10], chmod_file_cb);
    register_trap(drakvuf, "chown_common", &trap[11], chown_file_cb);
    // register_trap(drakvuf, "utimes_common.isra.0", &trap[12], utimes_file_cb);
    // register_trap(drakvuf, "do_faccessat", &trap[13], access_file_cb);

    // Directory Operations
    register_trap(drakvuf, "vfs_mkdir", &trap[14], mkdir_cb);
    register_trap(drakvuf, "vfs_rmdir", &trap[15], rmdir_cb);
    register_trap(drakvuf, "set_fs_pwd", &trap[16], chdir_cb);
    register_trap(drakvuf, "set_fs_root", &trap[17], chroot_cb);

    // Link Operations
    register_trap(drakvuf, "vfs_link", &trap[18], link_file_cb);
    register_trap(drakvuf, "vfs_unlink", &trap[19], unlink_file_cb);
    register_trap(drakvuf, "vfs_symlink", &trap[20], symbolic_link_file_cb);
    // register_trap(drakvuf, "vfs_readlink", &trap[21], read_link_cb);
}

linux_filetracer::~linux_filetracer()
{
    if (traps_to_free)
    {
        GSList* loop = traps_to_free;
        while (loop)
        {
            drakvuf_trap_t* t = (drakvuf_trap_t*)loop->data;
            struct linux_wrapper* lw = (struct linux_wrapper*)t->data;

            free_gstrings(lw);
            delete lw;
            g_free(loop->data);

            loop = loop->next;
        }
        g_slist_free(traps_to_free);
    }

    delete[] offsets;
}
