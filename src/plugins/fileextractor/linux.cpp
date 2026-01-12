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
 ***************************************************************************/

#include <inttypes.h>
#include <sys/stat.h>
#include <algorithm>
#include <cstring>
#include <fstream>

#include <libvmi/libvmi.h>
#include <libdrakvuf/libdrakvuf.h>

#include "linux.h"
#include "plugins/output_format.h"

/* x86_64 syscall numbers */
#define __NR_write      1
#define __NR_pwrite64   18
#define __NR_writev     20
#define __NR_pwritev    296
#define __NR_pwritev2   328

/* Offset names for drakvuf_get_kernel_struct_members_array_rva */
static const char* linux_offset_names[][2] =
{
    {"task_struct", "files"},
    {"files_struct", "fdt"},
    {"fdtable", "fd"},
    {"file", "f_path"},
    {"path", "dentry"},
};

static const char* pt_regs_offset_names[][2] =
{
    {"pt_regs", "r15"},
    {"pt_regs", "r14"},
    {"pt_regs", "r13"},
    {"pt_regs", "r12"},
    {"pt_regs", "bp"},
    {"pt_regs", "bx"},
    {"pt_regs", "r11"},
    {"pt_regs", "r10"},
    {"pt_regs", "r9"},
    {"pt_regs", "r8"},
    {"pt_regs", "ax"},
    {"pt_regs", "cx"},
    {"pt_regs", "dx"},
    {"pt_regs", "si"},
    {"pt_regs", "di"},
    {"pt_regs", "orig_ax"},
    {"pt_regs", "ip"},
    {"pt_regs", "cs"},
    {"pt_regs", "flags"},
    {"pt_regs", "sp"},
    {"pt_regs", "ss"},
};

static inline bool is_write_syscall(uint64_t nr)
{
    return nr == __NR_write || nr == __NR_pwrite64;
}

linux_fileextractor::linux_fileextractor(drakvuf_t drakvuf, const fileextractor_config* config, output_format_t output)
    : pluginex(drakvuf, output)
    , dump_folder(config->dump_folder)
    , extract_size(config->extract_size)
{
    PRINT_DEBUG("[FILEEXTRACTOR-LINUX] Initializing Linux fileextractor\n");
    PRINT_DEBUG("[FILEEXTRACTOR-LINUX] Dump folder: %s\n", dump_folder ? dump_folder : "(null)");
    PRINT_DEBUG("[FILEEXTRACTOR-LINUX] Extract size limit: %" PRIu64 "\n", extract_size);

    if (!dump_folder)
    {
        PRINT_DEBUG("[FILEEXTRACTOR-LINUX] No dump folder specified, extraction disabled\n");
        throw -1;
    }

    /* Create dump folder if it doesn't exist */
    mkdir(dump_folder, 0755);

    /* Get pt_regs offsets */
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, pt_regs_offset_names, this->regs.size(), this->regs.data()))
    {
        PRINT_DEBUG("[FILEEXTRACTOR-LINUX] Failed to get pt_regs offsets\n");
        throw -1;
    }

    /* Get Linux struct offsets for fd resolution */
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_offset_names, this->offsets.size(), this->offsets.data()))
    {
        PRINT_DEBUG("[FILEEXTRACTOR-LINUX] Warning: Failed to get some Linux offsets, fd resolution may not work\n");
    }

    /* Register x64_sys_call hook */
    syscall_hook = createSyscallHook("x64_sys_call", &linux_fileextractor::syscall_cb, "x64_sys_call");
    if (!syscall_hook)
    {
        PRINT_DEBUG("[FILEEXTRACTOR-LINUX] Failed to hook x64_sys_call\n");
        throw -1;
    }

    PRINT_DEBUG("[FILEEXTRACTOR-LINUX] Successfully initialized with x64_sys_call hook\n");
}

bool linux_fileextractor::stop_impl()
{
    PRINT_DEBUG("[FILEEXTRACTOR-LINUX] Stopping, extracted %d files\n", sequence_number);
    return true;
}

bool linux_fileextractor::get_pt_regs_and_nr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* pt_regs_addr, uint64_t* nr)
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

        /* Fallback: read orig_rax from pt_regs */
        auto vmi = vmi_lock_guard(drakvuf);
        return VMI_SUCCESS == vmi_read_addr_va(vmi, *pt_regs_addr + this->regs[PT_REGS_ORIG_RAX], 0, nr);
    }

    /* Alternate style: do_syscall_64(unsigned long nr, struct pt_regs *regs) */
    *nr = info->regs->rdi;
    *pt_regs_addr = info->regs->rsi;
    return true;
}

bool linux_fileextractor::read_pt_regs_arg(drakvuf_t drakvuf, addr_t pt_regs_addr, int arg_index, uint64_t* value)
{
    /* x64 syscall args in pt_regs: rdi, rsi, rdx, r10, r8, r9 */
    static const int arg_offsets[] = {
        PT_REGS_RDI, PT_REGS_RSI, PT_REGS_RDX, PT_REGS_R10, PT_REGS_R8, PT_REGS_R9
    };

    if (arg_index < 0 || arg_index >= 6)
        return false;

    auto vmi = vmi_lock_guard(drakvuf);
    return VMI_SUCCESS == vmi_read_addr_va(vmi, pt_regs_addr + this->regs[arg_offsets[arg_index]], 0, value);
}

std::string linux_fileextractor::get_filename_from_fd(drakvuf_t drakvuf, drakvuf_trap_info_t* info, int fd)
{
    if (fd < 0)
        return "";

    auto vmi = vmi_lock_guard(drakvuf);

    /* Get current task_struct */
    addr_t task = drakvuf_get_current_process(drakvuf, info);
    if (!task)
        return "";

    /* task->files */
    addr_t files_struct;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, task + this->offsets[LINUX_TASK_STRUCT_FILES], 0, &files_struct) || !files_struct)
        return "";

    /* files->fdt */
    addr_t fdtable;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, files_struct + this->offsets[LINUX_FILES_STRUCT_FDT], 0, &fdtable) || !fdtable)
        return "";

    /* fdt->fd (array of struct file*) */
    addr_t fd_array;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, fdtable + this->offsets[LINUX_FDTABLE_FD], 0, &fd_array) || !fd_array)
        return "";

    /* fd_array[fd] -> struct file* */
    addr_t file_struct;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, fd_array + fd * sizeof(addr_t), 0, &file_struct) || !file_struct)
        return "";

    /* file->f_path.dentry */
    addr_t dentry;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, file_struct + this->offsets[LINUX_FILE_F_PATH] + this->offsets[LINUX_PATH_DENTRY], 0, &dentry) || !dentry)
        return "";

    /* Use drakvuf helper to get full path from dentry */
    char* path = drakvuf_get_filepath_from_dentry(drakvuf, dentry);
    if (!path)
        return "";

    std::string result(path);
    g_free(path);
    return result;
}

bool linux_fileextractor::read_user_buffer(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t user_addr, size_t size, std::vector<uint8_t>& buffer)
{
    if (size == 0 || size > 64 * 1024 * 1024)  /* Limit to 64MB per read */
        return false;

    buffer.resize(size);

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = user_addr
    );

    size_t bytes_read = 0;
    if (VMI_FAILURE == vmi_read(vmi, &ctx, size, buffer.data(), &bytes_read))
    {
        buffer.clear();
        return false;
    }

    if (bytes_read < size)
        buffer.resize(bytes_read);

    return bytes_read > 0;
}

std::string linux_fileextractor::sanitize_filename(const std::string& filename)
{
    std::string result;
    result.reserve(filename.size());

    for (char c : filename)
    {
        if (c == '/' || c == '\\')
            result += '_';
        else if (c >= 32 && c < 127)
            result += c;
        else
            result += '_';
    }

    /* Limit length */
    if (result.size() > 200)
        result = result.substr(result.size() - 200);

    return result;
}

std::string linux_fileextractor::make_dump_filename(const std::string& original_name, int seq_num)
{
    char buf[512];
    std::string sanitized = sanitize_filename(original_name);
    snprintf(buf, sizeof(buf), "%s/%08d_%s", dump_folder, seq_num, sanitized.c_str());
    return std::string(buf);
}

bool linux_fileextractor::save_file_chunk(const std::string& dump_path, const std::vector<uint8_t>& data, bool append)
{
    std::ios_base::openmode mode = std::ios::binary;
    if (append)
        mode |= std::ios::app;
    else
        mode |= std::ios::trunc;

    std::ofstream file(dump_path, mode);
    if (!file.is_open())
        return false;

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

void linux_fileextractor::print_extraction_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
                                                 const std::string& filename, uint64_t size,
                                                 const std::string& dump_path, const char* reason)
{
    addr_t current_process = drakvuf_get_current_process(drakvuf, info);
    const char* process_name = drakvuf_get_process_name(drakvuf, current_process, false);

    fmt::print(this->m_output_format, "fileextractor", drakvuf, info,
        keyval("Reason", fmt::Qstr(reason)),
        keyval("FileName", fmt::Estr(filename)),
        keyval("Size", fmt::Nval(size)),
        keyval("DumpFile", fmt::Estr(dump_path)),
        keyval("ProcessName", fmt::Rstr(process_name ? process_name : ""))
    );

    if (process_name)
        g_free(const_cast<char*>(process_name));
}

event_response_t linux_fileextractor::syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t pt_regs_addr = 0;
    uint64_t nr = 0;

    if (!get_pt_regs_and_nr(drakvuf, info, &pt_regs_addr, &nr))
        return VMI_EVENT_RESPONSE_NONE;

    /* Only handle write syscalls */
    if (!is_write_syscall(nr))
        return VMI_EVENT_RESPONSE_NONE;

    /* Read syscall arguments from pt_regs */
    uint64_t fd_val = 0, buf_addr = 0, count = 0, offset = 0;
    read_pt_regs_arg(drakvuf, pt_regs_addr, 0, &fd_val);  /* fd */
    read_pt_regs_arg(drakvuf, pt_regs_addr, 1, &buf_addr); /* buf */
    read_pt_regs_arg(drakvuf, pt_regs_addr, 2, &count);    /* count */

    if (nr == __NR_pwrite64)
        read_pt_regs_arg(drakvuf, pt_regs_addr, 3, &offset); /* offset for pwrite64 */

    int fd = (int)fd_val;

    /* Skip stdin/stdout/stderr and invalid fds */
    if (fd < 3)
        return VMI_EVENT_RESPONSE_NONE;

    /* Skip very small writes (noise) and very large writes */
    if (count < 1 || count > 16 * 1024 * 1024)
        return VMI_EVENT_RESPONSE_NONE;

    /* Apply extract_size limit if set */
    if (extract_size > 0 && count > extract_size)
        count = extract_size;

    /* Get process info */
    vmi_pid_t pid = info->attached_proc_data.pid;
    auto file_key = std::make_pair(static_cast<uint64_t>(pid), fd);

    /* Get or create file tracking info */
    auto it = tracked_files.find(file_key);
    if (it == tracked_files.end())
    {
        /* New file - resolve filename and create tracking entry */
        std::string filename = get_filename_from_fd(drakvuf, info, fd);
        if (filename.empty())
            filename = "unknown_fd_" + std::to_string(fd);

        /* Skip certain paths that generate too much noise */
        if (filename.find("/dev/") == 0 ||
            filename.find("/proc/") == 0 ||
            filename.find("/sys/") == 0 ||
            filename.find("socket:") == 0 ||
            filename.find("pipe:") == 0 ||
            filename.find("anon_inode:") == 0)
        {
            return VMI_EVENT_RESPONSE_NONE;
        }

        file_info_t file_info;
        file_info.filename = filename;
        file_info.sequence_num = sequence_number++;
        file_info.dump_path = make_dump_filename(filename, file_info.sequence_num);
        file_info.total_bytes = 0;
        file_info.is_new = true;

        it = tracked_files.emplace(file_key, std::move(file_info)).first;

        PRINT_DEBUG("[FILEEXTRACTOR-LINUX] New file: %s (seq=%d, pid=%d, fd=%d)\n",
                    it->second.filename.c_str(), it->second.sequence_num, pid, fd);
    }

    file_info_t& file_info = it->second;

    /* Read buffer from guest memory */
    std::vector<uint8_t> buffer;
    if (!read_user_buffer(drakvuf, info, buf_addr, count, buffer))
    {
        PRINT_DEBUG("[FILEEXTRACTOR-LINUX] Failed to read buffer from guest\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    /* Save to file */
    bool append = !file_info.is_new;
    if (save_file_chunk(file_info.dump_path, buffer, append))
    {
        file_info.total_bytes += buffer.size();
        file_info.is_new = false;

        /* Print extraction info for first write or periodically */
        if (file_info.total_bytes == buffer.size())
        {
            print_extraction_info(drakvuf, info, file_info.filename, buffer.size(),
                                  file_info.dump_path, "WriteFile");
        }
    }
    else
    {
        PRINT_DEBUG("[FILEEXTRACTOR-LINUX] Failed to save chunk to %s\n", file_info.dump_path.c_str());
    }

    return VMI_EVENT_RESPONSE_NONE;
}
