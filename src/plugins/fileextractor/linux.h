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

#ifndef FILEEXTRACTOR_LINUX_H
#define FILEEXTRACTOR_LINUX_H

#include "plugins/plugins_ex.h"
#include "private.h"

#include <map>
#include <unordered_map>
#include <string>
#include <vector>
#include <fstream>

class linux_fileextractor : public pluginex
{
public:
    linux_fileextractor(drakvuf_t drakvuf, const fileextractor_config* config, output_format_t output);
    linux_fileextractor(const linux_fileextractor&) = delete;
    linux_fileextractor& operator=(const linux_fileextractor&) = delete;
    ~linux_fileextractor() = default;

    virtual bool stop_impl() override;

private:
    /* Configuration */
    const char* dump_folder;
    uint64_t extract_size;

    /* Sequence number for unique file naming */
    int sequence_number{0};

    /* pt_regs offsets for reading syscall arguments */
    enum
    {
        PT_REGS_R15,
        PT_REGS_R14,
        PT_REGS_R13,
        PT_REGS_R12,
        PT_REGS_RBP,
        PT_REGS_RBX,
        PT_REGS_R11,
        PT_REGS_R10,
        PT_REGS_R9,
        PT_REGS_R8,
        PT_REGS_RAX,
        PT_REGS_RCX,
        PT_REGS_RDX,
        PT_REGS_RSI,
        PT_REGS_RDI,
        PT_REGS_ORIG_RAX,
        PT_REGS_RIP,
        PT_REGS_CS,
        PT_REGS_EFLAGS,
        PT_REGS_RSP,
        PT_REGS_SS,
        __PT_REGS_MAX
    };

    std::array<size_t, __PT_REGS_MAX> regs;

    /* Linux struct offsets for fd-to-filename resolution */
    enum
    {
        LINUX_TASK_STRUCT_FILES,
        LINUX_FILES_STRUCT_FDT,
        LINUX_FDTABLE_FD,
        LINUX_FILE_F_PATH,
        LINUX_PATH_DENTRY,
        __LINUX_OFFSET_MAX
    };

    std::array<size_t, __LINUX_OFFSET_MAX> offsets;

    /* Track files being written: key = (pid, fd), value = file info */
    struct file_info_t
    {
        std::string filename;
        std::string dump_path;
        uint64_t total_bytes{0};
        int sequence_num{0};
        bool is_new{true};
    };

    std::map<std::pair<uint64_t, int>, file_info_t> tracked_files;

    /* Hooks */
    std::unique_ptr<libhook::SyscallHook> syscall_hook;

    /* Callbacks */
    event_response_t syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    /* Syscall argument extraction */
    bool get_pt_regs_and_nr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* pt_regs_addr, uint64_t* nr);
    bool read_pt_regs_arg(drakvuf_t drakvuf, addr_t pt_regs_addr, int arg_index, uint64_t* value);

    /* File operations */
    std::string get_filename_from_fd(drakvuf_t drakvuf, drakvuf_trap_info_t* info, int fd);
    bool read_user_buffer(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t user_addr, size_t size, std::vector<uint8_t>& buffer);
    std::string sanitize_filename(const std::string& filename);
    std::string make_dump_filename(const std::string& original_name, int seq_num);
    bool save_file_chunk(const std::string& dump_path, const std::vector<uint8_t>& data, bool append);

    /* Output */
    void print_extraction_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
                               const std::string& filename, uint64_t size,
                               const std::string& dump_path, const char* reason);
};

#endif // FILEEXTRACTOR_LINUX_H
