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

    /* pt_regs offsets for reading syscall arguments
     * Prefixed with FE_ to avoid conflict with filetracer_ns definitions */
    enum
    {
        FE_PT_REGS_R15,
        FE_PT_REGS_R14,
        FE_PT_REGS_R13,
        FE_PT_REGS_R12,
        FE_PT_REGS_RBP,
        FE_PT_REGS_RBX,
        FE_PT_REGS_R11,
        FE_PT_REGS_R10,
        FE_PT_REGS_R9,
        FE_PT_REGS_R8,
        FE_PT_REGS_RAX,
        FE_PT_REGS_RCX,
        FE_PT_REGS_RDX,
        FE_PT_REGS_RSI,
        FE_PT_REGS_RDI,
        FE_PT_REGS_ORIG_RAX,
        FE_PT_REGS_RIP,
        FE_PT_REGS_CS,
        FE_PT_REGS_EFLAGS,
        FE_PT_REGS_RSP,
        FE_PT_REGS_SS,
        __FE_PT_REGS_MAX
    };

    std::array<size_t, __FE_PT_REGS_MAX> regs;

    /* Linux struct offsets for fd-to-filename resolution */
    enum
    {
        FE_LINUX_TASK_STRUCT_FILES,
        FE_LINUX_FILES_STRUCT_FDT,
        FE_LINUX_FDTABLE_FD,
        FE_LINUX_FILE_F_PATH,
        FE_LINUX_PATH_DENTRY,
        __FE_LINUX_OFFSET_MAX
    };

    std::array<size_t, __FE_LINUX_OFFSET_MAX> offsets;

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
