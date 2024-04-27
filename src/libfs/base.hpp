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

#pragma once

#include <plugins/helpers/vmi_lock_guard.h>

#include <cstring>
#include <cstdlib>
#include <vector>
#include <memory>
#include <functional>
#include <string>

namespace libfs
{

#define ZERO_OFFSET 0
#define SECTOR_SIZE 512
#define LBA_SIZE SECTOR_SIZE

/* MBR related */
#define MBR_TYPE_UNUSED           0x00
#define MBR_TYPE_EXTENDED_DOS     0x05
#define MBR_TYPE_NTFS             0x07
#define MBR_TYPE_EXTENDED_WINDOWS 0x0F
#define MBR_TYPE_LINUX_SWAP       0x82
#define MBR_TYPE_LINUX            0x83
#define MBR_TYPE_EFI_GPT          0xEE

#define MBR_BOOT_SIGNATURE        0xAA55

// 0FC63DAF-8483-4772-8E79-3D69D8477DE4
const uint8_t GPT_GUID_LINUX_FILESYSTEM_DATA[16] = {0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4};

#pragma pack(push, 1)
typedef struct
{
    uint8_t   status;
    struct
    {
        uint8_t h;
        uint16_t cs;
    } start_chs;
    uint8_t type;
    struct
    {
        uint8_t h;
        uint16_t cs;
    } end_chs;
    uint32_t starting_lba;
    uint32_t number_of_sectors;
} mbr_partition_t;

typedef struct
{
    uint8_t         bootstrap_code[440];
    uint32_t        disk_signature;
    uint16_t        copy_protected;
    mbr_partition_t partition_table[4];
    uint16_t        boot_signature;
} mbr_t;
#pragma pack(pop)

/* GPT related */
#pragma pack(push, 1)
typedef struct
{
    char     signature[8];
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32_header;
    uint32_t reserved;
    uint64_t current_lba;
    uint64_t backup_lba;
    uint64_t first_use_lba_for_partitions;
    uint64_t last_use_lba_for_partitions;
    uint8_t  disk_guid[16];
    uint64_t partition_start_lba;
    uint32_t number_of_partitions;
    uint32_t size_of_partition;
    uint32_t crc32_of_partitions_array;
    uint8_t  zeroes[420];
} gpt_t;

typedef struct
{
    uint8_t  type_guid[16];
    uint8_t  unique_guid[16];
    uint64_t first_lba;
    uint64_t last_lba;
    uint64_t attributes;
    uint8_t  partition_name[72];
} gpt_partition_t;
#pragma pack(pop)

// file information taken from inode
struct file_info
{
    uint64_t inode_number;
    uint32_t uid;
    uint32_t gid;
    uint64_t filesize;
    uint32_t access_time;
    uint32_t modify_time;
    uint32_t change_time;
    uint16_t mode;

    file_info(
        uint64_t inode_number,
        uint32_t uid,
        uint32_t gid,
        uint64_t filesize,
        uint32_t access_time,
        uint32_t modify_time,
        uint32_t change_time,
        uint16_t mode
    ) : inode_number(inode_number),
        uid(uid),
        gid(gid),
        filesize(filesize),
        access_time(access_time),
        modify_time(modify_time),
        change_time(change_time),
        mode(mode)
    {}
};

class BaseFilesystem
{
public:
    virtual ~BaseFilesystem() = 0;

    BaseFilesystem(const BaseFilesystem&) = delete;

    BaseFilesystem(BaseFilesystem&&) noexcept;

    BaseFilesystem& operator=(const BaseFilesystem&) = delete;

    BaseFilesystem& operator=(BaseFilesystem&&) noexcept;

protected:
    explicit BaseFilesystem(drakvuf_t);

    drakvuf_t drakvuf_ = nullptr;

    uint64_t filesystem_start = 0;

    /* working disk */
    std::string device_id;

    /* disk initialization */
    void init_disk();

    /*
     * Read raw data in buffer
     *
     * @param offset absolute offset on disk
     * @param count amount of bytes
     * @param buffer destination
     * @return status
     */
    status_t get_raw_from_disk(size_t offset, size_t count, void* buffer)
    {
        auto vmi = vmi_lock_guard(drakvuf_);
        return vmi_read_disk(vmi, device_id.c_str(), offset, count, buffer);
    }

    /*
     * Read raw data in buffer
     *
     * @param offset absolute offset on disk
     * @param count amount of bytes
     * @param buffer destination
     * @return status
     */
    status_t get_raw_from_fs(size_t offset, size_t count, void* buffer)
    {
        return get_raw_from_disk(filesystem_start + offset, count, buffer);
    }

    /*
     * Returns the specified structure at the specified offset
     *
     * @param offset absolute offset on disk
     * @return specifed structure
     */
    template <typename T>
    std::unique_ptr<T> get_struct_from_disk(size_t offset)
    {
        std::vector<uint8_t> buffer(sizeof(T));

        if (VMI_FAILURE == get_raw_from_disk(offset, sizeof(T), buffer.data()))
        {
            PRINT_ERROR("[FILEEXTRACTOR] failed to read struct from disk\n");
            throw -1;
        }

        return std::make_unique<T>(*reinterpret_cast<T*>(buffer.data()));
    }

    /*
     * Returns the specified structure with an offset within the file system
     *
     * @param offset relative to the beginning of the file system
     * @return specifed structure
     */
    template <typename T>
    std::unique_ptr<T> get_struct_from_fs(size_t offset)
    {
        return get_struct_from_disk<T>(filesystem_start + offset);
    }

    /*
     * Returns the vector of specified structures
     *
     * @param offset absolute offset on disk
     * @param count of structures
     * @return vector of structures
     */
    template <typename T>
    std::vector<T> get_array_of_structs_from_disk(size_t offset, size_t count)
    {
        std::vector<T> buffer(count);
        if (VMI_FAILURE == get_raw_from_disk(offset, sizeof(T) * count, buffer.data()))
        {
            throw -1;
        }
        return buffer;
    }

    /*
     * Returns the vector of specified structures
     *
     * @param offset relative to the beginning of the file system
     * @param count of structures
     * @return vector of structures
     */
    template <typename T>
    std::vector<T> get_array_of_structs_from_fs(size_t offset, size_t count)
    {
        return get_array_of_structs_from_disk<T>(filesystem_start + offset, count);
    }

private:
    bool detect_filesystem_start();
    bool detect_filesystem_start_gpt();
};

} // end namespace