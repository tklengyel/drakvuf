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

#include <libfs/base.hpp>

namespace libfs
{

bool BaseFilesystem::detect_filesystem_start_gpt()
{
    auto gpt = get_struct_from_disk<gpt_t>(LBA_SIZE);
    auto partitions = get_array_of_structs_from_disk<gpt_partition_t>(LBA_SIZE * gpt->partition_start_lba, gpt->number_of_partitions);

    for (const auto& partition : partitions)
    {
        if (partition.first_lba == 0 || partition.last_lba == 0)
            continue;

        /* Detect linux data partition */
        if (!std::memcmp(partition.type_guid, GPT_GUID_LINUX_FILESYSTEM_DATA, 16))
        {
            filesystem_start = partition.first_lba * SECTOR_SIZE;
            return true;
        }
    }

    return false;
}

/*
 * find real offset to filesystem with detecting MBR or GPT layout
 * NOTE: currently support only Linux
 */
bool BaseFilesystem::detect_filesystem_start()
{
    if (drakvuf_get_os_type(drakvuf_) != VMI_OS_LINUX)
        return false;

    auto mbr = get_struct_from_disk<mbr_t>(ZERO_OFFSET);

    if (mbr->boot_signature != MBR_BOOT_SIGNATURE)
    {
        PRINT_ERROR("[FILEEXTRACTOR] MBR not found\n");
        throw -1;
    }

    for (int i = 0; i < 4; i++)
    {
        if (mbr->partition_table[i].type == MBR_TYPE_UNUSED)
            continue;

        /* special case for parsing gpt */
        if (mbr->partition_table[i].type == MBR_TYPE_EFI_GPT)
        {
            PRINT_DEBUG("[FILEEXTRACTOR] Detecting GPT disk layout\n");
            return detect_filesystem_start_gpt();
        }

        /* Currently support only linux */
        if (mbr->partition_table[i].type == MBR_TYPE_LINUX)
        {
            PRINT_DEBUG("[FILEEXTRACTOR] Detecting MBR disk layout\n");
            filesystem_start = mbr->partition_table[i].starting_lba * SECTOR_SIZE;
            return true;
        }
    }

    return false;
}

void BaseFilesystem::init_disk()
{
    auto vmi = vmi_lock_guard(drakvuf_);

    uint32_t number_of_disks;
    char** devices_ids = vmi_get_disks(vmi, &number_of_disks);
    if (!devices_ids)
    {
        PRINT_ERROR("[ext4] failed to get list of disks\n");
        throw -1;
    }

    /* by default use first device_id */
    device_id = std::string(devices_ids[0]);
    for (uint32_t i = 0; i < number_of_disks; i++)
        free(devices_ids[i]);
    free(devices_ids);
}

BaseFilesystem::BaseFilesystem(drakvuf_t drakvuf)
    : drakvuf_(drakvuf)
{
    init_disk();

    if (!detect_filesystem_start())
    {
        PRINT_ERROR("[FILEEXTRACTOR] can't find filesystem start offset\n");
        throw -1;
    }
};

BaseFilesystem::BaseFilesystem(BaseFilesystem&& rhs) noexcept
{
    std::swap(this->drakvuf_, rhs.drakvuf_);
}

BaseFilesystem& BaseFilesystem::operator=(BaseFilesystem&& rhs) noexcept
{
    std::swap(this->drakvuf_, rhs.drakvuf_);
    return *this;
}

BaseFilesystem::~BaseFilesystem()
{}

}; // namespace libfs