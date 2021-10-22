/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
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

#include "method_helpers.h"
#include "win_functions.h"

bool setup_create_file(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = (injector_t)info->trap->data;
    uint8_t buf[FILE_BUF_SIZE] = {0};
    unicode_string_t in;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = injector->payload_addr,
    );

    PRINT_DEBUG("Reading expanded variable\n");
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, info->regs->rax * 2, buf, NULL))
    {
        drakvuf_release_vmi(drakvuf);
        PRINT_DEBUG("Failed to read buffer at %lx\n", info->regs->rax * 2);
        return false;
    }
    drakvuf_release_vmi(drakvuf);
    in.contents = buf;
    in.length = info->regs->rax * 2;
    in.encoding = "UTF-16";

    PRINT_DEBUG("Converting target to UTF-8\n");
    injector->expanded_target = (unicode_string_t*)g_try_malloc0(sizeof(unicode_string_t));
    if (VMI_SUCCESS != vmi_convert_str_encoding(&in, injector->expanded_target, "UTF-8"))
    {
        PRINT_DEBUG("Failed to convert buffer\n");
        return false;
    }

    PRINT_DEBUG("Expanded: %s\n", injector->expanded_target->contents);
    PRINT_DEBUG("Opening file...\n");

    if (!setup_create_file_stack(injector, info->regs))
    {
        PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
        return false;
    }
    return true;
}

bool is_fun_error(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const char* err)
{
    if (info->regs->rax == (~0ULL) || !info->regs->rax)
    {
        injector_t injector = (injector_t)info->trap->data;
        fprintf(stderr, "%s\n", err);
        injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
        injector->error_code.valid = true;
        drakvuf_get_last_error(drakvuf, info, &injector->error_code.code, &injector->error_code.string);
        return true;
    }
    return false;
}

bool open_host_file(injector_t injector, const char* mode)
{
    injector->host_file = fopen(injector->binary_path, mode);

    if (!injector->host_file)
    {
        PRINT_DEBUG("Failed to open host file\n");
        injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
        injector->error_code.code = errno;
        injector->error_code.string = "HOST_FAILED_FOPEN";
        injector->error_code.valid = true;

        return false;
    }
    return true;
}
