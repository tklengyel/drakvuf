/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be aquired from the author.          *
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

#include "writevirtualmemmon.h"

static vmi_pid_t get_pid_from_handle(drakvuf_t drakvuf, uint64_t handle, drakvuf_trap_info_t* info){
    if (handle == 0 || handle == UINT64_MAX)
        return info->proc_data.pid;

    if (!info->proc_data.base_addr)
        return 0;

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, info->proc_data.base_addr, handle);
    if(!obj)
        return 0;
    
    vmi_pid_t pid;
    addr_t object_header_body = 0;
    if (!drakvuf_get_struct_member_rva(drakvuf, "_OBJECT_HEADER", "Body", &object_header_body))
        return 0;

    addr_t eprocess_base = obj + object_header_body;
    if (VMI_FAILURE == drakvuf_get_process_pid(drakvuf, eprocess_base, &pid))
        return 0;

    return pid;
}

static char* get_process_name_by_id(drakvuf_t drakvuf, vmi_pid_t pid)
{
    addr_t process_addr = 0;
    if (drakvuf_find_process(drakvuf, pid, nullptr, &process_addr))
        return drakvuf_get_process_name(drakvuf, process_addr, true);

    return "<UNKNOWN>";
}

static void extract_memory_allocation(drakvuf_t drakvuf, const drakvuf_trap_info_t* info,
 addr_t buffer, addr_t buffer_size, vmi_instance_t vmi, writevirtualmemmon* wvm)
{
    addr_t process_handle_val = 0;
    addr_t base_address_val = 0;
    addr_t buffer_val = buffer;
    addr_t buffer_size_val = buffer_size;

    if(buffer_val != 0 && buffer_size_val != 0){
        void* content = g_malloc(buffer_size_val);
        access_context_t ctx;
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = buffer_val;
        if ( VMI_FAILURE != vmi_read(vmi, &ctx, buffer_size_val, content, NULL )){
            char* filename = NULL;
            if(asprintf(&filename, "%s/" FORMAT_TIMEVAL "_%lu_write.bin", wvm->dump_folder, UNPACK_TIMEVAL(info->timestamp), buffer_val) >= 0){
                FILE* file = fopen(filename, "wb");
                fwrite(content, 1, buffer_size_val, file);
                fclose(file);
            }
        }
        g_free(content);
    }
}

static event_response_t trap_NtWriteVirtualMemory_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    writevirtualmemmon* wvm = (writevirtualmemmon*)info->trap->data;
    addr_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t base_address = drakvuf_get_function_argument(drakvuf, info, 2);
    addr_t buffer = drakvuf_get_function_argument(drakvuf, info, 3);
    addr_t buffer_size = drakvuf_get_function_argument(drakvuf, info, 4);
    addr_t nb_bytes_written = drakvuf_get_function_argument(drakvuf, info, 5);
                 
    if(wvm->dump_folder)
    {
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        extract_memory_allocation(drakvuf, info, buffer, buffer_size, vmi, wvm);
        drakvuf_release_vmi(drakvuf);
    }

    vmi_pid_t target_pid = get_pid_from_handle(drakvuf, process_handle, info);
    printf("FROM : [%d] %s TO : [%d] %s\n", info->proc_data.pid, drakvuf_escape_str(info->proc_data.name), target_pid, get_process_name_by_id(drakvuf, target_pid));
    return 0;
}

static void register_trap( drakvuf_t drakvuf, const char* syscall_name,
                           drakvuf_trap_t* trap,
                           event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    if ( !drakvuf_get_function_rva( drakvuf, syscall_name, &trap->breakpoint.rva) ) throw -1;

    trap->name = syscall_name;
    trap->cb   = hook_cb;

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}

writevirtualmemmon::writevirtualmemmon(drakvuf_t drakvuf, writevirtualmemmon_config* config, output_format_t output) : format{output}
{
    this->dump_folder = config->dump_folder;
    register_trap(drakvuf, "NtWriteVirtualMemory", &trap, trap_NtWriteVirtualMemory_cb);
}

writevirtualmemmon::~writevirtualmemmon(){

}