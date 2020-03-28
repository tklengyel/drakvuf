/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2020 Tamas K Lengyel.                                  *
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

#ifndef OS_H
#define OS_H

typedef struct process_data_priv proc_data_priv_t;

typedef struct os_interface
{
    addr_t (*get_current_thread)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    addr_t (*get_current_process)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    bool (*get_last_error)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* err, const char** err_str);

    addr_t (*export_lib_address)
    (drakvuf_t drakvuf, addr_t process_addr, const char* lib);

    char* (*get_process_name)
    (drakvuf_t drakvuf, addr_t process_base, bool fullpath);

    char* (*get_process_commandline)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t eprocess_base);

    char* (*get_current_process_name)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info, bool fullpath);

    int64_t (*get_process_userid)
    (drakvuf_t drakvuf, addr_t process_base);

    bool (*get_process_dtb)
    (drakvuf_t drakvuf, addr_t process_base, addr_t* dtb);

    bool (*get_process_pid)
    (drakvuf_t drakvuf, addr_t process_base, vmi_pid_t* pid);

    bool (*get_process_tid)
    (drakvuf_t drakvuf, addr_t process_base, uint32_t* tid);

    int64_t (*get_current_process_userid)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    bool (*get_current_thread_id)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* thread_id);

    bool (*get_thread_previous_mode)
    (drakvuf_t drakvuf, addr_t kthread, privilege_mode_t* previous_mode);

    bool (*get_current_thread_previous_mode)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info, privilege_mode_t* previous_mode);

    bool (*is_process)
    (drakvuf_t drakvuf, addr_t dtb, addr_t process_addr);

    bool (*is_thread)
    (drakvuf_t drakvuf, addr_t dtb, addr_t thread_addr);

    bool (*get_module_list)
    (drakvuf_t drakvuf, addr_t process_base, addr_t* module_list);

    bool (*get_module_list_wow)
    (drakvuf_t drakvuf, access_context_t* ctx, addr_t wow_peb, addr_t* module_list);

    bool (*find_process)
    (drakvuf_t drakvuf, vmi_pid_t find_pid, const char* find_procname, addr_t* process_addr);

    bool (*inject_traps_modules)
    (drakvuf_t drakvuf, drakvuf_trap_t* trap, addr_t list_head, vmi_pid_t pid);

    bool (*get_module_base_addr)
    (drakvuf_t drakvuf, addr_t module_list_head, const char* module_name, addr_t* base_addr_out);

    bool (*get_module_base_addr_ctx)
    (drakvuf_t drakvuf, addr_t module_list_head, access_context_t* ctx, const char* module_name, addr_t* base_addr_out);

    addr_t (*exportksym_to_va)
    (drakvuf_t drakvuf, const vmi_pid_t pid, const char* proc_name, const char* mod_name, addr_t rva);

    addr_t (*exportsym_to_va)
    (drakvuf_t drakvuf, addr_t process_addr, const char* module, const char* sym);

    bool (*get_process_ppid)
    (drakvuf_t drakvuf, addr_t process_base, vmi_pid_t* ppid);

    bool (*get_process_data)
    (drakvuf_t drakvuf, addr_t process_base, proc_data_priv_t* proc_data);

    gchar* (*get_registry_keyhandle_path)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint64_t key_handle);

    char* (*get_filename_from_handle)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle);

    bool (*is_wow64)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    addr_t (*get_function_argument)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info, int narg);

    bool (*enumerate_processes)
    (drakvuf_t drakvuf, void (*visitor_func)(drakvuf_t drakvuf, addr_t process, void* visitor_ctx), void* visitor_ctx);

    bool (*enumerate_processes_with_module)
    (drakvuf_t drakvuf, const char* module_name, bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx), void* visitor_ctx);

    bool (*is_crashreporter)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t* pid);

    bool (*find_mmvad)
    (drakvuf_t drakvuf, addr_t eprocess, addr_t vaddr, mmvad_info_t* out_mmvad);

    bool (*get_pid_from_handle)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle, vmi_pid_t* pid);

    bool (*get_wow_context)
    (drakvuf_t drakvuf, addr_t ethread, addr_t* wow_ctx);

    bool (*get_user_stack32)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* stack_ptr, addr_t* frame_ptr);

    bool (*get_user_stack64)
    (drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* stack_ptr);

    addr_t (*get_wow_peb)
    (drakvuf_t drakvuf, access_context_t* ctx, addr_t eprocess);

} os_interface_t;

bool set_os_windows(drakvuf_t drakvuf);
bool set_os_linux(drakvuf_t drakvuf);

bool fill_kernel_offsets(drakvuf_t drakvuf, size_t size, const char* names[][2]);

#endif
