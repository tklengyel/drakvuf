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

#ifndef MEMDUMP_PRIVATE_H
#define MEMDUMP_PRIVATE_H

#include <vector>
#include <list>

typedef enum
  {
   INVALID,
   WriteVirtualMemoryExtras,
   __MAX_EXTRAX__
  } extras_type_t;

typedef struct
{
  extras_type_t type;
  union
  {
    struct
    {
      vmi_pid_t target_pid;
      char* target_name;
      addr_t base_address;
    } write_virtual_memory_extras;
  };
} extras_t;

template<typename T>
struct map_view_of_section_result_t: public call_result_t<T>
{
    map_view_of_section_result_t(T* src) : call_result_t<T>(src), section_handle(), process_handle(), base_address_ptr() {}

    uint64_t section_handle;
    uint64_t process_handle;
    addr_t base_address_ptr;
};

enum target_hook_state
{
    HOOK_FIRST_TRY,
    HOOK_PAGEFAULT_RETRY,
    HOOK_FAILED,
    HOOK_OK
};

typedef event_response_t (*callback_t)(drakvuf_t drakvuf, drakvuf_trap_info* info);
class memdump;

struct hook_target_entry_t
{
    vmi_pid_t pid;
    std::string target_name;
    callback_t callback;
    size_t args_num;
    target_hook_state state;
    drakvuf_trap_t* trap;
    memdump* plugin;

    hook_target_entry_t(std::string target_name, callback_t callback, size_t args_num, memdump* plugin)
        : target_name(target_name), callback(callback), args_num(args_num), state(HOOK_FIRST_TRY), plugin(plugin) {}
};

struct return_hook_target_entry_t
{
	vmi_pid_t pid;
	drakvuf_trap_t* trap;
	memdump* plugin;
	std::vector < uint64_t > arguments;
};

template<typename T>
struct copy_on_write_result_t: public call_result_t<T>
{
    copy_on_write_result_t(T* src) : call_result_t<T>(src), vaddr(), pte(), old_cow_pa() {}

    addr_t vaddr;
    addr_t pte;
    addr_t old_cow_pa;
    std::vector<hook_target_entry_t*> hooks;
};

struct user_dll_t
{
    // relevant while loading
    addr_t dtb;
    uint32_t thread_id;
    addr_t real_dll_base;
    bool is_hooked;

    // internal, for page faults
    addr_t pf_current_addr;
    addr_t pf_max_addr;

    // one entry per hooked function
    std::vector<hook_target_entry_t> targets;
};

struct target_config_entry_t
{
    std::string dll_name;
    std::string function_name;
    size_t args_num;

    target_config_entry_t() : dll_name(), function_name(), args_num() {}
    target_config_entry_t(std::string&& dll_name, std::string&& function_name, size_t args_num)
        : dll_name(std::move(dll_name)), function_name(std::move(function_name)), args_num(args_num) {}
};

// type of a pointer residing on stack
enum sptr_type_t
{
    ERROR,   // problem with stack inspection
    MAIN,    // pointer to a main module
    LINKED,  // pointer to some linked DLL module
    UNLINKED // pointer to some non-legit memory
};

sptr_type_t check_module_linked_wow(drakvuf_t drakvuf,
                                    vmi_instance_t vmi,
                                    memdump* plugin,
                                    drakvuf_trap_info_t* info,
                                    addr_t dll_base);

sptr_type_t check_module_linked(drakvuf_t drakvuf,
                                vmi_instance_t vmi,
                                memdump* plugin,
                                drakvuf_trap_info_t* info,
                                addr_t dll_base);

bool dump_memory_region(
    drakvuf_t drakvuf,
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    memdump* plugin,
    access_context_t* ctx,
    size_t len_bytes,
    const char* reason,
    extras_t* extras,
    void (*printout_extras)(drakvuf_t drakvuf, output_format_t format, extras_t* extras));

bool inspect_stack_ptr(
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    memdump* plugin,
    bool is_32bit,
    addr_t stack_ptr);

bool dump_from_stack(
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    memdump* plugin);

#endif
