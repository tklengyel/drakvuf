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

#pragma once

#include <string>

#include "base.hpp"
#include "../call_result.hpp"

namespace libhook
{

class syscall_hook : public base_hook
{
public:
    /**
     * Factory function to create the trap and perform hooking at the same time.
     */
    template<typename Params = CallResult>
    [[nodiscard]]
    static auto create(drakvuf_t, const std::string& syscall_name, cb_wrapper_t cb)
    -> std::unique_ptr<syscall_hook>;

    /**
     * unhook on dctor
     */
    ~syscall_hook() override;

    /**
     * delete copy ctor, as this class has ownership via RAII
     */
    syscall_hook(const syscall_hook&) = delete;

    /**
     * move ctor, required for move semantics to work properly
     * important to be noexcept, otherwise bad things will happen
     */
    syscall_hook(syscall_hook&&) noexcept;

    /**
     * delete copy assignment operator, as this class has ownership via RAII
     */
    syscall_hook& operator=(const syscall_hook&) = delete;

    /**
     * move assignment operator, required for move semantics to work properly
     * important to be noexcept, otherwise bad things will happen
     */
    syscall_hook& operator=(syscall_hook&&) noexcept;

    std::string syscall_name_;
    cb_wrapper_t callback_;
    drakvuf_trap_t* trap_;

protected:
    /**
     * Hide ctor from users, as we enforce factory function usage.
     */
    syscall_hook(drakvuf_t, const std::string& syscall_name, cb_wrapper_t cb);
};

template<typename Params>
auto syscall_hook::create(drakvuf_t drakvuf, const std::string& syscall_name, cb_wrapper_t cb)
-> std::unique_ptr<syscall_hook>
{
    PRINT_DEBUG("[LIBHOOK] creating syscall hook\n");

    auto hook = std::unique_ptr<syscall_hook>(new syscall_hook(drakvuf, syscall_name, cb));
    hook->trap_ = new drakvuf_trap_t;

    if (!drakvuf_get_kernel_symbol_rva(hook->drakvuf_, hook->syscall_name_.c_str(), &hook->trap_->breakpoint.rva))
    {
        PRINT_DEBUG("[LIBHOOK] Failed to receive addr of function %s\n", hook->syscall_name_.c_str());
        delete hook->trap_;
        return std::unique_ptr<syscall_hook>();
    }

    hook->trap_->breakpoint.lookup_type = LOOKUP_PID;
    hook->trap_->breakpoint.pid = 4;
    hook->trap_->breakpoint.addr_type = ADDR_RVA;
    hook->trap_->breakpoint.module = "ntoskrnl.exe";

    hook->trap_->name = hook->syscall_name_.c_str();
    hook->trap_->type = BREAKPOINT;
    hook->trap_->cb = [](drakvuf_t drakvuf, drakvuf_trap_info_t* info)
    {
        return GetTrapHook<syscall_hook>(info)->callback_(drakvuf, info);
    };

    static_assert(std::is_base_of_v<CallResult, Params>, "Params must derive from CallResult");
    static_assert(std::is_default_constructible_v<Params>, "Params must be default constructible");

    // populate backref
    auto* params = new Params();
    params->hook_ = hook.get();
    hook->trap_->data = static_cast<void*>(params);

    if (!drakvuf_add_trap(drakvuf, hook->trap_))
    {
        PRINT_DEBUG("[LIBHOOK] failed to create trap for syscall hook\n");
        delete static_cast<CallResult*>(hook->trap_->data);
        delete hook->trap_;
        return std::unique_ptr<syscall_hook>();
    }

    PRINT_DEBUG("[LIBHOOK] return hook OK\n");
    return hook;
}

};  // namespace libhook
