/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2022 Tamas K Lengyel.                                  *
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

#ifndef DRAKVUF_PLUGINS_H
#define DRAKVUF_PLUGINS_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <array>
#include <memory>
#include <unordered_map>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>

#include <libdrakvuf/libdrakvuf.h>
#include <libdrakvuf/json-util.h>

struct plugins_options
{
    const char* dump_folder;            // PLUGIN_FILEDELETE, PLUGIN_FILEEXTRACTOR
#ifdef PLUGIN_ENABLE_FILEDELETE
    bool dump_modified_files;           // PLUGIN_FILEDELETE
    bool filedelete_use_injector;       // PLUGIN_FILEDELETE
#endif
    bool cpuid_stealth;                 // PLUGIN_CPUIDMON
    const char* tcpip_profile;          // PLUGIN_SOCKETMON
    const char* win32k_profile;         // PLUGIN_CLIPBOARDMON, PLUGIN_WINDOWMON, PLUGIN_SYSCALLS
    const char* sspicli_profile;        // PLUGIN_ENVMON
    const char* kernel32_profile;       // PLUGIN_ENVMON
    const char* kernelbase_profile;     // PLUGIN_ENVMON
    const char* wow_kernel32_profile;   // PLUGIN_ENVMON
    const char* iphlpapi_profile;       // PLUGIN_ENVMON
    const char* mpr_profile;            // PLUGIN_ENVMON
    const char* syscalls_filter_file;   // PLUGIN_SYSCALLS
    bool disable_sysret;                // PLUGIN_SYSCALLS
    bool abort_on_bsod;                 // PLUGIN_BSODMON
    const char* ntdll_profile;          // PLUGIN_LIBRARYMON
    const char* ole32_profile;          // PLUGIN_WMIMON
    const char* wow_ole32_profile;      // PLUGIN_WMIMON
    const char* combase_profile;        // PLUGIN_WMIMON
    const char* memdump_dir;            // PLUGIN_MEMDUMP
    bool memdump_disable_free_vm;       // PLUGIN_MEMDUMP
    bool memdump_disable_protect_vm;    // PLUGIN_MEMDUMP
    bool memdump_disable_write_vm;      // PLUGIN_MEMDUMP
    bool memdump_disable_terminate_proc;// PLUGIN_MEMDUMP
    bool memdump_disable_create_thread; // PLUGIN_MEMDUMP
    bool memdump_disable_set_thread;    // PLUGIN_MEMDUMP
    bool memdump_disable_shellcode_detect; // PLUGIN_MEMDUMP
    const char* dll_hooks_list;         // PLUGIN_MEMDUMP, PLUGIN_APIMON
    bool userhook_no_addr;              // PLUGIN_MEMDUMP, PLUGIN_APIMON
    const char* clr_profile;            // PLUGIN_MEMDUMP
    const char* mscorwks_profile;       // PLUGIN_MEMDUMP
    uint32_t procdump_timeout;          // PLUGIN_PROCDUMP
    const char* procdump_dir;           // PLUGIN_PROCDUMP
    bool compress_procdumps = false;    // PLUGIN_PROCDUMP
    vmi_pid_t procdump_on_finish;       // PLUGIN_PROCDUMP2
    std::shared_ptr<std::unordered_map<vmi_pid_t, bool>> terminated_processes; // PLUGIN_PROCDUMP
    const char* hal_profile;            // PLUGIN_PROCDUMP2
    bool procdump_disable_kideliverapc_hook; // PLUGIN_PROCDUMP2
    bool procdump_disable_kedelayexecutionthread_hook; // PLUGIN_PROCDUMP2
    const char* codemon_dump_dir;       // PLUGIN_CODEMON
    const char* codemon_filter_executable;  // PLUGIN_CODEMON
    bool codemon_log_everything;        // PLUGIN_CODEMON
    bool codemon_dump_vad;              // PLUGIN_CODEMON
    bool codemon_analyse_system_dll_vad;    // PLUGIN_CODEMON
    bool codemon_default_benign;        // PLUGIN_CODEMON
    bool exploitmon_kernel2user_detect; // PLUGIN_EXPLOITMON
    const char* ipt_dir;                // PLUGIN_IPT
    bool ipt_trace_os;                  // PLUGIN_IPT
    bool ipt_trace_user;                // PLUGIN_IPT
    bool objmon_disable_create_hook;    // PLUGIN_OBJMON
    bool objmon_disable_duplicate_hook; // PLUGIN_OBJMON
    const char* hidsim_template;        // PLUGIN_HIDSIM
    bool hidsim_monitor_gui;            // PLUGIN_HIDSIM
    bool hidsim_random_clicks;          // PLUGIN_HIDSIM
    const char* fwpkclnt_profile;       // PLUGIN_ROOTKITMON
    const char* fltmgr_profile;         // PLUGIN_ROOTKITMON
    const char* ci_profile;             // PLUGIN_ROOTKITMON
    const char* services_profile;       // PLUGIN_DKOMMON
    const char* netio_profile;          // PLUGIN_CALLBACKMON
    uint64_t hidevm_delay;              // PLUGIN_HIDEVM
};

typedef enum drakvuf_plugin
{
    PLUGIN_SYSCALLS,
    PLUGIN_POOLMON,
    PLUGIN_FILETRACER,
    PLUGIN_FILEDELETE,
    PLUGIN_FILEEXTRACTOR,
    PLUGIN_OBJMON,
    PLUGIN_EXMON,
    PLUGIN_SSDTMON,
    PLUGIN_DEBUGMON,
    PLUGIN_DELAYMON,
    PLUGIN_CPUIDMON,
    PLUGIN_SOCKETMON,
    PLUGIN_REGMON,
    PLUGIN_PROCMON,
    PLUGIN_BSODMON,
    PLUGIN_ENVMON,
    PLUGIN_CRASHMON,
    PLUGIN_CLIPBOARDMON,
    PLUGIN_WINDOWMON,
    PLUGIN_LIBRARYMON,
    PLUGIN_DKOMMON,
    PLUGIN_WMIMON,
    PLUGIN_MEMDUMP,
    PLUGIN_APIMON,
    PLUGIN_PROCDUMP,
    PLUGIN_PROCDUMP2,
    PLUGIN_RPCMON,
    PLUGIN_TLSMON,
    PLUGIN_CODEMON,
    PLUGIN_LIBHOOKTEST,
    PLUGIN_EXPLOITMON,
    PLUGIN_IPT,
    PLUGIN_HIDSIM,
    PLUGIN_ROOTKITMON,
    PLUGIN_SPRAYMON,
    PLUGIN_CALLBACKMON,
    PLUGIN_HIDEVM,
    PLUGIN_PTRACEMON,
    __DRAKVUF_PLUGIN_LIST_MAX
} drakvuf_plugin_t;

static const char* drakvuf_plugin_names[] =
{
    [PLUGIN_SYSCALLS] = "syscalls",
    [PLUGIN_POOLMON] = "poolmon",
    [PLUGIN_FILETRACER] = "filetracer",
    [PLUGIN_FILEDELETE] = "filedelete",
    [PLUGIN_FILEEXTRACTOR] = "fileextractor",
    [PLUGIN_OBJMON] = "objmon",
    [PLUGIN_EXMON] = "exmon",
    [PLUGIN_SSDTMON] = "ssdtmon",
    [PLUGIN_DEBUGMON] = "debugmon",
    [PLUGIN_DELAYMON] = "delaymon",
    [PLUGIN_CPUIDMON] = "cpuidmon",
    [PLUGIN_SOCKETMON] = "socketmon",
    [PLUGIN_REGMON] = "regmon",
    [PLUGIN_PROCMON] = "procmon",
    [PLUGIN_BSODMON] = "bsodmon",
    [PLUGIN_ENVMON] = "envmon",
    [PLUGIN_CRASHMON] = "crashmon",
    [PLUGIN_CLIPBOARDMON] = "clipboardmon",
    [PLUGIN_WINDOWMON] = "windowmon",
    [PLUGIN_LIBRARYMON] = "librarymon",
    [PLUGIN_DKOMMON] = "dkommon",
    [PLUGIN_WMIMON] = "wmimon",
    [PLUGIN_MEMDUMP] = "memdump",
    [PLUGIN_APIMON] = "apimon",
    [PLUGIN_PROCDUMP] = "procdump",
    [PLUGIN_PROCDUMP2] = "procdump2",
    [PLUGIN_RPCMON] = "rpcmon",
    [PLUGIN_TLSMON] = "tlsmon",
    [PLUGIN_CODEMON] = "codemon",
    [PLUGIN_LIBHOOKTEST] = "libhooktest",
    [PLUGIN_EXPLOITMON] = "exploitmon",
    [PLUGIN_IPT] = "ipt",
    [PLUGIN_HIDSIM] = "hidsim",
    [PLUGIN_ROOTKITMON] = "rootkitmon",
    [PLUGIN_SPRAYMON] = "spraymon",
    [PLUGIN_CALLBACKMON] = "callbackmon",
    [PLUGIN_HIDEVM] = "hidevm",
    [PLUGIN_PTRACEMON] = "ptracemon",
};

static const bool drakvuf_plugin_os_support[__DRAKVUF_PLUGIN_LIST_MAX][VMI_OS_WINDOWS+1] =
{
    [PLUGIN_SYSCALLS]     = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 1 },
    [PLUGIN_POOLMON]      = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_FILETRACER]   = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 1 },
    [PLUGIN_FILEDELETE]   = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_FILEEXTRACTOR]= { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_OBJMON]       = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_EXMON]        = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_SSDTMON]      = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_DEBUGMON]     = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 1 },
    [PLUGIN_DELAYMON]     = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_CPUIDMON]     = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 1 },
    [PLUGIN_SOCKETMON]    = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_REGMON]       = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_PROCMON]      = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 1 },
    [PLUGIN_BSODMON]      = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_ENVMON]       = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_CRASHMON]     = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_CLIPBOARDMON] = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_WINDOWMON]    = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_LIBRARYMON]   = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_DKOMMON]      = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_WMIMON]       = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_MEMDUMP]      = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_APIMON]       = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_PROCDUMP]     = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_PROCDUMP2]    = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_RPCMON]       = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_TLSMON]       = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_CODEMON]      = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_LIBHOOKTEST]  = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 1 },
    [PLUGIN_EXPLOITMON]   = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_IPT]          = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 1 },
    [PLUGIN_HIDSIM]       = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 1 },
    [PLUGIN_ROOTKITMON]   = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_SPRAYMON]     = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_CALLBACKMON]  = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_HIDEVM]       = { [VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 0 },
    [PLUGIN_PTRACEMON]    = { [VMI_OS_WINDOWS] = 0, [VMI_OS_LINUX] = 1 },
};

class plugin
{
public:
    virtual ~plugin() = default;

    bool stop()
    {
        if (is_stopped())
            return true;
        m_is_stopped = stop_impl();
        m_is_stopping = true;
        return m_is_stopped;
    }

    bool is_stopping() const
    {
        return m_is_stopping;
    }

    bool is_stopped() const
    {
        return m_is_stopped;
    }

protected:
    virtual bool stop_impl() = 0;

private:
    bool m_is_stopping = false;
    bool m_is_stopped = false;
};

class drakvuf_plugins
{
private:
    drakvuf_t drakvuf;
    output_format_t output;
    os_t os;
    std::array<std::unique_ptr<plugin>, __DRAKVUF_PLUGIN_LIST_MAX> plugins;

public:
    drakvuf_plugins(drakvuf_t drakvuf, output_format_t output, os_t os);
    int start(drakvuf_plugin_t plugin, const plugins_options* config);
    int stop(drakvuf_plugin_t plugin);
};

/***************************************************************************/

struct vmi_lock_guard
{
    vmi_lock_guard(drakvuf_t drakvuf_) : drakvuf(drakvuf_), vmi()
    {
        lock();
    }

    vmi_instance_t lock()
    {
        if (!vmi)
            vmi = drakvuf_lock_and_get_vmi(drakvuf);

        return vmi;
    }

    bool unlock()
    {
        if (vmi)
        {
            drakvuf_release_vmi(drakvuf);
            vmi = nullptr;
            return true;
        }
        return false;

    }

    bool is_lock() const
    {
        return vmi == nullptr ? true : false;
    }

    operator vmi_instance_t() const
    {
        return vmi;
    }

    ~vmi_lock_guard()
    {
        unlock();
    }

    drakvuf_t drakvuf;
    vmi_instance_t vmi;
};

#endif
