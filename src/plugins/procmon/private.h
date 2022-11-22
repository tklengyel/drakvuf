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

#ifndef PROCMON_PRIVATE_H
#define PROCMON_PRIVATE_H

#include "plugins/plugin_utils.h"
#include "plugins/plugins_ex.h"
#include "plugins/private.h"

namespace procmon_ns
{

struct execve_data : PluginResult
{
    execve_data()
        : PluginResult()
        , pid()
        , tid()
        , ppid()
        , new_pid()
        , new_tid()
        , rsp()
        , execat_rsp()
        , cr3()
        , process_name()
        , thread_name()
        , image_path_name()
        , command_line()
        , envp()
        , internal_error()
    {
    }

    vmi_pid_t pid;
    uint32_t tid;
    vmi_pid_t ppid;
    vmi_pid_t new_pid;
    uint32_t new_tid;
    addr_t rsp;
    addr_t execat_rsp;
    addr_t cr3;

    std::string process_name;
    std::string thread_name;
    std::string image_path_name;
    std::string command_line;
    std::map<std::string, std::string> envp;

    bool internal_error = false;
};

struct send_signal_data : PluginResult
{
    send_signal_data()
        : PluginResult()
        , pid()
        , target_pid()
        , tid()
        , target_tid()
        , target_ppid()
        , rsp()
        , target_process_name()
        , thread_name()
        , target_thread_name()
        , signal()
    {
    }

    vmi_pid_t pid;
    vmi_pid_t target_pid;
    uint32_t tid;
    uint32_t target_tid;
    vmi_pid_t target_ppid;
    addr_t rsp;

    std::string target_process_name;
    std::string thread_name;
    std::string target_thread_name;

    uint64_t signal;
};

struct kernel_clone_data : PluginResult
{
    kernel_clone_data()
        : PluginResult()
        , pid()
        , tid()
        , rsp()
        , flags()
        , exit_signal()
    {
    }
    vmi_pid_t pid;
    uint32_t tid;
    addr_t rsp;

    uint64_t flags;
    uint32_t exit_signal;
};

typedef enum exit_status
{
    EXIT_STATUS_SUCCESS                     = 0x00,
    EXIT_STATUS_FAILURE                     = 0x01,
    EXIT_USAGE                              = 0x40,
    EXIT_DATAERR                            = 0x41,
    EXIT_NOINPUT                            = 0x42,
    EXIT_NOUSER                             = 0x43,
    EXIT_NOHOST                             = 0x44,
    EXIT_UNAVAILABLE                        = 0x45,
    EXIT_SOFTWARE                           = 0x46,
    EXIT_OSERROR                            = 0x47,
    EXIT_OSFILE                             = 0x48,
    EXIT_CANTCREATE                         = 0x49,
    EXIT_IOERROR                            = 0x4A,
    EXIT_TEMPFAIL                           = 0x4B,
    EXIT_PROTOCOL                           = 0x4C,
    EXIT_NOPERMISSION                       = 0x4D,
    EXIT_CONFIG                             = 0x4E,
    EXIT_CANNOT_EXECUTE                     = 0x7E,
    EXIT_COMMAND_NOT_FOUND                  = 0x7F,
    EXIT_INVALID_ARGUMENT                   = 0x80,
    EXIT_SIGHUP                             = 0x81,
    EXIT_SIGINT                             = 0x82,
    EXIT_SIGQUIT                            = 0x83,
    EXIT_SIGILL                             = 0x84,
    EXIT_SIGABRT                            = 0x86,
    EXIT_SIGFPE                             = 0x88,
    EXIT_SIGKILL                            = 0x89,
    EXIT_SIGSEGV                            = 0x8B,
    EXIT_SIGPIPE                            = 0x8D,
    EXIT_SIGALRM                            = 0x8E,
    EXIT_SIGTERM                            = 0x8F
} exit_status_t;

static inline const char* exit_status_to_string(exit_status_t status)
{
    switch (status)
    {
        case EXIT_STATUS_SUCCESS:
            return "EXIT_SUCCESS";
        case EXIT_STATUS_FAILURE:
            return "EXIT_FAILURE";
        case EXIT_USAGE:
            return "EXIT_USAGE";
        case EXIT_DATAERR:
            return "EXIT_DATAERR";
        case EXIT_NOINPUT:
            return "EXIT_NOINPUT";
        case EXIT_NOUSER:
            return "EXIT_NOUSER";
        case EXIT_NOHOST:
            return "EXIT_NOHOST";
        case EXIT_UNAVAILABLE:
            return "EXIT_UNAVAILABLE";
        case EXIT_SOFTWARE:
            return "EXIT_SOFTWARE";
        case EXIT_OSERROR:
            return "EXIT_OSERROR";
        case EXIT_OSFILE:
            return "EXIT_OSFILE";
        case EXIT_CANTCREATE:
            return "EXIT_CANTCREATE";
        case EXIT_IOERROR:
            return "EXIT_IOERROR";
        case EXIT_TEMPFAIL:
            return "EXIT_TEMPFAIL";
        case EXIT_PROTOCOL:
            return "EXIT_PROTOCOL";
        case EXIT_NOPERMISSION:
            return "EXIT_NOPERMISSION";
        case EXIT_CONFIG:
            return "EXIT_CONFIG";
        case EXIT_CANNOT_EXECUTE:
            return "EXIT_CANNOT_EXECUTE";
        case EXIT_COMMAND_NOT_FOUND:
            return "EXIT_COMMAND_NOT_FOUND";
        case EXIT_INVALID_ARGUMENT:
            return "EXIT_INVALID_ARGUMENT";
        case EXIT_SIGHUP:
            return "EXIT_SIGHUP";
        case EXIT_SIGINT:
            return "EXIT_SIGINT";
        case EXIT_SIGQUIT:
            return "EXIT_SIGQUIT";
        case EXIT_SIGILL:
            return "EXIT_SIGILL";
        case EXIT_SIGABRT:
            return "EXIT_SIGABRT";
        case EXIT_SIGFPE:
            return "EXIT_SIGFPE";
        case EXIT_SIGKILL:
            return "EXIT_SIGKILL";
        case EXIT_SIGSEGV:
            return "EXIT_SIGSEGV";
        case EXIT_SIGPIPE:
            return "EXIT_SIGPIPE";
        case EXIT_SIGALRM:
            return "EXIT_SIGALRM";
        case EXIT_SIGTERM:
            return "EXIT_SIGTERM";
    }
    return "UNDEFINED";
}

typedef enum signal
{
    SIGNAL_HUP                =	0x01,
    SIGNAL_INT                = 0x02,
    SIGNAL_QUIT               = 0x03,
    SIGNAL_ILL                = 0x04,
    SIGNAL_TRAP               = 0x05,
    SIGNAL_ABRT               = 0x06,
    SIGNAL_BUS                = 0x07,
    SIGNAL_FPE                = 0x08,
    SIGNAL_KILL               = 0x09,
    SIGNAL_USR1               = 0x0A,
    SIGNAL_SEGV               =	0x0B,
    SIGNAL_USR2               =	0x0C,
    SIGNAL_PIPE               =	0x0D,
    SIGNAL_ALRM               =	0x0E,
    SIGNAL_TERM               =	0x0F,
    SIGNAL_STKFLT             =	0x10,
    SIGNAL_CHLD               =	0x11,
    SIGNAL_CONT               =	0x12,
    SIGNAL_STOP               =	0x13,
    SIGNAL_TSTP               =	0x14,
    SIGNAL_TTIN               =	0x15,
    SIGNAL_TTOU               =	0x16,
    SIGNAL_URG                =	0x17,
    SIGNAL_XCPU               =	0x18,
    SIGNAL_XFSZ               =	0x19,
    SIGNAL_VTALRM             =	0x1A,
    SIGNAL_PROF               =	0x1B,
    SIGNAL_WINCH              =	0x1C,
    SIGNAL_IO                 = 0x1D,
    SIGNAL_PWR                =	0x1E,
    SIGNAL_SYS                =	0x1F
} signal_t;

static inline const char* signal_to_string(signal_t signal)
{
    switch (signal)
    {
        case SIGNAL_HUP:
            return "SIGHUP";
        case SIGNAL_INT:
            return "SIGINT";
        case SIGNAL_QUIT:
            return "SIGQUIT";
        case SIGNAL_ILL:
            return "SIGILL";
        case SIGNAL_TRAP:
            return "SIGTRAP";
        case SIGNAL_ABRT:
            return "SIGABRT";
        case SIGNAL_BUS:
            return "SIGBUS";
        case SIGNAL_FPE:
            return "SIGFPE";
        case SIGNAL_KILL:
            return "SIGKILL";
        case SIGNAL_USR1:
            return "SIGUSR1";
        case SIGNAL_SEGV:
            return "SIGSEGV";
        case SIGNAL_USR2:
            return "SIGUSR2";
        case SIGNAL_PIPE:
            return "SIGPIPE";
        case SIGNAL_ALRM:
            return "SIGALRM";
        case SIGNAL_TERM:
            return "SIGTERM";
        case SIGNAL_STKFLT:
            return "SIGSTKFLT";
        case SIGNAL_CHLD:
            return "SIGCHLD";
        case SIGNAL_CONT:
            return "SIGCONT";
        case SIGNAL_STOP:
            return "SIGSTOP";
        case SIGNAL_TSTP:
            return "SIGTSTP";
        case SIGNAL_TTIN:
            return "SIGTTIN";
        case SIGNAL_TTOU:
            return "SIGTTOU";
        case SIGNAL_URG:
            return "SIGURG";
        case SIGNAL_XCPU:
            return "SIGXCPU";
        case SIGNAL_XFSZ:
            return "SIGXFSZ";
        case SIGNAL_VTALRM:
            return "SIGVTALRM";
        case SIGNAL_PROF:
            return "SIGPROF";
        case SIGNAL_WINCH:
            return "SIGWINCH";
        case SIGNAL_IO:
            return "SIGIO";
        case SIGNAL_PWR:
            return "SIGPWR";
        case SIGNAL_SYS:
            return "SIGSYS";
    }

    return "UNDEFINED";
}

enum
{
    CLONE_CLEAR_SIGHAND = 0x100000000ULL,
    CLONE_INTO_CGROUP = 0x200000000ULL,
#ifndef CLONE_PIDFD
    CLONE_PIDFD = 0x00001000ULL,
#endif
    CLONE_NEWTIME =	0x00000080
};

static const flags_str_t kernel_clone_flags =
{
    REGISTER_FLAG(CSIGNAL),              /* signal mask to be sent at exit */
    REGISTER_FLAG(CLONE_VM),             /* set if VM shared between processes */
    REGISTER_FLAG(CLONE_FS),             /* set if fs info shared between processes */
    REGISTER_FLAG(CLONE_FILES),          /* set if open files shared between processes */
    REGISTER_FLAG(CLONE_SIGHAND),        /* set if signal handlers and blocked signals shared */
    REGISTER_FLAG(CLONE_PIDFD),          /* set if a pidfd should be placed in parent */
    REGISTER_FLAG(CLONE_PTRACE),         /* set if we want to let tracing continue on the child too */
    REGISTER_FLAG(CLONE_VFORK),          /* set if the parent wants the child to wake it up on mm_release */
    REGISTER_FLAG(CLONE_PARENT),         /* set if we want to have the same parent as the cloner */
    REGISTER_FLAG(CLONE_THREAD),         /* Same thread group? */
    REGISTER_FLAG(CLONE_NEWNS),          /* New mount namespace group */
    REGISTER_FLAG(CLONE_SYSVSEM),        /* share system V SEM_UNDO semantics */
    REGISTER_FLAG(CLONE_SETTLS),         /* create a new TLS for the child */
    REGISTER_FLAG(CLONE_PARENT_SETTID),  /* set the TID in the parent */
    REGISTER_FLAG(CLONE_CHILD_CLEARTID), /* clear the TID in the child */
    REGISTER_FLAG(CLONE_DETACHED),       /* Unused, ignored */
    REGISTER_FLAG(CLONE_UNTRACED),       /* set if the tracing process can't force CLONE_PTRACE on this clone */
    REGISTER_FLAG(CLONE_CHILD_SETTID),   /* set the TID in the child */
    REGISTER_FLAG(CLONE_NEWCGROUP),      /* New cgroup namespace */
    REGISTER_FLAG(CLONE_NEWUTS),         /* New utsname namespace */
    REGISTER_FLAG(CLONE_NEWIPC),         /* New ipc namespace */
    REGISTER_FLAG(CLONE_NEWUSER),        /* New user namespace */
    REGISTER_FLAG(CLONE_NEWPID),         /* New pid namespace */
    REGISTER_FLAG(CLONE_NEWNET),         /* New network namespace */
    REGISTER_FLAG(CLONE_IO),             /* Clone io context */
    REGISTER_FLAG(CLONE_CLEAR_SIGHAND),  /* Clear any signal handler and reset to SIG_DFL. */
    REGISTER_FLAG(CLONE_INTO_CGROUP),    /* Clone into a specific cgroup given the right permissions. */
    REGISTER_FLAG(CLONE_NEWTIME)         /* New time namespace */
};

// Offsets name
enum
{
    _KERNEL_CLONE_ARGS_FLAGS,
    _KERNEL_CLONE_ARGS_EXIT_SIGNAL,
    _FILE_F_PATH,
    _PATH_DENTRY,
    __LINUX_OFFSET_MAX
};

static const char* linux_offset_names[__LINUX_OFFSET_MAX][2] =
{
    [_KERNEL_CLONE_ARGS_FLAGS] = {"kernel_clone_args", "flags"},
    [_KERNEL_CLONE_ARGS_EXIT_SIGNAL] = {"kernel_clone_args", "exit_signal"},
    [_FILE_F_PATH] = {"file", "f_path"},
    [_PATH_DENTRY] = {"path", "dentry"},
};

} // procmon_ns

#define ARG_MAX 131072
#define MAX_ERRNO 4095

#endif