/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2023 Tamas K Lengyel.                                  *
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
#ifndef SYSCALLS_LINUX_H
#define SYSCALLS_LINUX_H

#include "private.h"
#include "private_2.h"

class linux_syscalls : public syscalls_base
{
public:
    std::array<size_t, syscalls_ns::__PT_REGS_MAX> regs;
    std::unordered_map<uint64_t, std::unique_ptr<libhook::SyscallHook>> hooks;
    std::unordered_map<uint64_t, std::unique_ptr<libhook::ReturnHook>> ret_hooks;

    // Helpers
    std::vector<uint64_t> build_arguments_buffer(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t pt_regs_addr, addr_t nr);
    bool get_pt_regs_addr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* pt_regs_addr, addr_t* nr);
    bool register_hook(char* syscall_name, uint64_t syscall_number, const syscalls_ns::syscall_t* syscall_definition, bool is_x64);

    // Print information
    void print_syscall(drakvuf_t drakvuf, drakvuf_trap_info_t* info, std::vector<uint64_t> arguments);

    // Callbacks
    event_response_t linux_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t linux_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    bool trap_syscall_table_entries(drakvuf_t drakvuf);

    linux_syscalls(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output);
};
namespace syscalls_ns
{

#define SYSCALL_TYPE_LINUX_X32 "x32"
#define SYSCALL_TYPE_LINUX_X64 "x64"

namespace linuxsc
{

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-braces"

SYSCALL(read, LONG,
    "fd",    "", DIR_IN,    LONG,
    "buf",   "", DIR_IN,    PVOID,
    "count", "", DIR_OUT,   ULONG
);
SYSCALL(write, LONG,
    "fd",    "", DIR_IN,    LONG,
    "buf",   "", DIR_OUT,   PVOID,
    "count", "", DIR_OUT,   ULONG
);
SYSCALL(open, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "flags",    "", DIR_IN, ULONG,
    "mode",     "", DIR_IN, ULONG
);
SYSCALL(close, LONG,
    "fd", "", DIR_IN, LONG,
);
SYSCALL(openat, LONG,
    "dirfd",    "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "flags",    "", DIR_IN, ULONG,
    "mode",     "", DIR_IN, ULONG,
);
SYSCALL(stat, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "statbuf",  "", DIR_IN, PVOID,
);
SYSCALL(fstat, LONG,
    "fd",      "", DIR_IN, ULONG,
    "statbuf", "", DIR_IN, VOID,
);
SYSCALL(lstat, LONG,
    "filename", "", DIR_IN, PCHAR,
    "statbuf",  "", DIR_IN, VOID,
);
SYSCALL(poll, LONG,
    "fds",     "", DIR_IN, PVOID,
    "nfds",    "", DIR_IN, ULONG,
    "timeout", "", DIR_IN, LONG,
);
SYSCALL(lseek, LONG,
    "fd",     "", DIR_IN, ULONG,
    "offset", "", DIR_IN, LONG,
    "whence", "", DIR_IN, ULONG,
);
SYSCALL(mmap, PVOID,
    "addr",   "", DIR_IN, PVOID,
    "length", "", DIR_IN, ULONG,
    "prot",   "", DIR_IN, MMAP_PROT,
    "flags",  "", DIR_IN, LONG,
    "fd",     "", DIR_IN, ULONG,
    "offset", "", DIR_IN, ULONG,
);
SYSCALL(mprotect, LONG,
    "start", "", DIR_IN, ULONG,
    "len",   "", DIR_IN, ULONG,
    "prot",  "", DIR_IN, MMAP_PROT,
);
SYSCALL(munmap, LONG,
    "addr",   "", DIR_IN, PVOID,
    "length", "", DIR_IN, ULONG,
);
SYSCALL(brk, LONG,
    "brk", "", DIR_IN, ULONG,
);
SYSCALL(rt_sigaction, LONG,
    "signum", "", DIR_IN, LONG,
    "act",    "", DIR_IN, PVOID,
    "oldact", "", DIR_IN, PVOID,
);
SYSCALL(rt_sigprocmask, LONG,
    "how",    "", DIR_IN, LONG,
    "set",    "", DIR_IN, PVOID,
    "oldset", "", DIR_IN, PVOID,
);
SYSCALL(rt_sigreturn, LONG);
SYSCALL(ioctl, LONG,
    "fd",      "", DIR_IN, LONG,
    "request", "", DIR_IN, ULONG,
);
SYSCALL(pread64, ULONG,
    "fd",     "", DIR_IN, LONG,
    "buf",    "", DIR_IN, PVOID,
    "count",  "", DIR_IN, ULONG,
    "offset", "", DIR_IN, ULONG,
);
SYSCALL(pwrite64, ULONG,
    "fd",     "", DIR_IN, LONG,
    "buf",    "", DIR_IN, PVOID,
    "count",  "", DIR_IN, ULONG,
    "offset", "", DIR_IN, ULONG,
);
SYSCALL(readv, ULONG,
    "fd",     "", DIR_IN, LONG,
    "iov",    "", DIR_IN, PVOID,
    "iovcnt", "", DIR_IN, LONG,
);
SYSCALL(writev, ULONG,
    "fd",     "", DIR_IN, LONG,
    "iov",    "", DIR_IN, PVOID,
    "iovcnt", "", DIR_IN, LONG,
);
SYSCALL(access, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "mode", "", DIR_IN, LONG,
);
SYSCALL(pipe, LONG,
    "pipefd", "", DIR_IN, PVOID,
);
SYSCALL(select, LONG,
    "nfds",      "", DIR_IN, LONG,
    "readfds",   "", DIR_IN, PVOID,
    "writefds",  "", DIR_IN, PVOID,
    "exceptfds", "", DIR_IN, PVOID,
    "timeout",   "", DIR_IN, PVOID,
);
SYSCALL(sched_yield, VOID);
SYSCALL(mremap, PVOID,
    "old_address", "", DIR_IN, PVOID,
    "old_size",    "", DIR_IN, ULONG,
    "new_size",    "", DIR_IN, ULONG,
    "flags",       "", DIR_IN, LONG,
);
SYSCALL(msync, LONG,
    "addr",   "", DIR_IN, PVOID,
    "length", "", DIR_IN, ULONG,
    "flags",  "", DIR_IN, LONG,
);
SYSCALL(mincore, LONG,
    "addr",   "", DIR_IN, PVOID,
    "length", "", DIR_IN, ULONG,
    "vec",    "", DIR_IN, PCHAR,
);
SYSCALL(madvise, LONG,
    "addr",   "", DIR_IN, PVOID,
    "length", "", DIR_IN, ULONG,
    "advice", "", DIR_IN, LONG,
);
SYSCALL(shmget, LONG,
    "key",    "", DIR_IN, VOID,
    "size",   "", DIR_IN, ULONG,
    "shmflg", "", DIR_IN, LONG,
);
SYSCALL(shmat, VOID,
    "shmid",   "", DIR_IN, LONG,
    "shmaddr", "", DIR_IN, PVOID,
    "shmflg",  "", DIR_IN, LONG,
);
SYSCALL(shmctl, LONG,
    "shmid", "", DIR_IN, LONG,
    "cmd",   "", DIR_IN, LONG,
    "buf",   "", DIR_IN, PVOID,
);
SYSCALL(dup, LONG,
    "oldfd", "", DIR_IN, LONG
);
SYSCALL(dup2, LONG,
    "oldfd", "", DIR_IN, LONG,
    "newfd", "", DIR_IN, LONG,
);
SYSCALL(pause, LONG);
// A very expensive syscall, the interception of which will greatly slow down the guest
// It is recommended to exclude it using the filter file
SYSCALL(nanosleep, LONG,
    "req", "", DIR_IN, PVOID,
    "rem", "", DIR_IN, PVOID,
);
SYSCALL(getitimer, LONG,
    "which",      "", DIR_IN, LONG,
    "curr_value", "", DIR_IN, PVOID,
);
SYSCALL(alarm, ULONG,
    "seconds", "", DIR_IN, ULONG,
);
SYSCALL(setitimer, LONG,
    "which",     "", DIR_IN, LONG,
    "new_value", "", DIR_IN, PVOID,
    "old_value", "", DIR_IN, PVOID,
);
SYSCALL(getpid, LONG);
SYSCALL(sendfile64, LONG,
    "out_fd", "", DIR_IN, LONG,
    "in_fd",  "", DIR_IN, LONG,
    "offset", "", DIR_IN, ULONG,
    "count",  "", DIR_IN, ULONG,
);
SYSCALL(socket, LONG,
    "domain",   "", DIR_IN, LONG,
    "type",     "", DIR_IN, LONG,
    "protocol", "", DIR_IN, LONG,
);
SYSCALL(connect, LONG,
    "sockfd",  "", DIR_IN, LONG,
    "addr",    "", DIR_IN, PVOID,
    "addrlen", "", DIR_IN, ULONG,
);
SYSCALL(accept, LONG,
    "sockfd",  "", DIR_IN, LONG,
    "addr",    "", DIR_IN, PVOID,
    "addrlen", "", DIR_IN, ULONG,
);
SYSCALL(sendto, LONG,
    "sockfd",    "", DIR_IN, LONG,
    "buf",       "", DIR_IN, PVOID,
    "len",       "", DIR_IN, ULONG,
    "flags",     "", DIR_IN, LONG,
    "dest_addr", "", DIR_IN, PVOID,
    "addrlen",   "", DIR_IN, VOID,
);
SYSCALL(recvfrom, LONG,
    "sockfd",   "", DIR_IN, LONG,
    "buf",      "", DIR_IN, PVOID,
    "len",      "", DIR_IN, ULONG,
    "flags",    "", DIR_IN, LONG,
    "src_addr", "", DIR_IN, PVOID,
    "addrlen",  "", DIR_IN, VOID,
);
SYSCALL(sendmsg, LONG,
    "sockfd", "", DIR_IN, LONG,
    "msg",    "", DIR_IN, PVOID,
    "flags",  "", DIR_IN, LONG,
);
SYSCALL(recvmsg, LONG,
    "sockfd", "", DIR_IN, LONG,
    "msg",    "", DIR_IN, PVOID,
    "flags",  "", DIR_IN, LONG,
);
SYSCALL(shutdown, LONG,
    "sockfd", "", DIR_IN, LONG,
    "how",    "", DIR_IN, LONG,
);
SYSCALL(bind, LONG,
    "sockfd",  "", DIR_IN, LONG,
    "addr",    "", DIR_IN, PVOID,
    "addrlen", "", DIR_IN, ULONG,
);
SYSCALL(listen, LONG,
    "sockfd",  "", DIR_IN, LONG,
    "backlog", "", DIR_IN, LONG,
);
SYSCALL(getsockname, LONG,
    "sockfd",  "", DIR_IN, LONG,
    "addr",    "", DIR_IN, PVOID,
    "addrlen", "", DIR_IN, ULONG,
);
SYSCALL(getpeername, LONG,
    "sockfd",  "", DIR_IN, LONG,
    "addr",    "", DIR_IN, PVOID,
    "addrlen", "", DIR_IN, ULONG,
);
SYSCALL(socketpair, LONG,
    "domain",   "", DIR_IN, LONG,
    "type",     "", DIR_IN, LONG,
    "protocol", "", DIR_IN, LONG,
    "sv",       "", DIR_IN, PVOID,
);
SYSCALL(setsockopt, LONG,
    "sockfd",  "", DIR_IN, LONG,
    "level",   "", DIR_IN, LONG,
    "optname", "", DIR_IN, LONG,
    "optval",  "", DIR_IN, PVOID,
    "optlen",  "", DIR_IN, ULONG,
);
SYSCALL(getsockopt, LONG,
    "sockfd",  "", DIR_IN, LONG,
    "level",   "", DIR_IN, LONG,
    "optname", "", DIR_IN, LONG,
    "optval",  "", DIR_IN, PVOID,
    "optlen",  "", DIR_IN, ULONG,
);
// We can ignore these syscalls because there is a better interpretation going on in the procmon plugin
// procmon
SYSCALL(clone, VOID);
SYSCALL(fork, VOID);
SYSCALL(vfork, VOID);
SYSCALL(execve, VOID);
SYSCALL(exit, VOID);
// end procmon
SYSCALL(wait4, ULONG,
    "pid",     "", DIR_IN, LONG,
    "wstatus", "", DIR_IN, PLONG,
    "options", "", DIR_IN, LONG,
    "rusage",  "", DIR_IN, PVOID,
);
SYSCALL(kill, LONG,
    "pid", "", DIR_IN, LONG,
    "sig", "", DIR_IN, LONG,
);
SYSCALL(uname, LONG);
SYSCALL(semget, LONG,
    "key",    "", DIR_IN, ULONG,
    "nsems",  "", DIR_IN, LONG,
    "semflg", "", DIR_IN, LONG,
);
SYSCALL(semop, LONG,
    "semid", "", DIR_IN, LONG,
    "sops",  "", DIR_IN, PVOID,
    "nsops", "", DIR_IN, LONG,
);
SYSCALL(semctl, LONG,
    "semid",  "", DIR_IN, LONG,
    "semnum", "", DIR_IN, LONG,
    "cmd",    "", DIR_IN, LONG,
);
SYSCALL(shmdt, VOID);
SYSCALL(msgget, VOID);
SYSCALL(msgsnd, VOID);
SYSCALL(msgrcv, VOID);
SYSCALL(msgctl, VOID);
SYSCALL(fcntl, LONG,
    "fd",  "", DIR_IN, LONG,
    "cmd", "", DIR_IN, LONG,
);
SYSCALL(flock, LONG,
    "fd",  "", DIR_IN, LONG,
    "operation", "", DIR_IN, LONG,
);
SYSCALL(fsync, LONG,
    "fd",  "", DIR_IN, LONG,
);
SYSCALL(fdatasync, LONG,
    "fd",  "", DIR_IN, LONG,
);
SYSCALL(truncate, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "length",   "", DIR_IN, ULONG,
);
SYSCALL(ftruncate, LONG,
    "fd",     "", DIR_IN, LONG,
    "length", "", DIR_IN, ULONG,
);
SYSCALL(getdents, LONG,
    "fd",    "", DIR_IN, LONG,
    "dirp",  "", DIR_IN, PVOID,
    "count", "", DIR_IN, LONG,
);
SYSCALL(getcwd, PCHAR);
SYSCALL(chdir, LONG,
    "path", "", DIR_IN, PCHAR,
);
SYSCALL(fchdir, LONG,
    "fd", "", DIR_IN, LONG,
);
// filetracer
SYSCALL(rename, LONG,
    "oldpath", "", DIR_IN, PCHAR,
    "newpath", "", DIR_IN, PCHAR,
);
SYSCALL(mkdir, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "mode",     "", DIR_IN, LONG,
);
SYSCALL(rmdir, LONG,
    "pathname", "", DIR_IN, PCHAR,
);
SYSCALL(creat, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "flags",    "", DIR_IN, LONG,
);
SYSCALL(link, LONG,
    "oldpath", "", DIR_IN, PCHAR,
    "newpath", "", DIR_IN, PCHAR,
);
SYSCALL(unlink, LONG,
    "pathname", "", DIR_IN, PCHAR,
);
SYSCALL(symlink, LONG,
    "target",   "", DIR_IN, PCHAR,
    "linkpath", "", DIR_IN, PCHAR,
);
SYSCALL(readlink, LONG,
    "pathname", "", DIR_IN, PCHAR,
);
SYSCALL(chmod, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "mode",     "", DIR_IN, LONG,
);
SYSCALL(fchmod, LONG,
    "fd",   "", DIR_IN, LONG,
    "mode", "", DIR_IN, LONG,
);
SYSCALL(chown, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "owner",    "", DIR_IN, ULONG,
    "group",    "", DIR_IN, ULONG,
);
SYSCALL(fchown, LONG,
    "fd",    "", DIR_IN, LONG,
    "owner", "", DIR_IN, ULONG,
    "group", "", DIR_IN, ULONG,
);
SYSCALL(lchown, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "owner",    "", DIR_IN, ULONG,
    "group",    "", DIR_IN, ULONG,
);
// end filetracer
SYSCALL(umask, LONG,
    "mask", "", DIR_IN, LONG,
);
SYSCALL(gettimeofday, LONG);
SYSCALL(getrlimit, LONG);
SYSCALL(getrusage, LONG);
SYSCALL(sysinfo, LONG);
SYSCALL(times, LONG);
// ptracemon
SYSCALL(ptrace, LONG,
    "request", "", DIR_IN, LONG,
    "pid",     "", DIR_IN, LONG,
    "addr",    "", DIR_IN, PVOID,
    "data",    "", DIR_IN, PVOID,
);
// end ptracemon
SYSCALL(getuid, ULONG);
SYSCALL(syslog, LONG,
    "type", "", DIR_IN, LONG,
    "bufp", "", DIR_IN, PCHAR,
    "len",  "", DIR_IN, LONG,
);
SYSCALL(getgid, ULONG);
SYSCALL(setuid, LONG,
    "uid", "", DIR_IN, ULONG,
);
SYSCALL(setgid, LONG,
    "gid", "", DIR_IN, ULONG,
);
SYSCALL(geteuid, ULONG);
SYSCALL(getegid, ULONG);
SYSCALL(setpgid, LONG,
    "pid",  "", DIR_IN, LONG,
    "pgid", "", DIR_IN, ULONG,
);
SYSCALL(getppid, ULONG);
SYSCALL(getpgrp, ULONG);
SYSCALL(setsid, ULONG);
SYSCALL(setreuid, LONG,
    "ruid", "", DIR_IN, ULONG,
    "euid", "", DIR_IN, ULONG,
);
SYSCALL(setregid, LONG,
    "rgid", "", DIR_IN, ULONG,
    "egid", "", DIR_IN, ULONG,
);
SYSCALL(getgroups, LONG);
SYSCALL(setgroups, LONG);
SYSCALL(setresuid, LONG,
    "ruid", "", DIR_IN, ULONG,
    "euid", "", DIR_IN, ULONG,
    "suid", "", DIR_IN, ULONG,
);
SYSCALL(getresuid, LONG);
SYSCALL(setresgid, LONG,
    "rgid", "", DIR_IN, ULONG,
    "egid", "", DIR_IN, ULONG,
    "sgid", "", DIR_IN, ULONG,
);
SYSCALL(getresgid, LONG);
SYSCALL(getpgid, ULONG);
SYSCALL(setfsuid, LONG,
    "fsuid", "", DIR_IN, ULONG,
);
SYSCALL(setfsgid, LONG,
    "fsgid", "", DIR_IN, ULONG,
);
SYSCALL(getsid, ULONG);
SYSCALL(capget, LONG);
SYSCALL(capset, LONG);
SYSCALL(rt_sigpending, LONG);
SYSCALL(rt_sigtimedwait, LONG);
SYSCALL(rt_sigqueueinfo, LONG);
SYSCALL(rt_sigsuspend, LONG);
SYSCALL(sigaltstack, LONG);
SYSCALL(utime, LONG,
    "filename", "", DIR_IN, PCHAR,
    "times",    "", DIR_IN, PVOID,
);
// filetracer
SYSCALL(mknod, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "mode",     "", DIR_IN, LONG,
    "dev",      "", DIR_IN, LONG,
);
// end filetracer
SYSCALL(uselib, LONG,
    "library", "", DIR_IN, PCHAR,
);
SYSCALL(personality, LONG,
    "persona", "", DIR_IN, ULONG,
);
SYSCALL(ustat, LONG);
SYSCALL(statfs, LONG,
    "path", "", DIR_IN, PCHAR,
    "buf",  "", DIR_IN, PVOID,
);
SYSCALL(fstatfs, LONG,
    "fd",  "", DIR_IN, LONG,
    "buf", "", DIR_IN, PVOID,
);
SYSCALL(sysfs, LONG);
SYSCALL(getpriority, LONG,
    "which", "", DIR_IN, LONG,
    "who",   "", DIR_IN, LONG,
);
SYSCALL(setpriority, LONG,
    "which", "", DIR_IN, LONG,
    "who",   "", DIR_IN, LONG,
    "prio",  "", DIR_IN, LONG,
);
SYSCALL(sched_setparam, LONG,
    "pid",   "", DIR_IN, ULONG,
    "param", "", DIR_IN, PVOID,
);
SYSCALL(sched_getparam, LONG,
    "pid",   "", DIR_IN, ULONG,
    "param", "", DIR_IN, PVOID,
);
SYSCALL(sched_setscheduler, LONG,
    "pid",    "", DIR_IN, ULONG,
    "policy", "", DIR_IN, LONG,
    "param",  "", DIR_IN, PVOID,
);
SYSCALL(sched_getscheduler, LONG,
    "pid", "", DIR_IN, ULONG,
);
SYSCALL(sched_get_priority_max, LONG,
    "policy", "", DIR_IN, LONG,
);
SYSCALL(sched_get_priority_min, LONG,
    "policy", "", DIR_IN, LONG,
);
SYSCALL(sched_rr_get_interval, LONG,
    "pid", "", DIR_IN, ULONG,
    "tp",  "", DIR_IN, PVOID,
);
SYSCALL(mlock, LONG,
    "addr", "", DIR_IN, PVOID,
    "len",  "", DIR_IN, ULONG,
);
SYSCALL(munlock, LONG,
    "addr", "", DIR_IN, PVOID,
    "len",  "", DIR_IN, ULONG,
);
SYSCALL(mlockall, LONG,
    "flags", "", DIR_IN, LONG,
);
SYSCALL(munlockall, LONG);
SYSCALL(vhangup, LONG);
SYSCALL(modify_ldt, LONG);
SYSCALL(pivot_root, LONG,
    "new_root", "", DIR_IN, PCHAR,
    "put_old",  "", DIR_IN, PCHAR,
);
SYSCALL(_sysctl, LONG,
    "args", "", DIR_IN, PVOID,
);
SYSCALL(prctl, LONG,
    "option", "", DIR_IN, PRCTL_OPTION,
    "arg2",   "", DIR_IN, ULONG,
    "arg3",   "", DIR_IN, ULONG,
    "arg4",   "", DIR_IN, ULONG,
    "arg5",   "", DIR_IN, ULONG,
);
SYSCALL(arch_prctl, LONG,
    "code", "", DIR_IN, ARCH_PRCTL_CODE,
    "addr", "", DIR_IN, LONG,
);
SYSCALL(adjtimex, LONG,
    "buf", "", DIR_IN, PVOID,
);
SYSCALL(setrlimit, LONG,
    "resource", "", DIR_IN, LONG,
    "rlim",     "", DIR_IN, PVOID,
);
// filetracer
SYSCALL(chroot, LONG,
    "path", "", DIR_IN, PCHAR,
);
// end filetracer
SYSCALL(sync, VOID);
SYSCALL(acct, LONG,
    "filename", "", DIR_IN, PCHAR,
);
SYSCALL(settimeofday, LONG); // useless information
SYSCALL(mount, LONG,
    "source",         "", DIR_IN, PCHAR,
    "target",         "", DIR_IN, PCHAR,
    "filesystemtype", "", DIR_IN, PCHAR,
    "mountflags",     "", DIR_IN, ULONG,
    "data",           "", DIR_IN, PVOID,
);
SYSCALL(umount2, LONG,
    "target", "", DIR_IN, PCHAR,
    "flags",  "", DIR_IN, LONG,
);
SYSCALL(swapon, LONG,
    "path",      "", DIR_IN, PCHAR,
    "swapflags", "", DIR_IN, LONG,
);
SYSCALL(swapoff, LONG,
    "path", "", DIR_IN, PCHAR,
);
SYSCALL(reboot, LONG,
    "magic",  "", DIR_IN, LONG,
    "magic2", "", DIR_IN, LONG,
    "cmd",    "", DIR_IN, LONG,
    "arg",    "", DIR_IN, PVOID,
);
SYSCALL(sethostname, LONG,
    "name", "", DIR_IN, PCHAR,
    "len",  "", DIR_IN, ULONG,
);
SYSCALL(setdomainname, LONG,
    "name", "", DIR_IN, PCHAR,
    "len",  "", DIR_IN, ULONG,
);
SYSCALL(iopl, LONG,
    "level", "", DIR_IN, LONG,
);
SYSCALL(ioperm, LONG,
    "from",    "", DIR_IN, ULONG,
    "num",     "", DIR_IN, ULONG,
    "turn_on", "", DIR_IN, LONG,
);
SYSCALL(create_module, LONG,
    "name", "", DIR_IN, PCHAR,
    "size", "", DIR_IN, ULONG,
);
SYSCALL(init_module, LONG,
    "module_image", "", DIR_IN, PVOID,
    "len",          "", DIR_IN, ULONG,
    "param_values", "", DIR_IN, PCHAR,
);
SYSCALL(delete_module, LONG,
    "name",  "", DIR_IN, PCHAR,
    "flags", "", DIR_IN, ULONG,
);
SYSCALL(get_kernel_syms, LONG);
SYSCALL(query_module, LONG,
    "name",    "", DIR_IN, PCHAR,
    "wchich",  "", DIR_IN, LONG,
    "buf",     "", DIR_IN, PVOID,
    "bufsize", "", DIR_IN, ULONG,
    "ret",     "", DIR_IN, PULONG,
);
SYSCALL(quotactl, LONG,
    "cmd",     "", DIR_IN, LONG,
    "special", "", DIR_IN, PCHAR,
    "id",      "", DIR_IN, LONG,
    "addr",    "", DIR_IN, VOID,
);
SYSCALL(nfsservctl, LONG,
    "cmd",  "", DIR_IN, LONG,
    "argp", "", DIR_IN, PVOID,
    "resp", "", DIR_IN, PVOID,
);
SYSCALL(getpmsg, VOID);
SYSCALL(putpmsg, VOID);
SYSCALL(afs_syscall, VOID);
SYSCALL(tuxcall, VOID);
SYSCALL(security, VOID);
SYSCALL(gettid, LONG);
SYSCALL(readahead, LONG,
    "fd",     "", DIR_IN, LONG,
    "offset", "", DIR_IN, LONG,
    "count",  "", DIR_IN, ULONG,
);
SYSCALL(setxattr, LONG,
    "path",  "", DIR_IN, PCHAR,
    "name",  "", DIR_IN, PCHAR,
    "value", "", DIR_IN, PVOID,
    "size",  "", DIR_IN, ULONG,
    "flags", "", DIR_IN, LONG,
);
SYSCALL(lsetxattr, LONG,
    "path",  "", DIR_IN, PCHAR,
    "name",  "", DIR_IN, PCHAR,
    "value", "", DIR_IN, PVOID,
    "size",  "", DIR_IN, ULONG,
    "flags", "", DIR_IN, LONG,
);
SYSCALL(fsetxattr, LONG,
    "fd",    "", DIR_IN, PCHAR,
    "name",  "", DIR_IN, PCHAR,
    "value", "", DIR_IN, PVOID,
    "size",  "", DIR_IN, ULONG,
    "flags", "", DIR_IN, LONG,
);
SYSCALL(getxattr, LONG,
    "path",  "", DIR_IN, PCHAR,
    "name",  "", DIR_IN, PCHAR,
    "value", "", DIR_IN, PVOID,
    "size",  "", DIR_IN, ULONG,
);
SYSCALL(lgetxattr, LONG,
    "path",  "", DIR_IN, PCHAR,
    "name",  "", DIR_IN, PCHAR,
    "value", "", DIR_IN, PVOID,
    "size",  "", DIR_IN, ULONG,
);
SYSCALL(fgetxattr, LONG,
    "fd",    "", DIR_IN, PCHAR,
    "name",  "", DIR_IN, PCHAR,
    "value", "", DIR_IN, PVOID,
    "size",  "", DIR_IN, ULONG,
);
SYSCALL(listxattr, LONG,
    "path", "", DIR_IN, PCHAR,
    "list", "", DIR_INOUT, PCHAR,
    "size", "", DIR_IN, ULONG,
);
SYSCALL(llistxattr, LONG,
    "path", "", DIR_IN, PCHAR,
    "list", "", DIR_INOUT, PCHAR,
    "size", "", DIR_IN, ULONG,
);
SYSCALL(flistxattr, LONG,
    "fd",   "", DIR_IN, PCHAR,
    "list", "", DIR_INOUT, PCHAR,
    "size", "", DIR_IN, ULONG,
);
SYSCALL(removexattr, LONG,
    "path", "", DIR_IN, PCHAR,
    "name", "", DIR_IN, PCHAR,
);
SYSCALL(lremovexattr, LONG,
    "path", "", DIR_IN, PCHAR,
    "name", "", DIR_IN, PCHAR,
);
SYSCALL(fremovexattr, LONG,
    "fd",   "", DIR_IN, PCHAR,
    "name", "", DIR_IN, PCHAR,
);
SYSCALL(tkill, LONG,
    "pid", "", DIR_IN, LONG,
    "sig", "", DIR_IN, LONG,
);
SYSCALL(time, VOID);
SYSCALL(futex, VOID);
SYSCALL(sched_setaffinity, LONG);
SYSCALL(sched_getaffinity, LONG);
SYSCALL(set_thread_area, LONG);
SYSCALL(io_setup, LONG);
SYSCALL(io_destroy, LONG);
SYSCALL(io_getevents, LONG);
SYSCALL(io_submit, LONG);
SYSCALL(io_cancel, LONG);
SYSCALL(get_thread_area, LONG);
SYSCALL(lookup_dcookie, LONG);
SYSCALL(epoll_create, LONG);
SYSCALL(epoll_ctl_old, VOID);
SYSCALL(epoll_wait_old, VOID);
SYSCALL(remap_file_pages, VOID);
SYSCALL(getdents64, LONG,
    "fd",    "", DIR_IN, LONG,
    "dirp",  "", DIR_IN, PVOID,
    "count", "", DIR_IN, ULONG,
);
SYSCALL(set_tid_address, LONG);
SYSCALL(restart_syscall, LONG);
SYSCALL(semtimedop, VOID);
SYSCALL(fadvise64, VOID);
SYSCALL(timer_create, VOID);
SYSCALL(timer_settime, VOID);
SYSCALL(timer_gettime, VOID);
SYSCALL(timer_getoverrun, VOID);
SYSCALL(timer_delete, VOID);
SYSCALL(clock_settime, VOID);
SYSCALL(clock_gettime, VOID);
SYSCALL(clock_getres, VOID);
SYSCALL(clock_nanosleep, VOID);
SYSCALL(exit_group, VOID,
    "status", "", DIR_IN, LONG,
);
SYSCALL(epoll_wait, VOID);
SYSCALL(epoll_ctl, VOID);
SYSCALL(tgkill, LONG,
    "tgid", "", DIR_IN, LONG,
    "pid",  "", DIR_IN, LONG,
    "sig",  "", DIR_IN, LONG,
);
SYSCALL(utimes, LONG,
    "filename", "", DIR_IN, PCHAR,
    "times",    "", DIR_IN, PVOID,
);
SYSCALL(vserver, VOID);
SYSCALL(mbind, VOID);
SYSCALL(set_mempolicy, VOID);
SYSCALL(get_mempolicy, VOID);
SYSCALL(mq_open, VOID,
    "name",  "", DIR_IN, PCHAR,
    "oflag", "", DIR_IN, LONG,
);
SYSCALL(mq_unlink, LONG,
    "name",  "", DIR_IN, PCHAR,
);
SYSCALL(mq_timedsend, VOID);
SYSCALL(mq_timedreceive, VOID);
SYSCALL(mq_notify, VOID);
SYSCALL(mq_getsetattr, VOID);
SYSCALL(kexec_load, VOID);
SYSCALL(waitid, VOID);
SYSCALL(add_key, VOID,
    "type",        "", DIR_IN, PCHAR,
    "description", "", DIR_IN, PCHAR,
    "payload",     "", DIR_IN, PVOID,
    "plen",        "", DIR_IN, ULONG,
    "keyring",     "", DIR_IN, LONG,
);
SYSCALL(request_key, VOID,
    "type",         "", DIR_IN, PCHAR,
    "description",  "", DIR_IN, PCHAR,
    "callout_info", "", DIR_IN, PCHAR,
    "dest_keyring", "", DIR_IN, LONG,
);
SYSCALL(keyctl, LONG,
    "operation", "", DIR_IN, LONG,
    "arg2",      "", DIR_IN, ULONG,
    "arg3",      "", DIR_IN, ULONG,
    "arg4",      "", DIR_IN, ULONG,
    "arg5",      "", DIR_IN, ULONG,
);
SYSCALL(ioprio_set, VOID);
SYSCALL(ioprio_get, VOID);
SYSCALL(inotify_init, VOID);
SYSCALL(inotify_add_watch, LONG,
    "fd",       "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "mask",     "", DIR_IN, UINT,
);
SYSCALL(inotify_rm_watch, LONG,
    "fd", "", DIR_IN, LONG,
    "wd", "", DIR_IN, LONG,
);
SYSCALL(migrate_pages, LONG,
    "pid",       "", DIR_IN, LONG,
    "maxnode",   "", DIR_IN, ULONG,
    "old_nodes", "", DIR_IN, PULONG,
    "new_nodes", "", DIR_IN, PULONG,
);
SYSCALL(mkdirat, LONG,
    "dirfd",    "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "mode",     "", DIR_IN, ULONG,
);
SYSCALL(mknodat, LONG,
    "dirfd",     "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "mode",     "", DIR_IN, ULONG,
    "dev",      "", DIR_IN, ULONG,
);
SYSCALL(fchownat, LONG,
    "dirfd",    "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "owner",    "", DIR_IN, ULONG,
    "group",    "", DIR_IN, ULONG,
    "flags",    "", DIR_IN, LONG,
);
SYSCALL(futimesat, LONG,
    "dirfd",    "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "times",    "", DIR_IN, PVOID,
);
SYSCALL(newfstatat, LONG,
    "dirfd",    "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "statbuf",  "", DIR_IN, PVOID,
    "flags",    "", DIR_IN, LONG,
);
SYSCALL(unlinkat, LONG,
    "dirfd",    "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "flags",    "", DIR_IN, ULONG,
);
SYSCALL(renameat, LONG,
    "olddirfd", "", DIR_IN, LONG,
    "oldpath",  "", DIR_IN, PCHAR,
    "newdirfd", "", DIR_IN, LONG,
    "newpath",  "", DIR_IN, PCHAR,
);
SYSCALL(linkat, LONG,
    "olddirfd", "", DIR_IN, LONG,
    "oldpath",  "", DIR_IN, PCHAR,
    "newdirfd", "", DIR_IN, LONG,
    "newpath",  "", DIR_IN, PCHAR,
    "flags",    "", DIR_IN, LONG,
);
SYSCALL(symlinkat, LONG,
    "target",   "", DIR_IN, PCHAR,
    "newdirfd", "", DIR_IN, LONG,
    "linkpath", "", DIR_IN, PCHAR,
);
SYSCALL(readlinkat, LONG,
    "dirfd",    "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "buf",      "", DIR_INOUT, PCHAR,
    "bufsize",  "", DIR_IN, ULONG,
);
SYSCALL(fchmodat, LONG,
    "dirfd",    "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "mode",     "", DIR_IN, ULONG,
    "flags",    "", DIR_IN, LONG,
);
SYSCALL(faccessat, LONG,
    "dirfd",    "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "mode",     "", DIR_IN, LONG,
    "flags",    "", DIR_IN, LONG,
);
SYSCALL(pselect6, LONG);
SYSCALL(ppoll, LONG);
SYSCALL(unshare, LONG,
    "flags", "", DIR_IN, LONG,
);
SYSCALL(set_robust_list, VOID);
SYSCALL(get_robust_list, VOID);
SYSCALL(splice, VOID);
SYSCALL(tee, LONG,
    "fd_in",  "", DIR_IN, LONG,
    "fd_out", "", DIR_IN, LONG,
    "len",    "", DIR_IN, ULONG,
    "flags",  "", DIR_IN, ULONG,
);
SYSCALL(sync_file_range, VOID);
SYSCALL(vmsplice, VOID);
SYSCALL(move_pages, VOID);
SYSCALL(utimensat, LONG,
    "dirfd",    "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "times",    "", DIR_IN, PVOID,
    "flags",    "", DIR_IN, LONG,
);
SYSCALL(epoll_pwait, VOID);
SYSCALL(signalfd, VOID);
SYSCALL(timerfd_create, LONG,
    "clockid", "", DIR_IN, LONG,
    "flags",   "", DIR_IN, LONG,
);
SYSCALL(eventfd, LONG,
    "initval", "", DIR_IN, ULONG,
    "flags",   "", DIR_IN, LONG,
);
SYSCALL(fallocate, LONG,
    "fd",     "", DIR_IN, LONG,
    "mode",   "", DIR_IN, LONG,
    "offset", "", DIR_IN, ULONG,
    "len",    "", DIR_IN, ULONG,
);
SYSCALL(timerfd_settime, LONG,
    "fd",        "", DIR_IN, LONG,
    "flags",     "", DIR_IN, LONG,
    "new_value", "", DIR_IN, PVOID,
    "old_value", "", DIR_IN, PVOID,
);
SYSCALL(timerfd_gettime, LONG,
    "fd",         "", DIR_IN, LONG,
    "curr_value", "", DIR_IN, PVOID,
);
SYSCALL(accept4, LONG,
    "sockfd",  "", DIR_IN, LONG,
    "addr",    "", DIR_IN, PVOID,
    "addrlen", "", DIR_IN, PVOID,
    "flags",   "", DIR_IN, LONG,
);
SYSCALL(signalfd4, LONG);
SYSCALL(eventfd2, LONG,
    "initval", "", DIR_IN, LONG,
    "flags",   "", DIR_IN, LONG,
);
SYSCALL(epoll_create1, LONG,
    "flags", "", DIR_IN, LONG,
);
SYSCALL(dup3, LONG,
    "oldfd", "", DIR_IN, LONG,
    "newfd", "", DIR_IN, LONG,
    "flags", "", DIR_IN, LONG,
);
SYSCALL(pipe2, LONG);
SYSCALL(inotify_init1, LONG,
    "flags", "", DIR_IN, LONG,
);
SYSCALL(preadv, LONG);
SYSCALL(pwritev, LONG);
SYSCALL(rt_tgsigqueueinfo, LONG);
SYSCALL(perf_event_open, LONG);
SYSCALL(recvmmsg, LONG);
SYSCALL(fanotify_init, LONG,
    "flags",         "", DIR_IN, ULONG,
    "event_f_flags", "", DIR_IN, ULONG,
);
SYSCALL(fanotify_mark, LONG,
    "fanotify_id", "", DIR_IN, LONG,
    "flags",       "", DIR_IN, ULONG,
    "mask",        "", DIR_IN, ULONG,
    "dirfd",       "", DIR_IN, LONG,
    "pathname",    "", DIR_IN, PCHAR,
);
SYSCALL(prlimit64, LONG);
SYSCALL(name_to_handle_at, LONG,
    "dirfd",    "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "handle",   "", DIR_IN, PVOID,
    "mount_id", "", DIR_IN, PLONG,
    "flags",    "", DIR_IN, LONG,
);
SYSCALL(open_by_handle_at, LONG,
    "mount_fd", "", DIR_IN, LONG,
    "handle",   "", DIR_IN, PVOID,
    "flags",    "", DIR_IN, LONG,
);
SYSCALL(clock_adjtime, LONG);
SYSCALL(syncfs, LONG,
    "fd", "", DIR_IN, LONG,
);
SYSCALL(sendmmsg, LONG,
    "sockfd", "", DIR_IN, LONG,
    "msgvec", "", DIR_IN, PVOID,
    "vlen",   "", DIR_IN, ULONG,
    "flags",  "", DIR_IN, LONG,
);
SYSCALL(setns, LONG,
    "fd",     "", DIR_IN, LONG,
    "nstype", "", DIR_IN, LONG,
);
SYSCALL(getcpu, LONG);
SYSCALL(process_vm_readv, LONG,
    "pid", "", DIR_IN, LONG,
);
SYSCALL(process_vm_writev, LONG,
    "pid", "", DIR_IN, LONG,
);
SYSCALL(kcmp, LONG,
    "pid1", "", DIR_IN, LONG,
    "pid2", "", DIR_IN, LONG,
    "type", "", DIR_IN, LONG,
    "idx1", "", DIR_IN, ULONG,
    "idx2", "", DIR_IN, ULONG,
);
SYSCALL(finit_module, LONG,
    "fd",           "", DIR_IN, LONG,
    "param_values", "", DIR_IN, PCHAR,
    "flags",        "", DIR_IN, LONG,
);
SYSCALL(sched_setattr, LONG,
    "pid",   "", DIR_IN, LONG,
    "attr",  "", DIR_IN, PVOID,
    "flags", "", DIR_IN, ULONG,
);
SYSCALL(sched_getattr, LONG,
    "pid",   "", DIR_IN, LONG,
    "attr",  "", DIR_IN, PVOID,
    "size",  "", DIR_IN, ULONG,
    "flags", "", DIR_IN, ULONG,
);
// filetracer
SYSCALL(renameat2, LONG,
    "olddirfd", "", DIR_IN, LONG,
    "oldpath",  "", DIR_IN, PCHAR,
    "newdirfd", "", DIR_IN, LONG,
    "newpath",  "", DIR_IN, PCHAR,
    "flags",    "", DIR_IN, ULONG,
);
// end filetracer
SYSCALL(seccomp, LONG,
    "operation", "", DIR_IN, ULONG,
    "flags",     "", DIR_IN, ULONG,
    "args",      "", DIR_IN, PVOID,
);
SYSCALL(getrandom, VOID);
// filetracer
SYSCALL(memfd_create, LONG,
    "name",  "", DIR_IN, PCHAR,
    "flags", "", DIR_IN, ULONG,
);
// end filetracer
SYSCALL(kexec_file_load, LONG,
    "kernel_fd",   "", DIR_IN, LONG,
    "initrd_fd",   "", DIR_IN, LONG,
    "cmdline_len", "", DIR_IN, ULONG,
    "cmdline",     "", DIR_IN, PCHAR,
    "flags",       "",  DIR_IN, ULONG,
);
// ebpfmon
SYSCALL(bpf, LONG,
    "cmd",  "", DIR_IN, LONG,
    "attr", "", DIR_IN, PVOID,
    "size", "", DIR_IN, ULONG,
);
// ebpfmon
SYSCALL(execveat, VOID);
SYSCALL(userfaultfd, LONG,
    "flags", "", DIR_IN, LONG,
);
SYSCALL(membarrier, LONG);
SYSCALL(mlock2, LONG);
SYSCALL(copy_file_range, LONG);
SYSCALL(preadv2, LONG);
SYSCALL(pwritev2, LONG);
SYSCALL(pkey_mprotect, LONG,
    "addr", "", DIR_IN, PVOID,
    "len",  "", DIR_IN, ULONG,
    "prot", "", DIR_IN, LONG,
    "pkey", "", DIR_IN, LONG,
);
SYSCALL(pkey_alloc, LONG,
    "flags",         "", DIR_IN, ULONG,
    "access_rights", "", DIR_IN, ULONG,
);
SYSCALL(pkey_free, LONG,
    "pkey", "", DIR_IN, LONG,
);
SYSCALL(statx, LONG,
    "dirfd",    "", DIR_IN, LONG,
    "pathname", "", DIR_IN, PCHAR,
    "flags",    "", DIR_IN, ULONG,
    "mask",     "", DIR_IN, ULONG,
    "statxbuf", "", DIR_IN, PVOID,
);

#pragma clang diagnostic pop

static const syscall_t* linux_syscalls_table[] =
{
    [0] = &read,
    [1] = &write,
    [2] = &open,
    [3] = &close,
    [4] = &stat,
    [5] = &fstat,
    [6] = &lstat,
    [7] = &poll,
    [8] = &lseek,
    [9] = &mmap,
    [10] = &mprotect,
    [11] = &munmap,
    [12] = &brk,
    [13] = &rt_sigaction,
    [14] = &rt_sigprocmask,
    [15] = &rt_sigreturn,
    [16] = &ioctl,
    [17] = &pread64,
    [18] = &pwrite64,
    [19] = &readv,
    [20] = &writev,
    [21] = &access,
    [22] = &pipe,
    [23] = &select,
    [24] = &sched_yield,
    [25] = &mremap,
    [26] = &msync,
    [27] = &mincore,
    [28] = &madvise,
    [29] = &shmget,
    [30] = &shmat,
    [31] = &shmctl,
    [32] = &dup,
    [33] = &dup2,
    [34] = &pause,
    [35] = &nanosleep,
    [36] = &getitimer,
    [37] = &alarm,
    [38] = &setitimer,
    [39] = &getpid,
    [40] = &sendfile64,
    [41] = &socket,
    [42] = &connect,
    [43] = &accept,
    [44] = &sendto,
    [45] = &recvfrom,
    [46] = &sendmsg,
    [47] = &recvmsg,
    [48] = &shutdown,
    [49] = &bind,
    [50] = &listen,
    [51] = &getsockname,
    [52] = &getpeername,
    [53] = &socketpair,
    [54] = &setsockopt,
    [55] = &getsockopt,
    [56] = &clone,
    [57] = &fork,
    [58] = &vfork,
    [59] = &execve,
    [60] = &exit,
    [61] = &wait4,
    [62] = &kill,
    [63] = &uname,
    [64] = &semget,
    [65] = &semop,
    [66] = &semctl,
    [67] = &shmdt,
    [68] = &msgget,
    [69] = &msgsnd,
    [70] = &msgrcv,
    [71] = &msgctl,
    [72] = &fcntl,
    [73] = &flock,
    [74] = &fsync,
    [75] = &fdatasync,
    [76] = &truncate,
    [77] = &ftruncate,
    [78] = &getdents,
    [79] = &getcwd,
    [80] = &chdir,
    [81] = &fchdir,
    [82] = &rename,
    [83] = &mkdir,
    [84] = &rmdir,
    [85] = &creat,
    [86] = &link,
    [87] = &unlink,
    [88] = &symlink,
    [89] = &readlink,
    [90] = &chmod,
    [91] = &fchmod,
    [92] = &chown,
    [93] = &fchown,
    [94] = &lchown,
    [95] = &umask,
    [96] = &gettimeofday,
    [97] = &getrlimit,
    [98] = &getrusage,
    [99] = &sysinfo,
    [100] = &times,
    [101] = &ptrace,
    [102] = &getuid,
    [103] = &syslog,
    [104] = &getgid,
    [105] = &setuid,
    [106] = &setgid,
    [107] = &geteuid,
    [108] = &getegid,
    [109] = &setpgid,
    [110] = &getppid,
    [111] = &getpgrp,
    [112] = &setsid,
    [113] = &setreuid,
    [114] = &setregid,
    [115] = &getgroups,
    [116] = &setgroups,
    [117] = &setresuid,
    [118] = &getresuid,
    [119] = &setresgid,
    [120] = &getresgid,
    [121] = &getpgid,
    [122] = &setfsuid,
    [123] = &setfsgid,
    [124] = &getsid,
    [125] = &capget,
    [126] = &capset,
    [127] = &rt_sigpending,
    [128] = &rt_sigtimedwait,
    [129] = &rt_sigqueueinfo,
    [130] = &rt_sigsuspend,
    [131] = &sigaltstack,
    [132] = &utime,
    [133] = &mknod,
    [134] = &uselib,
    [135] = &personality,
    [136] = &ustat,
    [137] = &statfs,
    [138] = &fstatfs,
    [139] = &sysfs,
    [140] = &getpriority,
    [141] = &setpriority,
    [142] = &sched_setparam,
    [143] = &sched_getparam,
    [144] = &sched_setscheduler,
    [145] = &sched_getscheduler,
    [146] = &sched_get_priority_max,
    [147] = &sched_get_priority_min,
    [148] = &sched_rr_get_interval,
    [149] = &mlock,
    [150] = &munlock,
    [151] = &mlockall,
    [152] = &munlockall,
    [153] = &vhangup,
    [154] = &modify_ldt,
    [155] = &pivot_root,
    [156] = &_sysctl,
    [157] = &prctl,
    [158] = &arch_prctl,
    [159] = &adjtimex,
    [160] = &setrlimit,
    [161] = &chroot,
    [162] = &sync,
    [163] = &acct,
    [164] = &settimeofday,
    [165] = &mount,
    [166] = &umount2,
    [167] = &swapon,
    [168] = &swapoff,
    [169] = &reboot,
    [170] = &sethostname,
    [171] = &setdomainname,
    [172] = &iopl,
    [173] = &ioperm,
    [174] = &create_module,
    [175] = &init_module,
    [176] = &delete_module,
    [177] = &get_kernel_syms,
    [178] = &query_module,
    [179] = &quotactl,
    [180] = &nfsservctl,
    [181] = &getpmsg,
    [182] = &putpmsg,
    [183] = &afs_syscall,
    [184] = &tuxcall,
    [185] = &security,
    [186] = &gettid,
    [187] = &readahead,
    [188] = &setxattr,
    [189] = &lsetxattr,
    [190] = &fsetxattr,
    [191] = &getxattr,
    [192] = &lgetxattr,
    [193] = &fgetxattr,
    [194] = &listxattr,
    [195] = &llistxattr,
    [196] = &flistxattr,
    [197] = &removexattr,
    [198] = &lremovexattr,
    [199] = &fremovexattr,
    [200] = &tkill,
    [201] = &time,
    [202] = &futex,
    [203] = &sched_setaffinity,
    [204] = &sched_getaffinity,
    [205] = &set_thread_area,
    [206] = &io_setup,
    [207] = &io_destroy,
    [208] = &io_getevents,
    [209] = &io_submit,
    [210] = &io_cancel,
    [211] = &get_thread_area,
    [212] = &lookup_dcookie,
    [213] = &epoll_create,
    [214] = &epoll_ctl_old,
    [215] = &epoll_wait_old,
    [216] = &remap_file_pages,
    [217] = &getdents64,
    [218] = &set_tid_address,
    [219] = &restart_syscall,
    [220] = &semtimedop,
    [221] = &fadvise64,
    [222] = &timer_create,
    [223] = &timer_settime,
    [224] = &timer_gettime,
    [225] = &timer_getoverrun,
    [226] = &timer_delete,
    [227] = &clock_settime,
    [228] = &clock_gettime,
    [229] = &clock_getres,
    [230] = &clock_nanosleep,
    [231] = &exit_group,
    [232] = &epoll_wait,
    [233] = &epoll_ctl,
    [234] = &tgkill,
    [235] = &utimes,
    [236] = &vserver,
    [237] = &mbind,
    [238] = &set_mempolicy,
    [239] = &get_mempolicy,
    [240] = &mq_open,
    [241] = &mq_unlink,
    [242] = &mq_timedsend,
    [243] = &mq_timedreceive,
    [244] = &mq_notify,
    [245] = &mq_getsetattr,
    [246] = &kexec_load,
    [247] = &waitid,
    [248] = &add_key,
    [249] = &request_key,
    [250] = &keyctl,
    [251] = &ioprio_set,
    [252] = &ioprio_get,
    [253] = &inotify_init,
    [254] = &inotify_add_watch,
    [255] = &inotify_rm_watch,
    [256] = &migrate_pages,
    [257] = &openat,
    [258] = &mkdirat,
    [259] = &mknodat,
    [260] = &fchownat,
    [261] = &futimesat,
    [262] = &newfstatat,
    [263] = &unlinkat,
    [264] = &renameat,
    [265] = &linkat,
    [266] = &symlinkat,
    [267] = &readlinkat,
    [268] = &fchmodat,
    [269] = &faccessat,
    [270] = &pselect6,
    [271] = &ppoll,
    [272] = &unshare,
    [273] = &set_robust_list,
    [274] = &get_robust_list,
    [275] = &splice,
    [276] = &tee,
    [277] = &sync_file_range,
    [278] = &vmsplice,
    [279] = &move_pages,
    [280] = &utimensat,
    [281] = &epoll_pwait,
    [282] = &signalfd,
    [283] = &timerfd_create,
    [284] = &eventfd,
    [285] = &fallocate,
    [286] = &timerfd_settime,
    [287] = &timerfd_gettime,
    [288] = &accept4,
    [289] = &signalfd4,
    [290] = &eventfd2,
    [291] = &epoll_create1,
    [292] = &dup3,
    [293] = &pipe2,
    [294] = &inotify_init1,
    [295] = &preadv,
    [296] = &pwritev,
    [297] = &rt_tgsigqueueinfo,
    [298] = &perf_event_open,
    [299] = &recvmmsg,
    [300] = &fanotify_init,
    [301] = &fanotify_mark,
    [302] = &prlimit64,
    [303] = &name_to_handle_at,
    [304] = &open_by_handle_at,
    [305] = &clock_adjtime,
    [306] = &syncfs,
    [307] = &sendmmsg,
    [308] = &setns,
    [309] = &getcpu,
    [310] = &process_vm_readv,
    [311] = &process_vm_writev,
    [312] = &kcmp,
    [313] = &finit_module,
    [314] = &sched_setattr,
    [315] = &sched_getattr,
    [316] = &renameat2,
    [317] = &seccomp,
    [318] = &getrandom,
    [319] = &memfd_create,
    [320] = &kexec_file_load,
    [321] = &bpf,
    [322] = &execveat,
    [323] = &userfaultfd,
    [324] = &membarrier,
    [325] = &mlock2,
    [326] = &copy_file_range,
    [327] = &preadv2,
    [328] = &pwritev2,
    [329] = &pkey_mprotect,
    [330] = &pkey_alloc,
    [331] = &pkey_free,
    [332] = &statx,
};

// The actual max depends on the arch and actual kernel version
#define NUM_SYSCALLS_LINUX sizeof(linuxsc::linux_syscalls_table)/sizeof(syscall_t*)

}

}
#endif // SYSCALLS_LINUX_H
