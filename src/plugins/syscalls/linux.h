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
#ifndef SYSCALLS_LINUX_H
#define SYSCALLS_LINUX_H

#include "private.h"
#include "private_2.h"

class linux_syscalls : public syscalls_base
{
public:
    std::array<size_t, syscalls_ns::__PT_REGS_MAX> regs;
    std::unordered_map<uint64_t, std::unique_ptr<libhook::SyscallHook>> hooks;
    std::map<std::pair<uint64_t, addr_t>, std::unique_ptr<libhook::ReturnHook>> ret_hooks;

    // Helpers
    std::vector<uint64_t> build_arguments_buffer(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t pt_regs_addr, addr_t nr);
    bool get_pt_regs_addr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* pt_regs_addr, addr_t* nr);
    bool register_hook(char* syscall_name, uint64_t syscall_number, const syscalls_ns::syscall_t* syscall_definition, bool is_ret, bool is_x64);

    // Print information
    void print_syscall(drakvuf_t drakvuf, drakvuf_trap_info_t* info, std::vector<uint64_t> arguments, bool is_ret, std::optional<int> retcode);

    // Callbacks
    event_response_t linux_syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t linux_syscall_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t linux_sysret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

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

SYSCALL(read, linux_ssize_t,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("buf", "", DIR_INOUT, linux_void_ptr),
    ARG("count", "", DIR_IN, linux_size_t)
);
SYSCALL(write, linux_ssize_t,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("buf", "", DIR_IN, linux_void_ptr),
    ARG("count", "", DIR_IN, linux_size_t)
);
SYSCALL(open, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("flags", "", DIR_IN, linux_size_t),
    ARG("mode", "", DIR_IN, linux_mode_t)
);
SYSCALL(close, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
);
SYSCALL(openat, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("flags", "", DIR_IN, linux_int),
    ARG("mode", "", DIR_IN, linux_mode_t),
);
SYSCALL(stat, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("statbuf", "", DIR_OUT, linux_stat_ptr),
);
SYSCALL_EX(newstat, stat, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("statbuf", "", DIR_IN, linux_void_ptr),
);
SYSCALL(fstat, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("statbuf", "", DIR_OUT, linux_stat_ptr),
);
SYSCALL_EX(newfstat, fstat, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("statbuf", "", DIR_IN, linux_stat_ptr),
);
SYSCALL(lstat, linux_int,
    ARG("filename", "", DIR_IN, linux_char_ptr),
    ARG("statbuf", "", DIR_OUT, linux_stat_ptr),
);
SYSCALL_EX(newlstat, lstat, linux_int,
    ARG("filename", "", DIR_IN, linux_char_ptr),
    ARG("statbuf", "", DIR_IN, linux_stat_ptr),
);
SYSCALL(poll, linux_int,
    ARG("fds", "", DIR_OUT, linux_stat_ptr),
    ARG("nfds", "", DIR_IN, linux_nfds_t),
    ARG("timeout", "", DIR_IN, linux_int),
);
SYSCALL(lseek, linux_off_t,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("offset", "", DIR_IN, linux_off_t),
    ARG("whence", "", DIR_IN, linux_int),
);
SYSCALL(mmap, linux_void_ptr,
    ARG("addr", "", DIR_IN, linux_void_ptr),
    ARG("length", "", DIR_IN, linux_size_t),
    ARG("prot", "", DIR_IN, linux_intmask_prot_),
    ARG("flags", "", DIR_IN, linux_intmask_map_),
    ARG("fd", "", DIR_IN, linux_int),
    ARG("offset", "", DIR_IN, linux_off_t),
);
SYSCALL(mprotect, linux_int,
    ARG("start", "", DIR_IN, linux_size_t),
    ARG("len", "", DIR_IN, linux_size_t),
    ARG("prot", "", DIR_IN, linux_intmask_prot_),
);
SYSCALL(munmap, linux_int,
    ARG("addr", "", DIR_IN, linux_void_ptr),
    ARG("length", "", DIR_IN, linux_size_t),
);
SYSCALL(brk, linux_int,
    ARG("addr", "", DIR_IN, linux_void_ptr),
);
SYSCALL(rt_sigaction, linux_int,
    ARG("signum", "", DIR_IN, linux_int),
    ARG("act", "", DIR_IN, linux_sigaction_ptr),
    ARG("oldact", "", DIR_OUT, linux_sigaction_ptr),
);
SYSCALL(rt_sigprocmask, linux_int,
    ARG("how", "", DIR_IN, linux_int),
    ARG("set", "", DIR_IN, linux_sigset_t_ptr),
    ARG("oldset", "", DIR_OUT, linux_sigset_t_ptr),
);
SYSCALL(rt_sigreturn, linux_int);
SYSCALL(ioctl, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("request", "", DIR_IN, linux_int),
);
SYSCALL(pread64, linux_ssize_t,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("buf", "", DIR_INOUT, linux_void_ptr),
    ARG("count", "", DIR_IN, linux_size_t),
    ARG("offset", "", DIR_IN, linux_off64_t),
);
SYSCALL(pwrite64, linux_ssize_t,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("buf", "", DIR_IN, linux_void_ptr),
    ARG("count", "", DIR_IN, linux_size_t),
    ARG("offset", "", DIR_IN, linux_off64_t),
);
SYSCALL(readv, linux_ssize_t,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("iov", "", DIR_IN, linux_iovec_ptr),
    ARG("iovcnt", "", DIR_IN, linux_int),
);
SYSCALL(writev, linux_ssize_t,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("iov", "", DIR_IN, linux_iovec_ptr),
    ARG("iovcnt", "", DIR_IN, linux_int),
);
SYSCALL(access, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("mode", "", DIR_IN, linux_int),
);
SYSCALL(pipe, linux_int,
    ARG("pipefd", "", DIR_IN, linux_void_ptr), // int[2]
);
SYSCALL(select, linux_int,
    ARG("nfds", "", DIR_IN, linux_int),
    ARG("readfds", "", DIR_IN, linux_fd_set_ptr),
    ARG("writefds", "", DIR_IN, linux_fd_set_ptr),
    ARG("exceptfds", "", DIR_IN, linux_fd_set_ptr),
    ARG("timeout", "", DIR_IN, linux_timeval_ptr),
);
SYSCALL(sched_yield, linux_int);
SYSCALL(mremap, linux_void_ptr,
    ARG("old_address", "", DIR_IN, linux_void_ptr),
    ARG("old_size", "", DIR_IN, linux_size_t),
    ARG("new_size", "", DIR_IN, linux_size_t),
    ARG("flags", "", DIR_IN, linux_unsigned_long),
);
SYSCALL(msync, linux_int,
    ARG("addr", "", DIR_IN, linux_void_ptr),
    ARG("length", "", DIR_IN, linux_size_t),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(mincore, linux_int,
    ARG("addr", "", DIR_IN, linux_void_ptr),
    ARG("length", "", DIR_IN, linux_size_t),
    ARG("vec", "", DIR_OUT, linux_void_ptr), // unsigned char [length]
);
SYSCALL(madvise, linux_int,
    ARG("addr", "", DIR_IN, linux_void_ptr),
    ARG("length", "", DIR_IN, linux_size_t),
    ARG("advice", "", DIR_IN, linux_int),
);
SYSCALL(shmget, linux_int,
    ARG("key", "", DIR_IN, linux_key_t),
    ARG("size", "", DIR_IN, linux_int),
    ARG("shmflg", "", DIR_IN, linux_int),
);
SYSCALL(shmat, linux_void_ptr,
    ARG("shmid", "", DIR_IN, linux_int),
    ARG("shmaddr", "", DIR_IN, linux_void_ptr),
    ARG("shmflg", "", DIR_IN, linux_int),
);
SYSCALL(shmctl, linux_int,
    ARG("shmid", "", DIR_IN, linux_int),
    ARG("cmd", "", DIR_IN, linux_int),
    ARG("buf", "", DIR_IN, linux_shmid_ds_ptr),
);
SYSCALL(dup, linux_int,
    ARG("oldfd", "", DIR_IN, linux_int)
);
SYSCALL(dup2, linux_int,
    ARG("oldfd", "", DIR_IN, linux_int),
    ARG("newfd", "", DIR_IN, linux_int),
);
SYSCALL(pause, linux_int);
// A very expensive syscall, the interception of which will greatly slow down the guest
// It is recommended to exclude it using the filter file
SYSCALL(nanosleep, linux_int,
    ARG("req", "", DIR_IN, linux_void_ptr),
    ARG("rem", "", DIR_IN, linux_void_ptr),
);
SYSCALL(getitimer, linux_int,
    ARG("which", "", DIR_IN, linux_int),
    ARG("curr_value", "", DIR_INOUT, linux_void_ptr),
);
SYSCALL(alarm, linux_size_t,
    ARG("seconds", "", DIR_IN, linux_size_t),
);
SYSCALL(setitimer, linux_int,
    ARG("which", "", DIR_IN, linux_int),
    ARG("new_value", "", DIR_IN, linux_timespec_ptr),
    ARG("old_value", "", DIR_OUT, linux_timespec_ptr),
);
SYSCALL(getpid, linux_pid_t);
SYSCALL(sendfile64, linux_ssize_t,
    ARG("out_fd", "", DIR_IN, linux_int),
    ARG("in_fd", "", DIR_IN, linux_int),
    ARG("offset", "", DIR_IN, linux_off64_t_ptr),
    ARG("count", "", DIR_IN, linux_size_t),
);
SYSCALL(socket, linux_int,
    ARG("domain", "", DIR_IN, linux_int),
    ARG("type", "", DIR_IN, linux_int),
    ARG("protocol", "", DIR_IN, linux_int),
);
SYSCALL(connect, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("addr", "", DIR_IN, linux_sockaddr_ptr),
    ARG("addrlen", "", DIR_IN, linux_socklen_t),
);
SYSCALL(accept, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("addr", "", DIR_IN, linux_sockaddr_ptr),
    ARG("addrlen", "", DIR_IN, linux_socklen_t_ptr),
);
SYSCALL(sendto, linux_ssize_t,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("buf", "", DIR_IN, linux_void_ptr),
    ARG("len", "", DIR_IN, linux_size_t),
    ARG("flags", "", DIR_IN, linux_int),
    ARG("dest_addr", "", DIR_IN, linux_sockaddr_ptr),
    ARG("addrlen", "", DIR_IN, linux_socklen_t),
);
SYSCALL(recvfrom, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("buf", "", DIR_IN, linux_void_ptr),
    ARG("len", "", DIR_IN, linux_size_t),
    ARG("flags", "", DIR_IN, linux_int),
    ARG("src_addr", "", DIR_IN, linux_sockaddr_ptr),
    ARG("addrlen", "", DIR_IN, linux_socklen_t_ptr),
);
SYSCALL(sendmsg, linux_ssize_t,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("msg", "", DIR_IN, linux_msghdr_ptr),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(recvmsg, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("msg", "", DIR_INOUT, linux_msghdr_ptr),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(shutdown, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("how", "", DIR_IN, linux_int),
);
SYSCALL(bind, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("addr", "", DIR_IN, linux_sockaddr_ptr),
    ARG("addrlen", "", DIR_IN, linux_socklen_t),
);
SYSCALL(listen, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("backlog", "", DIR_IN, linux_int),
);
SYSCALL(getsockname, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("addr", "", DIR_OUT, linux_sockaddr_ptr),
    ARG("addrlen", "", DIR_OUT, linux_socklen_t_ptr),
);
SYSCALL(getpeername, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("addr", "", DIR_OUT, linux_sockaddr_ptr),
    ARG("addrlen", "", DIR_OUT, linux_socklen_t_ptr),
);
SYSCALL(socketpair, linux_int,
    ARG("domain", "", DIR_IN, linux_int),
    ARG("type", "", DIR_IN, linux_int),
    ARG("protocol", "", DIR_IN, linux_int),
    ARG("sv", "", DIR_IN, linux_void_ptr), // int[2]
);
SYSCALL(setsockopt, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("level", "", DIR_IN, linux_int),
    ARG("optname", "", DIR_IN, linux_int),
    ARG("optval", "", DIR_IN, linux_void_ptr),
    ARG("optlen", "", DIR_IN, linux_socklen_t),
);
SYSCALL(getsockopt, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("level", "", DIR_IN, linux_int),
    ARG("optname", "", DIR_IN, linux_int),
    ARG("optval", "", DIR_OUT, linux_void_ptr),
    ARG("optlen", "", DIR_OUT, linux_socklen_t_ptr),
);
// We can ignore these syscalls because there is a better interpretation going on in the procmon plugin
// procmon
SYSCALL(clone, linux_void);
SYSCALL(fork, linux_void);
SYSCALL(vfork, linux_void);
SYSCALL(execve, linux_void);
SYSCALL(exit, linux_void);
// end procmon
SYSCALL(wait4, linux_pid_t,
    ARG("pid", "", DIR_IN, linux_pid_t),
    ARG("wstatus", "", DIR_IN, linux_int_ptr),
    ARG("options", "", DIR_IN, linux_int),
    ARG("rusage", "", DIR_IN, linux_rusage_ptr),
);
SYSCALL(kill, linux_int,
    ARG("pid", "", DIR_IN, linux_pid_t),
    ARG("sig", "", DIR_IN, linux_int),
);
SYSCALL(uname, linux_int);
SYSCALL(semget, linux_int,
    ARG("key", "", DIR_IN, linux_key_t),
    ARG("nsems", "", DIR_IN, linux_int),
    ARG("semflg", "", DIR_IN, linux_int),
);
SYSCALL(semop, linux_int,
    ARG("semid", "", DIR_IN, linux_int),
    ARG("sops", "", DIR_IN, linux_sembuf_ptr),
    ARG("nsops", "", DIR_IN, linux_unsigned),
);
SYSCALL(semctl, linux_int,
    ARG("semid", "", DIR_IN, linux_int),
    ARG("semnum", "", DIR_IN, linux_int),
    ARG("cmd", "", DIR_IN, linux_int),
);
SYSCALL(shmdt, linux_void);
SYSCALL(msgget, linux_void);
SYSCALL(msgsnd, linux_void);
SYSCALL(msgrcv, linux_void);
SYSCALL(msgctl, linux_void);
SYSCALL(fcntl, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("cmd", "", DIR_IN, linux_int),
);
SYSCALL(flock, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("operation", "", DIR_IN, linux_int),
);
SYSCALL(fsync, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
);
SYSCALL(fdatasync, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
);
SYSCALL(truncate, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("length", "", DIR_IN, linux_off_t),
);
SYSCALL(ftruncate, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("length", "", DIR_IN, linux_off_t),
);
SYSCALL(getdents, linux_int,
    ARG("fd", "", DIR_IN, linux_unsigned_int),
    ARG("dirp", "", DIR_OUT, linux_dirent_ptr),
    ARG("count", "", DIR_IN, linux_unsigned_int),
);
SYSCALL(getcwd, linux_char_ptr);
SYSCALL(chdir, linux_int,
    ARG("path", "", DIR_IN, linux_char_ptr),
);
SYSCALL(fchdir, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
);
// filetracer
SYSCALL(rename, linux_int,
    ARG("oldpath", "", DIR_IN, linux_char_ptr),
    ARG("newpath", "", DIR_IN, linux_char_ptr),
);
SYSCALL(mkdir, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("mode", "", DIR_IN, linux_mode_t),
);
SYSCALL(rmdir, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
);
SYSCALL(creat, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("mode", "", DIR_IN, linux_mode_t),
);
SYSCALL(link, linux_int,
    ARG("oldpath", "", DIR_IN, linux_char_ptr),
    ARG("newpath", "", DIR_IN, linux_char_ptr),
);
SYSCALL(unlink, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
);
SYSCALL(symlink, linux_int,
    ARG("target", "", DIR_IN, linux_char_ptr),
    ARG("linkpath", "", DIR_IN, linux_char_ptr),
);
SYSCALL(readlink, linux_ssize_t,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("buf", "", DIR_OUT, linux_char_ptr),
    ARG("bufsiz", "", DIR_IN, linux_size_t),
);
SYSCALL(chmod, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("mode", "", DIR_IN, linux_mode_t),
);
SYSCALL(fchmod, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("mode", "", DIR_IN, linux_mode_t),
);
SYSCALL(chown, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("owner", "", DIR_IN, linux_uid_t),
    ARG("group", "", DIR_IN, linux_gid_t),
);
SYSCALL(fchown, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("owner", "", DIR_IN, linux_uid_t),
    ARG("group", "", DIR_IN, linux_gid_t),
);
SYSCALL(lchown, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("owner", "", DIR_IN, linux_uid_t),
    ARG("group", "", DIR_IN, linux_gid_t),
);
// end filetracer
SYSCALL(umask, linux_mode_t,
    ARG("mask", "", DIR_IN, linux_mode_t),
);
SYSCALL(gettimeofday, linux_int);
SYSCALL(getrlimit, linux_int);
SYSCALL(getrusage, linux_int);
SYSCALL(sysinfo, linux_int);
SYSCALL(times, linux_clock_t);
// ptracemon
SYSCALL(ptrace, linux_long,
    ARG("request", "", DIR_IN, linux_ptrace_request),
    ARG("pid", "", DIR_IN, linux_pid_t),
    ARG("addr", "", DIR_IN, linux_void_ptr),
    ARG("data", "", DIR_IN, linux_void_ptr),
);
// end ptracemon
SYSCALL(getuid, linux_uid_t);
SYSCALL(syslog, linux_int,
    ARG("type", "", DIR_IN, linux_int),
    ARG("bufp", "", DIR_IN, linux_char_ptr),
    ARG("len", "", DIR_IN, linux_int),
);
SYSCALL(getgid, linux_gid_t);
SYSCALL(setuid, linux_int,
    ARG("uid", "", DIR_IN, linux_uid_t),
);
SYSCALL(setgid, linux_int,
    ARG("gid", "", DIR_IN, linux_gid_t),
);
SYSCALL(geteuid, linux_uid_t);
SYSCALL(getegid, linux_gid_t);
SYSCALL(setpgid, linux_int,
    ARG("pid", "", DIR_IN, linux_pid_t),
    ARG("pgid", "", DIR_IN, linux_pid_t),
);
SYSCALL(getppid, linux_pid_t);
SYSCALL(getpgrp, linux_pid_t);
SYSCALL(setsid, linux_pid_t);
SYSCALL(setreuid, linux_int,
    ARG("ruid", "", DIR_IN, linux_uid_t),
    ARG("euid", "", DIR_IN, linux_uid_t),
);
SYSCALL(setregid, linux_int,
    ARG("rgid", "", DIR_IN, linux_gid_t),
    ARG("egid", "", DIR_IN, linux_gid_t),
);
SYSCALL(getgroups, linux_int);
SYSCALL(setgroups, linux_int);
SYSCALL(setresuid, linux_int,
    ARG("ruid", "", DIR_IN, linux_uid_t),
    ARG("euid", "", DIR_IN, linux_uid_t),
    ARG("suid", "", DIR_IN, linux_uid_t),
);
SYSCALL(getresuid, linux_int);
SYSCALL(setresgid, linux_int,
    ARG("rgid", "", DIR_IN, linux_gid_t),
    ARG("egid", "", DIR_IN, linux_gid_t),
    ARG("sgid", "", DIR_IN, linux_gid_t),
);
SYSCALL(getresgid, linux_int);
SYSCALL(getpgid, linux_pid_t);
SYSCALL(setfsuid, linux_int,
    ARG("fsuid", "", DIR_IN, linux_uid_t),
);
SYSCALL(setfsgid, linux_int,
    ARG("fsgid", "", DIR_IN, linux_gid_t),
);
SYSCALL(getsid, linux_pid_t);
SYSCALL(capget, linux_int);
SYSCALL(capset, linux_int);
SYSCALL(rt_sigpending, linux_int);
SYSCALL(rt_sigtimedwait, linux_int);
SYSCALL(rt_sigqueueinfo, linux_int);
SYSCALL(rt_sigsuspend, linux_int);
SYSCALL(sigaltstack, linux_int);
SYSCALL(utime, linux_int,
    ARG("filename", "", DIR_IN, linux_char_ptr),
    ARG("times", "", DIR_IN, linux_utimbuf_ptr),
);
// filetracer
SYSCALL(mknod, linux_int,
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("mode", "", DIR_IN, linux_mode_t),
    ARG("dev", "", DIR_IN, linux_dev_t),
);
// end filetracer
SYSCALL(uselib, linux_int,
    ARG("library", "", DIR_IN, linux_char_ptr),
);
SYSCALL(personality, linux_int,
    ARG("persona", "", DIR_IN, linux_unsigned_long),
);
SYSCALL(ustat, linux_int);
SYSCALL(statfs, linux_int,
    ARG("path", "", DIR_IN, linux_char_ptr),
    ARG("buf", "", DIR_OUT, linux_statfs_ptr),
);
SYSCALL(fstatfs, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("buf", "", DIR_OUT, linux_statfs_ptr),
);
SYSCALL(sysfs, linux_int);
SYSCALL(getpriority, linux_int,
    ARG("which", "", DIR_IN, linux_int),
    ARG("who", "", DIR_IN, linux_int),
);
SYSCALL(setpriority, linux_int,
    ARG("which", "", DIR_IN, linux_int),
    ARG("who", "", DIR_IN, linux_int),
    ARG("prio", "", DIR_IN, linux_int),
);
SYSCALL(sched_setparam, linux_int,
    ARG("pid", "", DIR_IN, linux_pid_t),
    ARG("param", "", DIR_IN, linux_sched_param_ptr),
);
SYSCALL(sched_getparam, linux_int,
    ARG("pid", "", DIR_IN, linux_pid_t),
    ARG("param", "", DIR_OUT, linux_sched_param_ptr),
);
SYSCALL(sched_setscheduler, linux_int,
    ARG("pid", "", DIR_IN, linux_pid_t),
    ARG("policy", "", DIR_IN, linux_int),
    ARG("param", "", DIR_IN, linux_sched_param_ptr),
);
SYSCALL(sched_getscheduler, linux_int,
    ARG("pid", "", DIR_IN, linux_pid_t),
);
SYSCALL(sched_get_priority_max, linux_int,
    ARG("policy", "", DIR_IN, linux_int),
);
SYSCALL(sched_get_priority_min, linux_int,
    ARG("policy", "", DIR_IN, linux_int),
);
SYSCALL(sched_rr_get_interval, linux_int,
    ARG("pid", "", DIR_IN, linux_pid_t),
    ARG("tp", "", DIR_OUT, linux_timespec_ptr),
);
SYSCALL(mlock, linux_int,
    ARG("addr", "", DIR_IN, linux_void_ptr),
    ARG("len", "", DIR_IN, linux_size_t),
);
SYSCALL(munlock, linux_int,
    ARG("addr", "", DIR_IN, linux_void_ptr),
    ARG("len", "", DIR_IN, linux_size_t),
);
SYSCALL(mlockall, linux_int,
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(munlockall, linux_int);
SYSCALL(vhangup, linux_int);
SYSCALL(modify_ldt, linux_int);
SYSCALL(pivot_root, linux_int,
    ARG("new_root", "", DIR_IN, linux_char_ptr),
    ARG("put_old", "", DIR_IN, linux_char_ptr),
);
SYSCALL(_sysctl, linux_int,
    ARG("args", "", DIR_IN, linux_sysctl_args_ptr),
);
SYSCALL(prctl, linux_int,
    ARG("option", "", DIR_IN, linux_intopt_pr_),
    ARG("arg2", "", DIR_IN, linux_unsigned_long),
    ARG("arg3", "", DIR_IN, linux_unsigned_long),
    ARG("arg4", "", DIR_IN, linux_unsigned_long),
    ARG("arg5", "", DIR_IN, linux_unsigned_long),
);
SYSCALL(arch_prctl, linux_int,
    ARG("code", "", DIR_IN, linux_intopt_arch_),
    ARG("addr", "", DIR_IN, linux_unsigned_long),
);
SYSCALL(adjtimex, linux_int,
    ARG("buf", "", DIR_IN, linux_timex_ptr),
);
SYSCALL(setrlimit, linux_int,
    ARG("resource", "", DIR_IN, linux_int),
    ARG("rlim", "", DIR_IN, linux_rlimit_ptr),
);
// filetracer
SYSCALL(chroot, linux_int,
    ARG("path", "", DIR_IN, linux_char_ptr),
);
// end filetracer
SYSCALL(sync, linux_void);
SYSCALL(acct, linux_int,
    ARG("filename", "", DIR_IN, linux_char_ptr),
);
SYSCALL(settimeofday, linux_int); // useless information
SYSCALL(mount, linux_int,
    ARG("source", "", DIR_IN, linux_char_ptr),
    ARG("target", "", DIR_IN, linux_char_ptr),
    ARG("filesystemtype", "", DIR_IN, linux_char_ptr),
    ARG("mountflags", "", DIR_IN, linux_unsigned_long),
    ARG("data", "", DIR_IN, linux_void_ptr),
);
SYSCALL(umount2, linux_int,
    ARG("target", "", DIR_IN, linux_char_ptr),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(swapon, linux_int,
    ARG("path", "", DIR_IN, linux_char_ptr),
    ARG("swapflags", "", DIR_IN, linux_int),
);
SYSCALL(swapoff, linux_int,
    ARG("path", "", DIR_IN, linux_char_ptr),
);
SYSCALL(reboot, linux_int,
    ARG("magic", "", DIR_IN, linux_int),
    ARG("magic2", "", DIR_IN, linux_int),
    ARG("cmd", "", DIR_IN, linux_int),
    ARG("arg", "", DIR_IN, linux_void_ptr),
);
SYSCALL(sethostname, linux_int,
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("len", "", DIR_IN, linux_size_t),
);
SYSCALL(setdomainname, linux_int,
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("len", "", DIR_IN, linux_size_t),
);
SYSCALL(iopl, linux_int,
    ARG("level", "", DIR_IN, linux_int),
);
SYSCALL(ioperm, linux_int,
    ARG("from", "", DIR_IN, linux_unsigned_long),
    ARG("num", "", DIR_IN, linux_unsigned_long),
    ARG("turn_on", "", DIR_IN, linux_int),
);
SYSCALL(create_module, linux_caddr_t,
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("size", "", DIR_IN, linux_size_t),
);
SYSCALL(init_module, linux_int,
    ARG("module_image", "", DIR_IN, linux_void_ptr),
    ARG("len", "", DIR_IN, linux_size_t),
    ARG("param_values", "", DIR_IN, linux_char_ptr),
);
SYSCALL(delete_module, linux_int,
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("flags", "", DIR_IN, linux_size_t),
);
SYSCALL(get_kernel_syms, linux_int);
SYSCALL(query_module, linux_int,
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("wchich", "", DIR_IN, linux_int),
    ARG("buf", "", DIR_INOUT, linux_void_ptr),
    ARG("bufsize", "", DIR_IN, linux_size_t),
    ARG("ret", "", DIR_OUT, linux_size_t_ptr),
);
SYSCALL(quotactl, linux_int,
    ARG("cmd", "", DIR_IN, linux_int),
    ARG("special", "", DIR_IN, linux_char_ptr),
    ARG("id", "", DIR_IN, linux_int),
    ARG("addr", "", DIR_IN, linux_caddr_t),
);
SYSCALL(nfsservctl, linux_int,
    ARG("cmd", "", DIR_IN, linux_int),
    ARG("argp", "", DIR_IN, linux_nfsctl_arg_ptr),
    ARG("resp", "", DIR_IN, linux_nfsctl_res_ptr),
);
SYSCALL(getpmsg, linux_void);
SYSCALL(putpmsg, linux_void);
SYSCALL(afs_syscall, linux_void);
SYSCALL(tuxcall, linux_void);
SYSCALL(security, linux_void);
SYSCALL(gettid, linux_pid_t);
SYSCALL(readahead, linux_ssize_t,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("offset", "", DIR_IN, linux_off64_t),
    ARG("count", "", DIR_IN, linux_size_t),
);
SYSCALL(setxattr, linux_int,
    ARG("path", "", DIR_IN, linux_char_ptr),
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("value", "", DIR_IN, linux_void_ptr),
    ARG("size", "", DIR_IN, linux_size_t),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(lsetxattr, linux_int,
    ARG("path", "", DIR_IN, linux_char_ptr),
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("value", "", DIR_IN, linux_void_ptr),
    ARG("size", "", DIR_IN, linux_size_t),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(fsetxattr, linux_int,
    ARG("fd", "", DIR_IN, linux_char_ptr),
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("value", "", DIR_IN, linux_void_ptr),
    ARG("size", "", DIR_IN, linux_size_t),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(getxattr, linux_ssize_t,
    ARG("path", "", DIR_IN, linux_char_ptr),
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("value", "", DIR_INOUT, linux_void_ptr),
    ARG("size", "", DIR_IN, linux_size_t),
);
SYSCALL(lgetxattr, linux_ssize_t,
    ARG("path", "", DIR_IN, linux_char_ptr),
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("value", "", DIR_INOUT, linux_void_ptr),
    ARG("size", "", DIR_IN, linux_size_t),
);
SYSCALL(fgetxattr, linux_ssize_t,
    ARG("fd", "", DIR_IN, linux_char_ptr),
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("value", "", DIR_INOUT, linux_void_ptr),
    ARG("size", "", DIR_IN, linux_size_t),
);
SYSCALL(listxattr, linux_ssize_t,
    ARG("path", "", DIR_IN, linux_char_ptr),
    ARG("list", "", DIR_INOUT, linux_char_ptr),
    ARG("size", "", DIR_IN, linux_size_t),
);
SYSCALL(llistxattr, linux_ssize_t,
    ARG("path", "", DIR_IN, linux_char_ptr),
    ARG("list", "", DIR_INOUT, linux_char_ptr),
    ARG("size", "", DIR_IN, linux_size_t),
);
SYSCALL(flistxattr, linux_ssize_t,
    ARG("fd", "", DIR_IN, linux_char_ptr),
    ARG("list", "", DIR_INOUT, linux_char_ptr),
    ARG("size", "", DIR_IN, linux_size_t),
);
SYSCALL(removexattr, linux_int,
    ARG("path", "", DIR_IN, linux_char_ptr),
    ARG("name", "", DIR_IN, linux_char_ptr),
);
SYSCALL(lremovexattr, linux_int,
    ARG("path", "", DIR_IN, linux_char_ptr),
    ARG("name", "", DIR_IN, linux_char_ptr),
);
SYSCALL(fremovexattr, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("name", "", DIR_IN, linux_char_ptr),
);
SYSCALL(tkill, linux_int,
    ARG("pid", "", DIR_IN, linux_pid_t),
    ARG("sig", "", DIR_IN, linux_int),
);
SYSCALL(time, linux_void);
SYSCALL(futex, linux_void);
SYSCALL(sched_setaffinity, linux_int);
SYSCALL(sched_getaffinity, linux_int);
SYSCALL(set_thread_area, linux_int);
SYSCALL(io_setup, linux_int);
SYSCALL(io_destroy, linux_int);
SYSCALL(io_getevents, linux_int);
SYSCALL(io_submit, linux_int);
SYSCALL(io_cancel, linux_int);
SYSCALL(get_thread_area, linux_int);
SYSCALL(lookup_dcookie, linux_int);
SYSCALL(epoll_create, linux_int);
SYSCALL(epoll_ctl_old, linux_void);
SYSCALL(epoll_wait_old, linux_void);
SYSCALL(remap_file_pages, linux_void);
SYSCALL(getdents64, linux_int,
    ARG("fd", "", DIR_IN, linux_unsigned_int),
    ARG("dirp", "", DIR_OUT, linux_linux_dirent64_ptr),
    ARG("count", "", DIR_IN, linux_unsigned_int),
);
SYSCALL(set_tid_address, linux_int);
SYSCALL(restart_syscall, linux_int);
SYSCALL(semtimedop, linux_void);
SYSCALL(fadvise64, linux_void);
SYSCALL(timer_create, linux_void);
SYSCALL(timer_settime, linux_void);
SYSCALL(timer_gettime, linux_void);
SYSCALL(timer_getoverrun, linux_void);
SYSCALL(timer_delete, linux_void);
SYSCALL(clock_settime, linux_void);
SYSCALL(clock_gettime, linux_void);
SYSCALL(clock_getres, linux_void);
SYSCALL(clock_nanosleep, linux_void);
SYSCALL(exit_group, linux_void,
    ARG("status", "", DIR_IN, linux_int),
);
SYSCALL(epoll_wait, linux_void);
SYSCALL(epoll_ctl, linux_void);
SYSCALL(tgkill, linux_int,
    ARG("tgid", "", DIR_IN, linux_int),
    ARG("pid", "", DIR_IN, linux_int),
    ARG("sig", "", DIR_IN, linux_int),
);
SYSCALL(utimes, linux_int,
    ARG("filename", "", DIR_IN, linux_char_ptr),
    ARG("times", "", DIR_IN, linux_void_ptr), // struct timeval[2]
);
SYSCALL(vserver, linux_void);
SYSCALL(mbind, linux_void);
SYSCALL(set_mempolicy, linux_void);
SYSCALL(get_mempolicy, linux_void);
SYSCALL(mq_open, linux_void,
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("oflag", "", DIR_IN, linux_int),
);
SYSCALL(mq_unlink, linux_int,
    ARG("name", "", DIR_IN, linux_char_ptr),
);
SYSCALL(mq_timedsend, linux_void);
SYSCALL(mq_timedreceive, linux_void);
SYSCALL(mq_notify, linux_void);
SYSCALL(mq_getsetattr, linux_void);
SYSCALL(kexec_load, linux_void);
SYSCALL(waitid, linux_void);
SYSCALL(add_key, linux_key_serial_t,
    ARG("type", "", DIR_IN, linux_char_ptr),
    ARG("description", "", DIR_IN, linux_char_ptr),
    ARG("payload", "", DIR_IN, linux_void_ptr),
    ARG("plen", "", DIR_IN, linux_size_t),
    ARG("keyring", "", DIR_IN, linux_key_serial_t),
);
SYSCALL(request_key, linux_key_serial_t,
    ARG("type", "", DIR_IN, linux_char_ptr),
    ARG("description", "", DIR_IN, linux_char_ptr),
    ARG("callout_info", "", DIR_IN, linux_char_ptr),
    ARG("dest_keyring", "", DIR_IN, linux_key_serial_t),
);
SYSCALL(keyctl, linux_long,
    ARG("operation", "", DIR_IN, linux_int),
    ARG("arg2", "", DIR_IN, linux_size_t),
    ARG("arg3", "", DIR_IN, linux_size_t),
    ARG("arg4", "", DIR_IN, linux_size_t),
    ARG("arg5", "", DIR_IN, linux_size_t),
);
SYSCALL(ioprio_set, linux_void);
SYSCALL(ioprio_get, linux_void);
SYSCALL(inotify_init, linux_void);
SYSCALL(inotify_add_watch, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("mask", "", DIR_IN, linux_uint32_t),
);
SYSCALL(inotify_rm_watch, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("wd", "", DIR_IN, linux_uint32_t),
);
SYSCALL(migrate_pages, linux_int,
    ARG("pid", "", DIR_IN, linux_int),
    ARG("maxnode", "", DIR_IN, linux_unsigned_long),
    ARG("old_nodes", "", DIR_INOUT, linux_void_ptr), // const unsigned long [maxnode]
    ARG("new_nodes", "", DIR_IN, linux_void_ptr), // const unsigned long [maxnode]
);
SYSCALL(mkdirat, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("mode", "", DIR_IN, linux_mode_t),
);
SYSCALL(mknodat, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("mode", "", DIR_IN, linux_mode_t),
    ARG("dev", "", DIR_IN, linux_dev_t),
);
SYSCALL(fchownat, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("owner", "", DIR_IN, linux_uid_t),
    ARG("group", "", DIR_IN, linux_gid_t),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(futimesat, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("times", "", DIR_IN, linux_void_ptr), // struct timeval[2]
);
SYSCALL(newfstatat, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("statbuf", "", DIR_OUT, linux_stat_ptr),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(unlinkat, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(renameat, linux_int,
    ARG("olddirfd", "", DIR_IN, linux_int),
    ARG("oldpath", "", DIR_IN, linux_char_ptr),
    ARG("newdirfd", "", DIR_IN, linux_int),
    ARG("newpath", "", DIR_IN, linux_char_ptr),
);
SYSCALL(linkat, linux_int,
    ARG("olddirfd", "", DIR_IN, linux_int),
    ARG("oldpath", "", DIR_IN, linux_char_ptr),
    ARG("newdirfd", "", DIR_IN, linux_int),
    ARG("newpath", "", DIR_IN, linux_char_ptr),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(symlinkat, linux_int,
    ARG("target", "", DIR_IN, linux_char_ptr),
    ARG("newdirfd", "", DIR_IN, linux_int),
    ARG("linkpath", "", DIR_IN, linux_char_ptr),
);
SYSCALL(readlinkat, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("buf", "", DIR_INOUT, linux_char_ptr),
    ARG("bufsize", "", DIR_IN, linux_size_t),
);
SYSCALL(fchmodat, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("mode", "", DIR_IN, linux_mode_t),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(faccessat, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("mode", "", DIR_IN, linux_int),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(pselect6, linux_int);
SYSCALL(ppoll, linux_int);
SYSCALL(unshare, linux_int,
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(set_robust_list, linux_void);
SYSCALL(get_robust_list, linux_void);
SYSCALL(splice, linux_void);
SYSCALL(tee, linux_long,
    ARG("fd_in", "", DIR_IN, linux_int),
    ARG("fd_out", "", DIR_IN, linux_int),
    ARG("len", "", DIR_IN, linux_size_t),
    ARG("flags", "", DIR_IN, linux_unsigned_int),
);
SYSCALL(sync_file_range, linux_void);
SYSCALL(vmsplice, linux_void);
SYSCALL(move_pages, linux_void);
SYSCALL(utimensat, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("times", "", DIR_IN, linux_void_ptr), // struct timeval[2]
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(epoll_pwait, linux_void);
SYSCALL(signalfd, linux_void);
SYSCALL(timerfd_create, linux_int,
    ARG("clockid", "", DIR_IN, linux_int),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(eventfd, linux_int,
    ARG("initval", "", DIR_IN, linux_unsigned_int),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(fallocate, linux_long,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("mode", "", DIR_IN, linux_int),
    ARG("offset", "", DIR_IN, linux_loff_t),
    ARG("len", "", DIR_IN, linux_loff_t),
);
SYSCALL(timerfd_settime, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("flags", "", DIR_IN, linux_int),
    ARG("new_value", "", DIR_IN, linux_itimerspec_ptr),
    ARG("old_value", "", DIR_OUT, linux_itimerspec_ptr),
);
SYSCALL(timerfd_gettime, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("curr_value", "", DIR_OUT, linux_itimerspec_ptr),
);
SYSCALL(accept4, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("addr", "", DIR_IN, linux_sockaddr_ptr),
    ARG("addrlen", "", DIR_IN, linux_socklen_t_ptr),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(signalfd4, linux_int);
SYSCALL(eventfd2, linux_int,
    ARG("initval", "", DIR_IN, linux_unsigned_int),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(epoll_create1, linux_int,
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(dup3, linux_int,
    ARG("oldfd", "", DIR_IN, linux_int),
    ARG("newfd", "", DIR_IN, linux_int),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(pipe2, linux_int);
SYSCALL(inotify_init1, linux_int,
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(preadv, linux_int);
SYSCALL(pwritev, linux_int);
SYSCALL(rt_tgsigqueueinfo, linux_int);
SYSCALL(perf_event_open, linux_int);
SYSCALL(recvmmsg, linux_int);
SYSCALL(fanotify_init, linux_int,
    ARG("flags", "", DIR_IN, linux_unsigned_int),
    ARG("event_f_flags", "", DIR_IN, linux_unsigned_int),
);
SYSCALL(fanotify_mark, linux_int,
    ARG("fanotify_id", "", DIR_IN, linux_int),
    ARG("flags", "", DIR_IN, linux_unsigned_int),
    ARG("mask", "", DIR_IN, linux_uint64_t),
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
);
SYSCALL(prlimit64, linux_int);
SYSCALL(name_to_handle_at, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("handle", "", DIR_OUT, linux_file_handle_ptr),
    ARG("mount_id", "", DIR_IN, linux_int_ptr),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(open_by_handle_at, linux_int,
    ARG("mount_fd", "", DIR_IN, linux_int),
    ARG("handle", "", DIR_IN, linux_file_handle_ptr),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(clock_adjtime, linux_int);
SYSCALL(syncfs, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
);
SYSCALL(sendmmsg, linux_int,
    ARG("sockfd", "", DIR_IN, linux_int),
    ARG("msgvec", "", DIR_IN, linux_mmsghdr_ptr),
    ARG("vlen", "", DIR_IN, linux_unsigned_int),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(setns, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("nstype", "", DIR_IN, linux_int),
);
SYSCALL(getcpu, linux_int);
SYSCALL(process_vm_readv, linux_ssize_t,
    ARG("pid", "", DIR_IN, linux_pid_t),
);
SYSCALL(process_vm_writev, linux_ssize_t,
    ARG("pid", "", DIR_IN, linux_pid_t),
);
SYSCALL(kcmp, linux_int,
    ARG("pid1", "", DIR_IN, linux_pid_t),
    ARG("pid2", "", DIR_IN, linux_pid_t),
    ARG("type", "", DIR_IN, linux_int),
    ARG("idx1", "", DIR_IN, linux_unsigned_long),
    ARG("idx2", "", DIR_IN, linux_unsigned_long),
);
SYSCALL(finit_module, linux_int,
    ARG("fd", "", DIR_IN, linux_int),
    ARG("param_values", "", DIR_IN, linux_char_ptr),
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(sched_setattr, linux_int,
    ARG("pid", "", DIR_IN, linux_pid_t),
    ARG("attr", "", DIR_IN, linux_sched_attr_ptr),
    ARG("flags", "", DIR_IN, linux_unsigned_int),
);
SYSCALL(sched_getattr, linux_int,
    ARG("pid", "", DIR_IN, linux_pid_t),
    ARG("attr", "", DIR_OUT, linux_sched_attr_ptr),
    ARG("size", "", DIR_IN, linux_unsigned_int),
    ARG("flags", "", DIR_IN, linux_unsigned_int),
);
// filetracer
SYSCALL(renameat2, linux_int,
    ARG("olddirfd", "", DIR_IN, linux_int),
    ARG("oldpath", "", DIR_IN, linux_char_ptr),
    ARG("newdirfd", "", DIR_IN, linux_int),
    ARG("newpath", "", DIR_IN, linux_char_ptr),
    ARG("flags", "", DIR_IN, linux_unsigned_int),
);
// end filetracer
SYSCALL(seccomp, linux_int,
    ARG("operation", "", DIR_IN, linux_unsigned_int),
    ARG("flags", "", DIR_IN, linux_unsigned_int),
    ARG("args", "", DIR_IN, linux_void_ptr),
);
SYSCALL(getrandom, linux_void);
// filetracer
SYSCALL(memfd_create, linux_int,
    ARG("name", "", DIR_IN, linux_char_ptr),
    ARG("flags", "", DIR_IN, linux_unsigned_int),
);
// end filetracer
SYSCALL(kexec_file_load, linux_int,
    ARG("kernel_fd", "", DIR_IN, linux_int),
    ARG("initrd_fd", "", DIR_IN, linux_int),
    ARG("cmdline_len", "", DIR_IN, linux_unsigned_long),
    ARG("cmdline", "", DIR_IN, linux_char_ptr),
    ARG("flags", "", DIR_IN, linux_unsigned_long),
);
// ebpfmon
SYSCALL(bpf, linux_int,
    ARG("cmd", "", DIR_IN, linux_int),
    ARG("attr", "", DIR_IN, linux_bpf_attr_ptr),
    ARG("size", "", DIR_IN, linux_unsigned_int),
);
// ebpfmon
SYSCALL(execveat, linux_void);
SYSCALL(userfaultfd, linux_int,
    ARG("flags", "", DIR_IN, linux_int),
);
SYSCALL(membarrier, linux_int);
SYSCALL(mlock2, linux_int);
SYSCALL(copy_file_range, linux_int);
SYSCALL(preadv2, linux_int);
SYSCALL(pwritev2, linux_int);
SYSCALL(pkey_mprotect, linux_int,
    ARG("addr", "", DIR_IN, linux_void_ptr),
    ARG("len", "", DIR_IN, linux_size_t),
    ARG("prot", "", DIR_IN, linux_int),
    ARG("pkey", "", DIR_IN, linux_int),
);
SYSCALL(pkey_alloc, linux_int,
    ARG("flags", "", DIR_IN, linux_unsigned_int),
    ARG("access_rights", "", DIR_IN, linux_unsigned_int),
);
SYSCALL(pkey_free, linux_int,
    ARG("pkey", "", DIR_IN, linux_int),
);
SYSCALL(statx, linux_int,
    ARG("dirfd", "", DIR_IN, linux_int),
    ARG("pathname", "", DIR_IN, linux_char_ptr),
    ARG("flags", "", DIR_IN, linux_int),
    ARG("mask", "", DIR_IN, linux_unsigned_int),
    ARG("statxbuf", "", DIR_INOUT, linux_statx_ptr),
);

#pragma clang diagnostic pop

static const syscall_t* linux_syscalls_table_x32[] =
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

/* use separate table, because on x64 kernels stat, fstat, lstat syscalls are
   serviced by sys_newstat, sys_newfstat, sys_newlstat methods, respectively */
static const syscall_t* linux_syscalls_table_x64[] =
{
    [0] = &read,
    [1] = &write,
    [2] = &open,
    [3] = &close,
    [4] = &newstat,
    [5] = &newfstat,
    [6] = &newlstat,
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
#define NUM_SYSCALLS_LINUX_X32 sizeof(linuxsc::linux_syscalls_table_x32)/sizeof(syscall_t*)
#define NUM_SYSCALLS_LINUX_X64 sizeof(linuxsc::linux_syscalls_table_x64)/sizeof(syscall_t*)

}

}
#endif // SYSCALLS_LINUX_H
