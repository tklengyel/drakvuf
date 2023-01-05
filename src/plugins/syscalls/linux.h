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

namespace syscalls_ns
{

void setup_linux(drakvuf_t drakvuf, syscalls* s);

/**
 * Older Linux kernels pass the arguments to the syscall functions via
 * registers, per the ABI. Newer kernels pass the arguments via a
 * struct pt_regs. This change was made Apr 2018 in/near commit
 * fa697140f9a20119a9ec8fd7460cc4314fbdaff3.
 *
 * See kernel: arch/x86/include/asm/syscall_wrapper.h
 *             arch/x86/entry/entry_64.S
 *             arch/x86/include/uapi/asm/ptrace.h
 */
enum linux_pt_regs
{
    PT_REGS_R15,
    PT_REGS_R14,
    PT_REGS_R13,
    PT_REGS_R12,
    PT_REGS_RBP,
    PT_REGS_RBX,

    PT_REGS_R11,
    PT_REGS_R10,
    PT_REGS_R9,
    PT_REGS_R8,
    PT_REGS_RAX,
    PT_REGS_RCX,
    PT_REGS_RDX,
    PT_REGS_RSI,
    PT_REGS_RDI,

    PT_REGS_ORIG_RAX,

    PT_REGS_RIP,
    PT_REGS_CS,
    PT_REGS_EFLAGS,
    PT_REGS_RSP,
    PT_REGS_SS,

    __PT_REGS_MAX
};

static const char* linux_pt_regs_names[__PT_REGS_MAX] =
{
    [PT_REGS_R15] = "r15",
    [PT_REGS_R14] = "r14",
    [PT_REGS_R13] = "r13",
    [PT_REGS_R12] = "r12",
    [PT_REGS_RBP] = "bp",
    [PT_REGS_RBX] = "bx",

    [PT_REGS_R11] = "r11",
    [PT_REGS_R10] = "r10",
    [PT_REGS_R9] = "r9",
    [PT_REGS_R8] = "r8",
    [PT_REGS_RAX] = "ax",
    [PT_REGS_RCX] = "cx",
    [PT_REGS_RDX] = "dx",
    [PT_REGS_RSI] = "si",
    [PT_REGS_RDI] = "di",

    [PT_REGS_ORIG_RAX] = "orig_ax",

    [PT_REGS_RIP] = "ip",
    [PT_REGS_CS] = "cs",
    [PT_REGS_EFLAGS] = "flags",
    [PT_REGS_RSP] = "sp",
    [PT_REGS_SS] = "ss",
};

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

// TODO: fill in missing ret & argument info
SYSCALL(stat, VOID);
SYSCALL(fstat, VOID);
SYSCALL(lstat, VOID);
SYSCALL(poll, VOID);
SYSCALL(lseek, VOID);
SYSCALL(mmap, VOID);
SYSCALL(mprotect, VOID);
SYSCALL(munmap, VOID);
SYSCALL(brk, VOID);
SYSCALL(rt_sigaction, VOID);
SYSCALL(rt_sigprocmask, VOID);
SYSCALL(rt_sigreturn, VOID);
SYSCALL(ioctl, VOID);
SYSCALL(pread64, VOID);
SYSCALL(pwrite64, VOID);
SYSCALL(readv, VOID);
SYSCALL(writev, VOID);
SYSCALL(access, VOID);
SYSCALL(pipe, VOID);
SYSCALL(select, VOID);
SYSCALL(sched_yield, VOID);
SYSCALL(mremap, VOID);
SYSCALL(msync, VOID);
SYSCALL(mincore, VOID);
SYSCALL(madvise, VOID);
SYSCALL(shmget, VOID);
SYSCALL(shmat, VOID);
SYSCALL(shmctl, VOID);
SYSCALL(dup, VOID);
SYSCALL(dup2, VOID);
SYSCALL(pause, VOID);
SYSCALL(nanosleep, VOID);
SYSCALL(getitimer, VOID);
SYSCALL(alarm, VOID);
SYSCALL(setitimer, VOID);
SYSCALL(getpid, VOID);
SYSCALL(sendfile64, VOID);
SYSCALL(socket, VOID);
SYSCALL(connect, VOID);
SYSCALL(accept, VOID);
SYSCALL(sendto, VOID);
SYSCALL(recvfrom, VOID);
SYSCALL(sendmsg, VOID);
SYSCALL(recvmsg, VOID);
SYSCALL(shutdown, VOID);
SYSCALL(bind, VOID);
SYSCALL(listen, VOID);
SYSCALL(getsockname, VOID);
SYSCALL(getpeername, VOID);
SYSCALL(socketpair, VOID);
SYSCALL(setsockopt, VOID);
SYSCALL(getsockopt, VOID);
SYSCALL(clone, VOID);
SYSCALL(fork, VOID);
SYSCALL(vfork, VOID);
SYSCALL(execve, VOID);
SYSCALL(exit, VOID);
SYSCALL(wait4, VOID);
SYSCALL(kill, VOID);
SYSCALL(uname, VOID);
SYSCALL(semget, VOID);
SYSCALL(semop, VOID);
SYSCALL(semctl, VOID);
SYSCALL(shmdt, VOID);
SYSCALL(msgget, VOID);
SYSCALL(msgsnd, VOID);
SYSCALL(msgrcv, VOID);
SYSCALL(msgctl, VOID);
SYSCALL(fcntl, VOID);
SYSCALL(flock, VOID);
SYSCALL(fsync, VOID);
SYSCALL(fdatasync, VOID);
SYSCALL(truncate, VOID);
SYSCALL(ftruncate, VOID);
SYSCALL(getdents, VOID);
SYSCALL(getcwd, VOID);
SYSCALL(chdir, VOID);
SYSCALL(fchdir, VOID);
SYSCALL(rename, VOID);
SYSCALL(mkdir, VOID);
SYSCALL(rmdir, VOID);
SYSCALL(creat, VOID);
SYSCALL(link, VOID);
SYSCALL(unlink, VOID);
SYSCALL(symlink, VOID);
SYSCALL(readlink, VOID);
SYSCALL(chmod, VOID);
SYSCALL(fchmod, VOID);
SYSCALL(chown, VOID);
SYSCALL(fchown, VOID);
SYSCALL(lchown, VOID);
SYSCALL(umask, VOID);
SYSCALL(gettimeofday, VOID);
SYSCALL(getrlimit, VOID);
SYSCALL(getrusage, VOID);
SYSCALL(sysinfo, VOID);
SYSCALL(times, VOID);
SYSCALL(ptrace, VOID);
SYSCALL(getuid, VOID);
SYSCALL(syslog, VOID);
SYSCALL(getgid, VOID);
SYSCALL(setuid, VOID);
SYSCALL(setgid, VOID);
SYSCALL(geteuid, VOID);
SYSCALL(getegid, VOID);
SYSCALL(setpgid, VOID);
SYSCALL(getppid, VOID);
SYSCALL(getpgrp, VOID);
SYSCALL(setsid, VOID);
SYSCALL(setreuid, VOID);
SYSCALL(setregid, VOID);
SYSCALL(getgroups, VOID);
SYSCALL(setgroups, VOID);
SYSCALL(setresuid, VOID);
SYSCALL(getresuid, VOID);
SYSCALL(setresgid, VOID);
SYSCALL(getresgid, VOID);
SYSCALL(getpgid, VOID);
SYSCALL(setfsuid, VOID);
SYSCALL(setfsgid, VOID);
SYSCALL(getsid, VOID);
SYSCALL(capget, VOID);
SYSCALL(capset, VOID);
SYSCALL(rt_sigpending, VOID);
SYSCALL(rt_sigtimedwait, VOID);
SYSCALL(rt_sigqueueinfo, VOID);
SYSCALL(rt_sigsuspend, VOID);
SYSCALL(sigaltstack, VOID);
SYSCALL(utime, VOID);
SYSCALL(mknod, VOID);
SYSCALL(uselib, VOID);
SYSCALL(personality, VOID);
SYSCALL(ustat, VOID);
SYSCALL(statfs, VOID);
SYSCALL(fstatfs, VOID);
SYSCALL(sysfs, VOID);
SYSCALL(getpriority, VOID);
SYSCALL(setpriority, VOID);
SYSCALL(sched_setparam, VOID);
SYSCALL(sched_getparam, VOID);
SYSCALL(sched_setscheduler, VOID);
SYSCALL(sched_getscheduler, VOID);
SYSCALL(sched_get_priority_max, VOID);
SYSCALL(sched_get_priority_min, VOID);
SYSCALL(sched_rr_get_interval, VOID);
SYSCALL(mlock, VOID);
SYSCALL(munlock, VOID);
SYSCALL(mlockall, VOID);
SYSCALL(munlockall, VOID);
SYSCALL(vhangup, VOID);
SYSCALL(modify_ldt, VOID);
SYSCALL(pivot_root, VOID);
SYSCALL(_sysctl, VOID);
SYSCALL(prctl, VOID);
SYSCALL(arch_prctl, VOID);
SYSCALL(adjtimex, VOID);
SYSCALL(setrlimit, VOID);
SYSCALL(chroot, VOID);
SYSCALL(sync, VOID);
SYSCALL(acct, VOID);
SYSCALL(settimeofday, VOID);
SYSCALL(mount, VOID);
SYSCALL(umount2, VOID);
SYSCALL(swapon, VOID);
SYSCALL(swapoff, VOID);
SYSCALL(reboot, VOID);
SYSCALL(sethostname, VOID);
SYSCALL(setdomainname, VOID);
SYSCALL(iopl, VOID);
SYSCALL(ioperm, VOID);
SYSCALL(create_module, VOID);
SYSCALL(init_module, VOID);
SYSCALL(delete_module, VOID);
SYSCALL(get_kernel_syms, VOID);
SYSCALL(query_module, VOID);
SYSCALL(quotactl, VOID);
SYSCALL(nfsservctl, VOID);
SYSCALL(getpmsg, VOID);
SYSCALL(putpmsg, VOID);
SYSCALL(afs_syscall, VOID);
SYSCALL(tuxcall, VOID);
SYSCALL(security, VOID);
SYSCALL(gettid, VOID);
SYSCALL(readahead, VOID);
SYSCALL(setxattr, VOID);
SYSCALL(lsetxattr, VOID);
SYSCALL(fsetxattr, VOID);
SYSCALL(getxattr, VOID);
SYSCALL(lgetxattr, VOID);
SYSCALL(fgetxattr, VOID);
SYSCALL(listxattr, VOID);
SYSCALL(llistxattr, VOID);
SYSCALL(flistxattr, VOID);
SYSCALL(removexattr, VOID);
SYSCALL(lremovexattr, VOID);
SYSCALL(fremovexattr, VOID);
SYSCALL(tkill, VOID);
SYSCALL(time, VOID);
SYSCALL(futex, VOID);
SYSCALL(sched_setaffinity, VOID);
SYSCALL(sched_getaffinity, VOID);
SYSCALL(set_thread_area, VOID);
SYSCALL(io_setup, VOID);
SYSCALL(io_destroy, VOID);
SYSCALL(io_getevents, VOID);
SYSCALL(io_submit, VOID);
SYSCALL(io_cancel, VOID);
SYSCALL(get_thread_area, VOID);
SYSCALL(lookup_dcookie, VOID);
SYSCALL(epoll_create, VOID);
SYSCALL(epoll_ctl_old, VOID);
SYSCALL(epoll_wait_old, VOID);
SYSCALL(remap_file_pages, VOID);
SYSCALL(getdents64, VOID);
SYSCALL(set_tid_address, VOID);
SYSCALL(restart_syscall, VOID);
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
SYSCALL(exit_group, VOID);
SYSCALL(epoll_wait, VOID);
SYSCALL(epoll_ctl, VOID);
SYSCALL(tgkill, VOID);
SYSCALL(utimes, VOID);
SYSCALL(vserver, VOID);
SYSCALL(mbind, VOID);
SYSCALL(set_mempolicy, VOID);
SYSCALL(get_mempolicy, VOID);
SYSCALL(mq_open, VOID);
SYSCALL(mq_unlink, VOID);
SYSCALL(mq_timedsend, VOID);
SYSCALL(mq_timedreceive, VOID);
SYSCALL(mq_notify, VOID);
SYSCALL(mq_getsetattr, VOID);
SYSCALL(kexec_load, VOID);
SYSCALL(waitid, VOID);
SYSCALL(add_key, VOID);
SYSCALL(request_key, VOID);
SYSCALL(keyctl, VOID);
SYSCALL(ioprio_set, VOID);
SYSCALL(ioprio_get, VOID);
SYSCALL(inotify_init, VOID);
SYSCALL(inotify_add_watch, VOID);
SYSCALL(inotify_rm_watch, VOID);
SYSCALL(migrate_pages, VOID);
SYSCALL(mkdirat, VOID);
SYSCALL(mknodat, VOID);
SYSCALL(fchownat, VOID);
SYSCALL(futimesat, VOID);
SYSCALL(newfstatat, VOID);
SYSCALL(unlinkat, VOID);
SYSCALL(renameat, VOID);
SYSCALL(linkat, VOID);
SYSCALL(symlinkat, VOID);
SYSCALL(readlinkat, VOID);
SYSCALL(fchmodat, VOID);
SYSCALL(faccessat, VOID);
SYSCALL(pselect6, VOID);
SYSCALL(ppoll, VOID);
SYSCALL(unshare, VOID);
SYSCALL(set_robust_list, VOID);
SYSCALL(get_robust_list, VOID);
SYSCALL(splice, VOID);
SYSCALL(tee, VOID);
SYSCALL(sync_file_range, VOID);
SYSCALL(vmsplice, VOID);
SYSCALL(move_pages, VOID);
SYSCALL(utimensat, VOID);
SYSCALL(epoll_pwait, VOID);
SYSCALL(signalfd, VOID);
SYSCALL(timerfd_create, VOID);
SYSCALL(eventfd, VOID);
SYSCALL(fallocate, VOID);
SYSCALL(timerfd_settime, VOID);
SYSCALL(timerfd_gettime, VOID);
SYSCALL(accept4, VOID);
SYSCALL(signalfd4, VOID);
SYSCALL(eventfd2, VOID);
SYSCALL(epoll_create1, VOID);
SYSCALL(dup3, VOID);
SYSCALL(pipe2, VOID);
SYSCALL(inotify_init1, VOID);
SYSCALL(preadv, VOID);
SYSCALL(pwritev, VOID);
SYSCALL(rt_tgsigqueueinfo, VOID);
SYSCALL(perf_event_open, VOID);
SYSCALL(recvmmsg, VOID);
SYSCALL(fanotify_init, VOID);
SYSCALL(fanotify_mark, VOID);
SYSCALL(prlimit64, VOID);
SYSCALL(name_to_handle_at, VOID);
SYSCALL(open_by_handle_at, VOID);
SYSCALL(clock_adjtime, VOID);
SYSCALL(syncfs, VOID);
SYSCALL(sendmmsg, VOID);
SYSCALL(setns, VOID);
SYSCALL(getcpu, VOID);
SYSCALL(process_vm_readv, VOID);
SYSCALL(process_vm_writev, VOID);
SYSCALL(kcmp, VOID);
SYSCALL(finit_module, VOID);

#pragma clang diagnostic pop

static const syscall_t* linux_syscalls[] =
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
};

// The actual max depends on the arch and actual kernel version
#define NUM_SYSCALLS_LINUX sizeof(linuxsc::linux_syscalls)/sizeof(syscall_t*)

}

}
#endif // SYSCALLS_LINUX_H
