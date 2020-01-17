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

#ifndef SYSCALLS_LINUX_H
#define SYSCALLS_LINUX_H

void setup_linux(drakvuf_t drakvuf, syscalls *s);

#include "private.h"

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

// The actual max depends on the arch and actual kernel version
#define NUM_SYSCALLS_LINUX 313

static const syscall_definition_t linux_syscalls[] =
{
    [0] =
    {
        .name = "read", .ret = LONG,   .num_args = 3, .args =
        {
            {.name = "fd",      .dir = DIR_IN, .type = LONG },
            {.name = "buf",     .dir = DIR_IN, .type = PVOID },
            {.name = "count",   .dir = DIR_IN, .type = ULONG },

        }
    },

    [1] =
    {
        .name = "write", .ret = LONG,    .num_args = 3, .args =
        {
            {.name = "fd",       .dir = DIR_IN,  .type = LONG },
            {.name = "buf",      .dir = DIR_OUT, .type = PVOID },
            {.name = "count",    .dir = DIR_OUT, .type = ULONG },
        },
    },

    [2] =
    {
        .name = "open",  .ret = LONG,   .num_args = 3, .args =
        {
            {.name = "pathname", .dir = DIR_IN, .type = PCHAR },
            {.name = "flags",    .dir = DIR_IN, .type = ULONG },
            {.name = "mode",     .dir = DIR_IN, .type = ULONG },

        },
    },

    [3] =
    {
        .name = "close", .ret = LONG,   .num_args = 1, .args =
        {
            {.name = "fd",       .dir = DIR_IN, .type = LONG },
        },
    },

    [257] =
    {
        .name = "openat",  .ret = LONG,   .num_args = 4, .args =
        {
            {.name = "dirfd",    .dir = DIR_IN, .type = LONG },
            {.name = "pathname", .dir = DIR_IN, .type = PCHAR },
            {.name = "flags",    .dir = DIR_IN, .type = ULONG },
            {.name = "mode",     .dir = DIR_IN, .type = ULONG },

        },
    },

    // TODO: define the full function prototype for the rest
    [4] = { .name = "stat" },
    [5] = { .name = "fstat" },
    [6] = { .name = "lstat" },
    [7] = { .name = "poll" },
    [8] = { .name = "lseek" },
    [9] = { .name = "mmap" },
    [10] = { .name = "mprotect" },
    [11] = { .name = "munmap" },
    [12] = { .name = "brk" },
    [13] = { .name = "rt_sigaction" },
    [14] = { .name = "rt_sigprocmask" },
    [15] = { .name = "rt_sigreturn" },
    [16] = { .name = "ioctl" },
    [17] = { .name = "pread64" },
    [18] = { .name = "pwrite64" },
    [19] = { .name = "readv" },
    [20] = { .name = "writev" },
    [21] = { .name = "access" },
    [22] = { .name = "pipe" },
    [23] = { .name = "select" },
    [24] = { .name = "sched_yield" },
    [25] = { .name = "mremap" },
    [26] = { .name = "msync" },
    [27] = { .name = "mincore" },
    [28] = { .name = "madvise" },
    [29] = { .name = "shmget" },
    [30] = { .name = "shmat" },
    [31] = { .name = "shmctl" },
    [32] = { .name = "dup" },
    [33] = { .name = "dup2" },
    [34] = { .name = "pause" },
    [35] = { .name = "nanosleep" },
    [36] = { .name = "getitimer" },
    [37] = { .name = "alarm" },
    [38] = { .name = "setitimer" },
    [39] = { .name = "getpid" },
    [40] = { .name = "sendfile64" },
    [41] = { .name = "socket" },
    [42] = { .name = "connect" },
    [43] = { .name = "accept" },
    [44] = { .name = "sendto" },
    [45] = { .name = "recvfrom" },
    [46] = { .name = "sendmsg" },
    [47] = { .name = "recvmsg" },
    [48] = { .name = "shutdown" },
    [49] = { .name = "bind" },
    [50] = { .name = "listen" },
    [51] = { .name = "getsockname" },
    [52] = { .name = "getpeername" },
    [53] = { .name = "socketpair" },
    [54] = { .name = "setsockopt" },
    [55] = { .name = "getsockopt" },
    [56] = { .name = "clone" },
    [57] = { .name = "fork" },
    [58] = { .name = "vfork" },
    [59] = { .name = "execve" },
    [60] = { .name = "exit" },
    [61] = { .name = "wait4" },
    [62] = { .name = "kill" },
    [63] = { .name = "uname" },
    [64] = { .name = "semget" },
    [65] = { .name = "semop" },
    [66] = { .name = "semctl" },
    [67] = { .name = "shmdt" },
    [68] = { .name = "msgget" },
    [69] = { .name = "msgsnd" },
    [70] = { .name = "msgrcv" },
    [71] = { .name = "msgctl" },
    [72] = { .name = "fcntl" },
    [73] = { .name = "flock" },
    [74] = { .name = "fsync" },
    [75] = { .name = "fdatasync" },
    [76] = { .name = "truncate" },
    [77] = { .name = "ftruncate" },
    [78] = { .name = "getdents" },
    [79] = { .name = "getcwd" },
    [80] = { .name = "chdir" },
    [81] = { .name = "fchdir" },
    [82] = { .name = "rename" },
    [83] = { .name = "mkdir" },
    [84] = { .name = "rmdir" },
    [85] = { .name = "creat" },
    [86] = { .name = "link" },
    [87] = { .name = "unlink" },
    [88] = { .name = "symlink" },
    [89] = { .name = "readlink" },
    [90] = { .name = "chmod" },
    [91] = { .name = "fchmod" },
    [92] = { .name = "chown" },
    [93] = { .name = "fchown" },
    [94] = { .name = "lchown" },
    [95] = { .name = "umask" },
    [96] = { .name = "gettimeofday" },
    [97] = { .name = "getrlimit" },
    [98] = { .name = "getrusage" },
    [99] = { .name = "sysinfo" },
    [100] = { .name = "times" },
    [101] = { .name = "ptrace" },
    [102] = { .name = "getuid" },
    [103] = { .name = "syslog" },
    [104] = { .name = "getgid" },
    [105] = { .name = "setuid" },
    [106] = { .name = "setgid" },
    [107] = { .name = "geteuid" },
    [108] = { .name = "getegid" },
    [109] = { .name = "setpgid" },
    [110] = { .name = "getppid" },
    [111] = { .name = "getpgrp" },
    [112] = { .name = "setsid" },
    [113] = { .name = "setreuid" },
    [114] = { .name = "setregid" },
    [115] = { .name = "getgroups" },
    [116] = { .name = "setgroups" },
    [117] = { .name = "setresuid" },
    [118] = { .name = "getresuid" },
    [119] = { .name = "setresgid" },
    [120] = { .name = "getresgid" },
    [121] = { .name = "getpgid" },
    [122] = { .name = "setfsuid" },
    [123] = { .name = "setfsgid" },
    [124] = { .name = "getsid" },
    [125] = { .name = "capget" },
    [126] = { .name = "capset" },
    [127] = { .name = "rt_sigpending" },
    [128] = { .name = "rt_sigtimedwait" },
    [129] = { .name = "rt_sigqueueinfo" },
    [130] = { .name = "rt_sigsuspend" },
    [131] = { .name = "sigaltstack" },
    [132] = { .name = "utime" },
    [133] = { .name = "mknod" },
    [134] = { .name = "uselib" },
    [135] = { .name = "personality" },
    [136] = { .name = "ustat" },
    [137] = { .name = "statfs" },
    [138] = { .name = "fstatfs" },
    [139] = { .name = "sysfs" },
    [140] = { .name = "getpriority" },
    [141] = { .name = "setpriority" },
    [142] = { .name = "sched_setparam" },
    [143] = { .name = "sched_getparam" },
    [144] = { .name = "sched_setscheduler" },
    [145] = { .name = "sched_getscheduler" },
    [146] = { .name = "sched_get_priority_max" },
    [147] = { .name = "sched_get_priority_min" },
    [148] = { .name = "sched_rr_get_interval" },
    [149] = { .name = "mlock" },
    [150] = { .name = "munlock" },
    [151] = { .name = "mlockall" },
    [152] = { .name = "munlockall" },
    [153] = { .name = "vhangup" },
    [154] = { .name = "modify_ldt" },
    [155] = { .name = "pivot_root" },
    [156] = { .name = "_sysctl" },
    [157] = { .name = "prctl" },
    [158] = { .name = "arch_prctl" },
    [159] = { .name = "adjtimex" },
    [160] = { .name = "setrlimit" },
    [161] = { .name = "chroot" },
    [162] = { .name = "sync" },
    [163] = { .name = "acct" },
    [164] = { .name = "settimeofday" },
    [165] = { .name = "mount" },
    [166] = { .name = "umount2" },
    [167] = { .name = "swapon" },
    [168] = { .name = "swapoff" },
    [169] = { .name = "reboot" },
    [170] = { .name = "sethostname" },
    [171] = { .name = "setdomainname" },
    [172] = { .name = "iopl" },
    [173] = { .name = "ioperm" },
    [174] = { .name = "create_module" },
    [175] = { .name = "init_module" },
    [176] = { .name = "delete_module" },
    [177] = { .name = "get_kernel_syms" },
    [178] = { .name = "query_module" },
    [179] = { .name = "quotactl" },
    [180] = { .name = "nfsservctl" },
    [181] = { .name = "getpmsg" },
    [182] = { .name = "putpmsg" },
    [183] = { .name = "afs_syscall" },
    [184] = { .name = "tuxcall" },
    [185] = { .name = "security" },
    [186] = { .name = "gettid" },
    [187] = { .name = "readahead" },
    [188] = { .name = "setxattr" },
    [189] = { .name = "lsetxattr" },
    [190] = { .name = "fsetxattr" },
    [191] = { .name = "getxattr" },
    [192] = { .name = "lgetxattr" },
    [193] = { .name = "fgetxattr" },
    [194] = { .name = "listxattr" },
    [195] = { .name = "llistxattr" },
    [196] = { .name = "flistxattr" },
    [197] = { .name = "removexattr" },
    [198] = { .name = "lremovexattr" },
    [199] = { .name = "fremovexattr" },
    [200] = { .name = "tkill" },
    [201] = { .name = "time" },
    [202] = { .name = "futex" },
    [203] = { .name = "sched_setaffinity" },
    [204] = { .name = "sched_getaffinity" },
    [205] = { .name = "set_thread_area" },
    [206] = { .name = "io_setup" },
    [207] = { .name = "io_destroy" },
    [208] = { .name = "io_getevents" },
    [209] = { .name = "io_submit" },
    [210] = { .name = "io_cancel" },
    [211] = { .name = "get_thread_area" },
    [212] = { .name = "lookup_dcookie" },
    [213] = { .name = "epoll_create" },
    [214] = { .name = "epoll_ctl_old" },
    [215] = { .name = "epoll_wait_old" },
    [216] = { .name = "remap_file_pages" },
    [217] = { .name = "getdents64" },
    [218] = { .name = "set_tid_address" },
    [219] = { .name = "restart_syscall" },
    [220] = { .name = "semtimedop" },
    [221] = { .name = "fadvise64" },
    [222] = { .name = "timer_create" },
    [223] = { .name = "timer_settime" },
    [224] = { .name = "timer_gettime" },
    [225] = { .name = "timer_getoverrun" },
    [226] = { .name = "timer_delete" },
    [227] = { .name = "clock_settime" },
    [228] = { .name = "clock_gettime" },
    [229] = { .name = "clock_getres" },
    [230] = { .name = "clock_nanosleep" },
    [231] = { .name = "exit_group" },
    [232] = { .name = "epoll_wait" },
    [233] = { .name = "epoll_ctl" },
    [234] = { .name = "tgkill" },
    [235] = { .name = "utimes" },
    [236] = { .name = "vserver" },
    [237] = { .name = "mbind" },
    [238] = { .name = "set_mempolicy" },
    [239] = { .name = "get_mempolicy" },
    [240] = { .name = "mq_open" },
    [241] = { .name = "mq_unlink" },
    [242] = { .name = "mq_timedsend" },
    [243] = { .name = "mq_timedreceive" },
    [244] = { .name = "mq_notify" },
    [245] = { .name = "mq_getsetattr" },
    [246] = { .name = "kexec_load" },
    [247] = { .name = "waitid" },
    [248] = { .name = "add_key" },
    [249] = { .name = "request_key" },
    [250] = { .name = "keyctl" },
    [251] = { .name = "ioprio_set" },
    [252] = { .name = "ioprio_get" },
    [253] = { .name = "inotify_init" },
    [254] = { .name = "inotify_add_watch" },
    [255] = { .name = "inotify_rm_watch" },
    [256] = { .name = "migrate_pages" },
    [258] = { .name = "mkdirat" },
    [259] = { .name = "mknodat" },
    [260] = { .name = "fchownat" },
    [261] = { .name = "futimesat" },
    [262] = { .name = "newfstatat" },
    [263] = { .name = "unlinkat" },
    [264] = { .name = "renameat" },
    [265] = { .name = "linkat" },
    [266] = { .name = "symlinkat" },
    [267] = { .name = "readlinkat" },
    [268] = { .name = "fchmodat" },
    [269] = { .name = "faccessat" },
    [270] = { .name = "pselect6" },
    [271] = { .name = "ppoll" },
    [272] = { .name = "unshare" },
    [273] = { .name = "set_robust_list" },
    [274] = { .name = "get_robust_list" },
    [275] = { .name = "splice" },
    [276] = { .name = "tee" },
    [277] = { .name = "sync_file_range" },
    [278] = { .name = "vmsplice" },
    [279] = { .name = "move_pages" },
    [280] = { .name = "utimensat" },
    [281] = { .name = "epoll_pwait" },
    [282] = { .name = "signalfd" },
    [283] = { .name = "timerfd_create" },
    [284] = { .name = "eventfd" },
    [285] = { .name = "fallocate" },
    [286] = { .name = "timerfd_settime" },
    [287] = { .name = "timerfd_gettime" },
    [288] = { .name = "accept4" },
    [289] = { .name = "signalfd4" },
    [290] = { .name = "eventfd2" },
    [291] = { .name = "epoll_create1" },
    [292] = { .name = "dup3" },
    [293] = { .name = "pipe2" },
    [294] = { .name = "inotify_init1" },
    [295] = { .name = "preadv" },
    [296] = { .name = "pwritev" },
    [297] = { .name = "rt_tgsigqueueinfo" },
    [298] = { .name = "perf_event_open" },
    [299] = { .name = "recvmmsg" },
    [300] = { .name = "fanotify_init" },
    [301] = { .name = "fanotify_mark" },
    [302] = { .name = "prlimit64" },
    [303] = { .name = "name_to_handle_at" },
    [304] = { .name = "open_by_handle_at" },
    [305] = { .name = "clock_adjtime" },
    [306] = { .name = "syncfs" },
    [307] = { .name = "sendmmsg" },
    [308] = { .name = "setns" },
    [309] = { .name = "getcpu" },
    [310] = { .name = "process_vm_readv" },
    [311] = { .name = "process_vm_writev" },
    [312] = { .name = "kcmp" },
    [313] = { .name = "finit_module" },
};

#endif // SYSCALLS_LINUX_H
