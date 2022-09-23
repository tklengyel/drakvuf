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

#ifndef EBPFMON_PRIVATE_H
#define EBPFMON_PRIVATE_H

typedef enum bpf_cmd
{
    BPF_MAP_CREATE,
    BPF_MAP_LOOKUP_ELEM,
    BPF_MAP_UPDATE_ELEM,
    BPF_MAP_DELETE_ELEM,
    BPF_MAP_GET_NEXT_KEY,
    BPF_PROG_LOAD,
    BPF_OBJ_PIN,
    BPF_OBJ_GET,
    BPF_PROG_ATTACH,
    BPF_PROG_DETACH,
    BPF_PROG_RUN,
    BPF_PROG_GET_NEXT_ID,
    BPF_MAP_GET_NEXT_ID,
    BPF_PROG_GET_FD_BY_ID,
    BPF_MAP_GET_FD_BY_ID,
    BPF_OBJ_GET_INFO_BY_FD,
    BPF_PROG_QUERY,
    BPF_RAW_TRACEPOINT_OPEN,
    BPF_BTF_LOAD,
    BPF_BTF_GET_FD_BY_ID,
    BPF_TASK_FD_QUERY,
    BPF_MAP_LOOKUP_AND_DELETE_ELEM,
    BPF_MAP_FREEZE,
    BPF_BTF_GET_NEXT_ID,
    BPF_MAP_LOOKUP_BATCH,
    BPF_MAP_LOOKUP_AND_DELETE_BATCH,
    BPF_MAP_UPDATE_BATCH,
    BPF_MAP_DELETE_BATCH,
    BPF_LINK_CREATE,
    BPF_LINK_UPDATE,
    BPF_LINK_GET_FD_BY_ID,
    BPF_LINK_GET_NEXT_ID,
    BPF_ENABLE_STATS,
    BPF_ITER_CREATE,
    BPF_LINK_DETACH,
    BPF_PROG_BIND_MAP,
} bpf_cmd_t;

static inline const char* bpf_cmd_to_str(bpf_cmd_t bpf_cmd)
{
    switch (bpf_cmd)
    {
        case BPF_MAP_CREATE:
            return "BPF_MAP_CREATE";
        case BPF_MAP_LOOKUP_ELEM:
            return "BPF_MAP_LOOKUP_ELEM";
        case BPF_MAP_UPDATE_ELEM:
            return "BPF_MAP_UPDATE_ELEM";
        case BPF_MAP_DELETE_ELEM:
            return "BPF_MAP_DELETE_ELEM";
        case BPF_MAP_GET_NEXT_KEY:
            return "BPF_MAP_GET_NEXT_KEY";
        case BPF_PROG_LOAD:
            return "BPF_PROG_LOAD";
        case BPF_OBJ_PIN:
            return "BPF_OBJ_PIN";
        case BPF_OBJ_GET:
            return "BPF_OBJ_GET";
        case BPF_PROG_ATTACH:
            return "BPF_PROG_ATTACH";
        case BPF_PROG_DETACH:
            return "BPF_PROG_DETACH";
        case BPF_PROG_RUN:
            return "BPF_PROG_RUN";
        case BPF_PROG_GET_NEXT_ID:
            return "BPF_PROG_GET_NEXT_ID";
        case BPF_MAP_GET_NEXT_ID:
            return "BPF_MAP_GET_NEXT_ID";
        case BPF_PROG_GET_FD_BY_ID:
            return "BPF_PROG_GET_FD_BY_ID";
        case BPF_MAP_GET_FD_BY_ID:
            return "BPF_MAP_GET_FD_BY_ID";
        case BPF_OBJ_GET_INFO_BY_FD:
            return "BPF_OBJ_GET_INFO_BY_FD";
        case BPF_PROG_QUERY:
            return "BPF_PROG_QUERY";
        case BPF_RAW_TRACEPOINT_OPEN:
            return "BPF_RAW_TRACEPOINT_OPEN";
        case BPF_BTF_LOAD:
            return "BPF_BTF_LOAD";
        case BPF_BTF_GET_FD_BY_ID:
            return "BPF_BTF_GET_FD_BY_ID";
        case BPF_TASK_FD_QUERY:
            return "BPF_TASK_FD_QUERY";
        case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
            return "BPF_MAP_LOOKUP_AND_DELETE_ELEM";
        case BPF_MAP_FREEZE:
            return "BPF_MAP_FREEZE";
        case BPF_BTF_GET_NEXT_ID:
            return "BPF_BTF_GET_NEXT_ID";
        case BPF_MAP_LOOKUP_BATCH:
            return "BPF_MAP_LOOKUP_BATCH";
        case BPF_MAP_LOOKUP_AND_DELETE_BATCH:
            return "BPF_MAP_LOOKUP_AND_DELETE_BATCH";
        case BPF_MAP_UPDATE_BATCH:
            return "BPF_MAP_UPDATE_BATCH";
        case BPF_MAP_DELETE_BATCH:
            return "BPF_MAP_DELETE_BATCH";
        case BPF_LINK_CREATE:
            return "BPF_LINK_CREATE";
        case BPF_LINK_UPDATE:
            return "BPF_LINK_UPDATE";
        case BPF_LINK_GET_FD_BY_ID:
            return "BPF_LINK_GET_FD_BY_ID";
        case BPF_LINK_GET_NEXT_ID:
            return "BPF_LINK_GET_NEXT_ID";
        case BPF_ENABLE_STATS:
            return "BPF_ENABLE_STATS";
        case BPF_ITER_CREATE:
            return "BPF_ITER_CREATE";
        case BPF_LINK_DETACH:
            return "BPF_LINK_DETACH";
        case BPF_PROG_BIND_MAP:
            return "BPF_PROG_BIND_MAP";
        default:
            return nullptr;
    }
}
typedef enum bpf_map_type
{
    BPF_MAP_TYPE_UNSPEC,
    BPF_MAP_TYPE_HASH,
    BPF_MAP_TYPE_ARRAY,
    BPF_MAP_TYPE_PROG_ARRAY,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BPF_MAP_TYPE_PERCPU_HASH,
    BPF_MAP_TYPE_PERCPU_ARRAY,
    BPF_MAP_TYPE_STACK_TRACE,
    BPF_MAP_TYPE_CGROUP_ARRAY,
    BPF_MAP_TYPE_LRU_HASH,
    BPF_MAP_TYPE_LRU_PERCPU_HASH,
    BPF_MAP_TYPE_LPM_TRIE,
    BPF_MAP_TYPE_ARRAY_OF_MAPS,
    BPF_MAP_TYPE_HASH_OF_MAPS,
    BPF_MAP_TYPE_DEVMAP,
    BPF_MAP_TYPE_SOCKMAP,
    BPF_MAP_TYPE_CPUMAP,
    BPF_MAP_TYPE_XSKMAP,
    BPF_MAP_TYPE_SOCKHASH,
    BPF_MAP_TYPE_CGROUP_STORAGE,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    BPF_MAP_TYPE_QUEUE,
    BPF_MAP_TYPE_STACK,
    BPF_MAP_TYPE_SK_STORAGE,
    BPF_MAP_TYPE_DEVMAP_HASH,
    BPF_MAP_TYPE_STRUCT_OPS,
    BPF_MAP_TYPE_RINGBUF,
    BPF_MAP_TYPE_INODE_STORAGE,
    BPF_MAP_TYPE_TASK_STORAGE,
    BPF_MAP_TYPE_BLOOM_FILTER,
} bpf_map_type_t;

static inline const char* bpf_map_type_to_str(bpf_map_type_t bpf_map_type)
{
    switch (bpf_map_type)
    {
        case BPF_MAP_TYPE_UNSPEC:
            return "BPF_MAP_TYPE_UNSPEC";
        case BPF_MAP_TYPE_HASH:
            return "BPF_MAP_TYPE_HASH";
        case BPF_MAP_TYPE_ARRAY:
            return "BPF_MAP_TYPE_ARRAY";
        case BPF_MAP_TYPE_PROG_ARRAY:
            return "BPF_MAP_TYPE_PROG_ARRAY";
        case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
            return "BPF_MAP_TYPE_PERF_EVENT_ARRAY";
        case BPF_MAP_TYPE_PERCPU_HASH:
            return "BPF_MAP_TYPE_PRESCPU_HAS";
        case BPF_MAP_TYPE_PERCPU_ARRAY:
            return "BPF_MAP_TYPE_PERCPU_ARRAY";
        case BPF_MAP_TYPE_STACK_TRACE:
            return "BPF_MAP_TYPE_STACK_TRACE";
        case BPF_MAP_TYPE_CGROUP_ARRAY:
            return "BPF_MAP_TYPE_CGROUP_ARRAY";
        case BPF_MAP_TYPE_LRU_HASH:
            return "BPF_MAP_TYPE_LRU_HASH";
        case BPF_MAP_TYPE_LRU_PERCPU_HASH:
            return "BPF_MAP_TYPE_LRU_PERCPU_HASH";
        case BPF_MAP_TYPE_LPM_TRIE:
            return "BPF_MAP_TYPE_LPM_TRIE";
        case BPF_MAP_TYPE_ARRAY_OF_MAPS:
            return "BPF_MAP_TYPE_ARRAY_OF_MAPS";
        case BPF_MAP_TYPE_HASH_OF_MAPS:
            return "BPF_MAP_TYPE_HASH_OF_MAPS";
        case BPF_MAP_TYPE_DEVMAP:
            return "BPF_MAP_TYPE_DEVMAP";
        case BPF_MAP_TYPE_SOCKMAP:
            return "BPF_MAP_TYPE_SOCKMAP";
        case BPF_MAP_TYPE_CPUMAP:
            return "BPF_MAP_TYPE_CPUMAP";
        case BPF_MAP_TYPE_XSKMAP:
            return "BPF_MAP_TYPE_XSKMAP";
        case BPF_MAP_TYPE_SOCKHASH:
            return "BPF_MAP_TYPE_SOCKHASH";
        case BPF_MAP_TYPE_CGROUP_STORAGE:
            return "BPF_MAP_TYPE_CGROUP_STORAGE";
        case BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:
            return "BPF_MAP_TYPE_REOUSEPORT_SOCKARRAY";
        case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
            return "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE";
        case BPF_MAP_TYPE_QUEUE:
            return "BPF_MAP_TYPE_QUEUE";
        case BPF_MAP_TYPE_STACK:
            return "BPF_MAP_TYPE_STACK";
        case BPF_MAP_TYPE_SK_STORAGE:
            return "BPF_MAP_TYPE_SK_STORAGE";
        case BPF_MAP_TYPE_DEVMAP_HASH:
            return "BPF_MAP_TYPE_DEVMAP_HASH";
        case BPF_MAP_TYPE_STRUCT_OPS:
            return "BPF_MAP_TYPE_STRUCT_OPS";
        case BPF_MAP_TYPE_RINGBUF:
            return "BPF_MAP_TYPE_RINGBUF";
        case BPF_MAP_TYPE_INODE_STORAGE:
            return "BPF_MAP_TYPE_INODE_STORAGE";
        case BPF_MAP_TYPE_TASK_STORAGE:
            return "BPF_MAP_TYPE_TASK_STORAGE";
        case BPF_MAP_TYPE_BLOOM_FILTER:
            return "BPF_MAP_TYPE_BLOOM_FILTER";
        default:
            return nullptr;
    }
}

typedef enum bpf_prog_type
{
    BPF_PROG_TYPE_UNSPEC,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_SCHED_CLS,
    BPF_PROG_TYPE_SCHED_ACT,
    BPF_PROG_TYPE_TRACEPOINT,
    BPF_PROG_TYPE_XDP,
    BPF_PROG_TYPE_PERF_EVENT,
    BPF_PROG_TYPE_CGROUP_SKB,
    BPF_PROG_TYPE_CGROUP_SOCK,
    BPF_PROG_TYPE_LWT_IN,
    BPF_PROG_TYPE_LWT_OUT,
    BPF_PROG_TYPE_LWT_XMIT,
    BPF_PROG_TYPE_SOCK_OPS,
    BPF_PROG_TYPE_SK_SKB,
    BPF_PROG_TYPE_CGROUP_DEVICE,
    BPF_PROG_TYPE_SK_MSG,
    BPF_PROG_TYPE_RAW_TRACEPOINT,
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    BPF_PROG_TYPE_LWT_SEG6LOCAL,
    BPF_PROG_TYPE_LIRC_MODE2,
    BPF_PROG_TYPE_SK_REUSEPORT,
    BPF_PROG_TYPE_FLOW_DISSECTOR,
    BPF_PROG_TYPE_CGROUP_SYSCTL,
    BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
    BPF_PROG_TYPE_CGROUP_SOCKOPT,
    BPF_PROG_TYPE_TRACING,
    BPF_PROG_TYPE_STRUCT_OPS,
    BPF_PROG_TYPE_EXT,
    BPF_PROG_TYPE_LSM,
    BPF_PROG_TYPE_SK_LOOKUP,
    BPF_PROG_TYPE_SYSCALL,
} bpf_prog_type_t;

static inline const char* bpf_prog_type_to_str(bpf_prog_type_t bpf_prog_type)
{
    switch (bpf_prog_type)
    {
        case BPF_PROG_TYPE_UNSPEC:
            return "BPF_PROG_TYPE_UNSPEC";
        case BPF_PROG_TYPE_SOCKET_FILTER:
            return "BPF_PROG_TYPE_SOCKET_FILTER";
        case BPF_PROG_TYPE_KPROBE:
            return "BPF_PROG_TYPE_KPROBE";
        case BPF_PROG_TYPE_SCHED_CLS:
            return "BPF_PROG_TYPE_SCHED_CLS";
        case BPF_PROG_TYPE_SCHED_ACT:
            return "BPF_PROG_TYPE_SCHED_ACT";
        case BPF_PROG_TYPE_TRACEPOINT:
            return "BPF_PROG_TYPE_TRACEPOINT";
        case BPF_PROG_TYPE_XDP:
            return "BPF_PROG_TYPE_XDP";
        case BPF_PROG_TYPE_PERF_EVENT:
            return "BPF_PROG_TYPE_PERF_EVENT";
        case BPF_PROG_TYPE_CGROUP_SKB:
            return "BPF_PROG_TYPE_CGROUP_SKB";
        case BPF_PROG_TYPE_CGROUP_SOCK:
            return "BPF_PROG_TYPE_CGROUP_SOCK";
        case BPF_PROG_TYPE_LWT_IN:
            return "BPF_PROG_TYPE_LWT_IN";
        case BPF_PROG_TYPE_LWT_OUT:
            return "BPF_PROG_TYPE_LWT_OUT";
        case BPF_PROG_TYPE_LWT_XMIT:
            return "BPF_PROG_TYPE_LWT_XMIT";
        case BPF_PROG_TYPE_SOCK_OPS:
            return "BPF_PROG_TYPE_SOCK_OPS";
        case BPF_PROG_TYPE_SK_SKB:
            return "BPF_PROG_TYPE_SK_SKB";
        case BPF_PROG_TYPE_CGROUP_DEVICE:
            return "BPF_PROG_TYPE_CGROUP_DEVICE";
        case BPF_PROG_TYPE_SK_MSG:
            return "BPF_PROG_TYPE_SK_MSG";
        case BPF_PROG_TYPE_RAW_TRACEPOINT:
            return "BPF_PROG_TYPE_RAW_TRACEPOINT";
        case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
            return "BPF_PROG_TYPE_CGROUP_SOCK_ADDR";
        case BPF_PROG_TYPE_LWT_SEG6LOCAL:
            return "BPF_PROG_TYPE_LWT_SEG6LOCAL";
        case BPF_PROG_TYPE_LIRC_MODE2:
            return "BPF_PROG_TYPE_LIRC_MODE2";
        case BPF_PROG_TYPE_SK_REUSEPORT:
            return "BPF_PROG_TYPE_SK_REUSEPORT";
        case BPF_PROG_TYPE_FLOW_DISSECTOR:
            return "BPF_PROG_TYPE_FLOW_DISSECTOR";
        case BPF_PROG_TYPE_CGROUP_SYSCTL:
            return "BPF_PROG_TYPE_CGROUP_SYSCTL";
        case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
            return "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE";
        case BPF_PROG_TYPE_CGROUP_SOCKOPT:
            return "BPF_PROG_TYPE_CGROUP_SOCKOPT";
        case BPF_PROG_TYPE_TRACING:
            return "BPF_PROG_TYPE_TRACING";
        case BPF_PROG_TYPE_STRUCT_OPS:
            return "BPF_PROG_TYPE_STRUCT_OPS";
        case BPF_PROG_TYPE_EXT:
            return "BPF_PROG_TYPE_EXT";
        case BPF_PROG_TYPE_LSM:
            return "BPF_PROG_TYPE_LSM";
        case BPF_PROG_TYPE_SK_LOOKUP:
            return "BPF_PROG_TYPE_SK_LOOKUP";
        case BPF_PROG_TYPE_SYSCALL:
            return "BPF_PROG_TYPE_SYSCALL";
        default:
            return nullptr;
    }
}

typedef enum bpf_attach_type
{
    BPF_CGROUP_INET_INGRESS,
    BPF_CGROUP_INET_EGRESS,
    BPF_CGROUP_INET_SOCK_CREATE,
    BPF_CGROUP_SOCK_OPS,
    BPF_SK_SKB_STREAM_PARSER,
    BPF_SK_SKB_STREAM_VERDICT,
    BPF_CGROUP_DEVICE,
    BPF_SK_MSG_VERDICT,
    BPF_CGROUP_INET4_BIND,
    BPF_CGROUP_INET6_BIND,
    BPF_CGROUP_INET4_CONNECT,
    BPF_CGROUP_INET6_CONNECT,
    BPF_CGROUP_INET4_POST_BIND,
    BPF_CGROUP_INET6_POST_BIND,
    BPF_CGROUP_UDP4_SENDMSG,
    BPF_CGROUP_UDP6_SENDMSG,
    BPF_LIRC_MODE2,
    BPF_FLOW_DISSECTOR,
    BPF_CGROUP_SYSCTL,
    BPF_CGROUP_UDP4_RECVMSG,
    BPF_CGROUP_UDP6_RECVMSG,
    BPF_CGROUP_GETSOCKOPT,
    BPF_CGROUP_SETSOCKOPT,
    BPF_TRACE_RAW_TP,
    BPF_TRACE_FENTRY,
    BPF_TRACE_FEXIT,
    BPF_MODIFY_RETURN,
    BPF_LSM_MAC,
    BPF_TRACE_ITER,
    BPF_CGROUP_INET4_GETPEERNAME,
    BPF_CGROUP_INET6_GETPEERNAME,
    BPF_CGROUP_INET4_GETSOCKNAME,
    BPF_CGROUP_INET6_GETSOCKNAME,
    BPF_XDP_DEVMAP,
    BPF_CGROUP_INET_SOCK_RELEASE,
    BPF_XDP_CPUMAP,
    BPF_SK_LOOKUP,
    BPF_XDP,
    BPF_SK_SKB_VERDICT,
    BPF_SK_REUSEPORT_SELECT,
    BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
    BPF_PERF_EVENT,
    BPF_TRACE_KPROBE_MULTI,
} bpf_attach_type_t;

static inline const char*
bpf_attach_type_to_str(bpf_attach_type_t bpf_attach_type)
{
    switch (bpf_attach_type)
    {
        case BPF_CGROUP_INET_INGRESS:
            return "BPF_CGROUP_INET_INGRESS";
        case BPF_CGROUP_INET_EGRESS:
            return "BPF_CGROUP_INET_EGRESS";
        case BPF_CGROUP_INET_SOCK_CREATE:
            return "BPF_CGROUP_INET_SOCK_CREATE";
        case BPF_CGROUP_SOCK_OPS:
            return "BPF_CGROUP_SOCK_OPS";
        case BPF_SK_SKB_STREAM_PARSER:
            return "BPF_SK_SKB_STREAM_PARSER";
        case BPF_SK_SKB_STREAM_VERDICT:
            return "BPF_SK_SKB_STREAM_VERDICT";
        case BPF_CGROUP_DEVICE:
            return "BPF_CGROUP_DEVICE";
        case BPF_SK_MSG_VERDICT:
            return "BPF_SK_MSG_VERDICT";
        case BPF_CGROUP_INET4_BIND:
            return "BPF_CGROUP_INET4_BIND";
        case BPF_CGROUP_INET6_BIND:
            return "BPF_CGROUP_INET6_BIND";
        case BPF_CGROUP_INET4_CONNECT:
            return "BPF_CGROUP_INET4_CONNECT";
        case BPF_CGROUP_INET6_CONNECT:
            return "BPF_CGROUP_INET6_CONNECT";
        case BPF_CGROUP_INET4_POST_BIND:
            return "BPF_CGROUP_INET4_POST_BIND";
        case BPF_CGROUP_INET6_POST_BIND:
            return "BPF_CGROUP_INET6_POST_BIND";
        case BPF_CGROUP_UDP4_SENDMSG:
            return "BPF_CGROUP_UDP4_SENDMSG";
        case BPF_CGROUP_UDP6_SENDMSG:
            return "BPF_CGROUP_UDP6_SENDMSG";
        case BPF_LIRC_MODE2:
            return "BPF_LIRC_MODE2";
        case BPF_FLOW_DISSECTOR:
            return "BPF_FLOW_DISSECTOR";
        case BPF_CGROUP_SYSCTL:
            return "BPF_CGROUP_SYSCTL";
        case BPF_CGROUP_UDP4_RECVMSG:
            return "BPF_CGROUP_UDP4_RECVMSG";
        case BPF_CGROUP_UDP6_RECVMSG:
            return "BPF_CGROUP_UDP6_RECVMSG";
        case BPF_CGROUP_GETSOCKOPT:
            return "BPF_CGROUP_GETSOCKOPT";
        case BPF_CGROUP_SETSOCKOPT:
            return "BPF_CGROUP_SETSOCKOPT";
        case BPF_TRACE_RAW_TP:
            return "BPF_TRACE_RAW_TP";
        case BPF_TRACE_FENTRY:
            return "BPF_TRACE_FENTRY";
        case BPF_TRACE_FEXIT:
            return "BPF_TRACE_FEXIT";
        case BPF_MODIFY_RETURN:
            return "BPF_MODIFY_RETURN";
        case BPF_LSM_MAC:
            return "BPF_LSM_MAC";
        case BPF_TRACE_ITER:
            return "BPF_TRACE_ITER";
        case BPF_CGROUP_INET4_GETPEERNAME:
            return "BPF_CGROUP_INET4_GETPEERNAME";
        case BPF_CGROUP_INET6_GETPEERNAME:
            return "BPF_CGROUP_INET6_GETPEERNAME";
        case BPF_CGROUP_INET4_GETSOCKNAME:
            return "BPF_CGROUP_INET4_GETSOCKNAME";
        case BPF_CGROUP_INET6_GETSOCKNAME:
            return "BPF_CGROUP_INET6_GETSOCKNAME";
        case BPF_XDP_DEVMAP:
            return "BPF_XDP_DEVMAP";
        case BPF_CGROUP_INET_SOCK_RELEASE:
            return "BPF_CGROUP_INET_SOCK_RELEASE";
        case BPF_XDP_CPUMAP:
            return "BPF_XDP_CPUMAP";
        case BPF_SK_LOOKUP:
            return "BPF_SK_LOOKUP";
        case BPF_XDP:
            return "BPF_XDP";
        case BPF_SK_SKB_VERDICT:
            return "BPF_SK_SKB_VERDICT";
        case BPF_SK_REUSEPORT_SELECT:
            return "BPF_SK_REUSEPORT_SELECT";
        case BPF_SK_REUSEPORT_SELECT_OR_MIGRATE:
            return "BPF_SK_REUSEPORT_SELECT_OR_MIGRATE";
        case BPF_PERF_EVENT:
            return "BPF_PERF_EVENT";
        case BPF_TRACE_KPROBE_MULTI:
            return "BPF_TRACE_KPROBE_MULTI";
        default:
            return nullptr;
    }
}

#endif