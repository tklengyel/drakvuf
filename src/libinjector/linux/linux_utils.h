#ifndef LINUX_UTILS_H
#define LINUX_UTILS_H

#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <json-c/json.h>
#include <libinjector/libinjector.h>
#include <libvmi/libvmi.h>
#include <libvmi/x86.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>
#include <libdrakvuf/libdrakvuf.h>
#include <libinjector/private.h>

typedef enum
{
    INJECT_RESULT_SUCCESS,
    INJECT_RESULT_TIMEOUT,
    INJECT_RESULT_CRASH,
    INJECT_RESULT_ERROR_CODE,
    INJECT_RESULT_METHOD_UNSUPPORTED,
} inject_result_t;

typedef enum
{
    STEP1,
    STEP2,
    STEP3,
    STEP4,
    STEP5,
    STEP6,
    STEP7,
    STEP8,
    STEP9,
} injector_step_t;

typedef enum
{
    sys_read = 0,
    sys_write = 1,
    sys_open = 2,
    sys_close = 3,
    sys_stat = 4,
    sys_mmap = 9,
    sys_mprotect = 10,
    sys_munmap = 11,
    sys_exit = 60,
    sys_kill = 62,
} syscall_t;

struct injector
{
    // Inputs:
    vmi_pid_t target_pid;
    uint32_t target_tid;
    const char* target_file;
    int args_count;
    const char** args;
    output_format_t format;

    // Internal:
    drakvuf_t drakvuf;
    injection_method_t method;
    syscall_t syscall_no;
    addr_t syscall_addr;
    injector_step_t step;

    // shellcode
    struct
    {
        void* data;
        int len;
    } shellcode;

    // mmap
    addr_t virtual_memory_addr;

    // for restoring stack
    x86_registers_t saved_regs;

    // int3 trap
    drakvuf_trap_t* bp;

    // Traps
    drakvuf_trap_t* cr3_trap;

    // Results:
    injector_status_t rc;
    inject_result_t result;
    struct
    {
        bool valid;
        uint32_t code;
        const char* string;
    } error_code;
};

void free_bp_trap(drakvuf_t drakvuf, injector_t injector, drakvuf_trap_t* trap);
void free_injector(injector_t injector);
bool save_rip_for_ret(drakvuf_t drakvuf, x86_registers_t* regs);
addr_t find_vdso(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
addr_t find_syscall(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t vdso);
bool setup_post_syscall_trap(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t syscall_addr);
bool load_shellcode_from_file(injector_t injector, const char* file);
bool check_userspace_int3_trap(injector_t injector, drakvuf_trap_info_t* info);

#endif
