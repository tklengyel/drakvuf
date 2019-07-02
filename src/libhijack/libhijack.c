#include <config.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include "libhijack.h"
#include "libdrakvuf/libdrakvuf.h"
#include "libinjector/libinjector.h"
#include "private.h"
#include "colors.h"

bool hijack_get_driver_function_rva(hijacker_t hijacker, char *function_name, addr_t *rva)
{
    bool rva_found =  rekall_get_function_rva(hijacker->driver_rekall_profile_json, function_name, rva);
    if(!rva_found){
        rva_found = drakvuf_get_function_rva(hijacker->drakvuf, function_name, rva);
    }
    return rva_found;
}

static addr_t hijack_get_function_address(hijacker_t hijacker, char* function_name, char *lib_name){
        PRINT_DEBUG("Trying to Get address for %s\n", function_name);
        addr_t rva = 0;
        hijack_get_driver_function_rva(hijacker, function_name, &rva);
        if(!rva)
            return 0;
        PRINT_DEBUG("Returned RVA = %"PRIx64"\n", rva);        
        return  drakvuf_exportksym_to_va(hijacker->drakvuf, 4, function_name, lib_name, rva);;
}

static void release_ozzer_lock(hijacker_t hijacker)
{
    g_atomic_int_set(hijacker->spin_lock, false);   

}

static event_response_t hijack_return_path(drakvuf_t drakvuf, drakvuf_trap_info_t *info)
{
    //Return path
    hijacker_t hijacker = info->trap->data;
    
    if ( info->proc_data.pid != hijacker->target_pid)
    {
        // PRINT_DEBUG("INT3 received but '%s' PID (%u) doesn't match target process (%u)\n",
                    // info->proc_data.name, info->proc_data.pid, hijacker->target_pid);
        return 0;
    }
    PRINT_DEBUG("[+] int3_cb for return \n");
    uint32_t tid;
    drakvuf_get_current_thread_id(drakvuf, info->vcpu, &tid);
    PRINT_DEBUG(BGYELLOW BLACK"[+] In INT3 CB PID=%d, Process Name = %s ThreadId = %d "BLUE"cr3 = %lx"RESET"\n", info->proc_data.pid
                                                                        , info->proc_data.name
                                                                        , tid
                                                                        , info->regs->cr3);
    if(hijacker->target_tid != 0 && tid != hijacker->target_tid)
    {
        return 0;
    }

    //TODO check rsp, vcpu
    if(hijacker->int3_status == STATUS_NULL){
        /**
         * Two major tasks here
         *  1) Restoring the registers
         *  2) Reporting the return value from the called function
         */
        uint64_t ret_value = info->regs->rax;
        fprintf(stderr, BGGREEN "[+] RAX = %"PRId64 RESET  "\n", ret_value);
        hijacker->int3_status = STATUS_RESTORE_OK;
        PRINT_DEBUG("[+] Restoring registers\n");
        memcpy(info->regs, &hijacker->saved_regs, sizeof(x86_registers_t));        
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    else if( hijacker->int3_status == STATUS_RESTORE_OK)
    {   
        /**
         * We reach here when the hijacked process is working fine
         * 
         */
        drakvuf_pause(drakvuf);
        PRINT_DEBUG("[+] Removing return trap\n");
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
        hijacker->int3_status = STATUS_RESUME_OK;
        release_ozzer_lock(hijacker);
        drakvuf_interrupt(drakvuf,SIGINT);
        drakvuf_resume(drakvuf);
    }
    return 0;
}

static bool hijack_setup_int3_trap(hijacker_t hijacker, drakvuf_trap_info_t* info, addr_t bp_addr)
{   
    
    hijacker->bp.type = BREAKPOINT;
    hijacker->bp.name = "returnpath";
    hijacker->bp.cb = hijack_return_path;
    hijacker->bp.data = hijacker;
    hijacker->bp.breakpoint.lookup_type = LOOKUP_DTB;
    hijacker->bp.breakpoint.dtb = info->regs->cr3;
    hijacker->bp.breakpoint.addr_type = ADDR_VA;
    hijacker->bp.breakpoint.addr = bp_addr;

    return drakvuf_add_trap(hijacker->drakvuf, &hijacker->bp);
}

static event_response_t hijack_wait_for_kernel_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info)
{

    
    hijacker_t hijacker = info->trap->data;
    
    if ( info->proc_data.pid != hijacker->target_pid )
    {
        // PRINT_DEBUG("cr3cb received but '%s' PID (%u) doesn't match target process (%u)\n",
        //             info->proc_data.name, info->proc_data.pid, hijacker->target_pid);
        return 0;
    }

    uint32_t tid;
    drakvuf_get_current_thread_id(drakvuf, info->vcpu, &tid);
    PRINT_DEBUG(BGCYAN BLACK"[+] In CR3 CB PID=%d, Process Name = %s ThreadId = %d "BLUE"cr3 = %lx"RESET"\n", info->proc_data.pid
                                                                        , info->proc_data.name
                                                                        , tid
                                                                        , info->regs->cr3);
    if(hijacker->target_tid != 0 && tid != hijacker->target_tid)
    {
        return 0;
    }

    if(hijacker->cr3_status == STATUS_NULL){
        PRINT_DEBUG("[+] Saving register state\n");
        memcpy(&hijacker->saved_regs, info->regs, sizeof(x86_registers_t));
        PRINT_DEBUG("[+] Removing wait for kernel trap\n");
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
        // UNUSED(hijack_setup_int3_trap);
        hijacker->cr3_status = STATUS_CREATE_OK;
        if(!setup_stack_from_json(hijacker, info))
        {
            PRINT_DEBUG("[+] Could not setup stack\n");
            hijacker->rc = false;
            drakvuf_interrupt(drakvuf, 2);
            drakvuf_resume(drakvuf);
            release_ozzer_lock(hijacker);
            return 0;
        }
        
        PRINT_DEBUG("[+] Hijacking to  %"PRIx64"\n",hijacker->exec_func);
        if(!hijack_setup_int3_trap(hijacker, info, info->regs->rip))
        {
            PRINT_DEBUG("[+] Could not setup return trap: leaving");
            return 0;
        }
        info->regs->rip = hijacker->exec_func;
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    return 0;
}


int hijack(
    drakvuf_t drakvuf,
    vmi_pid_t target_pid,
    uint32_t target_tid,
    char *function_name,
    char *driver_rekall,
    char *lib_name,
    json_object *args,
    volatile  int *spin_lock
)
{

    PRINT_DEBUG("[+] Hijacking PID %u to function %s\n", target_pid, function_name );

    hijacker_t hijacker = (hijacker_t)g_malloc0(sizeof(struct hijacker));
    if (!hijacker)
    {
        PRINT_DEBUG("[+] hijacker g_malloc failed\n");
        return false;
    }

    hijacker->drakvuf = drakvuf;
    hijacker->target_pid = target_pid;
    hijacker->function_name = function_name;
    // hijacker->target_tid = tid;
    // hijacker->target_file_us = target_file_us;
    hijacker->global_search = true;
    hijacker->int3_status = STATUS_NULL;
    hijacker->cr3_status = STATUS_NULL;
    hijacker->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    // hijacker->break_loop_on_detection = break_loop_on_detection;
    // hijacker->error_code.valid = false;
    // hijacker->error_code.code = -1;
    // hijacker->error_code.string = "<UNKNOWN>";
    hijacker->driver_rekall_profile_json = json_object_from_file(driver_rekall);
    hijacker->exec_func = hijack_get_function_address(hijacker, function_name, lib_name);
    hijacker->spin_lock = spin_lock;
    hijacker->args = args;
    hijacker->rc = true;
    hijacker->cr3_valid = false;
    if(target_tid != 0)
    {
        hijacker->target_tid = target_tid;
    }
    if(!hijacker->exec_func)
    {
        PRINT_DEBUG("%s Address Not found\n",function_name);
        return 0;
    }
    PRINT_DEBUG("Address for %s found: %"PRIx64"\n", function_name, hijacker->exec_func);
    
    drakvuf_trap_t trap =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = hijack_wait_for_kernel_cb,
        .data = hijacker
    };

     if (!drakvuf_add_trap(drakvuf, &trap))
        return false;

    PRINT_DEBUG("Starting injection loop\n");
    if (!drakvuf_is_interrupted(drakvuf))
    {
        drakvuf_loop(drakvuf);
    }    
    g_free(hijacker);
    drakvuf_interrupt(drakvuf, 0);
    return hijacker->rc;

}
