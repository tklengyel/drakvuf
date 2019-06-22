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

bool hijack_get_driver_function_rva(hijacker_t hijacker, char *function_name, addr_t *rva)
{
    return rekall_get_function_rva(hijacker->driver_rekall_profile_json, function_name, rva);
}

static addr_t hijack_get_function_address(hijacker_t hijacker, char* function_name){
        PRINT_DEBUG("Trying to Get address for %s\n", function_name);
        addr_t rva = 0;
        hijack_get_driver_function_rva(hijacker, function_name, &rva);
        if(!rva)
            return 0;
        PRINT_DEBUG("Returned RVA = %"PRIx64"\n", rva);        
        return  drakvuf_exportksym_to_va(hijacker->drakvuf, 4, function_name, "DummyDriver.sys", rva);;
}



static event_response_t hijack_return_path(drakvuf_t drakvuf, drakvuf_trap_info_t *info)
{
    //Return path
    PRINT_DEBUG("[+] int3_cb for return \n");
    hijacker_t hijacker = info->trap->data;
    if ( info->proc_data.pid != hijacker->target_pid)
    {
        PRINT_DEBUG("INT3 received but '%s' PID (%u) doesn't match target process (%u)\n",
                    info->proc_data.name, info->proc_data.pid, hijacker->target_pid);
        return 0;
    }

    //TODO check rsp, vcpu

    if(hijacker->status == STATUS_CREATE_OK){
        drakvuf_pause(drakvuf);
        PRINT_DEBUG("[+] Removing return trap\n");
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
        PRINT_DEBUG("[+] Restoring registers\n");
        memcpy(info->regs, &hijacker->saved_regs, sizeof(x86_registers_t));
        drakvuf_resume(drakvuf);
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    return 0;
}

static int setup_hijack_int3_trap(hijacker_t hijacker, drakvuf_trap_info_t* info, addr_t bp_addr)
{   
    drakvuf_trap_t trap = 
    {
        .type = BREAKPOINT,
        .name = "returnpath",
        .cb = hijack_return_path,
        .data = hijacker,
        .breakpoint.lookup_type = LOOKUP_DTB,
        .breakpoint.dtb = info->regs->cr3,
        .breakpoint.addr_type = ADDR_VA,
        .breakpoint.addr = bp_addr
    };

    return drakvuf_add_trap(hijacker->drakvuf, &trap);
}

static event_response_t hijack_wait_for_kernel_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info)
{

    hijacker_t hijacker = info->trap->data;
    PRINT_DEBUG("[+] Hijack In cr3cb\n");
    if ( info->proc_data.pid != hijacker->target_pid )
    {
        PRINT_DEBUG("cr3cb received but '%s' PID (%u) doesn't match target process (%u)\n",
                    info->proc_data.name, info->proc_data.pid, hijacker->target_pid);
        return 0;
    }
    
    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    if( hijacker->status == STATUS_NULL)
    {
        drakvuf_pause(drakvuf);
            PRINT_DEBUG("[+] Saving register state\n");
            memcpy(&hijacker->saved_regs, info->regs, sizeof(x86_registers_t));

            setup_hijack_int3_trap(hijacker, info, info->regs->rip);

            PRINT_DEBUG("[+] Hijacking to  %"PRIx64"\n",hijacker->exec_func);
            info->regs->rip = hijacker->exec_func;
            drakvuf_resume(drakvuf);

            hijacker->status = STATUS_CREATE_OK;

            return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    drakvuf_resume(drakvuf); 
    return 0;
    
}






int hijack(
    drakvuf_t drakvuf,
    vmi_pid_t target_pid,
    char *function_name,
    char *driver_rekall
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
    hijacker->status = STATUS_NULL;
    hijacker->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    // hijacker->break_loop_on_detection = break_loop_on_detection;
    // hijacker->error_code.valid = false;
    // hijacker->error_code.code = -1;
    // hijacker->error_code.string = "<UNKNOWN>";
    hijacker->status = STATUS_NULL;
    hijacker->driver_rekall_profile_json = json_object_from_file(driver_rekall);

    hijacker->exec_func = hijack_get_function_address(hijacker, function_name);
    if(!hijacker->exec_func)
    {
        PRINT_DEBUG("%s Address Not found\n",function_name);
        return 0;
    }
    PRINT_DEBUG("Address for %s found: %"PRIx64"\n", function_name, hijacker->exec_func);
    return 0;
    
    drakvuf_trap_t trap =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = hijack_wait_for_kernel_cb,
        .data = hijacker,
    };

     if (!drakvuf_add_trap(drakvuf, &trap))
        return false;

    if (!drakvuf_is_interrupted(drakvuf))
    {
        PRINT_DEBUG("Starting injection loop\n");
        drakvuf_loop(drakvuf);
    }



    return true;

}
