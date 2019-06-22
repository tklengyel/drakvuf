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

static addr_t hijack_get_function_address(drakvuf_t drakvuf, char* function_name){
        PRINT_DEBUG("Trying to Get function va\n");
        addr_t rva = 0;
        drakvuf_get_function_rva(drakvuf, "noError", &rva);
        if(!rva)
            return 0;
        PRINT_DEBUG("Returned RVA = %"PRIx64"\n", rva);
        addr_t bugcheckaddr = 0;
        bugcheckaddr = drakvuf_exportksym_to_va(drakvuf, 4, "ndoError", "DummyDriver.sys", rva);
        return bugcheckaddr;
}

static bool setup_message_box_stack(hijacker_t hijacker, drakvuf_trap_info_t *info){
    /**
     * int MessageBox(
        HWND    hWnd,           ==>NULL
        LPCTSTR lpText,         ==>String
        LPCTSTR lpCaption,      ==>NULL
        UINT    uType           ==>0x00000000L
    );
    */
   struct argument args[4] = { {0} };
   init_int_argument(&args[0], 0);
   char *str = "Hijacked";
   unicode_string_t *message = convert_utf8_to_utf16(str);
   init_unicode_argument(&args[1], message);
   init_int_argument(&args[2], 0);
   init_int_argument(&args[3], 0);
   //assuming 64 bit
   //TODO add checks for 32 bit
   bool success = setup_stack(hijacker->drakvuf, info, args, ARRAY_SIZE(args));
   return success;

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
    drakvuf_pause(drakvuf);
    PRINT_DEBUG("[+] Removing return trap\n");
    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    PRINT_DEBUG("[+] Restoring registers\n");
    memcpy(info->regs, &hijacker->saved_regs, sizeof(x86_registers_t));
    drakvuf_resume(drakvuf);
    return VMI_EVENT_RESPONSE_SET_REGISTERS;

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

    (void)setup_hijack_int3_trap;
    hijacker_t hijacker = info->trap->data;
    addr_t msg_box_addr;
    addr_t eprocess_base;
    PRINT_DEBUG("[+] Hijack In cr3cb\n");
    if ( info->proc_data.pid != hijacker->target_pid )
    {
        PRINT_DEBUG("cr3cb received but '%s' PID (%u) doesn't match target process (%u)\n",
                    info->proc_data.name, info->proc_data.pid, hijacker->target_pid);
        return 0;
    }
    
    PRINT_DEBUG("[+] Finding Process\n");
    if ( !drakvuf_find_process(drakvuf, hijacker->target_pid, NULL, &eprocess_base) ){
        PRINT_DEBUG("[+] Find process failed\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    if( hijacker->status == STATUS_NULL)
    {
        drakvuf_pause(drakvuf);
        PRINT_DEBUG("[+] Searching for function\n");
            addr_t bugcheckaddr = hijacker->exec_func;            
            if(bugcheckaddr){
                PRINT_DEBUG("[+] Saving register state\n");
                memcpy(&hijacker->saved_regs, info->regs, sizeof(x86_registers_t));
                PRINT_DEBUG("[+] Hijacking to KeBugCheckAddress %"PRIx64"\n",bugcheckaddr);
                // struct argument args[1];
                // unicode_string_t *str = convert_utf8_to_utf16("hello from vmi");
                // setup_hijack_int3_trap(hijacker, info, info->regs->rip);
                // init_unicode_argument(&args[0], str);
                // setup_stack(drakvuf, info, args, ARRAY_SIZE(args));
                // info->regs->rip = bugcheckaddr;
                drakvuf_resume(drakvuf);
                return 0;
            }
            else{
                PRINT_DEBUG("KeBugCheck Address NOT found\n");
                drakvuf_resume(drakvuf);
                return 0;
            }
        //#########################################################

        msg_box_addr = get_function_va(drakvuf, eprocess_base, "user32.dll", "Mes2sageBoxW", true);
        if (!msg_box_addr){
            PRINT_DEBUG("msg_box_addr not found\n");
            return VMI_EVENT_RESPONSE_NONE;
        }
        memcpy(&hijacker->saved_regs, info->regs, sizeof(x86_registers_t));
        PRINT_DEBUG("[+] In usermode by hijack cb... "
            "\n[+] Setting up stack\n");
        if (!setup_message_box_stack(hijacker, info))
            PRINT_DEBUG("[+] Hijacking: Stack setup failed\n");
        PRINT_DEBUG("[+] Stack setup\n");

        return 0;

        PRINT_DEBUG("[+] Modifying rip\n");
        info->regs->rip = msg_box_addr;
        hijacker->status = STATUS_CREATE_OK;
        drakvuf_resume(drakvuf);
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    
    return 0;
    
}






int hijack(
    drakvuf_t drakvuf,
    vmi_pid_t target_pid,
    char *function_name
)
{
    PRINT_DEBUG("Trying to Get function va\n");
    addr_t bugcheckaddr = 0;
    #if 1
    bugcheckaddr = hijack_get_function_address(drakvuf, function_name);
    #else
    // addr_t proc_base = 0;
    // drakvuf_find_process(drakvuf, target_pid, NULL, &proc_base);
    // bugcheckaddr = get_function_va(drakvuf, proc_base, "DummyDriver.sys", "noError", true);
    #endif
    if(bugcheckaddr)
        PRINT_DEBUG("Address found for KeBugCheck %"PRIx64"\n", bugcheckaddr);
    else
        PRINT_DEBUG("KeBugCheck Address NOT found\n");


    return 0;
    // #######################  checking  ##############################        

    PRINT_DEBUG("[+] Target PID %u to jump to function %s\n", target_pid, function_name );

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

    hijacker->exec_func = hijack_get_function_address(drakvuf);
    if(!hijacker->exec_func)
    {
        PRINT_DEBUG("KeBugCheck Address Not found");
        return 0;
    }
    
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
