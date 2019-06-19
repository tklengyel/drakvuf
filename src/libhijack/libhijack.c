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

static event_response_t hijack_return_path(drakvuf_t drakvuf, drakvuf_trap_info_t *info)
{
    //Return from msg box
    PRINT_DEBUG("[+] int3_cb for return from msgbox\n");
    injector_t injector = info->trap->data;
    if ( info->proc_data.pid != injector->target_pid)
    {
        PRINT_DEBUG("INT3 received but '%s' PID (%u) doesn't match target process (%u)\n",
                    info->proc_data.name, info->proc_data.pid, injector->target_pid);
        return 0;
    }
    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    PRINT_DEBUG("[+] Removing return trap\n");
    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    PRINT_DEBUG("[+] Restoring registers\n");
    return VMI_EVENT_RESPONSE_SET_REGISTERS;

}

static bool setup_hijack_int3_trap(injector_t injector, drakvuf_trap_info_t* info, addr_t bp_addr)
{
    injector->bp.type = BREAKPOINT;
    injector->bp.name = "return path";
    injector->bp.cb = hijack_return_path;
    injector->bp.data = injector;
    injector->bp.breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp.breakpoint.dtb = info->regs->cr3;
    injector->bp.breakpoint.addr_type = ADDR_VA;
    injector->bp.breakpoint.addr = bp_addr;

    return drakvuf_add_trap(injector->drakvuf, &injector->bp);
}

static event_response_t hijack_wait_for_kernel_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info)
{

    (void)setup_hijack_int3_trap;
    addr_t msg_box_addr;
    addr_t eprocess_base;
    injector_t injector = info->trap->data;
    PRINT_DEBUG("[+] Hijack In int3\n");
    if ( info->proc_data.pid != injector->target_pid )
    {
        PRINT_DEBUG("int3cb received but '%s' PID (%u) doesn't match target process (%u)\n",
                    info->proc_data.name, info->proc_data.pid, injector->target_pid);
        return 0;
    }
    
    PRINT_DEBUG("[+] Finding Process\n");
    if ( !drakvuf_find_process(drakvuf, injector->target_pid, NULL, &eprocess_base) ){
        PRINT_DEBUG("[+] Find process failed\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    if( injector->status == STATUS_NULL)
    {
        drakvuf_pause(drakvuf);
        PRINT_DEBUG("[+] Searching for function\n");
        msg_box_addr = get_function_va(drakvuf, eprocess_base, "ntoskrnl.dll", "MessageBoxW", true);
        if (!msg_box_addr){
            PRINT_DEBUG("msg_box_addr not found\n");
            return VMI_EVENT_RESPONSE_NONE;
        }
        memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));
        PRINT_DEBUG("[+] In usermode by hijack cb... "
            "\n[+] Setting up stack\n");
        if (!setup_message_box_stack(injector, info))
            PRINT_DEBUG("[+] Hijacking: Stack setup failed\n");
        PRINT_DEBUG("[+] Stack setup\n");

        

        PRINT_DEBUG("[+] Modifying rip\n");

        info->regs->rip = msg_box_addr;
        injector->status = STATUS_CREATE_OK;
        drakvuf_resume(drakvuf);
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    else if(injector->status == STATUS_CREATE_OK){
        // PRINT_DEBUG("[+] Setting up return trap\n");
        // if(!setup_hijack_int3_trap(injector, info, info->regs->rip))
        // {
        //     PRINT_DEBUG("[+] Failed setting up return trap\n");
        //     return VMI_EVENT_RESPONSE_NONE;
        // }
        drakvuf_pause(drakvuf);
        PRINT_DEBUG("[+] Restoring registers\n");
        memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
        PRINT_DEBUG("[+] Removing trap\n");
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
        drakvuf_resume(drakvuf);
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    return 0;
    
}





static bool setup_message_box_stack(injector_t injector, drakvuf_trap_info_t *info){
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
   bool success = setup_stack(injector->drakvuf, info, args, ARRAY_SIZE(args));
   return success;

}

bool hijack(
    drakvuf_t drakvuf,
    vmi_pid_t target_pid,
    char *function_name
)
{
    PRINT_DEBUG("[+] Target PID %u to jump to function %s\n", target_pid, function_name );

    injector_t injector = (injector_t)g_malloc0(sizeof(struct injector));
    if (!injector)
    {
        PRINT_DEBUG("[+] Injector g_malloc failed\n");
        return false;
    }

    injector->drakvuf = drakvuf;
    injector->target_pid = target_pid;
    // injector->target_tid = tid;
    // injector->target_file_us = target_file_us;
    // injector->cwd_us = cwd_us;
    injector->method = INJECT_METHOD_CREATEPROC;
    injector->global_search = true;
    // injector->binary_path = binary_path;
    // injector->target_process = target_process;
    injector->status = STATUS_NULL;
    injector->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    // injector->break_loop_on_detection = break_loop_on_detection;
    injector->error_code.valid = false;
    injector->error_code.code = -1;
    injector->error_code.string = "<UNKNOWN>";
    injector->status = STATUS_NULL;

    if (!initialize_injector_functions(drakvuf, injector, NULL, NULL))
    {
        PRINT_DEBUG("Unable to initialize injector functions\n");
        free_injector(injector);
        return 0;
    }
    drakvuf_trap_t trap =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = hijack_wait_for_kernel_cb,
        .data = injector,
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