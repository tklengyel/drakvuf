#include <config.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <libhijack.h>
#include "libdrakvuf/libdrakvuf.h"
#include "libinjector/libinjector.h"
#include "colors.h"
#include "libvmi/libvmi_extra.h"
#include "private.h"

void print_page_info(page_info_t *pi, int entry_number)
{
    if(entry_number%2 == 0)
    {
        fprintf(stderr, BGBLUE BLACK);
    }
    else
    {
        fprintf(stderr, BGCYAN BLACK);
    }
    fprintf(stderr, "pte_location = %lx \n", pi->x86_ia32e.pte_location);
    fprintf(stderr, "pte_value = %lx \n", pi->x86_ia32e.pte_value);
    fprintf(stderr, "pgd_location = %lx \n", pi->x86_ia32e.pgd_location);
    fprintf(stderr, "pgd_value = %lx \n", pi->x86_ia32e.pgd_value);
    fprintf(stderr, "pdpte_location = %lx \n", pi->x86_ia32e.pdpte_location);
    fprintf(stderr, "pdpte_value = %lx \n", pi->x86_ia32e.pdpte_value);
    fprintf(stderr, "pml4e_location = %lx \n", pi->x86_ia32e.pml4e_location);
    fprintf(stderr, "pml4e_value = %lx \n", pi->x86_ia32e.pml4e_value);
    fprintf(stderr, RESET);
}

void print_page_table(drakvuf_t drakvuf, addr_t dtb)
{
    vmi_instance_t vmi;
    vmi = drakvuf_lock_and_get_vmi(drakvuf);
    drakvuf_pause(drakvuf);
    fprintf(stderr, BGGREEN BLACK"Printing page table for dtb = %lx" RESET "\n", dtb);

    GSList* loop = vmi_get_va_pages(vmi, dtb);
    fprintf(stderr, BGGREEN BLACK"Got page table for dtb = %lx" RESET "\n", dtb);
    int i = 0;
    while(loop)
    {
        page_info_t *page = loop->data;
        print_page_info(page, i);
        i++;
        free(loop->data);
        loop = loop->next;
    }
    drakvuf_resume(drakvuf);
    drakvuf_release_vmi(drakvuf);
}

addr_t hijack_get_user_dtb(drakvuf_t drakvuf, addr_t process, hijacker_t hijacker)
{
    addr_t udtb = 0;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    vmi_read_64_va(vmi, process + hijacker->offsets[KPROCESS_USERDIRECTORYTABLEBASE],
        hijacker->target_pid, &udtb);
    drakvuf_release_vmi(drakvuf);
    return udtb;
}

addr_t hijack_get_dtb(drakvuf_t drakvuf, addr_t process, hijacker_t hijacker)
{
    addr_t dtb = 0;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    vmi_read_64_va(vmi, process + hijacker->offsets[KPROCESS_DIRECTORYTABLEBASE],
        hijacker->target_pid, &dtb);
    drakvuf_release_vmi(drakvuf);
    return dtb;
}

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
        PRINT_DEBUG("INT3 received but '%s' PID (%u) doesn't match target process (%u)\n",
                    info->proc_data.name, info->proc_data.pid, hijacker->target_pid);
        return 0;
    }
    PRINT_DEBUG("[+] int3_cb for return \n");
    uint32_t tid;
    drakvuf_get_current_thread_id(drakvuf, info->vcpu, &tid);
    PRINT_DEBUG(BGYELLOW BLACK"[+] In INT3 CB PID=%d, Process Name = %s ThreadId = %d " BLUE"cr3 = %lx"RESET"\n", info->proc_data.pid
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
        /**
         * We should only release the lock when we have returned to rip second time
         * Which is when the registers are restored and os restored to state it was
         * in bfore hijacking.
         */
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

bool hijack_get_user_rsp(hijacker_t hijacker, addr_t thread, addr_t *rsp)
{
    drakvuf_t drakvuf = hijacker->drakvuf;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    drakvuf_pause(drakvuf);
    addr_t ktrap_frame;
    if( vmi_read_64_va(vmi, thread + hijacker->offsets[KTHREAD_TRAPFRAME],
                                        hijacker->target_pid,
                                        &ktrap_frame ) != VMI_SUCCESS)
    {
        fprintf(stderr, "Reading KTRAP_FRAME failed \n");   
        goto error;
    }
    fprintf(stderr, "KTRAP_FRAME  = %lx \n", ktrap_frame);
    if( vmi_read_64_va(vmi, ktrap_frame + hijacker->offsets[KTRAP_FRAME_RSP],
                                        hijacker->target_pid,
                                        rsp ) != VMI_SUCCESS )
    {
        fprintf(stderr, "Reading TRAPFRAME_RSP failed \n");   
        goto error;
    }
    drakvuf_resume(drakvuf);
    drakvuf_release_vmi(drakvuf);
    return true;

    error:
    drakvuf_resume(drakvuf);
    drakvuf_release_vmi(drakvuf);
    return false;
}

static event_response_t hijack_wait_for_kernel_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info)
{
    hijacker_t hijacker = info->trap->data;
    if ( info->proc_data.pid != hijacker->target_pid )
    {
        PRINT_DEBUG("cr3cb received but '%s' PID (%u) doesn't match target process (%u)\n",
                    info->proc_data.name, info->proc_data.pid, hijacker->target_pid);
        return 0;
    }

   
    uint8_t cpl = info->regs->cs_sel & 3;
    if(cpl != 0 )
    {
        fprintf(stderr, "Something serverely wrong, Not in ring 0 Ring = %d\n", cpl);
        return 0;
    }

    uint32_t tid;
    drakvuf_get_current_thread_id(drakvuf, info->vcpu, &tid);
    
    fprintf(stderr, BGCYAN BLACK"[+] In CR3 CB PID=%d, Process Name = %s"
    "ThreadId = %d, PPID = %d, BASE Addr = %lx, "
    "User Id = %"PRIx64 BOLD BLACK", cr3 = %lx"RESET"\n", info->proc_data.pid
                                                , info->proc_data.name
                                                , tid
                                                , info->proc_data.ppid
                                                , info->proc_data.base_addr
                                                , info->proc_data.userid
                                                , info->regs->cr3);

    if(hijacker->target_tid != 0 && tid != hijacker->target_tid)
    {
        return 0;
    }

    addr_t udtb;
    udtb = hijack_get_user_dtb(drakvuf, info->proc_data.base_addr, hijacker);
    fprintf(stderr, "user dtb = %"PRIx64"\n", udtb);
    addr_t dtb;
    dtb = hijack_get_dtb(drakvuf, info->proc_data.base_addr, hijacker);
    fprintf(stderr, "dtb = %"PRIx64"\n", dtb);

    if(info->regs->cr3 != dtb)
    {
        fprintf(stderr, BGYELLOW BLACK"[+] CR3 is userdtb PID=%d, "
            "cr3 = %lx"RESET"\n", info->proc_data.pid
                                , info->regs->cr3);
        return 0;
    }

    // addr_t thread;
    // thread = drakvuf_get_current_thread(drakvuf, info->vcpu);
    // addr_t rsp;
    // if(!hijack_get_user_rsp(hijacker, thread, &rsp))
    // {
    //     fprintf(stderr, "Getting user RSP failed \n");
    //     drakvuf_remove_trap(drakvuf, info->trap, NULL);
    //     goto error;
    // }
    // fprintf(stderr, BGMAGENTA BLACK "User RSP = %"PRIx64 RESET "\n", rsp);
    // if(rsp == info->regs->rsp)
    // {
    //     PRINT_DEBUG("Callback with user rsp\n");
    //     return 0;
    // }

    if(info->regs->rsp < 0xffff800000000000)
    {
        fprintf(stderr, BGMAGENTA BLACK "We are with user RSP try again \n");
        return 0;
    }

    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    
    
    if(hijacker->cr3_status == STATUS_NULL){
        PRINT_DEBUG("[+] Saving register state\n");
        memcpy(&hijacker->saved_regs, info->regs, sizeof(x86_registers_t));
        PRINT_DEBUG("[+] Removing wait for kernel trap\n");
        // UNUSED(hijack_setup_int3_trap);
        hijacker->cr3_status = STATUS_CREATE_OK;
        if(!setup_stack_from_json(hijacker, info))
        {
            fprintf(stderr, "[+] Could not setup stack\n");  
            goto error;          
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
    error:
    hijacker->rc = false;
    drakvuf_interrupt(drakvuf, 2);
    drakvuf_resume(drakvuf);
    release_ozzer_lock(hijacker);
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
    if(target_tid != 0)
    {
        hijacker->target_tid = target_tid;
    }

    // Get the offsets from the Rekall profile
    if ( !drakvuf_get_struct_members_array_rva(drakvuf, offset_names, OFFSET_MAX, hijacker->offsets) )
        PRINT_DEBUG("Failed to find one of offsets.\n");

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
