#include "linux_shellcode.h"
#include "linux_debug.h"
#include "linux_syscalls.h"

event_response_t cleanup(drakvuf_t drakvuf, drakvuf_trap_info_t* info, bool clear_trap);
bool setup_mmap_trap(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
bool write_shellcode_to_mmap_location(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

/* This function handles the shellcode injection, it does so in total of 5 steps
 *
 * STEP1:
 * The job of this step is to find syscall instruction inside of vdso associated
 * with the process, we will be using this to call mmap by jumping to the syscall
 * after setting up the registers and trapping into the next instruction after syscall
 * we won't be removing the initial trap in this step as that can be used
 * for cleanup in the end i.e STEP5
 *
 * STEP2:
 * This is the trap that we are reaching after the mmap is successful,
 * now we can copy our shellcode to the mmapped location and jump to it,
 * we will trap the mmap location so that we can track the shellcode execution
 * and restore the state after it is done
 *
 * STEP3:
 * Since we just jumped to it and mmap location was trapped, we hit this, now we will
 * be saving rip on the stack as the user shellcode is being appended by ret internally
 * so that we come back to the same trap for furthur processing down the line
 *
 * STEP4:
 * We will reach this trap after the shellcode is executed and the ret at the end
 * of the shellcode is executed, since rip was saved, we will come back to the same mmap trap
 * and this will tell us that the shellcode has been successfully executed, now we will restore
 * the state of the process as it was before all the injection
 *
 * STEP5:
 * Now since we had kept the initial trap active in STEP1 and the registers are restored, we will hit
 * the initial rip trap now. This time we can remove the trap and interrupt the drakvuf loop so that the
 * injection can exit successfully, any failure step should just restore the registers
 * and set the injector->step as this step for cleanup;
 */
event_response_t handle_shellcode(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = (injector_t)info->trap->data;

    event_response_t event;

    switch (injector->step)
    {
        case STEP1: // Finds vdso and sets up mmap
        {
            memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

            addr_t vdso = find_vdso(drakvuf, info);
            if (!vdso)
                return cleanup(drakvuf, info, false); // STEP1 trap is being cleared in STEP5

            addr_t syscall_addr = find_syscall(drakvuf, info, vdso);
            if (!syscall_addr)
                return cleanup(drakvuf, info, false);

            setup_post_syscall_trap(drakvuf, info, syscall_addr);
            // don't remove the initial trap
            // it is used for cleanup after restoring registers

            if (!setup_mmap_syscall(injector, info->regs, 4096))
            {
                PRINT_DEBUG("Failed to setup mmap syscall");
                return cleanup(drakvuf, info, false);
            }

            info->regs->rip = syscall_addr;
            info->regs->rax = injector->syscall_no;

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;

            break;
        }
        case STEP2: // setup shellcode
        {
            PRINT_DEBUG("memory address allocated using mmap: %lx\n", info->regs->rax);

            // save it for future use
            injector->virtual_memory_addr = info->regs->rax;

            if (!write_shellcode_to_mmap_location(drakvuf, info))
                return cleanup(drakvuf, info, true);

            setup_mmap_trap(drakvuf, info);
            info->regs->rip = injector->virtual_memory_addr;

            free_bp_trap(drakvuf, injector, info->trap);

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP3: //since mmap starting location is trapped, the first one will be this
        {
            PRINT_DEBUG("Shellcode begin\n");

            if (!save_rip_for_ret(drakvuf, info->regs))
                return cleanup(drakvuf, info, true);

            // rsp is being updated
            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP4: // shellcode should've executed and we will be returned to the same trap as ret is appended in the end
        {
            PRINT_DEBUG("Shellcode end\n");
            free_bp_trap(drakvuf, injector, info->trap);

            // restore regs
            memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP5: // cleanup
        {
            PRINT_DEBUG("Removing traps and exiting\n");

            // remove the initial trap here
            free_bp_trap(drakvuf, injector, info->trap);
            drakvuf_interrupt(drakvuf, SIGINT);

            event = VMI_EVENT_RESPONSE_NONE;
            break;
        }
        default:
        {
            PRINT_DEBUG("Should not be here\n");
            assert(false);
        }
    }

    injector->step+=1;

    return event;
}

event_response_t cleanup(drakvuf_t drakvuf, drakvuf_trap_info_t* info, bool clear_trap)
{
    PRINT_DEBUG("Doing premature cleanup\n");
    injector_t injector = (injector_t)info->trap->data;

    // restore regs
    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

    if (clear_trap)
        free_bp_trap(drakvuf, injector, info->trap);

    // give the last step
    injector->step = STEP5;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

bool setup_mmap_trap(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    injector->bp = g_try_malloc0(sizeof(drakvuf_trap_t));

    injector->bp->type = BREAKPOINT;
    injector->bp->name = "injector_mmap_trap";
    // cb will be set from previous call only
    // we don't have injector_int3_userspace_cb function
    // in scope here so we will use it from the previous trap
    injector->bp->cb = info->trap->cb; //injector_int3_userspace_cb;
    injector->bp->data = injector;
    injector->bp->breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp->breakpoint.dtb = info->regs->cr3;
    injector->bp->breakpoint.addr_type = ADDR_VA;
    injector->bp->breakpoint.addr = injector->virtual_memory_addr;
    injector->bp->ttl = UNLIMITED_TTL;
    injector->bp->ah_cb = NULL;

    if ( drakvuf_add_trap(drakvuf, injector->bp) )
    {
        PRINT_DEBUG("mmap trap successful\n");
        return true;
    }
    else
    {
        fprintf(stderr, "Couldn't trap mmap location\n");
        return false;
    }


}

bool write_shellcode_to_mmap_location(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = (injector_t)info->trap->data;

    // access rip location
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = injector->virtual_memory_addr
    );

    size_t bytes_write = 0;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if (vmi_write(vmi, &ctx, injector->shellcode.len, injector->shellcode.data, &bytes_write)!=VMI_SUCCESS)
    {
        drakvuf_release_vmi(drakvuf);
        fprintf(stderr, "Could not write the shellcode in memory\n");
        return false;
    }

    PRINT_DEBUG("Shellcode write success in memory\n");
    print_hex(injector->shellcode.data, injector->shellcode.len, bytes_write);

    drakvuf_release_vmi(drakvuf);

    return true;

}
