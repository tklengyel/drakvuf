#include "win_terminate.h"

#include <win/method_helpers.h>
#include <win/win_functions.h>

static event_response_t cleanup(injector_t injector, drakvuf_trap_info_t* info);

static bool setup_open_process_stack(injector_t injector, x86_registers_t* regs)
{
    struct argument args[3] = { {0} };

    enum
    {
        PROCESS_TERMINATE = 0x1,
        PROCESS_CREATE_THREAD = 0x2,
        PROCESS_VM_OPERATION = 0x8,
        PROCESS_VM_WRITE = 0x10,
        PROCESS_VM_READ = 0x20,
        PROCESS_QUERY_INFORMATION = 0x400,
    };

    // OpenProcess(PROCESS_TERMINATE, false, PID)
    init_int_argument(&args[0], PROCESS_TERMINATE | PROCESS_CREATE_THREAD |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION);

    init_int_argument(&args[1], 0);
    init_int_argument(&args[2], injector->terminate_pid);

    if (!setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args)))
    {
        fprintf(stderr, "Failed to setup open process stack!\n");
        return false;
    }
    return true;
}

static bool setup_create_remote_thread_stack(injector_t injector, x86_registers_t* regs)
{
    struct argument args[7] = { {0} };

    // CreateRemoteThread(handle, NULL, NULL, ExitProcess, 0, NULL, NULL)
    init_int_argument(&args[0], regs->rax);
    init_int_argument(&args[1], 0);
    init_int_argument(&args[2], 0);
    init_int_argument(&args[3], injector->exit_process);
    init_int_argument(&args[4], 0);
    init_int_argument(&args[5], 0);
    init_int_argument(&args[6], 0);

    if (!setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args)))
    {
        fprintf(stderr, "Failed to setup stack for passing inputs!\n");
        return false;
    }
    return true;

}

event_response_t handle_win_terminate(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;
    event_response_t event;

    switch (injector->step)
    {
        case STEP1:
        {
            // save registers
            PRINT_DEBUG("Saving registers\n");
            memcpy(&injector->x86_saved_regs, info->regs, sizeof(x86_registers_t));

            /* We just hit the RIP from the trapframe */
            PRINT_DEBUG("Open process %d to terminate it.\n", injector->terminate_pid);

            if (!setup_open_process_stack(injector, info->regs))
                return cleanup(injector, info);

            info->regs->rip = injector->open_process;
            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP2:
        {
            if (is_fun_error(drakvuf, info, "Could not open process handle"))
                return cleanup(injector, info);

            PRINT_DEBUG("Process %d opened with handle %#lx. Terminate it!\n", injector->terminate_pid, info->regs->rax);

            if (!setup_create_remote_thread_stack(injector, info->regs))
                return cleanup(injector, info);

            info->regs->rip = injector->exec_func;
            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP3:
        {
            if (is_fun_error(drakvuf, info, "Could not terminate process"))
                return cleanup(injector, info);

            PRINT_DEBUG("Process %d terminated successfully!\n", injector->terminate_pid);

            memcpy(info->regs, &injector->x86_saved_regs, sizeof(x86_registers_t));
            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP4:
        {
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
            event = VMI_EVENT_RESPONSE_NONE;
            break;
        }
        default:
        {
            PRINT_DEBUG("Should not be here\n");
            assert(false);
        }
    }
    return event;
}

static event_response_t cleanup(injector_t injector, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("Exiting prematurely\n");

    if (injector->rc == INJECTOR_SUCCEEDED)
        injector->rc = INJECTOR_FAILED;

    memcpy(info->regs, &injector->x86_saved_regs, sizeof(x86_registers_t));
    return override_step(injector, STEP4, VMI_EVENT_RESPONSE_SET_REGISTERS);
}
