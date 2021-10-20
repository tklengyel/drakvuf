#include "win_write_file.h"
#include "win_functions.h"
#include "method_helpers.h"

static event_response_t cleanup(injector_t injector, drakvuf_trap_info_t* info);
static bool write_chunk_to_buffer(injector_t injector, x86_registers_t* regs, uint8_t* buf, size_t amount);

event_response_t handle_writefile_x64(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;
    event_response_t event;

    switch (injector->step)
    {
        case STEP1: // allocate virtual memory
        {
            // save registers
            memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

            if (!setup_virtual_alloc_stack(injector, info->regs))
            {
                PRINT_DEBUG("Failed to setup virtual alloc for passing inputs!\n");
                return cleanup(injector, info);
            }

            info->regs->rip = injector->exec_func;
            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP2: // write payload to virtual memory
        {
            // any error checks?
            PRINT_DEBUG("Writing to allocated virtual memory to allocate physical memory..\n");
            injector->payload_addr = info->regs->rax;
            PRINT_DEBUG("Payload is at: 0x%lx\n", injector->payload_addr);

            if (!setup_memset_stack(injector, info->regs))
            {
                PRINT_DEBUG("Failed to setup memset stack for passing inputs!\n");
                return cleanup(injector, info);
            }

            info->regs->rip = injector->memset;
            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP3: // expand env in memory
        {
            PRINT_DEBUG("Expanding shell...\n");
            if (!setup_expand_env_stack(injector, info->regs))
            {
                PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
                return cleanup(injector, info);
            }

            info->regs->rip = injector->expand_env;
            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP4: // open file handle
        {
            if (is_fun_error(drakvuf, info, "Failed to expand environment variables!\n"))
                return cleanup(injector, info);

            PRINT_DEBUG("Env expand status: %lx\n", info->regs->rax);

            if (info->regs->rax * 2 > FILE_BUF_SIZE)
            {
                PRINT_DEBUG("Env expand reported more than the buffer can carry.\n");
                return VMI_EVENT_RESPONSE_NONE;
            }

            if (!setup_create_file(drakvuf, info))
                return VMI_EVENT_RESPONSE_NONE;

            info->regs->rip = injector->create_file;
            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP5: // verify file handle and open host file
        {
            PRINT_DEBUG("File create result %lx\n", info->regs->rax);

            if (is_fun_error(drakvuf, info, "Couldn't open guest file"))
                return cleanup(injector, info);

            injector->file_handle = info->regs->rax;
            injector->host_file = fopen(injector->binary_path, "rb");

            if (!injector->host_file)
            {
                PRINT_DEBUG("Failed to open host file\n");
                injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
                injector->error_code.code = errno;
                injector->error_code.string = "HOST_FAILED_FOPEN";
                injector->error_code.valid = true;

                return cleanup(injector, info);
            }
        }
        // fall through
        case STEP6: // read chunk from host and write to guest
        {
            uint8_t buf[FILE_BUF_SIZE];
            size_t amount;

            if (is_fun_error(drakvuf, info, "Failed to write to the guest file"))
                return cleanup(injector, info);

            PRINT_DEBUG("Writing file...\n");
            amount = fread(buf + FILE_BUF_RESERVED, 1, FILE_BUF_SIZE - FILE_BUF_RESERVED, injector->host_file);
            PRINT_DEBUG("Amount: %lx\n", amount);

            if (!amount) // close if file has finished writing
            {
                PRINT_DEBUG("Finishing\n");

                if (!setup_close_handle_stack(injector, info->regs))
                {
                    PRINT_DEBUG("Failed to setup stack for closing handle\n");
                    return cleanup(injector, info);
                }

                info->regs->rip = injector->close_handle;
                event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            }
            else
            {
                PRINT_DEBUG("Writing...\n");

                if (!write_chunk_to_buffer(injector, info->regs, buf + FILE_BUF_RESERVED, amount))
                    return cleanup(injector, info);

                if (!setup_write_file_stack(injector, info->regs, amount))
                {
                    PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
                    return cleanup(injector, info);
                }

                info->regs->rip = injector->write_file;
                event = override_step(injector, STEP6, VMI_EVENT_RESPONSE_SET_REGISTERS);
            }
            break;
        }
        case STEP7: // close file handle
        {
            PRINT_DEBUG("Close handle RAX: 0x%lx\n", info->regs->rax);
            fclose(injector->host_file);

            if (is_fun_error(drakvuf, info, "Could not close File handle"))
                return cleanup(injector, info);

            memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

            PRINT_DEBUG("File operation executed OK\n");
            injector->rc = INJECTOR_SUCCEEDED;

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP8: // exit loop
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
    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    return override_step(injector, STEP8, VMI_EVENT_RESPONSE_SET_REGISTERS);
}

static bool write_chunk_to_buffer(injector_t injector, x86_registers_t* regs, uint8_t* buf, size_t amount)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = regs->cr3,
        .addr = injector->payload_addr + FILE_BUF_RESERVED
    );

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(injector->drakvuf);
    bool success = (VMI_SUCCESS == vmi_write(vmi, &ctx, amount, buf, NULL));
    drakvuf_release_vmi(injector->drakvuf);

    if (!success)
    {
        PRINT_DEBUG("Failed to write payload chunk!\n");
        return false;
    }
    return true;
}
