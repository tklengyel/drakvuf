#include "linux_debug.h"

void print_hex(char* array, int len, int bytes_write_read)
{

    if (bytes_write_read != -1)
        PRINT_DEBUG("Bytes processed: %d/%d\n", bytes_write_read, len);
    else
        PRINT_DEBUG("Total length of shellcode: %d\n", len);
    PRINT_DEBUG("Data: \n");
    for (int i=0; i<len; i++)
    {
        PRINT_DEBUG("%02x ", *(array + i) & 0xff);
    }
    PRINT_DEBUG("\n");
}

void print_stack(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("\nRSP: %lx\n", info->regs->rsp);
    PRINT_DEBUG("Stack");
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    uint32_t offset = 0;
    for (int i=0; i < 16; i++)
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_PID,
            .pid = info->proc_data.pid,
            .addr = (info->regs->rsp - offset + i*8)
        );
        addr_t val = 0;
        vmi_read_64(vmi, &ctx, &val);
        if ((i%4)==0)
            PRINT_DEBUG("\n%016lx:", info->regs->rsp - offset + (i/4)*32);
        PRINT_DEBUG(" %016lx", val);
    }
    PRINT_DEBUG("\n");

    // print instruction in rip
    PRINT_DEBUG("\nRIP: %lx\n", info->regs->rip);
    PRINT_DEBUG("Stack");
    offset = 0;
    for (int i=0; i < 16; i++)
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_PID,
            .pid = info->proc_data.pid,
            .addr = (info->regs->rip - offset + i*8)
        );
        addr_t val = 0;
        vmi_read_64(vmi, &ctx, &val);
        if ((i%4)==0)
            PRINT_DEBUG("\n%016lx:", info->regs->rip - offset + (i/4)*32);
        PRINT_DEBUG(" %016lx", val);
    }
    PRINT_DEBUG("\n\n");

    drakvuf_release_vmi(drakvuf);
}

static char* repeatStr (const char* str, size_t count)
{
    if (count == 0) return NULL;
    char* ret = malloc (strlen (str) * count + count);
    if (ret == NULL) return NULL;
    strcpy (ret, str);
    while (--count > 0)
    {
        strcat (ret, " ");
        strcat (ret, str);
    }
    return ret;
}

void print_registers(drakvuf_trap_info_t* info)
{
    const char* fmt_base = "%s:\t%016lx\n";
    char* fmt= repeatStr(fmt_base, 24);
    PRINT_DEBUG(fmt,
        "rax",    info->regs->rax,
        "rcx",    info->regs->rcx,
        "rdx",    info->regs->rdx,
        "rbx",    info->regs->rbx,
        "rsp",    info->regs->rsp,
        "rbp",    info->regs->rbp,
        "rsi",    info->regs->rsi,
        "rdi",    info->regs->rdi,
        "r8",     info->regs->r8,
        "r9",     info->regs->r9,
        "r10",    info->regs->r10,
        "r11",    info->regs->r11,
        "r12",    info->regs->r12,
        "r13",    info->regs->r13,
        "r14",    info->regs->r14,
        "r15",    info->regs->r15,
        "rflags", info->regs->rflags,
        "dr6",    info->regs->dr6,
        "dr7",    info->regs->dr7,
        "rip",    info->regs->rip,
        "cr0",    info->regs->cr0,
        "cr2",    info->regs->cr2,
        "cr3",    info->regs->cr3,
        "cr4",    info->regs->cr4
    );
    g_free((void*)fmt);


}
