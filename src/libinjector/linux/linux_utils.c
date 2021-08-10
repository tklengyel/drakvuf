#include "linux_utils.h"
#include "linux_debug.h"
#include <sys/mman.h>
#include <fcntl.h>

addr_t find_vdso(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t process_base = drakvuf_get_current_process(drakvuf, info);
    PRINT_DEBUG("Process base: %lx\n", process_base);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = info->proc_data.pid
    );

    addr_t addr = 0;
    size_t offset = 0;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    // task_struct to mm
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "task_struct", "mm", &offset))
        PRINT_DEBUG("Failed to get mm offset\n");
    else
        PRINT_DEBUG("mm offset: %ld\n", offset);

    ctx.addr = process_base + offset;

    // since mm is a pointer
    if (VMI_SUCCESS != vmi_read_64(vmi, &ctx, &addr))
        PRINT_DEBUG("Failed to read mm address\n");
    else
        PRINT_DEBUG("Got mm address: %lx\n", addr);

    // mm_struct to unnamed_field_0
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "mm_struct", "unnamed_field_0", &offset))
        PRINT_DEBUG("Failed to get unnamed_field_0 offset\n");
    else
        PRINT_DEBUG("unnamed_field_0 offset: %ld\n", offset);

    addr = addr + offset;

    // unnamed_d740b18b8642642a to context
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "unnamed_d740b18b8642642a", "context", &offset))
        PRINT_DEBUG("Failed to get context offset\n");
    else
        PRINT_DEBUG("context offset: %ld\n", offset);

    addr = addr + offset;

    // unnamed_1b032a1ce51217e5 to vdso
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "unnamed_1b032a1ce51217e5", "vdso", &offset))
        PRINT_DEBUG("Failed to get vdso offset\n");
    else
        PRINT_DEBUG("vdso offset: %ld\n", offset);

    ctx.addr = addr + offset;

    // since vdso is a pointer
    if (VMI_SUCCESS != vmi_read_64(vmi, &ctx, &addr))
        PRINT_DEBUG("Failed to read vdso address\n");
    else
        PRINT_DEBUG("Got vdso address: %lx\n", addr);

    drakvuf_release_vmi(drakvuf);

    return addr;

}

/** src: https://www.geeksforgeeks.org/naive-algorithm-for-pattern-searching/ **/
static size_t search(char* txt, char* pat, int N, int M)
{
    /* A loop to slide pat[] one by one */
    for (int i = 0; i <= N - M; i++)
    {
        int j;

        /* For current index i, check for pattern match */
        for (j = 0; j < M; j++)
            if (txt[i + j] != pat[j])
                break;

        if (j == M) // if pat[0...M-1] = txt[i, i+1, ...i+M-1]
            return i;
    }
    return -1;
}

addr_t find_syscall(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t vdso)
{
    // lock vmi
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = info->proc_data.pid,
        .addr = vdso
    );

    size_t size = 4096;
    size_t bytes_read = 0;
    char* vdso_memory = g_try_malloc(size);

    // read the vdso memory
    bool success = (VMI_SUCCESS == vmi_read(vmi, &ctx, size, (void*)vdso_memory, &bytes_read));
    if (!success)
        fprintf(stderr, "Could not vdso memory\n");
    else
    {
        PRINT_DEBUG("vdso memory read successful\n");
    }

    // release vmi
    drakvuf_release_vmi(drakvuf);

    char syscall[] = { 0xf, 0x5 };
    size_t syscall_offset = search(vdso_memory, syscall, size, 2);
    PRINT_DEBUG("syscall offset: %ld\n", syscall_offset);
    PRINT_DEBUG("syscall addr: %lx\n", vdso + syscall_offset);

    free(vdso_memory);

    injector_t injector = info->trap->data;
    injector->syscall_addr = vdso + syscall_offset;

    return vdso + syscall_offset;
}

bool setup_post_syscall_trap(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t syscall_addr)
{
    injector_t injector = info->trap->data;

    injector->bp = g_try_malloc0(sizeof(drakvuf_trap_t));

    // setup int3 trap
    injector->bp->type = BREAKPOINT;
    injector->bp->name = "injector_post_syscall_trap";
    // cb will be set from previous call only
    // we don't have injector_int3_userspace_cb function
    // in scope here so we will use it from the previous trap
    injector->bp->cb = info->trap->cb; //injector_int3_userspace_cb;
    injector->bp->data = injector;
    injector->bp->breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp->breakpoint.dtb = info->regs->cr3;
    injector->bp->breakpoint.addr_type = ADDR_VA;
    injector->bp->breakpoint.addr = syscall_addr + 2;
    injector->bp->ttl = UNLIMITED_TTL;
    injector->bp->ah_cb = NULL;

    if ( drakvuf_add_trap(drakvuf, injector->bp) )
    {
        PRINT_DEBUG("Post syscall trap success\n");
        return true;
    }
    else
    {
        fprintf(stderr, "Couldn't trap next instruction after syscall\n");
        return false;
    }

}

bool save_rip_for_ret(drakvuf_t drakvuf, x86_registers_t* regs)
{

    // lock vmi
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = regs->cr3
    );
    addr_t addr = regs->rsp;

    // make space for storing rip
    addr -= 0x8;
    ctx.addr = addr;

    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &regs->rip))
    {
        // release before returning
        drakvuf_release_vmi(drakvuf);
        return false;
    }

    regs->rsp = addr;

    // release vmi
    drakvuf_release_vmi(drakvuf);
    return true;

}

bool load_file_to_injector_shellcode(injector_t injector, const char* file)
{
    FILE* fp = fopen(file, "rb");
    if (!fp)
    {
        fprintf(stderr, "Shellcode file (%s) not existing\n", file);
        return false;
    }

    fseek (fp, 0, SEEK_END);
    if ( (injector->shellcode.len = ftell (fp)) < 0 )
    {
        fclose(fp);
        return false;
    }
    rewind (fp);

    // we are adding +1 as we will append ret instruction for restoring the state of the VM
    injector->shellcode.data = g_try_malloc0(injector->shellcode.len + 1);
    if ( !injector->shellcode.data )
    {
        fclose(fp);
        injector->shellcode.len = 0;
        return false;
    }

    if ( (size_t)injector->shellcode.len != fread(injector->shellcode.data, 1, injector->shellcode.len, fp))
    {
        g_free(injector->shellcode.data);
        injector->shellcode.data = NULL;
        injector->shellcode.len = 0;
        fclose(fp);
        return false;
    }
    *(char*)(injector->shellcode.data + injector->shellcode.len ) = 0xc3;  //ret
    injector->shellcode.len += 1; // increase the length in variable

    PRINT_DEBUG("Shellcode loaded to injector->shellcode\n");
    print_hex(injector->shellcode.data, injector->shellcode.len, -1);

    fclose(fp);

    return true;
}

void free_bp_trap(drakvuf_t drakvuf, injector_t injector, drakvuf_trap_t* trap)
{
    drakvuf_remove_trap(drakvuf, trap, (drakvuf_trap_free_t)g_free);
    injector->bp = NULL;
}

void free_injector(injector_t injector)
{
    if (!injector) return;

    PRINT_DEBUG("Injector freed\n");

    if (injector->bp)
        g_free((void*)injector->bp);

    if (injector->shellcode.data)
        g_free((void*)injector->shellcode.data);

    if (injector)
        g_free((void*)injector);


    injector = NULL;
}
