//aj
#include <unistd.h>
#include <afl_injector.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>
#include <config.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <glib.h>
#include <gmodule.h>
#include "libhijack/libhijack.h"
#include "libdrakvuf/libdrakvuf.h"
#include "colors.h"
#include "plugins/plugins.h"
#include <fcntl.h>
#include <capstone/capstone.h>

#define NUM_LOCATIONS 20000
#define SEED 321651

#define AFL_BRANCH_INSTRUMENT \
do\
{\
    if(afl_mode)\
    {\
        afl_area_ptr[cur_loc[__LINE__] ^ prev_loc]++;\
        prev_loc = cur_loc[__LINE__] >> 1;\
    }\
}\
while(0)

#define AFL_BRANCH_INSTRUMENT2(x) \
do\
{\
    if(afl_mode)\
    {\
        afl_area_ptr[x&(MAP_SIZE-1) ^ prev_loc]++;\
        prev_loc = cur_loc[x&(MAP_SIZE-1)] >> 1;\
    }\
}\
while(0)

#define VALUE_OF_REG(base, reg)* ((uint64_t* )base + (offset((x86_reg)reg)/8))

char* afl_mode;
void afl_setup();
void afl_forkserver();

int cur_loc[NUM_LOCATIONS], prev_loc = 0;

GRand* grand;
static drakvuf_t drakvuf;
static bool continue_fuzzing = true;
volatile int spin_lock_held = false;

int prev;

event_response_t afl_branch_bp(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

/**
 * Helper function to extract string value from a json object with given key
 */
char* get_json_string(json_object* obj, const char* key)
{
    json_object* str_obj;
    json_object_object_get_ex(obj, key, &str_obj);
    return (char* )json_object_get_string(str_obj);
}

/**
 * Helper function to extract int value from a json object with given key
 */
int64_t get_json_int(json_object* obj, const char* key)
{
    json_object* int_obj;
    json_object_object_get_ex(obj, key, &int_obj);
    return json_object_get_int64(int_obj);
}

/**
 * Takes in capstone register and return offset of that register in libvmi's
 * struct x86_regs
 */
int offset(x86_reg reg)
{
    switch (reg)
    {
        case X86_REG_RAX:
            return offsetof(x86_regs, rax);
            break;
        case X86_REG_RBX:
            return offsetof(x86_regs, rbx);
            break;
        case X86_REG_RCX:
            return offsetof(x86_regs, rcx);
            break;
        case X86_REG_RDX:
            return offsetof(x86_regs, rdx);
            break;
        case X86_REG_RIP:
            return offsetof(x86_regs, rip);
            break;
        case X86_REG_RSP:
            return offsetof(x86_regs, rsp);
            break;
        case X86_REG_RBP:
            return offsetof(x86_regs, rbp);
            break;
        case X86_REG_RSI:
            return offsetof(x86_regs, rsi);
            break;
        case X86_REG_RDI:
            return offsetof(x86_regs, rdi);
            break;
        default:
            fprintf(stderr, "Register %d not handled\n", reg);
            return -1;
            break;
    }
}


/**
 * Placed breakpoint before and after control transfer instructions
 * Note: breakpoints placed after call instruction to continue recording path
 * information in the called function resume calling path information after
 * returning to caller.
 */
addr_t handle_insn(drakvuf_t drakvuf, cs_insn* t, drakvuf_trap_info_t* info)
{
    cs_detail* d = t->detail;
    x86_op_mem om;
    addr_t addr = 0;
    x86_registers_t* r = info->regs;
    for (int i = 0; i < d->groups_count; i++)
    {
        if (d->groups[i] == X86_GRP_JUMP)
        {
            //There will only be one operand but just to cover all bases
            for (int j = 0; j < d->x86.op_count; j++)
            {
                //should be called only when we are at a breakpoint on a jump insn
                cs_x86_op op = d->x86.operands[j];
                switch (op.type)
                {
                    case X86_OP_IMM:
                        addr = op.imm;
                        break;
                    case X86_OP_REG:
                        addr = VALUE_OF_REG(r, op.reg);
                        break;
                    case X86_OP_MEM:
                        om = op.mem;
                        addr = t->address +
                               om.index*   om.scale + om.disp;
                        break;
                    default:
                        fprintf(stderr, "Unknown type of operand" RESET "\n");
                }
            }
            drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
            trap->type = BREAKPOINT;
            trap->breakpoint.addr = addr;
            trap->breakpoint.dtb = info->regs->cr3;
            trap->breakpoint.lookup_type = LOOKUP_DTB;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->cb = afl_branch_bp;
            if (!drakvuf_add_trap(drakvuf, trap))
                printf(RED "Could not setup breakpoint for branch target" RESET "\n");
            else
                printf(BGGREEN "Breakpoints set for branch target: %lx " RESET "\n",
                       trap->breakpoint.addr);
            t++;
            drakvuf_trap_t* next_trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
            next_trap->type = BREAKPOINT;
            next_trap->breakpoint.addr_type = ADDR_VA;
            next_trap->breakpoint.addr = t->address;
            next_trap->breakpoint.dtb = info->regs->cr3;
            next_trap->breakpoint.lookup_type = LOOKUP_DTB;
            next_trap->cb = afl_branch_bp;
            if (!drakvuf_add_trap(drakvuf, next_trap))
                printf(RED "Could not setup breakpoint for branch fall through" RESET "\n");
            else
                printf(BGGREEN "Breakpoints set for branch fall through: %lx" RESET "\n",
                       next_trap->breakpoint.addr);

            return 1;
        }
        else if (d->groups[i] ==X86_GRP_CALL)
        {
            for (int j = 0; j < d->x86.op_count; j++)
            {
                //should be called only when we are at a breakpoint on a jump insn
                cs_x86_op op = d->x86.operands[j];
                switch (op.type)
                {
                    case X86_OP_IMM:
                        addr = op.imm;
                        break;
                    case X86_OP_REG:
                        addr = VALUE_OF_REG(r, op.reg);
                        break;
                    case X86_OP_MEM:
                        om = op.mem;
                        addr = t->address +
                               om.index*   om.scale + om.disp;
                        break;
                    default:
                        fprintf(stderr, "Unknown type of operand" RESET "\n");
                }
            }
            drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
            trap->type = BREAKPOINT;
            trap->breakpoint.addr = addr;
            trap->breakpoint.dtb = info->regs->cr3;
            trap->breakpoint.lookup_type = LOOKUP_DTB;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->cb = afl_branch_bp;
            if (!drakvuf_add_trap(drakvuf, trap))
                fprintf(stderr, RED "Could not setup breakpoint for call target" RESET "\n");
            else
                fprintf(stderr, BGGREEN "Breakpoints set for call target: %lx " RESET "\n",
                        trap->breakpoint.addr);

            t++;
            drakvuf_trap_t* next_trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
            next_trap->type = BREAKPOINT;
            next_trap->breakpoint.addr = t->address;
            next_trap->breakpoint.dtb = info->regs->cr3;
            next_trap->breakpoint.lookup_type = LOOKUP_DTB;
            next_trap->breakpoint.addr_type = ADDR_VA;
            next_trap->cb = afl_branch_bp;
            if (!drakvuf_add_trap(drakvuf, next_trap))
                fprintf(stderr, RED "Could not setup breakpoint for call fall through" RESET "\n");
            else
                fprintf(stderr, BGGREEN "Breakpoints set for call fall through: %lx" RESET "\n",
                        next_trap->breakpoint.addr);
            return 1;
        }
    }
    return 0;
}

/**
 * Called first at the entry of the injection function. This function
 * disassembles instruction from function_entry to first control transfer
 * instruction and set breakpoints with callbacks to this function itself
 */
event_response_t afl_branch_bp(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    AFL_BRANCH_INSTRUMENT2( info->regs->rip );
    printf(CYAN "In breakpoint" RESET "\n");
    char code[1000];
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    size_t read;
    access_context_t ctx;
    ctx.addr = info->regs->rip;
    ctx.pid = 4;
    ctx.translate_mechanism = VMI_TM_PROCESS_PID;
    bool continue_disassembly = true;

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        fprintf(stderr, "Could not open capstone handle");
        continue_fuzzing = false;
        return VMI_EVENT_RESPONSE_NONE;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    while (continue_disassembly)
    {
        if (vmi_read(vmi, &ctx, 1000, code, &read) != VMI_FAILURE)
        {
            drakvuf_release_vmi(drakvuf);
            cs_insn* insn;
            size_t count;
            count = cs_disasm(handle, (const uint8_t*) code, sizeof(code)-1, info->regs->rip, 0, &insn);
            if (count > 0)
            {
                size_t j;

                //delibrately iterating over only count-2 insns because
                //the last instruction may lie across 1000 bytes boundary and may not have
                //been read
                for (j = 0; j < count-2; j++)
                {
                    printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
                    if ( !strcmp(insn[j].mnemonic, "ret") )
                    {
                        continue_disassembly = false;
                        ctx.addr = ctx.addr + insn[j].size;
                        break;
                    }
                    else if (handle_insn(drakvuf, &insn[j], info))
                    {
                        continue_disassembly = false;
                        ctx.addr = ctx.addr + insn[j].size;
                        break;
                    }
                    ctx.addr = ctx.addr + insn[j].size;
                }
                cs_free(insn, count);
            }
        }
        else
        {
            drakvuf_release_vmi(drakvuf);
            fprintf(stderr, RED "[+] Could not read binary from rip" RESET "\n");
        }
    }
    cs_close(&handle);
    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * Set breakpoints for all injection function candidates.
 * Currently breakpoints are set for all the injection function candidates
 * This should be optimized to add breakpoints only when function
 * is to be injected.
 */
bool set_init_breakpoints(drakvuf_t drakvuf, json_object* candidates)
{
    char* f_name;
    addr_t f_addr;
    addr_t f_rva;
    json_object* mod_rekall_profile = NULL;
    char* mod_rekal_profile_path=NULL;
    char* module_name = NULL;
    json_object* calls = NULL;
    json_object_object_get_ex(candidates, "calls", &calls);
    int len = json_object_array_length(calls);
    for (int i=0; i<len; i++)
    {
        json_object* call;
        call = json_object_array_get_idx(calls, i);
        f_name = get_json_string(call, "function-name");
        mod_rekal_profile_path = get_json_string(call, "module-rekall-profile");
        mod_rekall_profile = json_object_from_file(mod_rekal_profile_path);
        //Insert Trap
        if (!rekall_get_function_rva(mod_rekall_profile, f_name, &f_rva) )
        {
            if (!drakvuf_get_function_rva(drakvuf, f_name, &f_rva))
            {
                fprintf(stderr, "FATAL Couldn't get function rva\n");
                return false;
            }
        }
        module_name = get_json_string(call, "module-name");
        f_addr = drakvuf_exportksym_to_va(drakvuf, 4, f_name, module_name, f_rva);
        if (!f_addr)
        {
            drakvuf_exportksym_to_va(drakvuf, 4, f_name, "ntoskrnl.exe", f_rva);
            fprintf(stderr, "Couldn't export ksym to va\n");
            return false;
        }
        drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));

        trap->type = BREAKPOINT;
        trap->breakpoint.lookup_type = LOOKUP_PID;
        trap->breakpoint.addr_type = ADDR_VA;
        trap->breakpoint.addr = f_addr;
        trap->breakpoint.pid = 4;
        trap->name = f_name;
        trap->cb = afl_branch_bp;

        if (!drakvuf_add_trap(drakvuf, trap))
        {
            fprintf(stderr, "Couldn't add trap for function %s\n", f_name);
        }
        else
        {
            fprintf(stderr, GREEN "Trap successfully added for %s" RESET "\n", f_name);
        }
    }

    fprintf(stderr, "Traps added successfully for kernel functions" RESET "\n");
    return true;
}

static void close_handler(int sig)
{
    drakvuf_interrupt(drakvuf, sig);
    continue_fuzzing  = false;
    g_atomic_int_set(&spin_lock_held, false);
}

plugins_options options;
drakvuf_plugins* plugins;

bool start_bsodmon(drakvuf_t drakvuf, json_object* function)
{
    (void)function;
    plugins = new drakvuf_plugins(drakvuf, OUTPUT_DEFAULT,
                                  drakvuf_get_os_type(drakvuf));
    options = {0};
    options.input = function;
    options.abort_on_bsod = true;
    options.continue_fuzzing = &continue_fuzzing;
    options.spin_lock = &spin_lock_held;
    plugins->start(PLUGIN_BSODMON, &options);
    return true;
}

void stop_bsodmon()
{
    delete plugins;
}

void initialize_locations()
{
    for (int i = 0; i<NUM_LOCATIONS; i++)
    {
        cur_loc[i] = g_rand_int_range(grand, 0, ((1<<16)-1));
    }
}

/**
 * If domain not available, recreate the domain
 */
void retry_creating_domain()
{
    FILE* fp;
    char list_output[2048];
    fp = popen("xl list", "r");
    bool domain_live = false;

    while (fgets(list_output, 2047, fp) != NULL )
    {
        if (strstr(list_output, "win10"))
        {
            domain_live = true;
        }
    }
    pclose(fp);
    if (domain_live)
        (void)system("xl destroy win10");
    (void)system("./restore_script.sh");
}

int main(int argc, char* argv[])
{
    afl_mode = getenv(SHM_ENV_VAR);         // If non null we are being run by afl
    FILE* temp_stderr ;                     // Temp variable to store stderr and stdout
    FILE* temp_stdout ;
    temp_stderr = NULL;
    temp_stdout = NULL;
    grand = g_rand_new_with_seed(SEED);     // Initialize random no generator
    if (afl_mode)
    {
        // We are in AFL mode
        temp_stderr = stderr;
        temp_stdout = stdout;
        stdout = fopen("stdout.log", "w");  // since AFL redirects stderr and stdout
        stderr = fopen("stderr.log", "w");  // we setup log files for stderr and stdout
        afl_setup();                        // sets up the AFL shared memory
        afl_forkserver();                   // spins up forkserver, and waits for command from afl
        initialize_locations();
        fprintf(stderr, "---------Releasing forkserver--------------\n");
    }
    char* domain=NULL, *rekall_profile=NULL, *rekall_wow_profile = NULL;
    const char* lib_name=NULL;
    const char* driver_rekal_profile=NULL;
    const char* function_name = NULL;
    char* fuzz_candidates_path=NULL;
    int injection_pid = 0;
    uint32_t injection_tid = 0;
    int num_calls = 0;
    bool verbose = false,  libvmi_conf = false;
    char c;
    int num_args=0, call_idx=0;
    int rc = -1;
    json_object* candidates;
    int successfull = 0;
    (void)rekall_wow_profile;
    (void)libvmi_conf;
    eprint_current_time();
    fprintf(stderr, "%s v%s\n", PACKAGE_NAME, PACKAGE_VERSION);
    if (argc < 4)
    {
        fprintf(stderr, "Required input:\n"
                "\t -r, --rekall-kernel <rekall profile>\n"
                "\t                           The Rekall profile of the OS kernel\n"
                "\t -d <domain ID or name>    The domain's ID or name\n"
                "\t -f <fuzzing-candidates-file>\n"
                "                             The file containing candidates for fuzzer\n"
                "\t -i <injection-pid>        The pid of the process to be used for kernel hijacking\n"
                "\t -t <inection-tid>         Thread id to be used for injection\n"
                "\t -c <iteration-count>      Fuzzing iteration count\n"
               );
        return rc;
    }
    const char* opts = "r:d:i:vf:t:c:";

    while ((c = getopt (argc, argv, opts)) != -1)
        switch (c)
        {
            case 'r':
                rekall_profile = optarg;
                break;
            case 'd':
                domain = optarg;
                break;
            case 'i':
                injection_pid = atoi(optarg);
                break;
            case 'f':
                fuzz_candidates_path  = optarg;
                break;
            case 't':
                injection_tid = (uint32_t)atoi(optarg);
                break;
#ifdef DRAKVUF_DEBUG
            case 'v':
                verbose = true;
                break;
#endif
            default:
                if (isalnum(c))
                    fprintf(stderr, "Unrecognized option: %c\n", c);
                else
                    fprintf(stderr, "other error");
                return rc;
        }
    /* for a clean exit */
    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;


    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    // Initialize drakvuf
    if (!drakvuf_init(&drakvuf, domain, rekall_profile, rekall_wow_profile, verbose, libvmi_conf))
    {
        // Here drakvuf could not be initialized, assuming initialization failed because domain
        // was not available try creating domain and retry initialization
        retry_creating_domain();
        if (!drakvuf_init(&drakvuf, domain, rekall_profile, rekall_wow_profile, verbose, libvmi_conf))
        {
            sleep(5);

            fprintf(stderr, "Failed to initialize DRAKVUF\n %s", domain);
            return rc;
        }
    }

    successfull = 0;
    candidates = json_object_from_file(fuzz_candidates_path);
    if ( candidates == NULL)
    {
        AFL_BRANCH_INSTRUMENT;
        fprintf(stderr, RED "[+] Could not read candidates" RESET "\n");
        goto error;
    }
    if (!set_init_breakpoints(drakvuf, candidates))
    {
        fprintf(stderr, RED "[+] Could not init kernel functions" RESET "\n");
        goto error;
    }
    AFL_BRANCH_INSTRUMENT;
    start_bsodmon(drakvuf, candidates);

    fprintf(stderr, "STARTING FUZZING\n");
    json_object* calls;
    json_object_object_get_ex(candidates, "calls", &calls);
    if (calls == NULL)
    {
        fprintf(stderr, RED "[+]Could not parse candidates" RESET "\n");
    }
    num_calls = json_object_array_length(calls);

    while (call_idx < num_calls)
    {
        AFL_BRANCH_INSTRUMENT;
        if (!continue_fuzzing)
            break;
        fprintf(stderr, "Generating Input iteration %d\n", call_idx);
        json_object* call = json_object_array_get_idx(calls, call_idx);
        if (call == NULL)
        {

            fprintf(stderr, RED "[+]Could not parse call" RESET "\n");
            goto error;
        }

        json_object* inputs;
        json_object_object_get_ex(call, "arguments", &inputs);
        if (inputs == NULL)
        {
            fprintf(stderr, RED "[+]Could not parse get inputs" RESET "\n");
            goto error;
        }
        lib_name = get_json_string(call, "module-name");
        function_name = get_json_string(call, "function-name");
        driver_rekal_profile = get_json_string(call, "module-rekall-profile");
        num_args = json_object_array_length(inputs);

        fprintf(stderr, "Calling %s!%s, with %d arguments\n", lib_name, function_name, num_args);
        fprintf(stderr, "Calling With Input\n");
        fprintf(stderr, "%s\n",
                json_object_to_json_string_ext(inputs, JSON_C_TO_STRING_PRETTY));
        if (
            !hijack(drakvuf,
                    injection_pid,
                    injection_tid,
                    (char*)function_name,
                    (char*)driver_rekal_profile,
                    (char*)lib_name,
                    inputs,
                    &spin_lock_held)
        )
        {
            AFL_BRANCH_INSTRUMENT;
            fprintf(stderr, BGRED WHITE "[+] Hijack Failed" RESET "\n");
        }
        else
        {
            AFL_BRANCH_INSTRUMENT;
            call_idx++;
            successfull++;
        }
        AFL_BRANCH_INSTRUMENT;
        fprintf(stderr, "waiting for lock\n");
        while (!g_atomic_int_compare_and_exchange(&spin_lock_held, false, true));
        fprintf(stderr, "Returned\n");
    }
error:
    AFL_BRANCH_INSTRUMENT;
    drakvuf_resume(drakvuf);
    stop_bsodmon();
    drakvuf_close(drakvuf, 0);
    fprintf(stderr, "[+] Successfull = %d\n", successfull);
    fclose(stderr);
    fclose(stdout);
    stderr = temp_stderr;
    stdout = temp_stdout;
    return successfull;

}

/* Fork server logic, invoked once we hit _start. */

void afl_forkserver()
{
    int run_num = 0;
    static unsigned char tmp[4];

    if (!afl_area_ptr) return;

    /* Tell the parent that we're alive. If the parent doesn't want
       to talk, assume that we're not running in forkserver mode. */

    if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

    afl_forksrv_pid = getpid();

    /* All right, let's await orders... */

    while (1)
    {

        pid_t child_pid;
        int status;

        /* Whoops, parent dead? */
        if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);
        child_pid = fork();
        if (child_pid < 0) exit(4);

        if (!child_pid)
        {

            /* Child process. Close descriptors and run free. */

            afl_fork_child = 1;
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            return;

        }

        /* Parent. */

        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

        /* Get and relay exit status to parent. */
        if (waitpid(child_pid, &status, 0) < 0) exit(6);
        if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);
        run_num++;
    }

}

void afl_setup()
{

    char* id_str = getenv(SHM_ENV_VAR),
          *inst_r = getenv("AFL_INST_RATIO");

    int shm_id;

    if (inst_r)
    {
        unsigned int r;
        r = atoi(inst_r);
        if (r > 100) r = 100;
        if (!r) r = 1;
        afl_inst_rms = MAP_SIZE * r / 100;
    }

    if (id_str)
    {
        shm_id = atoi(id_str);
        afl_area_ptr = (unsigned char*)shmat(shm_id, NULL, 0);
        if (afl_area_ptr == (void*)-1)
        {
            fprintf(stderr, "shmat failed\n");
            exit(1);
        }
        /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
           so that the parent doesn't give up on us. */

        if (inst_r) afl_area_ptr[0] = 1;
    }
}