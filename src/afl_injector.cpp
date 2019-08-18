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
#define NUM_LOCATIONS 2000

char *afl_mode;
void afl_setup();
void afl_forkserver();

int cur_loc[NUM_LOCATIONS], prev_loc = 0;

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

#define SEED 321651

GHashTable *ke_func_index;      //Mapping from kernel function to index in AFL-SHM
GRand *grand;
static drakvuf_t drakvuf;
static bool continue_fuzzing = true;
volatile int spin_lock_held = false;

int prev;
struct afl_map_update_data
{
    char *function_name;
    int curr;
};

struct module_data
{
    char *module_path;
    char *module_name;
};

const char *get_json_string(json_object *obj, const char *key)
{
    json_object *str_obj;
    json_object_object_get_ex(obj, key, &str_obj);
    return json_object_get_string(str_obj);
}

int64_t get_json_int(json_object *obj, const char *key)
{
    json_object *int_obj;
    json_object_object_get_ex(obj, key, &int_obj);
    return json_object_get_int64(int_obj);
}

status_t handle_insn(vmi_instance_t vmi, cs_insn *t)
{
    (void)(vmi);
    cs_detail *d = t->detail;
    for( int i = 0; i < d->groups_count; i++)
    {
        if(d->groups[i] == X86_GRP_JUMP)
        {
            
        }
    }
    return VMI_SUCCESS;
}

event_response_t function_entry_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info)
{
    (void)(drakvuf);
    struct afl_map_update_data *afl_data = 
        (struct afl_map_update_data *)info->trap->data;
    (void)(afl_data);
    printf(BGYELLOW BLACK "In afl_map_update_cb for function"
        "%s with pid = %d" RESET "\n",afl_data->function_name, info->proc_data.pid);
    char code[100];
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    size_t read;
    access_context_t ctx;
    ctx.addr = info->regs->rip;
    ctx.pid = 4;
    vmi_read(vmi, &ctx,100, code, &read);
		csh handle;
		cs_insn *insn;
		size_t count;
		if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		{
				fprintf(stderr, "Could not open capstone handle");
				continue_fuzzing = false;
		}
		count = cs_disasm(handle,(const uint8_t *) code, sizeof(code)-1, 0x0, 0, &insn);
		if(count > 0)
		{
				size_t j;
				for(j = 0; j < count; j++)
				{
                    handle_insn(vmi, &insn[j]);
                    printf("0x%" PRIx64 ":\t%s\t\t%s",insn[j].address, insn[j].mnemonic, insn[j].op_str);
				}
				cs_free(insn, count);
		}
		cs_close(&handle);
        continue_fuzzing = false;
    return VMI_EVENT_RESPONSE_NONE;
}

int find_string_cmp(const void *a, const void *b)
{
    return g_strcmp0( ((struct module_data *)a)->module_path, 
                            ((struct module_data*)b)->module_path);
}

GList *collect_rekall_profiles(json_object *candidates)
{
    GList *files=NULL;
    json_object *calls;
    json_object_object_get_ex(candidates, "calls", &calls);
    if(calls == NULL)
    {
        fprintf(stderr, RED "[+]Could not parse candidates" RESET "\n");
    }
    int num_calls = json_object_array_length(calls);
    for(int call_idx = 0; call_idx < num_calls; call_idx++)
    {
        json_object *call = json_object_array_get_idx(calls, call_idx);
        if(call == NULL)
        {
            fprintf(stderr, RED "[+]Could not parse call" RESET "\n");
            return NULL;
        }
        json_object *mod_rekal_profile = NULL;
        json_object_object_get_ex(call, "module-rekall-profile", &mod_rekal_profile);
        char *rekall_path = (char *)json_object_get_string(mod_rekal_profile);
        struct module_data *elem = (struct module_data*)
                                        g_malloc0(sizeof(struct module_data));
        elem->module_name = g_strdup(get_json_string(call, "module-name"));
        elem->module_path = g_strdup(rekall_path);
        if(!g_list_find_custom(files, elem, find_string_cmp))
        {
            files = g_list_append(files, elem);
        }
    }
    
    return files;
}

bool init_kernel_func_indices(drakvuf_t drakvuf, json_object *candidates)
{
    (void)(drakvuf);
    char *f_name;
    addr_t f_addr;
    addr_t f_rva;
    json_object *functions=NULL;
    json_object *mod_rekall_profile = NULL;
    // json_object *guest_rekall = drakvuf_get_rekall_profile_json(drakvuf);
    GList *loop = collect_rekall_profiles(candidates);
    printf("length of the list %d", g_list_length(loop));
    while(loop)
    {
        struct module_data* mod = (struct module_data*)loop->data;
        mod_rekall_profile = json_object_from_file(mod->module_path);
        printf("Rekall Profile : %s\n", mod->module_path);
        if(!json_object_object_get_ex(mod_rekall_profile, "$FUNCTIONS", &functions))
        {
            fprintf(stderr, "Couldn't find $FUNCTIONS in rekall profile of guest\n");
            return false;
        }
        json_object_iterator it, END;
        it = json_object_iter_begin(functions);
        END = json_object_iter_end(functions);
        while( !json_object_iter_equal(&it, &END) )
        {
            f_name = (char *)json_object_iter_peek_name(&it);
            f_addr = json_object_get_int64(json_object_iter_peek_value(&it));
            int index = g_rand_int_range(grand, 0, 1<<16);
            g_hash_table_insert(ke_func_index, f_name, (void *)(uintptr_t)index);
            
            //Insert Trap
            if ( !rekall_get_function_rva(mod_rekall_profile, f_name, &f_rva) )
            {
                if( !drakvuf_get_function_rva(drakvuf, f_name, &f_rva))
                {
                    fprintf(stderr, "FATAL Couldn't get function rva\n");
                    return false;
                }
            }
            
            f_addr = drakvuf_exportksym_to_va(drakvuf, 4, f_name, mod->module_name, f_rva);
            if(!f_addr)
            {
                drakvuf_exportksym_to_va(drakvuf, 4, f_name, "ntoskrnl.exe", f_rva);
                fprintf(stderr, "Couldn't export ksym to va\n");
                return false;
            }
            drakvuf_trap_t *trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
            
            trap->type = BREAKPOINT;
            trap->breakpoint.lookup_type = LOOKUP_PID;
            trap->breakpoint.pid = 4;
            trap->breakpoint.addr_type = ADDR_RVA;
            trap->breakpoint.module = "ntoskrnl.exe";
            trap->breakpoint.rva = f_rva;
            
            struct afl_map_update_data *afl_data =
                (struct afl_map_update_data *) g_malloc0(sizeof(struct afl_map_update_data));
            afl_data->function_name = g_strdup(f_name);
            afl_data->curr = index;
        
            trap->data = afl_data;
            trap->cb = function_entry_cb;

            if(!drakvuf_add_trap(drakvuf, trap))
            {
                fprintf(stderr, "Couldn't add trap for function %s\n", f_name);
                return false;
            }
            json_object_iter_next(&it);
        }
        loop = loop->next;
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
drakvuf_plugins *plugins;

bool start_bsodmon(drakvuf_t drakvuf, json_object *function)
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
    for(int i = 0; i<NUM_LOCATIONS; i++)
    {
        cur_loc[i] = g_rand_int_range(grand, 0,((1<<16)-1));
    }   
}

json_object *get_inputs(json_object *call){
    json_object *args;
    json_object_object_get_ex(call, "arguments", &args);
    int len = json_object_array_length(args);
    json_object *array = json_object_new_array();
    for(int i = 0; i<len; i++)
    {
        json_object *temp_obj = json_object_new_object();
        json_object *arg = json_object_array_get_idx(args, i);
        json_object *jarg_type;
        json_object_object_get_ex(arg, "type", &jarg_type);
        const char* arg_type = json_object_get_string(jarg_type);
        json_object *jarg_val;
        json_object_object_get_ex(arg, "value", &jarg_val);
        int num = json_object_get_int(jarg_val);
        if(!strcmp(arg_type, "INTEGER")){
            json_object *val = json_object_new_int(num);
            json_object *jtype = json_object_new_string(arg_type);
            json_object_object_add(temp_obj, "type", jtype);
            json_object_object_add(temp_obj, "value", val);
            json_object_array_add(array, temp_obj);
        }
        // else if(strcmp(arg_type, "STRING")){
        //     int num = g_rand_int(grand);
        //     json_object *val = json_object_new_int64(num);
        //     json_object *jtype = json_object_new_string(arg_type);
        //     json_object_object_add(temp_obj, "arg_type", jtype);
        //     json_object_object_add(temp_obj, "value", val);
        //     json_object_array_add(array, temp_obj);
        // }
    }
    return array;
}


void retry_creating_domain()
{
    FILE *fp;
    char list_output[2048];
    fp = popen("xl list", "r");
    bool domain_live = false;
    
    while(fgets(list_output, 2047, fp) != NULL )
    {
        if(strstr(list_output, "win10"))
        {
            domain_live = true;
        }
    }
    pclose(fp);
    if(domain_live)
     (void)system("xl destroy win10");
    fp = popen("./restore_script.sh", "r");
    
    while(fgets(list_output, 2047, fp) != NULL )
    {
        fprintf(stderr, "%s",list_output);
    }
    pclose(fp);
}

int main(int argc, char *argv[])
{
    // int file  = open("/home/ajinkya/College/gsoc19/AFL/log.txt", O_WRONLY | O_CREAT );
    afl_mode = getenv(SHM_ENV_VAR);
    FILE *temp_stderr ;
    FILE *temp_stdout ;
    temp_stderr = NULL;
    temp_stdout = NULL;
    grand = g_rand_new_with_seed(SEED);
    if(afl_mode){
        temp_stderr = stderr;
        temp_stdout = stdout;
        stdout = fopen("/home/ajinkya/College/gsoc19/AFL/log_stdout.txt", "w");
        stderr = fopen("/home/ajinkya/College/gsoc19/AFL/log_stderr.txt", "w");
        afl_setup();    
        afl_forkserver();
        initialize_locations();
        fprintf(stderr,"---------Releasing forkserver--------------\n");
    }
    char *domain=NULL, *rekall_profile=NULL, *rekall_wow_profile = NULL;
    const char *lib_name=NULL;
    const char *driver_rekal_profile=NULL;
    const char *function_name = NULL;
    char *fuzz_candidates_path=NULL;
    int injection_pid = 0;
    uint32_t injection_tid = 0;
    int num_calls = 0;
    bool verbose = false,  libvmi_conf = false;
    char c;
    int num_args=0, call_idx=0;
    int rc = -1;
    json_object *candidates;
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
    const char *opts = "r:d:i:vf:t:c:";
    
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

    if(!drakvuf_init(&drakvuf, domain, rekall_profile, rekall_wow_profile, verbose, libvmi_conf))
    {
        retry_creating_domain();
        if(!drakvuf_init(&drakvuf, domain, rekall_profile, rekall_wow_profile, verbose, libvmi_conf))
        {    sleep(5);

            fprintf(stderr, "Failed to initialize DRAKVUF\n %s", domain);
            return rc;
        }
    }

    //setup ke_function_breakpoints
    ke_func_index = g_hash_table_new_full(g_str_hash, g_int_equal, free, NULL);

    successfull = 0;
    candidates = json_object_from_file(fuzz_candidates_path);
    if( candidates == NULL)
    {
        AFL_BRANCH_INSTRUMENT;
        fprintf(stderr, RED "[+] Could not read candidates" RESET "\n");
        goto error;
    }
    if(!init_kernel_func_indices(drakvuf, candidates))
    {
        fprintf(stderr, RED "[+] Could not init kernel functions" RESET "\n");
        goto error;
    }
    AFL_BRANCH_INSTRUMENT;
    // start_bsodmon(drakvuf, candidates);

    fprintf(stderr, "STARTING FUZZING >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    json_object *calls;
    json_object_object_get_ex(candidates, "calls", &calls);
    if(calls == NULL)
    {
        fprintf(stderr, RED "[+]Could not parse candidates" RESET "\n");
    }
    num_calls = json_object_array_length(calls);

    while(call_idx < num_calls)
    {   
        AFL_BRANCH_INSTRUMENT;    
        if(!continue_fuzzing)
            break;
        fprintf(stderr, "Generating Input iteration %d >>>>>>>>>>>>>>>>\n", call_idx);     
        json_object *call = json_object_array_get_idx(calls, call_idx);
        if(call == NULL)
        {

            fprintf(stderr, RED "[+]Could not parse call" RESET "\n");
            goto error;
        }

        json_object *inputs;
        json_object_object_get_ex(call, "arguments", &inputs);
        if(inputs == NULL)
        {
            fprintf(stderr, RED "[+]Could not parse get inputs" RESET "\n");
            goto error;
        }
        lib_name = get_json_string(call, "module-name");
        function_name = get_json_string(call, "function-name");
        driver_rekal_profile = get_json_string(call, "module-rekall-profile");
        num_args = json_object_array_length(inputs);
        
        fprintf(stderr, "Calling %s!%s, with %d arguments\n",lib_name, function_name, num_args);
        fprintf(stderr, "Calling With Input >>>>>>>>>>>>>>>>\n");
        fprintf(stderr, "%s\n", 
                json_object_to_json_string_ext(inputs, JSON_C_TO_STRING_PRETTY));
        if(
        !hijack(drakvuf, 
            injection_pid, 
            injection_tid,
            (char *)function_name, 
            (char *)driver_rekal_profile,
            (char *)lib_name,
            inputs, 
            &spin_lock_held)
        )
        {
            AFL_BRANCH_INSTRUMENT;
            fprintf(stderr, BGRED WHITE "[+] Hijack Failed" RESET "\n");
            // goto error;
        }
        else
        {
            AFL_BRANCH_INSTRUMENT;
            call_idx++;
            successfull++;
        }
        AFL_BRANCH_INSTRUMENT;
        fprintf(stderr, "waiting for lock\n");
        while(!g_atomic_int_compare_and_exchange(&spin_lock_held,false, true));
        fprintf(stderr, "Returned >>>>>>>>>>>>>>>>\n");
        // sleep(1);
        
    }
    error:
    // sleep(5);
    AFL_BRANCH_INSTRUMENT;
    drakvuf_resume(drakvuf); 
    // stop_bsodmon();
    drakvuf_close(drakvuf, 0);
    fprintf(stderr,"[+] Successfull = %d\n", successfull);
    fclose(stderr);
    fclose(stdout);
    stderr = temp_stderr;
    stdout = temp_stdout;
    //give time to wait as immediate calling crashes

    return successfull;
  
}

/* Fork server logic, invoked once we hit _start. */

void afl_forkserver() {
  int run_num = 0;
  static unsigned char tmp[4];

  if (!afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status;

    /* Whoops, parent dead? */
    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);
    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

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

  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = (unsigned char *)shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1)
    {
        fprintf(stderr,"shmat failed\n");
        exit(1);
    }

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }

}

