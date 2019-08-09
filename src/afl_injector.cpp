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

#define NUM_LOCATIONS 2000

void afl_setup();
void afl_forkserver();

int cur_loc[NUM_LOCATIONS], prev_loc = 0;

#define AFL_BRANCH_INSTRUMENT \
do\
{\
    afl_area_ptr[cur_loc[__LINE__] ^ prev_loc]++;\
    prev_loc = cur_loc[__LINE__] >> 1;\
}\
while(0)

#define SEED 321651
GRand *grand;
static drakvuf_t drakvuf;
static bool continue_fuzzing = true;
volatile int spin_lock_held = false;

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

void try_some_other_shit()
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

using namespace std;
int main(int argc, char *argv[])
{
    // int file  = open("/home/ajinkya/College/gsoc19/AFL/log.txt", O_WRONLY | O_CREAT );
    char *afl = getenv(SHM_ENV_VAR);
    FILE *temp_stderr ;
    FILE *temp_stdout ;
    temp_stderr = NULL;
    temp_stdout = NULL;
    grand = g_rand_new_with_seed(SEED);
    if(afl){
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
    (void)rekall_wow_profile;
    (void)libvmi_conf;
    eprint_current_time();
    fprintf(stderr, "%s v%s\n", PACKAGE_NAME, PACKAGE_VERSION);
    int argc_ind = 0;
    while(argc_ind<argc)
    {
      fprintf(stderr, "%s \n", argv[argc_ind]);
      argc_ind++;
    }
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
        try_some_other_shit();
        if(!drakvuf_init(&drakvuf, domain, rekall_profile, rekall_wow_profile, verbose, libvmi_conf))
        {    sleep(5);

            fprintf(stderr, "Failed to initialize DRAKVUF\n %s", domain);
            return rc;
        }
    }
    int successfull = 0;
    json_object *candidates = json_object_from_file(fuzz_candidates_path);
    if( candidates == NULL)
    {
        AFL_BRANCH_INSTRUMENT;
        fprintf(stderr, RED "[+] Could not read candidates" RESET "\n");
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


    while(call_idx<num_calls)
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

AFL_BRANCH_INSTRUMENT;}

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

