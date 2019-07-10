#include <config.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <gmodule.h>
#include "libhijack/libhijack.h"
#include "libdrakvuf/libdrakvuf.h"
#include "colors.h"
#include "plugins/plugins.h"

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
    // options = {0};
    // options.input = function;
    // options.abort_on_bsod = true;
    // options.continue_fuzzing = &continue_fuzzing;
    // options.spin_lock = &spin_lock_held;
    options.syscalls_filter_file = NULL;
    // plugins->start(PLUGIN_BSODMON, &options);
    plugins->start(PLUGIN_SYSCALLS, &options);
    return true;
}

void stop_bsodmon()
{
    delete plugins;
}

// char * generate_random_string()
// {

// }

json_object *get_inputs(json_object *function){
    json_object *args = hijack_get_arguments(function);
    int len = hijack_get_num_arguments(args);
    json_object *array = json_object_new_array();
    for(int i = 0; i<len; i++)
    {
        json_object *temp_obj = json_object_new_object();
        json_object *arg = json_object_array_get_idx(args, i);
        const char* arg_type = json_object_get_string(arg);
        if(!strcmp(arg_type, "INTEGER")){
            int num = g_rand_int(grand);
            num = num>=0?num:(-num);
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

int main(int argc, char **argv){
    char *domain=NULL, *rekall_profile=NULL, *rekall_wow_profile = NULL, *function_name = NULL;
    char *lib_name=NULL;
    char *driver_rekal_profile=NULL;
    char *fuzz_candidates_path=NULL;
    int injection_pid = 0;
    uint32_t injection_tid = 0;
    int num_iterations = 0;
    bool verbose = false,  libvmi_conf = false;
    char c;
    int num_libs = 0, num_functions = 0, num_args=0, fuzz_iterations=0;
    int rc = -1;
    grand = g_rand_new_with_seed(SEED);
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
            case 'c':
                num_iterations = atoi(optarg);
                break;
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
        fprintf(stderr, "Failed to initialize DRAKVUF\n %s", domain);
        return rc;
    }
    json_object *candidates = json_object_from_file(fuzz_candidates_path);
    int successfull = 0;
    fprintf(stderr, "STARTING FUZZING >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    while(fuzz_iterations<num_iterations)
    {   
        // sleep(5);
        if(!continue_fuzzing)
            break;
        fprintf(stderr, "Generating Input iteration %d>>>>>>>>>>>>>>>>\n", fuzz_iterations);     
        json_object *modules_list = hijack_get_modules(candidates);
        num_libs = hijack_get_num_modules(modules_list);
        int lib_no = g_rand_int_range(grand, 0,num_libs);
        json_object *module = json_object_array_get_idx(modules_list, lib_no);
        json_object *function_list = hijack_get_functions(module);
        num_functions = hijack_get_num_functions(function_list);
        int func_no = g_rand_int_range(grand, 0, num_functions);
        json_object *function = json_object_array_get_idx(function_list, func_no);

        json_object *inputs = get_inputs(function);

        lib_name = hijack_get_module_name(module);
        function_name = hijack_get_fucntion_name(function);
        json_object* args = hijack_get_arguments(function);
        num_args = hijack_get_num_arguments(args);
        driver_rekal_profile = hijack_get_module_rekall_profile(module);
        
        
        // start_bsodmon(drakvuf, inputs);
        fprintf(stderr, "Calling %s!%s, with %d arguments\n",lib_name, function_name, num_args);
        fprintf(stderr, "Calling With Input >>>>>>>>>>>>>>>>\n");
        fprintf(stderr, "%s\n", 
                json_object_to_json_string_ext(inputs, JSON_C_TO_STRING_PRETTY));
        if(
        !hijack(drakvuf, 
            injection_pid, 
            injection_tid,
            function_name, 
            driver_rekal_profile,
            lib_name,
            inputs, 
            &spin_lock_held)
        )
        {
            fprintf(stderr, BGRED WHITE "Hijack Failed [+]" RESET "\n");
            // goto error;
        }
        else
        {
            fuzz_iterations++;
            successfull++;
        }
        
        fprintf(stderr, "waiting for lock\n");
        while(!g_atomic_int_compare_and_exchange(&spin_lock_held,false, true));
        // stop_bsodmon();
        fprintf(stderr, "Returned >>>>>>>>>>>>>>>>\n");
        // sleep(1);
        
    }
    // error:
    drakvuf_resume(drakvuf); 
    drakvuf_close(drakvuf, 0);
    printf("[+] Successfull = %d", successfull);
    

}

