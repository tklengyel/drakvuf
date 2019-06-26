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
#include "plugins/plugins.h"
static drakvuf_t drakvuf;
static bool open = true;
static void close_handler(int sig)
{
    drakvuf_interrupt(drakvuf, sig);
    open  = false;

}
plugins_options options;
drakvuf_plugins *plugins;

bool start_bsodmon(drakvuf_t drakvuf)
{
    plugins = new drakvuf_plugins(drakvuf, OUTPUT_DEFAULT, 
        drakvuf_get_os_type(drakvuf));
    options = {0};
    options.abort_on_bsod = true;
    plugins->start(PLUGIN_BSODMON, &options);
    return true;
}

int main(int argc, char **argv){
    char *domain=NULL, *rekall_profile=NULL, *rekall_wow_profile = NULL, *function_name = NULL;
    char *lib_name=NULL;
    char *driver_rekal_profile=NULL;
    char *fuzz_candidates_path=NULL;
    int injection_pid = 0;
    bool verbose = false,  libvmi_conf = false;
    char c;
    int num_libs = 0, num_functions = 0, num_args=0, fuzz_iterations=0;
    int rc = -1;
    GMutex __hijacker_dispatcher_mutex_obj;
    GMutex *hijacker_dispatcher_mutex = &__hijacker_dispatcher_mutex_obj;
    bool spin_lock = false;
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
                "\t -i <injection-pid>        The pid of the process to be used for kernel hijacking"
            );
        return rc;
    }
    const char *opts = "r:d:i:vf:";
    
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


    
    g_mutex_init(hijacker_dispatcher_mutex);
    if(!drakvuf_init(&drakvuf, domain, rekall_profile, rekall_wow_profile, verbose, libvmi_conf))
    {
        fprintf(stderr, "Failed to initialize DRAKVUF\n %s", domain);
        return rc;
    }
    start_bsodmon(drakvuf);
    json_object *candidates = json_object_from_file(fuzz_candidates_path);
    fprintf(stderr, "STARTING FUZZING >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    while(fuzz_iterations<1000)
    {   
        fprintf(stderr, "Generating Input iteration %d>>>>>>>>>>>>>>>>\n", fuzz_iterations);
        if(!open)
            break;
        while(true)
        {
            g_mutex_lock(hijacker_dispatcher_mutex);
            bool temp_sl = spin_lock;
            g_mutex_unlock(hijacker_dispatcher_mutex);
            if(!temp_sl){
                g_mutex_lock(hijacker_dispatcher_mutex);
                spin_lock = true;
                g_mutex_unlock(hijacker_dispatcher_mutex);
                break;
            }
        }        
        GRand *rand = g_rand_new_with_seed(fuzz_iterations);
        json_object *modules_list = hijack_get_modules(candidates);
        num_libs = hijack_get_num_modules(modules_list);
        int lib_no = g_rand_int_range(rand, 0,num_libs);
        json_object *module = json_object_array_get_idx(modules_list, lib_no);
        json_object *function_list = hijack_get_functions(module);
        num_functions = hijack_get_num_functions(function_list);
        int func_no = g_rand_int_range(rand, 0, num_functions);
        json_object *function = json_object_array_get_idx(function_list, func_no);

        lib_name = hijack_get_module_name(module);
        function_name = hijack_get_fucntion_name(function);
        json_object* args = hijack_get_arguments(function);
        num_args = hijack_get_num_arguments(args);
        driver_rekal_profile = hijack_get_module_rekall_profile(module);
        fprintf(stderr, "Calling %s!%s, with %d arguments\n",lib_name, function_name, num_args);
        fprintf(stderr, "Calling With Input >>>>>>>>>>>>>>>>\n");
        if(
        !hijack(drakvuf, 
            injection_pid, 
            function_name, 
            driver_rekal_profile,
            lib_name,
            hijacker_dispatcher_mutex,
            &spin_lock)
        )
        {
            fprintf(stderr, "Hijack Failed [+]\n");
            goto error;
        }
        fprintf(stderr, "Returned >>>>>>>>>>>>>>>>\n");
        fuzz_iterations++;
    }
            error:

    drakvuf_resume(drakvuf); 
    drakvuf_close(drakvuf, 0);

    

}

