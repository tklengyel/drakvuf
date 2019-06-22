#include <config.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include "libhijack/libhijack.h"
#include "libdrakvuf/libdrakvuf.h"

static drakvuf_t drakvuf;
static void close_handler(int sig)
{
    drakvuf_interrupt(drakvuf, sig);
}
int main(int argc, char **argv){
    char *domain=NULL, *rekall_profile=NULL, *rekall_wow_profile = NULL, *function_name = NULL;
    int injection_pid = 0;
	// int injection_thread;
    // output_format_t output = OUTPUT_DEFAULT;
    bool verbose = false,  libvmi_conf = false;
    // bool leave_paused = false, injection_global_search = false;
    char c;
    char *driver_rekal_profile=NULL;
    
    int rc = -1;
    eprint_current_time();
    fprintf(stderr, "%s v%s\n", PACKAGE_NAME, PACKAGE_VERSION);
    if (argc < 4)
    {
        fprintf(stderr, "Required input:\n"
                "\t -r, --rekall-kernel <rekall profile>\n"
                "\t                           The Rekall profile of the OS kernel\n"
                "\t -d <domain ID or name>    The domain's ID or name\n"
                "\t -f function-name          The function to call after hijacking\n"
                "\t -g <driver rekall profile> \n"
                "\t                           The Rekall profile of the Driver"
            );
        return rc;
    }
    const char *opts = "r:d:i:I:e:g:vf:p";
    
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
            case 'I':
                // injection_thread = atoi(optarg);
                break;
            case 'e':
                // inject_file = optarg;
                break;
            case 'g':
                driver_rekal_profile = optarg;
                break;
            case 'f':
                function_name  = optarg;
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

    fprintf(stderr, "driver rekall profile %s", driver_rekal_profile);

    if(!drakvuf_init(&drakvuf, domain, rekall_profile, rekall_wow_profile, verbose, libvmi_conf)){
        fprintf(stderr, "Failed to initialize DRAKVUF\n %s", domain);
        return rc;
    }
    if(
        !hijack(drakvuf, 
            injection_pid, 
            function_name, 
            driver_rekal_profile)
    )
    {
        fprintf(stderr, "Hijack Failed [+]\n");
    }
    drakvuf_resume(drakvuf); 
    drakvuf_close(drakvuf, 0);

    

}

