#include "libdrakvuf/libdrakvuf.h"
#include "unistd.h"
static drakvuf_t drakvuf;
int main()
{
    char *domain = "win10";
    char *rekall_profile = "/home/ajinkya/College/gsoc19/pdbs/win10/win10.rekall.json";
    char *rekall_wow_profile = NULL;
    bool verbose = true;
    bool libvmi_conf = false;
    /** bool drakvuf_init(drakvuf_t* drakvuf, const char* domain, 
        const char* rekall_profile, 
        const char* rekall_wow_profile, 
        bool _verbose, 
        bool libvmi_conf)
    */
    int i = 0;
    while(i<100)
    {   
        fprintf(stderr, "opening %d\n", i);
        if(!drakvuf_init(&drakvuf, domain, rekall_profile, rekall_wow_profile, verbose, libvmi_conf))
        {
            fprintf(stderr, "Failed to initialize DRAKVUF\n %s", domain);
            return 0;
        }
        sleep(1);
        fprintf(stderr, "closing %d\n", i);
        drakvuf_close(drakvuf,0);
        i++;
    
    }
    return 1;
}