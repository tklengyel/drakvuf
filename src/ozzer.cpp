#include "drakvuf.h"
#include <glib.h>
#include <exception>
#include <stdlib.h>
#include <getopt.h>
#include <libinjector/libinjector.h>

int main(int argc, char **argv){

    drakvuf_c drakvuf;
    eprint_current_time();
    fprintf(stderr, "%s v%s\n", PACKAGE_NAME, PACKAGE_VERSION);
    if (argc < 4)
    {
        fprintf(stderr, "Required input:\n"
                "\t -r, --rekall-kernel <rekall profile>\n"
                "\t                           The Rekall profile of the OS kernel\n"
                "\t -d <domain ID or name>    The domain's ID or name\n"
                "\t -f function-name          The function to call after hijacking\n"
            );
        return rc;
    }

}
