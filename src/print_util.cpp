#include "print_util.h"

struct timeval get_time()
{
    struct timeval now;
    gettimeofday(&now, 0);
    return now;
}
