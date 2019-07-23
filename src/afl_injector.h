#define FORKSRV_FD          198
/* Environment variable used to pass SHM ID to the called program. */

#define SHM_ENV_VAR         "__AFL_SHM_ID"

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)

static unsigned int afl_inst_rms = MAP_SIZE;
static unsigned char *afl_area_ptr;
static unsigned int afl_forksrv_pid;
static int afl_fork_child = 0;

