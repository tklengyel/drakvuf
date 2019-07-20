#include <iostream>
#include <unistd.h>
#include <afl_injector.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <fstream>
void afl_setup();
void afl_forkserver();


using namespace std;
int main()
{
    fstream file;
    file.open("/home/ajinkya/College/gsoc19/AFL/ajinkya.txt", fstream::in|fstream::out|fstream::app);
    if(file.fail())
        cout<<"Couldnt open the file \n";
    file<<"Setting up afl\n";
    afl_setup();
    file<<"Starting forkserver\n";
    afl_forkserver();
    file<<"Bye Bye\n";
    file<<"In main folder";
    afl_area_ptr[1<<10] = 12;
    file.close();
    return -1;
}

/* Fork server logic, invoked once we hit _start. */

void afl_forkserver() {

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
      printf("In child\n");
      return;

    }

    /* Parent. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

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
        printf("shmat failed\n");
        exit(1);
    }

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }

}