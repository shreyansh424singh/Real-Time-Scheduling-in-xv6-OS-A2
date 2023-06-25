#include "types.h"
#include "stat.h"
#include "user.h"

// TC#2: RM Schedulable test case
int main(int argc, char *argv[])
{   
    int num_procs = 2;
    int rate_value[2] = {21, 11};
    int exectime[2] = {1, 2};

    int parent_pid = getpid();

    // Set the scheduling policy to RM
    rate(parent_pid, 1);
    exec_time(parent_pid, 10);
    sched_policy(parent_pid, 1);

    for(int i = 0; i < num_procs; i++)
    {
        int cid = fork();
        if (cid != 0)
        {
            // Set the scheduling policy to RM
            rate(cid, rate_value[i]);
            exec_time(cid, exectime[i]);
            sched_policy(cid, 1);
        }
        else
        {
            /*The XV6 kills the process if the exec time is completed*/
            while(1) {
                
            }
        }
    }

    while(1) {

    }
}
