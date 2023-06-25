#include "types.h"
#include "stat.h"
#include "user.h"

// TC#4: EDF same deadline test case
int main(int argc, char *argv[])
{   
    int num_procs = 4;
    int deadline_value[4] = {28, 28, 24, 52};
    int exectime[4] = {8, 4, 5, 4};

    int parent_pid = getpid();

    // Set the scheduling policy to EDF
    deadline(parent_pid, 25);
    exec_time(parent_pid, 10);
    sched_policy(parent_pid, 0);

    for(int i = 0; i < num_procs; i++)
    {
        int cid = fork();
        if (cid != 0)
        {
            // Set the scheduling policy to EDF
            deadline(cid, deadline_value[i]);
            exec_time(cid, exectime[i]);
            sched_policy(cid, 0);
        }
        else
        {
            /*The XV6 kills the process if th exec time is completed*/
            while(1) {
                
            }
        }
    }

    while(1) {

    }
}
