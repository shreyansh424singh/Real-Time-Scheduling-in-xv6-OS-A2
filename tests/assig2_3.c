#include "types.h"
#include "stat.h"
#include "user.h"

// TC#3: EDF Non-schedulable test case
int main(int argc, char *argv[])
{   
    int num_procs = 4;
    int deadline_value[4] = {26, 24, 28, 31};
    int exectime[4] = {4, 13, 6, 8};

    int parent_pid = getpid();

    // Set the scheduling policy to EDF
    deadline(parent_pid, 23);
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
