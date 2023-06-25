// Test that fork fails gracefully.
// Tiny executable so that the limit can be filling the proc table.

#include "types.h"
#include "stat.h"
#include "user.h"

#define N 1000

void printf(int fd, const char *s, ...)
{
  write(fd, s, strlen(s));
}

void forktest(void)
{
  int n, pid;

  printf(1, "fork test\n");

  for (n = 0; n < N; n++)
  {
    pid = fork();
    if (pid < 0)
      break;
    if (pid == 0)
    {
      // int k = 1000000000;
      // while(k);
      // if (n == 63)
      //   sleep(1000);
      exit();
    }
  }

  if (n == N)
  {
    printf(1, "fork claimed to work N times!\n", N);
    exit();
  }

  for (; n > 0; n--)
  {
    if (wait() < 0)
    {
      printf(1, "wait stopped early\n");
      exit();
    }
  }

  if (wait() != -1)
  {
    printf(1, "wait got too many\n");
    exit();
  }

  printf(1, "fork test OK\n");
}

int main(void)
{
  // struct process_state *ps;
  // memset(&ps, 0, sizeof(process_state));
  // ps->pid[0] = 1;
  // prinf(ps->pid[0]);
  // exec_time(2, 2);
  // deadline(2, 2);
  // rate(2, 2);
  // sched_policy(2, 2);
  // getpinfo(ps);
  forktest();
  exit();
}
