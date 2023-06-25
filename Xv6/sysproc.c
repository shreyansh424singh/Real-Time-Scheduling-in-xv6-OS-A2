#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

int sys_exec_time(void) {
  int pid, time;

  if(argint(0, &pid) < 0)
    return -1;
  if(argint(1, &time) < 0)
    return -1;
  return exec_time(pid, time);
}

int sys_deadline(void) {
  int pid, time;

  if(argint(0, &pid) < 0)
    return -1;
  if(argint(1, &time) < 0)
    return -1;
  return deadline(pid, time);
}

int sys_rate(void) {
  int pid, rate_val;

  if(argint(0, &pid) < 0)
    return -1;
  if(argint(1, &rate_val) < 0)
    return -1;
  return rate(pid, rate_val);
}

int sys_sched_policy(void) {
  int pid, policy;

  if(argint(0, &pid) < 0)
    return -1;
  if(argint(1, &policy) < 0)
    return -1;
  return sched_policy(pid, policy);
}

