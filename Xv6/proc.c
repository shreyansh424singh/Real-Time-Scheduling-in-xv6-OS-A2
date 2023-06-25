// TODO: Terminate process here if TAs do not terminate on returning -22 in user process in futture test cases

#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"

struct spinlock pstate_lock;

int LIU_BOUND[] = {0, 1000000, 828427, 779763, 756828, 743491, 734772, 728626, 724061, 720537, 717734, 715451, 713557, 711958, 710592, 709411, 708380, 707472, 706666, 705945, 705298, 704713, 704182, 703697, 703253, 702845, 702469, 702121, 701797, 701497, 701216, 700954, 700708, 700478, 700260, 700056, 699863, 699680, 699507, 699343, 699187, 699039, 698898, 698763, 698635, 698513, 698395, 698283, 698176, 698072, 697973, 697878, 697787, 697699, 697614, 697533, 697454, 697378, 697305, 697234, 697166, 697100, 697036, 696974, 696914};

struct
{
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int sched_pol = -1;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int cpuid()
{
  return mycpu() - cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu *
mycpu(void)
{
  int apicid, i;

  if (readeflags() & FL_IF)
    panic("mycpu called with interrupts enabled\n");

  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i)
  {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc *
myproc(void)
{
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}

// PAGEBREAK: 32
//  Look in the process table for an UNUSED proc.
//  If found, change state to EMBRYO and initialize
//  state required to run in the kernel.
//  Otherwise return 0
static struct proc *
allocproc(void)
{
  struct proc *p;
  char *sp;

  acquire(&ptable.lock);

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if (p->state == UNUSED)
      goto found;

  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  p->pid = nextpid++;

  p->elapsed_time = 0;
  p->sched_policy = -1;
  p->exec_time = 1000000;
  p->priority = 10;
  p->rate = 1;
  p->deadline = 1000000;
  p->wait_time = 0;
  p->last_tick = ticks;

  release(&ptable.lock);

  // Allocate kernel stack.
  if ((p->kstack = kalloc()) == 0)
  {
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe *)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint *)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context *)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  return p;
}

// PAGEBREAK: 32
//  Set up first user process.
void userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();

  initproc = p;
  if ((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0; // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if (n > 0)
  {
    if ((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  else if (n < 0)
  {
    if ((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if ((np = allocproc()) == 0)
  {
    return -1;
  }

  // Copy process state from proc.
  if ((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0)
  {
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for (i = 0; i < NOFILE; i++)
    if (curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if (curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for (fd = 0; fd < NOFILE; fd++)
  {
    if (curproc->ofile[fd])
    {
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if (p->parent == curproc)
    {
      p->parent = initproc;
      if (p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  curproc->state = ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();

  acquire(&ptable.lock);
  for (;;)
  {
    // Scan through table looking for exited children.
    havekids = 0;
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
      if (p->parent != curproc)
        continue;
      havekids = 1;
      if (p->state == ZOMBIE)
      {
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if (!havekids || curproc->killed)
    {
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock); // DOC: wait-sleep
  }
}

int exec_time(int pid, int exec_time)
{
  struct proc *p;

  acquire(&ptable.lock);
  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if (p->pid == pid)
      break;

  if (p->exec_time != 1000000)
  {
    release(&ptable.lock);
    // cprintf("%d: Returned at exectime\n", pid);
    return -22;
  }
  if (p->deadline != 1000000 && exec_time > p->deadline)
  {
    release(&ptable.lock);
    // cprintf("%d: Returned at exectime\n", pid);
    return -22;
  }

  p->exec_time = exec_time;
  release(&ptable.lock);

  return 0;
}

int deadline(int pid, int deadline)
{
  struct proc *p;

  acquire(&ptable.lock);
  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if (p->pid == pid)
      break;

  if (p->exec_time != 1000000 && p->exec_time > deadline)
  {
    release(&ptable.lock);
    // cprintf("%d: Returned at deadline\n", pid);
    return -22;
  }
  p->deadline = deadline;
  release(&ptable.lock);

  return 0;
}

int rate(int pid, int rate)
{
  struct proc *p;

  acquire(&ptable.lock);
  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if (p->pid == pid)
      break;

  if (rate < 0 || rate > 30)
  {
    release(&ptable.lock);
    // cprintf("%d: Returned at rate\n", pid);
    return -22;
  }

  p->rate = rate;
  int temp = ((30 - rate) * 3 + 28) / 29;
  p->priority = (temp < 1) ? 1 : temp;

  // cprintf("Set process %d with rate %d priority to %d\n", pid, rate, p->priority);

  release(&ptable.lock);

  return 0;
}

int sched_policy(int pid, int policy)
{
  struct proc *p;

  acquire(&ptable.lock);
  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if (p->pid == pid)
      break;

  if (sched_pol != -1 && sched_pol != policy)
  {
    release(&ptable.lock);
    kill(pid);
    return -22;
  }

  // *************** EDF ******************** //
  if (policy == 0)
  {
    int temp = (1000000 * p->exec_time) / p->deadline;

    // cprintf("%d: temp %d\n", p->pid, temp);
    for (struct proc *p1 = ptable.proc; p1 < &ptable.proc[NPROC]; p1++)
    {
      if (p1->pid == 0)
        continue;
      // add the time left of all the processes which will start before p
      if (p1->sched_policy == 0 && p->pid != p1->pid && p1->exec_time < 1000000)
        temp += (1000000 * p1->exec_time) / p1->deadline;

      if (temp > 1000000)
      {
        release(&ptable.lock);
        kill(pid);
        return -22;
      }
    }

    if (temp > 1000000)
    {
      release(&ptable.lock);
      kill(pid);
      return -22;
    }
  }

  // *************** RMS ******************** //
  else if (policy == 1)
  {
    // int temp = (1000000 * p->rate * (p->exec_time - p->elapsed_time)) / (100 + p->rate * (p->arrival_time - ticks));
    // int temp = (1000000 * p->rate * (p->exec_time - p->elapsed_time)) / (100 + p->rate);
    int temp = (10000 * p->rate * p->exec_time);
    int n = 1;

    for (struct proc *p1 = ptable.proc; p1 < &ptable.proc[NPROC]; p1++)
    {
      if (p1->sched_policy == 1 && p->pid != p1->pid && p1->exec_time < 1000000)
      {
        temp += (10000 * p1->rate * p1->exec_time);
        n++;
      }
    }

    // cprintf("1 temp: %d,\t n: %d,\t Liu_bound %d\n", temp, n, LIU_BOUND[n]);

    if (temp > LIU_BOUND[n])
    {
      release(&ptable.lock);
      kill(pid);
      return -22;
    }
  }

  p->arrival_time = ticks;
  p->sched_policy = policy;
  sched_pol = policy;
  release(&ptable.lock);

  // cprintf("%d: pol set to %d\n", p->pid, policy);

  return 0;
}

// PAGEBREAK: 42
//  Per-CPU process scheduler.
//  Each CPU calls scheduler() after setting itself up.
//  Scheduler never returns.  It loops, doing:
//   - choose a process to run
//   - swtch to start running that process
//   - eventually that process transfers control
//       via swtch back to the scheduler.
void scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;

  for (;;)
  {
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);

    int temp = -1;
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
      if (p->state != RUNNABLE)
        continue;
      temp = (p->sched_policy > temp) ? p->sched_policy : temp;
    }

    if (temp == -1 && temp < 3)
      sched_pol = -1;

    // *************** EDF ******************** //
    if (sched_pol == 0)
    {
      int earliest_deadline = 100000000, pid_to_sched = -10;

      for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
      {
        if (p->state != RUNNABLE || p->sched_policy != sched_pol)
          continue;

        int time_left = p->arrival_time + p->deadline - ticks;
        if (time_left < earliest_deadline)
        {
          earliest_deadline = time_left;
          pid_to_sched = p->pid;
        }
        else if (time_left == earliest_deadline)
        {
          if (p->pid < pid_to_sched)
            pid_to_sched = p->pid;
        }
      }

      if (pid_to_sched == -10)
        continue;

      for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
        if (p->pid == pid_to_sched)
          break;

      // cprintf("pid: %d\n", p->pid);

      if (p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      struct proc *p1;
      for (p1 = ptable.proc; p1 < &ptable.proc[NPROC]; p1++)
        if (p1->state == RUNNABLE && p1->pid != p->pid)
          p1->wait_time++;

      // Increment run time of the running process
      if (ticks > p->last_tick)
      {
        p->last_tick = ticks;
        p->elapsed_time++;
      }

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }

    // *************** RMS ******************** //

    else if (sched_pol == 1)
    {
      int lowest_prio = 100, pid_to_sched = -10;

      for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
      {
        if (p->state != RUNNABLE || p->sched_policy != sched_pol)
          continue;

        if (p->priority < lowest_prio)
        {
          lowest_prio = p->priority;
          pid_to_sched = p->pid;
        }
        else if (p->priority == lowest_prio)
        {
          if (p->pid < pid_to_sched)
            pid_to_sched = p->pid;
        }
      }

      if (pid_to_sched == -10)
        continue;

      for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
        if (p->pid == pid_to_sched)
          break;

      // cprintf("pid: %d\n", p->pid);

      if (p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      struct proc *p1;
      for (p1 = ptable.proc; p1 < &ptable.proc[NPROC]; p1++)
        if (p1->state == RUNNABLE && p1->pid != p->pid)
          p1->wait_time++;

      // Increment run time of the running process
      if (ticks > p->last_tick)
      {
        p->last_tick = ticks;
        p->elapsed_time++;
      }

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }

    // *************** RR ******************** //

    else
    {
      for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
      {
        if (p->state != RUNNABLE)
          continue;

        // cprintf("pid: %d\n", p->pid);

        // Switch to chosen process.  It is the process's job
        // to release ptable.lock and then reacquire it
        // before jumping back to us.
        c->proc = p;
        switchuvm(p);
        p->state = RUNNING;

        swtch(&(c->scheduler), p->context);

        // struct proc *p1;
        // for (p1 = ptable.proc; p1 < &ptable.proc[NPROC]; p1++)
        //   if (p1->state == RUNNABLE && p1->pid != p->pid)
        //     p1->wait_time++;

        // // Increment run time of the running process
        // p->elapsed_time++;

        switchkvm();

        struct proc *p1;
        for (p1 = ptable.proc; p1 < &ptable.proc[NPROC]; p1++)
          if (p1->state == RUNNABLE && p1->pid != p->pid)
            p1->wait_time++;

        // Increment run time of the running process
        if (ticks > p->last_tick)
        {
          p->last_tick = ticks;
          p->elapsed_time++;
        }

        // Process is done running for now.
        // It should have changed its p->state before coming back.
        c->proc = 0;
      }
    }
    release(&ptable.lock);
  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void sched(void)
{
  int intena;
  struct proc *p = myproc();

  if (!holding(&ptable.lock))
    panic("sched ptable.lock");
  if (mycpu()->ncli != 1)
    panic("sched locks");
  if (p->state == RUNNING)
    panic("sched running");
  if (readeflags() & FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;

  // // Increment run time of the running process
  // p->elapsed_time++; // done in scheduler

  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void yield(void)
{
  acquire(&ptable.lock); // DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first)
  {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();

  if (p == 0)
    panic("sleep");

  if (lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if (lk != &ptable.lock)
  {                        // DOC: sleeplock0
    acquire(&ptable.lock); // DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if (lk != &ptable.lock)
  { // DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

// PAGEBREAK!
//  Wake up all processes sleeping on chan.
//  The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if (p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if (p->pid == pid)
    {
      p->killed = 1;
      // Wake process from sleep if necessary.
      if (p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

// PAGEBREAK: 36
//  Print a process listing to console.  For debugging.
//  Runs when user types ^P on console.
//  No lock to avoid wedging a stuck machine further.
void procdump(void)
{
  static char *states[] = {
      [UNUSED] "unused",
      [EMBRYO] "embryo",
      [SLEEPING] "sleep ",
      [RUNNABLE] "runble",
      [RUNNING] "run   ",
      [ZOMBIE] "zombie"};
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if (p->state == UNUSED)
      continue;
    if (p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if (p->state == SLEEPING)
    {
      getcallerpcs((uint *)p->context->ebp + 2, pc);
      for (i = 0; i < 10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}