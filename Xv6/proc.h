// Per-CPU state
struct cpu {
  uchar apicid;                // Local APIC ID
  struct context *scheduler;   // swtch() here to enter scheduler
  struct taskstate ts;         // Used by x86 to find stack for interrupt
  struct segdesc gdt[NSEGS];   // x86 global descriptor table
  volatile uint started;       // Has the CPU started?
  int ncli;                    // Depth of pushcli nesting.
  int intena;                  // Were interrupts enabled before pushcli?
  struct proc *proc;           // The process running on this cpu or null
};

extern struct cpu cpus[NCPU];
extern int ncpu;

//PAGEBREAK: 17
// Saved registers for kernel context switches.
// Don't need to save all the segment registers (%cs, etc),
// because they are constant across kernel contexts.
// Don't need to save %eax, %ecx, %edx, because the
// x86 convention is that the caller has saved them.
// Contexts are stored at the bottom of the stack they
// describe; the stack pointer is the address of the context.
// The layout of the context matches the layout of the stack in swtch.S
// at the "Switch stacks" comment. Switch doesn't save eip explicitly,
// but it is on the stack and allocproc() manipulates it.
struct context {
  uint edi;
  uint esi;
  uint ebx;
  uint ebp;
  uint eip;
};

enum procstate { UNUSED, EMBRYO, SLEEPING, RUNNABLE, RUNNING, ZOMBIE };

// Per-process state
struct proc {
  uint sz;                     // Size of process memory (bytes)
  pde_t* pgdir;                // Page table
  char *kstack;                // Bottom of kernel stack for this process
  enum procstate state;        // Process state
  int pid;                     // Process ID
  struct proc *parent;         // Parent process
  struct trapframe *tf;        // Trap frame for current syscall
  struct context *context;     // swtch() here to run process
  void *chan;                  // If non-zero, sleeping on chan
  int killed;                  // If non-zero, have been killed
  struct file *ofile[NOFILE];  // Open files
  struct inode *cwd;           // Current directory
  char name[16];               // Process name (debugging)
  
  int sched_policy;            // Scheduling policy of the process ( -1: XV6 default policy or 0: EDF or 1: RMA )
  int elapsed_time;            // Elapsed time of the process
  int exec_time;               // Execution time of the process
  int priority;                // current priority level of each process (1-3) ( higher value represents lower priority )
  int rate;                    // Rate of the process
  int deadline;                // Deadline of the process
  int wait_time;               // Wait time of the process
  int arrival_time;              // Start time of the process
  int last_tick;               // LAst tick value at which it was incremented
};

// Process memory is laid out contiguously, low addresses first:
//   text
//   original data and bss
//   fixed-size stack
//   expandable heap

// struct process_state
// {
//   int inuse[NPROC];            // whether this slot of the process table is in use (1 or 0)
//   int pid[NPROC];              // PID of each process
//   int sched_policy[NPROC];     // current scheduling policy of the process ( -1: XV6 default policy or 0: EDF or 1: RMA )
//   int priority[NPROC];         // current priority level of each process (1 -3) ( higher value represents lower priority )
//   enum procstate state[NPROC]; // current state of each process
//   int rate[NPROC];
//   int execution_time[NPROC];
//   int elapsed_time[NPROC];
//   int wait_time[NPROC];
//   int deadline[NPROC];
// };
