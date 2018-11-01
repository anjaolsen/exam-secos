/* GPLv2 (c) Airbus */


//singpolyma.net 

#include <debug.h>
#include <segmem.h>
#include <intr.h>
#include <info.h>

extern info_t *info;

#define c0_idx  1
#define d0_idx  2
#define c3_idx  3
#define d3_idx  4
#define ts_idx  5

#define c0_sel  gdt_krn_seg_sel(c0_idx)
#define d0_sel  gdt_krn_seg_sel(d0_idx)
#define c3_sel  gdt_usr_seg_sel(c3_idx)
#define d3_sel  gdt_usr_seg_sel(d3_idx)
#define ts_sel  gdt_krn_seg_sel(ts_idx)

seg_desc_t GDT[6];
tss_t      TSS;

#define gdt_flat_dsc(_dSc_,_pVl_,_tYp_)                                 \
   ({                                                                   \
      (_dSc_)->raw     = 0;                                             \
      (_dSc_)->limit_1 = 0xffff;                                        \
      (_dSc_)->limit_2 = 0xf;                                           \
      (_dSc_)->type    = _tYp_;                                         \
      (_dSc_)->dpl     = _pVl_;                                         \
      (_dSc_)->d       = 1;                                             \
      (_dSc_)->g       = 1;                                             \
      (_dSc_)->s       = 1;                                             \
      (_dSc_)->p       = 1;                                             \
   })

#define tss_dsc(_dSc_,_tSs_)                                            \
   ({                                                                   \
      raw32_t addr    = {.raw = _tSs_};                                 \
      (_dSc_)->raw    = sizeof(tss_t);                                  \
      (_dSc_)->base_1 = addr.wlow;                                      \
      (_dSc_)->base_2 = addr._whigh.blow;                               \
      (_dSc_)->base_3 = addr._whigh.bhigh;                              \
      (_dSc_)->type   = SEG_DESC_SYS_TSS_AVL_32;                        \
      (_dSc_)->p      = 1;                                              \
   })

#define c0_dsc(_d) gdt_flat_dsc(_d,0,SEG_DESC_CODE_XR)
#define d0_dsc(_d) gdt_flat_dsc(_d,0,SEG_DESC_DATA_RW)
#define c3_dsc(_d) gdt_flat_dsc(_d,3,SEG_DESC_CODE_XR)
#define d3_dsc(_d) gdt_flat_dsc(_d,3,SEG_DESC_DATA_RW)

// Per-process state
// struct proc {
//   char *mem;                   // Start of process memory (kernel address)
//   uint32_t sz;                     // Size of process memory (bytes)
//   char *kstack;                // Bottom of kernel stack for this process
// //   enum procstate state;       // Process state
// //   volatile int pid;            // Process ID
// //   struct proc *parent;         // Parent process
//   struct trapframe *tf;        // Trap frame for current syscall
//   struct context *context;     // Switch here to run process
// //   void *chan;                  // If non-zero, sleeping on chan
// //   int killed;                  // If non-zero, have been killed
// //   struct file *ofile[NOFILE];  // Open files
// //   struct inode *cwd;           // Current directory
// //   char name[16];               // Process name (debugging)
// };

// static struct proc *proc1;
// static struct proc *proc2;
static int incr = 0;

static uint32_t   ustack1 = 0x600000;
static uint32_t   ustack2 = 0x700000; //0x 100000 = 16^5 = 1M

// void proc* allocprocs(struct proc * p1, struct proc * p2)
// {
//   p1->kstack = (char*) 0x6000000; //obsobs! Fiks adressen. 
//   p2->kstack = (char*) 0x7000000;
//   p->tf = (struct trapframe*)(p->kstack + KSTACKSIZE) - 1;

//   // Set up new context to start executing at forkret (see below).
//   p->context = (struct context *)p->tf - 1;
//   memset(p->context, 0, sizeof(*p->context));
//   p->context->eip = (uint)forkret;
//   return p;
// }

void user1()
{
   debug("user1\n");
   while(1);
}

void user2()
{
   debug("user2\n");
//    asm("int $32");
   while(1);
}

void __regparm__(1) syscall_handler(int_ctx_t *ctx)
{
//    3
   debug("SYSCALL eax = %p\n", ctx->gpr.eax);

//    4
   debug("print syscall: %s", ctx->gpr.esi);
}

void syscall_isr()
{
   // 3: stack ninjutsu to access int_ctx_t*
   asm volatile (
      "leave ; pusha        \n"
      "mov %esp, %eax       \n"
      "call syscall_handler \n"
      "popa ; iret"
      );
}

void init_user()
{
   gdt_reg_t gdtr;

   GDT[0].raw = 0ULL;

   c0_dsc( &GDT[c0_idx] );
   d0_dsc( &GDT[d0_idx] );
   c3_dsc( &GDT[c3_idx] );
   d3_dsc( &GDT[d3_idx] );

   gdtr.desc  = GDT;
   gdtr.limit = sizeof(GDT) - 1;
   set_gdtr(gdtr);

   set_ds(d3_sel);
   set_es(d3_sel);
   set_fs(d3_sel);
   set_gs(d3_sel);

   TSS.s0.esp = get_ebp();
   TSS.s0.ss  = d0_sel;
   tss_dsc(&GDT[ts_idx], (offset_t)&TSS);
   set_tr(ts_sel);

//    // 2: fix IDT for syscall 48
   int_desc_t *dsc;
   idt_reg_t  idtr;

   // Je dois attribuer Á chaque tache une pile utilisateur ET une pile noyau.
   // Il faut donc peut-^etre 2 TSS ???
    

//MON PROBLEME : je ne sais pas comment configurer les zones d adresses 
//le noyau est identity mappé
//    . les tâches sont identity mappées
//    . les tâches possèdent leurs propres PGD/PTB
//    . les tâches ont une zone de mémoire partagée:
//      . de la taille d'une page (4KB)
//      . à l'adresse physique de votre choix
//      . à des adresses virtuelles différentes
//    . les tâches doivent avoir leur propre pile noyau (4KB)
//    . les tâches doivent avoir leur propre pile utilisateur (4KB)

   get_idtr(idtr);
   dsc = &idtr.desc[48];
   dsc->dpl = 3;

   // 3: install kernel syscall handler
   dsc->offset_1 = (uint16_t)((uint32_t)syscall_isr);
   dsc->offset_2 = (uint16_t)(((uint32_t)syscall_isr)>>16);


}

//=============================================================================

// It is the interrupt 32 that will switch between the two tasks.
// (irq0 = horloge)
// It must therefore ;  know if it it interrupts a kernel or a user task
//                      know if it should switch from user1 to user2 or the opposite
// put the following things on the stack : if it switches from a kernel task to a user task
//       "push %0 \n" // ss
//       "push %1 \n" // esp
//       "pushf   \n" // eflags
//       "push %2 \n" // cs
//       "push %3 \n" // eip
// and put only the three last if it changes from user to user
void int32_handler() 
{
    asm volatile ("pusha");
    debug("\n\n\n\n");
    debug("Int32 handler\n");
    // int var=1;
    // asm volatile ("mov (%esp), %0\n\t"
    // : "=r" (var));
    // asm volatile ("movl $0, %eax");
    asm volatile ("mov 48(%eax), %esp");
    // debug("Var: %x", var);

    //idea to find out what privilege level we came from: pop/read cs (here: esp+12*4)
    // and see what privilege level it was...

     //===============================
    //aller vers une tache
    // SI dans cs juste avant on dètecte qu on etait dans ring 0, on met ss et esp.
    // SINON on met juste eflags, cs et eip. 
    //=========================================
    // 1: enter user
//    asm volatile (
//       "push %0 \n" // ss
//       "push %1 \n" // esp
//       "pushf   \n" // eflags
//       "push %2 \n" // cs
//       "push %3 \n" // eip
//       "iret"
//       ::
//        "i"(d3_sel),
//        "m"(ustack),
//        "i"(c3_sel),
//        "r"(&userland)
//       );

    if (incr == 1){
        //display number
        debug("Display\n");
        incr = 0;
        asm volatile (
            "push %0 \n" // ss
            "push %1 \n" // esp
            "pushf   \n" // eflags
            "push %2 \n" // cs
            "push %3 \n" // eip
            "iret"
            ::
            "i"(d3_sel),
            "m"(ustack1),
            "i"(c3_sel),
            "r"(&user1)
        );
    } else {
        //increment number
        debug("Increment\n");
        incr = 1;
        asm volatile (
            "push %0 \n" // ss
            "push %1 \n" // esp
            "pushf   \n" // eflags
            "push %2 \n" // cs
            "push %3 \n" // eip
            "iret"
            ::
            "i"(d3_sel),
            "m"(ustack2),
            "i"(c3_sel),
            "r"(&user2)
        );
    }

    ///3.5: aligner la pile et avoir le bon esp.
    asm volatile ("popa; leave ; iret");
}

void int32_trigger()  //for test purposes
{
    debug("int32 trigger\n");
    asm("int $32"); 
    //int3();
    debug("\n\n\n\n");
    debug("int32 trigger retour\n");
}


//=============================================================================

void init_IDT()
{
    idt_reg_t idt_r; 
    get_idtr(idt_r);   

    int_desc_t *bp_dsc = &idt_r.desc[32];

    bp_dsc->offset_1 = (uint16_t)((uint32_t)int32_handler);
    bp_dsc->offset_2 = (uint16_t)(((uint32_t)int32_handler)>>16);

}


// void
// userinit(void)
// {
//   struct proc *p;
//   extern uchar _binary_initcode_start[], _binary_initcode_size[];
  
//   p = allocproc();
//   initproc = p;

//   // Initialize memory from initcode.S
//   p->sz = PAGE;
//   p->mem = kalloc(p->sz);
//   memmove(p->mem, _binary_initcode_start, (int)_binary_initcode_size);

//   memset(p->tf, 0, sizeof(*p->tf));
//   p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
//   p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
//   p->tf->es = p->tf->ds;
//   p->tf->ss = p->tf->ds;
//   p->tf->eflags = FL_IF;
//   p->tf->esp = p->sz;
//   p->tf->eip = 0;  // beginning of initcode.S

//   safestrcpy(p->name, "initcode", sizeof(p->name));
//   p->cwd = namei("/");

//   p->state = RUNNABLE;
// }

void tp()
{
   init_user();
   init_IDT();
   //enable interrupts
   asm volatile("sti"); 
   while(1);
}
