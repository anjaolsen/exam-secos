/* GPLv2 (c) Airbus */

#include <debug.h>
#include <segmem.h>
#include <intr.h>
#include <info.h>
#include <cr.h>
#include <pagemem.h>

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

// static int incr = 1;

//userstacks a partir de 0x1000000 - 1 page de 4ko chacune (derniere @)
static uint32_t   ustack1 = 0x1001000 - 0x04;
static uint32_t   ustack2 = 0x1402000 - 0x04; //0x 100000 = 16^5 = 1M , 0x001000 = 4k
static uint32_t   user_kstack1 = 0x1004000 - 0x04;
static uint32_t   user_kstack2 = 0x1406000 - 0x04;

// static pde32_t *pgd = (pde32_t*)0x600000; //PGD
// static pde32_t *pgd_user1 = (pde32_t*)0x610000; //PGD de user1
// static pde32_t *pgd_user2 = (pde32_t*)0x620000; //PGD de user2

#define PGD_USER_1 0x610000
#define PGD_USER_2 0x620000


struct task_struct
{
	int_ctx_t 	context;
	uint32_t 	kernel_stack;
	uint32_t 	cr3;
	struct task_struct * next_task;
};

void create_task(struct task_struct* task, uint32_t function_address,
	uint32_t kernel_stack, uint32_t user_stack, struct task_struct* next_task, uint32_t cr3)
{
	memset(task, 0, sizeof(struct task_struct));
    //initialize the context as if the task was interrupted
	task->context.eip.raw = function_address;
	task->context.cs.raw = c3_sel;
	task->context.eflags.raw = get_flags()|0x200;
	task->context.esp.raw = user_stack;
	task->context.ss.raw = d3_sel;

	task->kernel_stack = kernel_stack;

	task->next_task = next_task;

    task->cr3 = cr3;
}

// void store_context_before_switch(struct task_struct* task, int_ctx_t* ctx)
// {
//     // "pop" the context by moving the stack pointer to what was pushed before the context (eip)
// 	task->kernel_stack = (uint32_t)(ctx) + sizeof(int_ctx_t);
//     // put the context in the context-attribute
// 	memcpy(&task->context, ctx, sizeof(int_ctx_t));
// }


struct task_struct task1;
struct task_struct task2;

struct task_struct * current;

void int32_trigger()  //for test purposes
{
    debug("int32 trigger\n");
    asm("int $32");
    debug("\n\n\n\n");
    debug("int32 trigger retour\n");
}

void sys_counter(uint32_t *counter)
{
// eax : syscall number
// ebx : parameter 1 (address of counter)
   asm volatile (
      "mov %0, %%eax\n"
      "int $0x80"
      :
      :"a"(counter)
    );
}

void __regparm__(1) sys_counter_kernel(int_ctx_t *ctx)
{
    // Check if virtual address mapped in userland for the current pgd.
    uint32_t * ptr = (uint32_t * )(ctx->gpr.eax.raw);
    int address_in_userland = 0;

    pde32_t* pgd = (pde32_t*)get_cr3();
	pte32_t* pte = (pte32_t*)(pgd[pd32_idx(ptr)].addr << 12);

    int ptb_idx = pt32_idx(ptr);
    int pgd_idx = pd32_idx(ptr);
    uint32_t config_pgd = pgd[pgd_idx].raw & (PG_USR | PG_P);
    uint32_t config_ptb = pte[ptb_idx].raw & (PG_USR | PG_P);

    if( config_pgd == (PG_USR | PG_P))
    {
		if( config_ptb == (PG_USR | PG_P))
		{
        	address_in_userland = 1;
        }
    }

    if (address_in_userland)
    {
        debug("SYSCALL counter = %d\n",  *ptr);
    }
    else
    {
        debug("Address not in userland\n");
    }

}

// note: 0x802000 = virtual address for user1 to the shared memory
void __attribute__ ((section(".user1"),aligned(PAGE_SIZE))) user1()
{
    uint32_t *v1 = (uint32_t*)0x802000;
    while(1){
        *v1 = (*v1) + 1;
    }
}

// note: 0xc02000 = virtual address for user2 to the shared memory
void __attribute__ ((section(".user2"),aligned(PAGE_SIZE))) user2()
{
   while(1){
        sys_counter((uint32_t *)0xc0200);
    }
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

    // change ISR for syscall 0x80
   int_desc_t *dsc;
   idt_reg_t  idtr;

   get_idtr(idtr);

   dsc = &idtr.desc[32];
   dsc->dpl = 3;

   dsc = &idtr.desc[0x80];
   dsc->dpl = 3;

   // 3: install kernel syscall handler
   dsc->offset_1 = (uint16_t)((uint32_t)sys_counter_kernel);
   dsc->offset_2 = (uint16_t)(((uint32_t)sys_counter_kernel)>>16);
 
// mettre les choses pertinentes dans les piles noyaux, comme si ils avaient deja ete
// interrompues par une interruption par exemple.
// flags
// cs
// eip  <---esp
//    user_kstack1

    create_task(&task1, (uint32_t) &user1, user_kstack1, ustack1, &task2, PGD_USER_1);
    create_task(&task2, (uint32_t)&user2, user_kstack2, ustack2, &task1, PGD_USER_2);

}

void switch_to_task (struct task_struct * task)
{
   
   TSS.s0.esp = task->kernel_stack;
   TSS.s0.ss  = d3_sel;

   asm volatile (
      "mov %0, %%cr3	\n"			// Change cr3 - the address of the page directory for this task
      "mov %1, %%esp \n"	// Change kernel stack

    // push the appropriate registers onto the stack in order to "resume" task execution
      "pushl %2	    \n" //	 ss
	  "pushl %3	    \n" //	 esp
	  "pushl %4	    \n"	//   eflags
	  "pushl %5		\n" //	 push cs
	  "pushl %6		\n" //	 push eip

	  "pushl %7		\n" //	 eax
	  "pushl %8		\n" //	 ecx
	  "pushl %9		\n" //	 edx
	  "pushl %10		\n" //	 ebx
	  "pushl %11			\n" //	 esp
	  "pushl %12			\n" //	 ebp
	  "pushl %13			\n" //	 esi
	  "pushl %14			\n" //	 edi
      "popa ; iret;"
      :
      :"r"(task->cr3),
      "r"(task->kernel_stack),
      "g"(task->context.ss.raw),
      "g"(task->context.esp.raw),
      "g"(task->context.eflags.raw),
      "g"(task->context.cs.raw),
      "g"(task->context.eip.raw),
      "g"(task->context.gpr.eax),
      "g"(task->context.gpr.ecx),
      "g"(task->context.gpr.edx),
      "g"(task->context.gpr.ebx),
      "g"(task->context.gpr.esp),
      "g"(task->context.gpr.ebp),
      "g"(task->context.gpr.esi),
      "g"(task->context.gpr.edi)
      :
   );

}

void save_task (uint32_t * stack_ptr, struct task_struct * task)
{
    //observations with gdb led to : edi is at stack_ptr[2]
    task->context.gpr.edi.raw = stack_ptr[0];
    debug("Test save: edi = %d\n", task->context.gpr.edi.raw);
    task->context.gpr.esi.raw = stack_ptr[1];
    debug("Test save: esi = %d\n", task->context.gpr.esi.raw);
    task->context.gpr.ebp.raw = stack_ptr[2];
    debug("Test save: ebp = %d\n", task->context.gpr.ebp.raw);
    task->context.gpr.esp.raw = stack_ptr[3];
    debug("Test save: esp = %d\n", task->context.gpr.esp.raw);
    task->context.gpr.ebx.raw = stack_ptr[4];
    debug("Test save: ebx = %d\n", task->context.gpr.ebx.raw);
    task->context.gpr.edx.raw = stack_ptr[5];
    debug("Test save: edx = %d\n", task->context.gpr.edx.raw);
    task->context.gpr.ecx.raw = stack_ptr[6];
    debug("Test save: ecx = %d\n", task->context.gpr.ecx.raw);
    task->context.gpr.eax.raw = stack_ptr[7];
    debug("Test save: eax = %d\n", task->context.gpr.eax.raw);
    task->context.nr.raw = stack_ptr[8];
    debug("Test save: nr = %d\n", task->context.nr.raw);
    task->context.err.raw = stack_ptr[9];
    debug("Test save: err = %d\n", task->context.err.raw);
    task->context.eip.raw = stack_ptr[10];
    debug("Test save: eip = %d\n", task->context.eip.raw);
    task->context.cs.raw = stack_ptr[11];
    debug("Test save: cs = %d\n", task->context.cs.raw);
    task->context.eflags.raw = stack_ptr[12];
    debug("Test save: eflags = %d\n", task->context.eflags.raw);
    task->context.esp.raw = stack_ptr[13];
    debug("Test save: esp = %d\n", task->context.esp.raw);
    debug("Test save: ss  = %d\n", task->context.ss.raw);
    task->kernel_stack = stack_ptr[14];
    debug("Test save: kernel stack = %d\n", stack_ptr[17]);

}

void int32_handler(int_ctx_t* ctx)
{
    asm volatile ("pusha");
    debug("\n\n\n\n");
    debug("Int32 handler\n");
    debug("esp: %lx\n", ctx->gpr.esp);
    if (ctx->gpr.esp.raw < 0x800000){
        debug("La tache interrompue est une tache noyau\n");
    } else {
        debug("La tache interrompue est une tache utilisateur\n");
        uint32_t * stack_ptr = (uint32_t *) ctx->esp.raw;
        debug ("stack content: %x\n", *stack_ptr);
        save_task(stack_ptr, current);

        //puis switch task au prochain
        switch_to_task(current);
    }

}




//=============================================================================

void init_IDT()
{
    // idt_reg_t idt_r;
    // get_idtr(idt_r);
    // int_desc_t *bp_dsc = &idt_r.desc[32];

    // bp_dsc->offset_1 = (uint16_t)((uint32_t)int32_handler);
    // bp_dsc->offset_2 = (uint16_t)(((uint32_t)int32_handler)>>16);

}

void show_cr3()
{
   cr3_reg_t cr3 = {.raw = get_cr3()};
   debug("CR3 = %p\n", cr3.raw);
}


void enable_paging()
{
   uint32_t cr0 = get_cr0();
   set_cr0(cr0|CR0_PG);
}

void paging_init()
{
   int      i;
   pde32_t *pgd = (pde32_t*)0x600000; //PGD
   pte32_t *ptb1 = (pte32_t*)0x601000;  //0
   pte32_t *ptb2 = (pte32_t*)0x602000;  //0x400000
   pte32_t *ptb3 = (pte32_t*)0x603000;  //0x800000
   pte32_t *ptb4 = (pte32_t*)0x604000;  //0xc00000

   pde32_t *pgd_user1 = (pde32_t*)0x610000; //PGD de user1
   pde32_t *pgd_user2 = (pde32_t*)0x620000; //PGD de user2

    //================ map the kernel ===============
   for(i=0;i<1024;i++)
      pg_set_entry(&ptb1[i], PG_KRN|PG_RW, i);

   memset((void*)pgd, 0, PAGE_SIZE);
   pg_set_entry(&pgd[0], PG_KRN|PG_RW, page_nr(ptb1));

   memset((void*)pgd_user1, 0, PAGE_SIZE);
   pg_set_entry(&pgd_user1[0], PG_KRN|PG_RW, page_nr(ptb1));

   memset((void*)pgd_user2, 0, PAGE_SIZE);
   pg_set_entry(&pgd_user2[0], PG_KRN|PG_RW, page_nr(ptb1));


   //=============== map the PTBs============
   for(i=0;i<1024;i++)
      pg_set_entry(&ptb2[i], PG_KRN|PG_RW, i+1024);

   pg_set_entry(&pgd[1], PG_KRN|PG_RW, page_nr(ptb2));
   pg_set_entry(&pgd_user1[1], PG_KRN|PG_RW, page_nr(ptb2));
   pg_set_entry(&pgd_user2[1], PG_KRN|PG_RW, page_nr(ptb2));


// map the user1-memory section (from 0x800000)
   for(i=0;i<1024;i++)
      pg_set_entry(&ptb3[i], PG_USR|PG_RO, i+2*1024);

   pg_set_entry(&pgd_user1[2], PG_USR|PG_RW, page_nr(ptb3));


// map the user2-memory section (from 0xc00000)
    for(i=0;i<1024;i++)
      pg_set_entry(&ptb4[i], PG_USR|PG_RO, i+3*1024);

   pg_set_entry(&pgd_user2[3], PG_USR|PG_RW, page_nr(ptb4));

// stack addresses (the sp decrements addresses so these are the last)
// static uint32_t   ustack1 = 0x1001000 - 0x04; (range: 0 to  0x1001000 - 0x04)
// static uint32_t   ustack2 = 0x1402000 - 0x04; (range: 0x1401000 to  0x1402000 - 0x04)
// static uint32_t   user_kstack1 = 0x1004000 - 0x04; (range: 0x1003000 to  0x1404000 - 0x04)
// static uint32_t   user_kstack2 = 0x1406000 - 0x04; (range: 0x1405000 to  0x1406000 - 0x04)

   pte32_t *ptb_ustack1 = (pte32_t*)0x605000; //les stacks en 1000000
   pte32_t *ptb_ustack2 = (pte32_t*)0x606000; //les stacks en 1400000

   memset((void*)ptb_ustack1, 0, PAGE_SIZE);
   memset((void*)ptb_ustack2, 0, PAGE_SIZE);

   pg_set_entry(&ptb_ustack1[0], PG_USR|PG_RW, 0+4*1024); //ustack1 from 0 to 0x1001000 -0x04
   pg_set_entry(&ptb_ustack2[1], PG_USR|PG_RW, 1+4*1024); //ustack2

   pg_set_entry(&ptb_ustack1[3], PG_KRN|PG_RW, 3+4*1024); //user kstack1

   pg_set_entry(&ptb_ustack2[5], PG_KRN|PG_RW, 5+4*1024); //user kstack2

   pg_set_entry(&pgd_user1[4], PG_USR|PG_RW, page_nr(ptb_ustack1));
   pg_set_entry(&pgd_user2[5], PG_USR|PG_RW, page_nr(ptb_ustack2));

// set the physical address 0x1801000 to be the shared page (chosen arbitrarily)

   uint32_t *v1 = (uint32_t*)0x802000; //virtual address for user1 to the shared memory
   uint32_t *v2 = (uint32_t*)0xc02000; //virtual address for user2 to the shared memory

   int ptb_idx = pt32_idx(v1);
   pg_set_entry(&ptb3[ptb_idx], PG_USR|PG_RW, 0x1801); //read write for user1

   ptb_idx = pt32_idx(v2);
   pg_set_entry(&ptb4[ptb_idx], PG_USR|PG_RO, 0x1801); //read only for user2

// load the address of the PGD to CR3 and activate paging
   set_cr3((uint32_t)pgd);
   enable_paging();

}


void tp()
{
   uint32_t *v2 = (uint32_t*)0x1801000;
   *v2 = 0;

   init_user();
   init_IDT();
   paging_init();
   //enable interrupts
   asm volatile("sti; nop");

   debug("START task1\n");
   current = &task1;
   switch_to_task(&task1);
   while(1);
}

/* per 28.12.2018
Le code de user1 demarre l execution et incremente le contenu du compteur.
Apres quelques increments, le noyau redemarre... Meme quand je
n enable pas les interruptions--- C est curieux.
*/