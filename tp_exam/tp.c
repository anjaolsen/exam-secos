/* GPLv2 (c) Airbus */

// Ting som fortsatt må gjøres
// - lage flere PGD
// - sette ting i RO i pgd (alt er RW nå)
// - fikse sånn at handleren min blir kalt
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

static int incr = 0;

//userstacks a partir de 0x1000000 - 1 page de 4ko chacune
static uint32_t   ustack1 = 0x1001000;
static uint32_t   ustack2 = 0x1002000; //0x 100000 = 16^5 = 1M , 0x001000 = 4k
// static uint32_t   user_kstack1 = 0x1003000;
// static uint32_t   user_kstack2 = 0x1004000;

//note: this is not finished... I don t know quite how to implement this yet. 
void sys_counter(uint32_t *counter)
{
//    debug("sys_counter\n");
   debug("Counter: %d\n", *counter);
    asm volatile (
      "leave ; pusha        \n"
      "mov %esp, %eax      \n"
      "call sys_counter_kernel \n"
      "popa ; iret"
      );
}

//note: this is not finished... I don t know quite how to implement this yet. 
void __regparm__(1) sys_counter_kernel(int_ctx_t *ctx)
{
  //utiliser qqch de ctx???
   debug("print syscall: %s", ctx->gpr.esi);
}

// note: 0x802000 = virtual address for user1 to the shared memory
void __attribute__ ((section(".user1"),aligned(PAGE_SIZE))) user1()
{
   debug("user1\n");
   uint32_t *v1 = (uint32_t*)0x802000;
   *v1 += 1;
   while(1);
}

// note: 0xc02000 = virtual address for user2 to the shared memory
void __attribute__ ((section(".user2"),aligned(PAGE_SIZE))) user2()
{
   debug("user2\n");
   uint32_t *v2 = (uint32_t*)0xc02000;
   sys_counter(v2);
//    asm volatile("cli"); // this privileged instruction causes a GPF, as we are in usermode
   while(1);
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
   dsc = &idtr.desc[0x80];
   dsc->dpl = 3;

   // 3: install kernel syscall handler
   dsc->offset_1 = (uint16_t)((uint32_t)sys_counter);
   dsc->offset_2 = (uint16_t)(((uint32_t)sys_counter)>>16);
 
// mettre les choses pertinentes dans les piles noyaux, comme si ils avaient deja ete
// interrompues par une interruption par exemple. 
// flags
// cs
// eip <---esp
//    user_kstack1

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
void int32_handler(int_ctx_t* ctx) 
{
    asm volatile ("pusha");
    debug("\n\n\n\n");
    debug("Int32 handler\n");
    debug("esp: %lx\n", ctx->gpr.esp);
    if (ctx->gpr.esp.raw < 0x1001000){
        debug("La tache interrompue est une tache noyau\n");
    } else {
        debug("La tache interrompue est une tache utilisateur\n");
    }

    //========== 
    // ce bout de code est ce que j`ai fait pour l`instant pour savoir si on a interrompu
    // le kernel ou le user. Mon idee est de regarder la valeur du esp ou cs qui ont ete empiles
    //
    // asm volatile ("mov 48(%eax), %esp"); //ne marche pas.... 
    // debug("Var: %x", var);

    // idea to find out what privilege level we came from: pop/read cs (here: esp+12*4) 
    // 
    // and see what privilege level it was...
    // le nombre 12 a ete trouve avec gdb : esp a avance de 12 apres avoir epmile cs.

    //=========================================

    if (incr == 0){
        //display number
        debug("Display\n");
        incr = 1;
        // set_cr3((uint32_t)0x610000);
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

// 3
void enable_paging()
{
   uint32_t cr0 = get_cr0();
   set_cr0(cr0|CR0_PG);
}

void identity_init()
{
   int      i;
   pde32_t *pgd = (pde32_t*)0x600000; //PGD
   pte32_t *ptb1 = (pte32_t*)0x601000;  //0
   pte32_t *ptb2 = (pte32_t*)0x602000;  //0x400000
   pte32_t *ptb3 = (pte32_t*)0x603000;  //0x800000
   pte32_t *ptb4 = (pte32_t*)0x604000;  //0xc00000
   pte32_t *ptb5 = (pte32_t*)0x605000; //0x1000000

///====================paging user1=======================
//    pde32_t *pdg_user1 = (pde32_t*)0x610000; //PGD de user1
//    pte32_t *ptb_user1 = (pte32_t*)0x611000; //pour mapper kernel (mettre dans pdg_user1[2])
//    pte32_t *ptb2_user1 = (pte32_t*)0x612000;

//    pde32_t *pdg_user2 = (pde32_t*)0x613000; //PGD de user1
//    pte32_t *ptb_user2 = (pte32_t*)0x614000; //pour mapper user1 (mettre dans pdg_user1[2])


//===========paging normal============
   // 4
   for(i=0;i<1024;i++)
      pg_set_entry(&ptb1[i], PG_USR|PG_RW, i);

   memset((void*)pgd, 0, PAGE_SIZE);
   pg_set_entry(&pgd[0], PG_USR|PG_RW, page_nr(ptb1));

   // 6: il faut mapper les PTBs également
   
   for(i=0;i<1024;i++)
      pg_set_entry(&ptb2[i], PG_KRN|PG_RW, i+1024);

   pg_set_entry(&pgd[1], PG_KRN|PG_RW, page_nr(ptb2));

//  mapper les fonctions user1 et user2
// TODO: mettre la page en user et read only (comme c est du code)

//============================================
// questions: droit des PTB/PGD
// comment acceder depuis userland ???
//============================================

// map the user1-memory section (from 0x800000)
   for(i=0;i<1024;i++)
      pg_set_entry(&ptb3[i], PG_USR|PG_RO, i+2*1024);

   pg_set_entry(&pgd[2], PG_USR|PG_RW, page_nr(ptb3));


// map the user2-memory section (from 0xc00000)
    for(i=0;i<1024;i++)
      pg_set_entry(&ptb4[i], PG_USR|PG_RO, i+3*1024);

   pg_set_entry(&pgd[3], PG_USR|PG_RW, page_nr(ptb4));

// user data (user stacks) (from 0x1000000)
   for(i=0;i<1024;i++)
      pg_set_entry(&ptb5[i], PG_USR|PG_RW, i+4*1024);

   pg_set_entry(&pgd[4], PG_USR|PG_RW, page_nr(ptb5));

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

   // 5: #PF car l'adresse virtuelle 0x700000 n'est pas mappée
   debug("kernel: á partir de PTB[0] = %p\n", ptb1[0].raw);
   debug("PGD/PTB: a partir dePTB2[0] = %p\n", ptb2[0].raw);
   debug("memory section user1 PTB3[0] = %p\n", ptb3[0].raw);
   debug("memory section user2 PTB4[1] = %p\n", ptb4[0].raw);
   debug("Adresse user1 = %p\n", &user1);

}



void tp()
{
   init_user();
   init_IDT();
   //enable interrupts
   identity_init();
   asm volatile("sti"); 
//    int32_trigger();
   while(1);
}
