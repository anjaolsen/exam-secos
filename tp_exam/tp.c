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

void user1()
{
   while(1);
}

void user2()
{
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
//    uint32_t   ustack = 0x600000;

   get_idtr(idtr);
   dsc = &idtr.desc[48];
   dsc->dpl = 3;

   // 3: install kernel syscall handler
   dsc->offset_1 = (uint16_t)((uint32_t)syscall_isr);
   dsc->offset_2 = (uint16_t)(((uint32_t)syscall_isr)>>16);

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

    ///3.5: aligner la pile et avoir le bon esp. 
    asm volatile ("popa; leave ; iret");
}

void int32_trigger() 
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


void tp()
{
   init_user();
   init_IDT();
   int32_trigger();
}
