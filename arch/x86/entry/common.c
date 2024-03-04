// SPDX-License-Identifier: GPL-2.0-only
/*
 * common.c - C code for kernel entry and exit
 * Copyright (c) 2015 Andrew Lutomirski
 *
 * Based on asm and ptrace code by many authors.  The code here originated
 * in ptrace.c and signal.c.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/entry-common.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/export.h>
#include <linux/nospec.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#ifdef CONFIG_XEN_PV
#include <xen/xen-ops.h>
#include <xen/events.h>
#endif

#include <asm/desc.h>
#include <asm/traps.h>
#include <asm/vdso.h>
#include <asm/cpufeature.h>
#include <asm/fpu/api.h>
#include <asm/nospec-branch.h>
#include <asm/io_bitmap.h>
#include <asm/syscall.h>
#include <asm/irq_stack.h>

#ifdef CONFIG_X86_64
#ifdef CONFIG_SAFEFETCH
#include <linux/safefetch.h>
#include <linux/region_allocator.h>
#include <linux/mem_range.h>
#include <linux/safefetch_static_keys.h>
#ifdef SAFEFETCH_WHITELISTING
#warning "Using DFCACHER whitelisting"
static noinline void should_whitelist(unsigned long syscall_nr){
    switch(syscall_nr){
		case __NR_futex:
		case __NR_execve:                       
		case __NR_writev:
		case __NR_pwritev2:
		case __NR_pwrite64:
		case __NR_write:
                                current->df_prot_struct_head.is_whitelisted = 1;
                                return;
    }
    current->df_prot_struct_head.is_whitelisted = 0;
}
#endif
#endif

__visible noinstr void do_syscall_64(unsigned long nr, struct pt_regs *regs)
{


        // If interrupts using current execute prior to the next syscall
        // then we will enter the syscall with the mem_range intialized
        // we could chose to clean this info (shrink_region) or simply 
        // trust that the interrupt doesn't fetch something nasty and just
        // operate the next syscall on the interrupt state (happens for
        // sigaction calls mostly during IPI's that save the signal frame
        // prior to executing a sigaction call). Or simply clear state
        // on irq end (might slow down irqs so avoid this). 
#if defined(CONFIG_SAFEFETCH)
       IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_hooks_key){
        if (unlikely(SAFEFETCH_MEM_RANGE_INIT_FLAG)){
             // An IPI probably sent us a signal and the signal
             // enabled the defense in interrupt context. Reset
             // dfcache interrupt state.
#ifndef SAFEFETCH_DEBUG
             // If in debug mode, we actually reset the range in
             // df_debug_syscall_entry.
             SAFEFETCH_RESET_MEM_RANGE(); 
#endif                        
             shrink_region(DF_CUR_STORAGE_REGION_ALLOCATOR);        
             shrink_region(DF_CUR_METADATA_REGION_ALLOCATOR);
        }
       }
#endif

#ifdef SAFEFETCH_MEASURE_DEFENSE
        // We only use this for measuring so execute this without the static key
        // else we get into nasty scenarios if we miss this initialization step.
        df_init_measure_structs(current);
#endif

	nr = syscall_enter_from_user_mode(regs, nr);
#if defined(CONFIG_SAFEFETCH) && defined(SAFEFETCH_WHITELISTING)
        should_whitelist(nr);
#endif



#if defined(CONFIG_SAFEFETCH) && defined(SAFEFETCH_DEBUG)
       IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_hooks_key){
          df_debug_syscall_entry(nr, regs);
       }
#endif


	instrumentation_begin();
	if (likely(nr < NR_syscalls)) {
		nr = array_index_nospec(nr, NR_syscalls);
		regs->ax = sys_call_table[nr](regs);
#ifdef CONFIG_X86_X32_ABI
	} else if (likely((nr & __X32_SYSCALL_BIT) &&
			  (nr & ~__X32_SYSCALL_BIT) < X32_NR_syscalls)) {
		nr = array_index_nospec(nr & ~__X32_SYSCALL_BIT,
					X32_NR_syscalls);
		regs->ax = x32_sys_call_table[nr](regs);
#endif
	}
	instrumentation_end();

       syscall_exit_to_user_mode(regs);

#ifdef CONFIG_SAFEFETCH
       // Note, we might have rseq regions executing in syscall_exit_to_user_mode
       // and irqs so delay resetting region after this.
      IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_hooks_key){
#ifdef SAFEFETCH_DEBUG
        df_debug_syscall_exit();
#endif
#ifdef SAFEFETCH_MEASURE_DEFENSE
        df_destroy_measure_structs();
#endif
        reset_regions();
      }
#endif
}
#endif

#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)
static __always_inline unsigned int syscall_32_enter(struct pt_regs *regs)
{
	if (IS_ENABLED(CONFIG_IA32_EMULATION))
		current_thread_info()->status |= TS_COMPAT;

	return (unsigned int)regs->orig_ax;
}

/*
 * Invoke a 32-bit syscall.  Called with IRQs on in CONTEXT_KERNEL.
 */
static __always_inline void do_syscall_32_irqs_on(struct pt_regs *regs,
						  unsigned int nr)
{
	if (likely(nr < IA32_NR_syscalls)) {
		nr = array_index_nospec(nr, IA32_NR_syscalls);
		regs->ax = ia32_sys_call_table[nr](regs);
	}
}

/* Handles int $0x80 */
__visible noinstr void do_int80_syscall_32(struct pt_regs *regs)
{
	unsigned int nr = syscall_32_enter(regs);

	/*
	 * Subtlety here: if ptrace pokes something larger than 2^32-1 into
	 * orig_ax, the unsigned int return value truncates it.  This may
	 * or may not be necessary, but it matches the old asm behavior.
	 */
	nr = (unsigned int)syscall_enter_from_user_mode(regs, nr);
	instrumentation_begin();

	do_syscall_32_irqs_on(regs, nr);

	instrumentation_end();
	syscall_exit_to_user_mode(regs);
}

static noinstr bool __do_fast_syscall_32(struct pt_regs *regs)
{
	unsigned int nr = syscall_32_enter(regs);
	int res;

	/*
	 * This cannot use syscall_enter_from_user_mode() as it has to
	 * fetch EBP before invoking any of the syscall entry work
	 * functions.
	 */
	syscall_enter_from_user_mode_prepare(regs);

	instrumentation_begin();
	/* Fetch EBP from where the vDSO stashed it. */
	if (IS_ENABLED(CONFIG_X86_64)) {
		/*
		 * Micro-optimization: the pointer we're following is
		 * explicitly 32 bits, so it can't be out of range.
		 */
		res = __get_user(*(u32 *)&regs->bp,
			 (u32 __user __force *)(unsigned long)(u32)regs->sp);
	} else {
		res = get_user(*(u32 *)&regs->bp,
		       (u32 __user __force *)(unsigned long)(u32)regs->sp);
	}

	if (res) {
		/* User code screwed up. */
		regs->ax = -EFAULT;

		instrumentation_end();
		syscall_exit_to_user_mode(regs);
		return false;
	}

	/* The case truncates any ptrace induced syscall nr > 2^32 -1 */
	nr = (unsigned int)syscall_enter_from_user_mode_work(regs, nr);

	/* Now this is just like a normal syscall. */
	do_syscall_32_irqs_on(regs, nr);

	instrumentation_end();
	syscall_exit_to_user_mode(regs);
	return true;
}

/* Returns 0 to return using IRET or 1 to return using SYSEXIT/SYSRETL. */
__visible noinstr long do_fast_syscall_32(struct pt_regs *regs)
{
	/*
	 * Called using the internal vDSO SYSENTER/SYSCALL32 calling
	 * convention.  Adjust regs so it looks like we entered using int80.
	 */
	unsigned long landing_pad = (unsigned long)current->mm->context.vdso +
					vdso_image_32.sym_int80_landing_pad;

	/*
	 * SYSENTER loses EIP, and even SYSCALL32 needs us to skip forward
	 * so that 'regs->ip -= 2' lands back on an int $0x80 instruction.
	 * Fix it up.
	 */
	regs->ip = landing_pad;

	/* Invoke the syscall. If it failed, keep it simple: use IRET. */
	if (!__do_fast_syscall_32(regs))
		return 0;

#ifdef CONFIG_X86_64
	/*
	 * Opportunistic SYSRETL: if possible, try to return using SYSRETL.
	 * SYSRETL is available on all 64-bit CPUs, so we don't need to
	 * bother with SYSEXIT.
	 *
	 * Unlike 64-bit opportunistic SYSRET, we can't check that CX == IP,
	 * because the ECX fixup above will ensure that this is essentially
	 * never the case.
	 */
	return regs->cs == __USER32_CS && regs->ss == __USER_DS &&
		regs->ip == landing_pad &&
		(regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF)) == 0;
#else
	/*
	 * Opportunistic SYSEXIT: if possible, try to return using SYSEXIT.
	 *
	 * Unlike 64-bit opportunistic SYSRET, we can't check that CX == IP,
	 * because the ECX fixup above will ensure that this is essentially
	 * never the case.
	 *
	 * We don't allow syscalls at all from VM86 mode, but we still
	 * need to check VM, because we might be returning from sys_vm86.
	 */
	return static_cpu_has(X86_FEATURE_SEP) &&
		regs->cs == __USER_CS && regs->ss == __USER_DS &&
		regs->ip == landing_pad &&
		(regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF | X86_EFLAGS_VM)) == 0;
#endif
}

/* Returns 0 to return using IRET or 1 to return using SYSEXIT/SYSRETL. */
__visible noinstr long do_SYSENTER_32(struct pt_regs *regs)
{
	/* SYSENTER loses RSP, but the vDSO saved it in RBP. */
	regs->sp = regs->bp;

	/* SYSENTER clobbers EFLAGS.IF.  Assume it was set in usermode. */
	regs->flags |= X86_EFLAGS_IF;

	return do_fast_syscall_32(regs);
}
#endif

SYSCALL_DEFINE0(ni_syscall)
{
	return -ENOSYS;
}

#ifdef CONFIG_XEN_PV
#ifndef CONFIG_PREEMPTION
/*
 * Some hypercalls issued by the toolstack can take many 10s of
 * seconds. Allow tasks running hypercalls via the privcmd driver to
 * be voluntarily preempted even if full kernel preemption is
 * disabled.
 *
 * Such preemptible hypercalls are bracketed by
 * xen_preemptible_hcall_begin() and xen_preemptible_hcall_end()
 * calls.
 */
DEFINE_PER_CPU(bool, xen_in_preemptible_hcall);
EXPORT_SYMBOL_GPL(xen_in_preemptible_hcall);

/*
 * In case of scheduling the flag must be cleared and restored after
 * returning from schedule as the task might move to a different CPU.
 */
static __always_inline bool get_and_clear_inhcall(void)
{
	bool inhcall = __this_cpu_read(xen_in_preemptible_hcall);

	__this_cpu_write(xen_in_preemptible_hcall, false);
	return inhcall;
}

static __always_inline void restore_inhcall(bool inhcall)
{
	__this_cpu_write(xen_in_preemptible_hcall, inhcall);
}
#else
static __always_inline bool get_and_clear_inhcall(void) { return false; }
static __always_inline void restore_inhcall(bool inhcall) { }
#endif

static void __xen_pv_evtchn_do_upcall(void)
{
	irq_enter_rcu();
	inc_irq_stat(irq_hv_callback_count);

	xen_hvm_evtchn_do_upcall();

	irq_exit_rcu();
}

__visible noinstr void xen_pv_evtchn_do_upcall(struct pt_regs *regs)
{
	struct pt_regs *old_regs;
	bool inhcall;
	irqentry_state_t state;

	state = irqentry_enter(regs);
	old_regs = set_irq_regs(regs);

	instrumentation_begin();
	run_on_irqstack_cond(__xen_pv_evtchn_do_upcall, regs);
	instrumentation_begin();

	set_irq_regs(old_regs);

	inhcall = get_and_clear_inhcall();
	if (inhcall && !WARN_ON_ONCE(state.exit_rcu)) {
		instrumentation_begin();
		irqentry_exit_cond_resched();
		instrumentation_end();
		restore_inhcall(inhcall);
	} else {
		irqentry_exit(regs, state);
	}
}
#endif /* CONFIG_XEN_PV */
