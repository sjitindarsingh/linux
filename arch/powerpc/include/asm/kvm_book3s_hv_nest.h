/*
 * Copyright IBM Corporation, 2017
 * Author Suraj Jitindar Singh <sjitindarsingh@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License or (at your optional) any later version of the license.
 *
 */

#ifndef __POWERPC_KVM_BOOK3S_HV_NEST_H__
#define __POWERPC_KVM_BOOK3S_HV_NEST_H__

#ifdef CONFIG_KVM_BOOK3S_HV_NEST_POSSIBLE

struct hv_reg {
	ulong val;
	bool inited;
};

/* Registers required to run a nested hypervisor */
struct kvm_arch_nested_hv_regs {
	ulong nested_dpdes;
	/* HV registers we purely emulate */
	ulong hsprg0;
	ulong hsprg1;
	ulong hdsisr;
	ulong hdar;
	ulong hsrr0;
	ulong hsrr1;
	ulong asdr;
	/*
	 * HV registers we only use the nested value of when actually entering
	 * the nested guest because they'd modify L1 behaviour if updated
	 * immediately.
	 */
	struct hv_reg dawr;
	struct hv_reg ciabr;
	struct hv_reg dawrx;
	struct hv_reg hfscr;
	struct hv_reg lpcr;
	struct hv_reg pcr;
	struct hv_reg amor;
};

struct kvm_arch_nested {
	struct list_head list;
	struct mutex lock;		/* Lock against modifying the state */
	unsigned int running_vcpus;	/* number of vcpus running this guest */
	unsigned int lpid;              /* real lpid of this nested guest */
	unsigned int host_lpid;         /* lpid of top level L1 guest */
	unsigned int shadow_lpid;       /* lpid L1 guest thinks this guest is */
	pgd_t *shadow_pgtable;          /* our page table for this guest */
	u64 process_table;              /* process table entry for this guest */
};

/*
 * Used to store the reverse mappings of nested guest real addresses
 * The unsigned long rmap value in the memslot->arch is used to store a pointer
 * to a struct list_head of one of these.
 */
struct kvm_nest_rmap {
	struct list_head list;
	unsigned int lpid;
	unsigned long pfn;
	unsigned long nest_gpa;
	unsigned long npages;
};

#define KVMPPC_NEST_RMAP_LOCK_BIT	0
#define KVMPPC_NEST_RMAP_LOCK_MASK	~(1UL << KVMPPC_NEST_RMAP_LOCK_BIT)

static inline void lock_rmap_nest(unsigned long *rmap)
{
	do {
		while (test_bit(KVMPPC_NEST_RMAP_LOCK_BIT, rmap))
			cpu_relax();
	} while (test_and_set_bit_lock(KVMPPC_NEST_RMAP_LOCK_BIT, rmap));
}

static inline void unlock_rmap_nest(unsigned long *rmap)
{
	 __clear_bit_unlock(KVMPPC_NEST_RMAP_LOCK_BIT, rmap);
}

static inline struct list_head *get_rmap_nest(unsigned long *rmap)
{
	unsigned long val;

	val = *rmap & KVMPPC_NEST_RMAP_LOCK_MASK;

	return (struct list_head *) val;
}

static inline void set_rmap_nest(unsigned long *rmap, struct list_head *val)
{
	*rmap &= ~KVMPPC_NEST_RMAP_LOCK_MASK;
	*rmap |= (((unsigned long) val) & KVMPPC_NEST_RMAP_LOCK_MASK);
}

int kvmppc_insert_nest_rmap_entry(unsigned long *rmap,
				  struct kvm_nest_rmap *rmap_entry);
unsigned long kvmppc_radix_remove_nest_pte(struct kvm *kvm, pte_t *ptep,
					   unsigned long addr,
					   unsigned int shift,
					   unsigned int lpid);
void kvmppc_clear_nest_rmap(struct kvm *kvm,
			    struct kvm_memory_slot *memslot,
			    unsigned long base_gfn,
			    unsigned long npages);
void kvmppc_clear_all_nest_rmap(struct kvm *kvm,
				struct kvm_memory_slot *memslot);
void kvmppc_vcpu_nested_init(struct kvm_vcpu *vcpu);
int kvmppc_emulate_priv(struct kvm_run *run, struct kvm_vcpu *vcpu,
			unsigned int instr);
void kvmppc_exit_nested(struct kvm_vcpu *vcpu);
int kvmppc_can_deliver_hv_int(struct kvm_vcpu *vcpu, int vec);
void kvmppc_inject_hv_interrupt(struct kvm_vcpu *vcpu, int vec, u64 flags);
int kvmppc_book3s_radix_page_fault_nested(struct kvm_run *run,
					  struct kvm_vcpu *vcpu,
					  unsigned long ea,
					  unsigned long dsisr);
int kvmppc_handle_trap_nested(struct kvm_run *run, struct kvm_vcpu *vcpu,
			      struct task_struct *tsk);
void kvmppc_init_vm_hv_nest(struct kvm *kvm);
void kvmppc_destroy_vm_hv_nest(struct kvm *kvm);

#else /* CONFIG_KVM_BOOK3S_HV_NEST_POSSIBLE */

static inline int kvmppc_can_deliver_hv_int(struct kvm_vcpu *vcpu, int vec)
{
	WARN(1, "KVM: hv_int 0x%x queued but no nested guest support", vec);
	kvmppc_book3s_dequeue_irqprio(vcpu, vec);
	return 0;
}

static inline void kvmppc_inject_hv_interrupt(struct kvm_vcpu *vcpu, int vec,
					      u64 flags)
{
	WARN_ON(1);
	kvmppc_book3s_dequeue_irqprio(vcpu, vec);
}

#endif /* CONFIG_KVM_BOOK3S_HV_NEST_POSSIBLE */

#endif /* __POWERPC_KVM_BOOK3S_HV_NEST_H__ */
