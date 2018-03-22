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
	ulong hsrr0;
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

void kvmppc_vcpu_nested_init(struct kvm_vcpu *vcpu);
int kvmppc_emulate_priv(struct kvm_run *run, struct kvm_vcpu *vcpu,
			unsigned int instr);
int kvmppc_handle_trap_nested(struct kvm_run *run, struct kvm_vcpu *vcpu,
			      struct task_struct *tsk);
void kvmppc_init_vm_hv_nest(struct kvm *kvm);
void kvmppc_destroy_vm_hv_nest(struct kvm *kvm);

#endif /* CONFIG_KVM_BOOK3S_HV_NEST_POSSIBLE */

#endif /* __POWERPC_KVM_BOOK3S_HV_NEST_H__ */
