/*
 * Copyright IBM Corporation, 2017
 * Author Suraj Jitindar Singh <sjitindarsingh@gmail.com>
 *
 * Description: KVM functions specific to running nested KVM-HV guests
 * on Book3S processors (specifically POWER9 and later).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License or (at your optional) any later version of the license.
 */

#include <linux/kvm_host.h>

#include <asm/reg.h>
#include <asm/ppc-opcode.h>
#include <asm/disassemble.h>
#include <asm/kvm_ppc.h>
#include <asm/kvm_book3s_hv_nest.h>
#include <asm/book3s/64/mmu.h>

#undef DEBUG

void kvmppc_vcpu_nested_init(struct kvm_vcpu *vcpu)
{
	vcpu->arch.hdec_expires = (1ULL << 63) - 1; /* A big number... */
}

static struct kvm_arch_nested *kvmppc_find_nested(struct kvm *kvm,
						  int lpid)
{
	struct kvm_arch_nested *cur, *n;

	list_for_each_entry_safe(cur, n, &kvm->arch.nested, list) {
		if (cur->shadow_lpid == lpid) {
			return cur;
		}
	}

	return NULL;
}

/* Must be called with nested lock held */
static void kvmppc_setup_partition_table_nested(struct kvm_arch_nested *nested)
{
	unsigned long dw0, dw1;

	dw0 = PATB_HR | radix__get_tree_size() | __pa(nested->shadow_pgtable) |
	      RADIX_PGD_INDEX_SIZE;
	dw1 = PATB_GR | nested->process_table;

	WARN(!nested->lpid,
	     "KVM: Setting LPID 0 partition table entry in nest code\n");

	mmu_partition_table_set_entry(nested->lpid, dw0, dw1);
}

/* If nested != NULL -> must be called with nested->lock held */
static int kvmppc_find_update_process_table(struct kvm *kvm,
					    struct kvm_arch_nested *nested)
{
	u64 ptcr = kvm->arch.ptcr;
	struct patb_entry patbe;
	unsigned int lpid;
	u64 patb0, patb1;
	int rc;

	lpid = nested ? nested->shadow_lpid : 0;

	/* Check partition table big enough to contain that lpid entry */
	if ((lpid * sizeof(patbe)) >= (1 << ((ptcr & PATS_MASK) + 12))) {
		return -EINVAL;
	}
	/* Read the partition table entry from guest memory */
	rc = kvm_read_guest(kvm, (ptcr & PATB_MASK) +
				 (lpid * sizeof(patbe)),
			    &patbe, sizeof(patbe));
	if (rc < 0) {
		pr_err("KVM: Unable to access guest partition table\n");
		return rc;
	}
	patb0 = be64_to_cpu(patbe.patb0);
	patb1 = be64_to_cpu(patbe.patb1);
	/* If the guest doesn't think it's radix we're a bit stuffed */
	if (!(patb0 & PATB_HR)) {
		pr_err("KVM: Invalid entry in guest partition table\n");
		return -EINVAL;
	}
	/* Process table size field must be reasonable, i.e. <= 24 */
	if ((patb1 & PRTS_MASK) > 24) {
		pr_err("KVM: Invalid entry in guest partition table\n");
		return -EINVAL;
	}

	if (lpid) {
		nested->process_table = patb1;
		if (nested->lpid) {
			/*
			 * Have we allocated an lpid for this nested guest yet?
			 * If not then the partition table setup will be done
			 * when allocating the lpid.
			 */
			kvmppc_setup_partition_table_nested(nested);
		}
	} else {
		if (patb1) {
			struct prtb_entry prtbe;

			rc = kvm_read_guest(kvm, (patb1 & PRTB_MASK),
					    &prtbe, sizeof(prtbe));
			if (rc < 0) {
				pr_err("KVM: Unable to access guest process table\n");
				return -EINVAL;
			}
			/*
			 * Partition scoped translation for lpid 0 is provided
			 * for the sole purpose of translating the address of
			 * process table entries to remove the requirement for
			 * the process table to be in contiguous memory. We
			 * don't support that case and so expect to find the
			 * guest kernels linear mapping, the same as should be
			 * in the guests process table entry for pid 0. If
			 * these don't point to the same radix tree then
			 * there's not much we can do -> print an error message
			 */
			if ((be64_to_cpu(prtbe.prtb0) & RPDB_MASK) !=
			    (patb0 & RPDB_MASK)) {
				pr_err("KVM: Unable to handle guest process table translation\n");
				return -EINVAL;
			}
		}

		kvm->arch.process_table = patb1;
		kvmppc_setup_partition_table(kvm);
	}

#ifdef DEBUG
	pr_info("%s: lpid: %d, process table: 0x%.16llx\n", __func__, lpid,
		patb1);
#endif
	return 0;
}

static inline int get_ric(unsigned int instr)
{
	return (instr >> 18) & 0x3;
}

static inline int get_prs(unsigned int instr)
{
	return (instr >> 17) & 0x1;
}

static inline int get_r(unsigned int instr)
{
	return (instr >> 16) & 0x1;
}

static inline int get_lpid(unsigned long r_val)
{
	return r_val & 0xffffffff;
}

static inline int get_is(unsigned long r_val)
{
	return (r_val >> 10) & 0x3;
}

static inline int get_ap(unsigned long r_val)
{
	return (r_val >> 5) & 0x7;
}

static inline long get_epn(unsigned long r_val)
{
	return r_val >> 12;
}

static int kvmppc_emulate_priv_tlbie(struct kvm_vcpu *vcpu, unsigned int instr)
{
	int rc = 0;
	int rs, rb;
	int ric, prs, r, is, ap = 0;
	int lpid;
	long epn = 0;

	rs = get_rs(instr);
	rb = get_rb(instr);

	ric = get_ric(instr);
	prs = get_prs(instr);
	r = get_r(instr);
	lpid = get_lpid(vcpu->arch.gpr[rs]);
	is = get_is(vcpu->arch.gpr[rb]);
	if (!is) {
		epn = get_epn(vcpu->arch.gpr[rb]);
		ap = get_ap(vcpu->arch.gpr[rb]);
	}

#ifdef DEBUG
	pr_info("%s: lpid: %d ric: %d prs: %d r: %d is: %d epn: 0x%.16lx ap: %d\n",
		__func__, lpid, ric, prs, r, is, epn, ap);
#endif

	/*
	 * These cases should have resulted in a machine check.
	 * prs == 1 -> Not HV privileged -> Shouldn't have caused interrupt
	 * ric == 3 -> No cluster bombs for radix
	 * (!is) && (ric == 1 || ric == 2) -> Not Supported by ISA
	 * is == 1 -> Partition scoped translations not associated with pid
	 */
	if (prs || (ric == 3) || ((!is) && (ric == 1 || ric == 2)) || (is == 1)) {
		WARN(1, "KVM: Invalid tlbie instruction form\n");
		return EMULATE_FAIL;
	}

	switch (is) {
	case 0: /* Invalidate target address TLB entry (we know ric == 0) */
		/* XXX TODO */
		return EMULATE_FAIL;
	case 2:	/* Invalidate matching lpid */
		switch (ric) {
		case 2:
			/*
			 * Invalidate caching of partition table entries ->
			 * DW0 -> Not cached (looked up when needed)
			 * DW1 -> Guest process table location (stored in the
			 * parition table) may have changed -> zero it so it
			 * gets looked up again on guest entry. OR go and find
			 * it now for LPID 0.
			 */
			if (lpid) {
				struct kvm_arch_nested *nested;
				nested = kvmppc_find_nested(vcpu->kvm, lpid);

				if (nested) {
					mutex_lock(&nested->lock);
					nested->process_table = 0ULL;
					mutex_unlock(&nested->lock);
				}
			} else {
				rc = kvmppc_find_update_process_table(vcpu->kvm,
								      NULL);
				if (rc) {
					return EMULATE_FAIL;
				}
			}
		case 0:
			/*
			 * Invalidate TLB -> invalidate our shadow page table
			 * Note: No shadow page table for lpid == 0
			 */
			if (lpid) {
				struct kvm_arch_nested *nested;
				nested = kvmppc_find_nested(vcpu->kvm, lpid);

				/* Nothing to do if haven't alloced pgtable */
				if (nested && nested->shadow_pgtable) {
					/* XXX TODO */
					return EMULATE_FAIL;
				}
			}
		case 1:
			/*
			 * Invalidate Page Walk Cache
			 * Currently we don't perform any caching of the page
			 * walk itself, just the resulting translation which
			 * would also have needed to be invalidated (with a tlb
			 * invalidation) if it had changed (and thus would have
			 * been handled in one of the above two cases)
			 * -> thus nothing to do
			 */
			break;
		default:
			break;
		}
		break;
	case 3: /* Invalidate all entries */
		/* XXX TODO */
		return EMULATE_FAIL;
	default:
		return EMULATE_FAIL;
	}

	return EMULATE_DONE;
}

static int kvmppc_emulate_priv_mtspr(struct kvm_run *run, struct kvm_vcpu *vcpu,
				     unsigned int instr)
{
	int rs, sprn, rc = EMULATE_FAIL;
	long val;

	rs = get_rs(instr);
	sprn = get_sprn(instr);
	val = vcpu->arch.gpr[rs];

	switch (sprn) {
	case SPRN_DPDES:
		vcpu->arch.hv_regs.nested_dpdes = val & 0x1UL;
		rc = EMULATE_DONE;
		break;
	case SPRN_DAWR:
		vcpu->arch.hv_regs.dawr.val = val;
		vcpu->arch.hv_regs.dawr.inited = 1;
		rc = EMULATE_DONE;
		break;
	case SPRN_RPR:
		/* XXX TODO */
		break;
	case SPRN_CIABR:
		if ((val & CIABR_PRIV) != CIABR_PRIV_HYPER) {
			/* Guest can't set hypervisor state matching */
			vcpu->arch.hv_regs.ciabr.val = val;
			vcpu->arch.hv_regs.ciabr.inited = 1;
		}
		rc = EMULATE_DONE;
		break;
	case SPRN_DAWRX:
		if (!(val & DAWRX_HYP)) {
			/* Guest can't set hypervisor state matching */
			vcpu->arch.hv_regs.dawrx.val = val;
			vcpu->arch.hv_regs.dawrx.inited = 1;
		}
		rc = EMULATE_DONE;
		break;
	case SPRN_HFSCR:
		{
			/* Facility enable/disable is HFSCR[55:0] */
			ulong mask = (1ULL << 56) - 1;

			/* Don't allow enabling disabled facilities */
			val = (vcpu->arch.hfscr & mask & val) | (~mask & val);

			vcpu->arch.hv_regs.hfscr.val = val;
			vcpu->arch.hv_regs.hfscr.inited = 1;
			rc = EMULATE_DONE;
			break;
		}
	case SPRN_TBWL:
	case SPRN_TBWU:
		/* XXX TODO */
		break;
	case SPRN_TBU40:
		/*
		 * Update the tb offset in the vcore accordingly
		 * Can do this since on P9 there is only 1 thread per vcore
		 */
		vcpu->arch.vcore->tb_offset = ALIGN(val - mftb(), 1UL << 24);
		rc = EMULATE_DONE;
		break;
	case SPRN_HSPRG0:
		vcpu->arch.hv_regs.hsprg0 = val;
		rc = EMULATE_DONE;
		break;
	case SPRN_HSPRG1:
		vcpu->arch.hv_regs.hsprg1 = val;
		rc = EMULATE_DONE;
		break;
	case SPRN_HDSISR:
	case SPRN_HDAR:
		/* XXX TODO */
		break;
	case SPRN_SPURR:
		vcpu->arch.spurr = val;
		rc = EMULATE_DONE;
		break;
	case SPRN_PURR:
		vcpu->arch.purr = val;
		rc = EMULATE_DONE;
		break;
	case SPRN_HDEC:
		vcpu->arch.hdec_expires = val + mftb();
		rc = EMULATE_DONE;
		break;
	case SPRN_HRMOR:
		/* XXX TODO */
		break;
	case SPRN_HSRR0:
		vcpu->arch.hv_regs.hsrr0 = val;
		rc = EMULATE_DONE;
		break;
	case SPRN_HSRR1:
		/* XXX TODO */
		break;
	case SPRN_LPCR:
		{
			u64 mask = kvmppc_get_lpcr_mask();

			if (!(val & LPCR_HR)) {
				/* We only support radix nested guests */
				pr_err("KVM: nested HV running hpt guest\n");
				break;
			}

			/* Only use userspace settable bits of lpcr */
			vcpu->arch.hv_regs.lpcr.val = vcpu->arch.vcore->lpcr
						      & ~mask;
			vcpu->arch.hv_regs.lpcr.val |= (mask & val);
			vcpu->arch.hv_regs.lpcr.inited = 1;
			rc = EMULATE_DONE;
			break;
		}
	case SPRN_LPID:
		vcpu->arch.shadow_lpid = val;
		rc = EMULATE_DONE;
		break;
	case SPRN_HMER:
	case SPRN_HMEER:
		/* XXX TODO */
		break;
	case SPRN_PCR:
		/* Don't allow enabling disabled facilities */
		vcpu->arch.hv_regs.pcr.val = val | vcpu->arch.vcore->pcr;
		vcpu->arch.hv_regs.pcr.inited = 1;
		rc = EMULATE_DONE;
		break;
	case SPRN_HEIR:
		/* XXX TODO */
		break;
	case SPRN_AMOR:
		/* The guest can reduce permissions, but can't add them */
		vcpu->arch.hv_regs.amor.val = val & vcpu->arch.amor;
		vcpu->arch.hv_regs.amor.inited = 1;
		rc = EMULATE_DONE;
		break;
	case SPRN_PTCR:
		vcpu->kvm->arch.ptcr = val;
		rc = EMULATE_DONE;
		break;
	case SPRN_ASDR:
		/* XXX TODO */
		break;
	case SPRN_IC:
		vcpu->arch.ic = val;
		rc = EMULATE_DONE;
		break;
	case SPRN_VTB:
		/* Can do this since on P9 there is only 1 thread per vcore */
		vcpu->arch.vcore->vtb = val;
		rc = EMULATE_DONE;
		break;
	case SPRN_PSSCR:
		vcpu->arch.psscr = val & PSSCR_GUEST_VIS;
		rc = EMULATE_DONE;
		break;
	default:
		break;
	}

#ifdef DEBUG
	if (rc == EMULATE_FAIL)
		pr_info("%s: mtspr %d,0x%.16lx\n", __func__, sprn, vcpu->arch.gpr[rs]);
#endif

	return rc;
}

static int kvmppc_emulate_priv_mfspr(struct kvm_run *run, struct kvm_vcpu *vcpu,
				     unsigned int instr)
{
	int rt, sprn, rc = EMULATE_FAIL;
	ulong *val;

	rt = get_rt(instr);
	sprn = get_sprn(instr);
	val = &vcpu->arch.gpr[rt];

	switch (sprn) {
	case SPRN_DAWR:
		*val = vcpu->arch.hv_regs.dawr.inited ?
		       vcpu->arch.hv_regs.dawr.val : vcpu->arch.dawr;
		rc = EMULATE_DONE;
		break;
	case SPRN_RPR:
		/* XXX TODO */
		break;
	case SPRN_CIABR:
		*val = vcpu->arch.hv_regs.ciabr.inited ?
		       vcpu->arch.hv_regs.ciabr.val : vcpu->arch.ciabr;
		rc = EMULATE_DONE;
		break;
	case SPRN_DAWRX:
		*val = vcpu->arch.hv_regs.dawrx.inited ?
		       vcpu->arch.hv_regs.dawrx.val : vcpu->arch.dawrx;
		rc = EMULATE_DONE;
		break;
	case SPRN_HFSCR:
		*val = vcpu->arch.hv_regs.hfscr.inited ?
		       vcpu->arch.hv_regs.hfscr.val : vcpu->arch.hfscr;
		rc = EMULATE_DONE;
		break;
	case SPRN_HSPRG0:
		*val = vcpu->arch.hv_regs.hsprg0;
		rc = EMULATE_DONE;
		break;
	case SPRN_HSPRG1:
		*val = vcpu->arch.hv_regs.hsprg1;
		rc = EMULATE_DONE;
		break;
	case SPRN_HDSISR:
	case SPRN_HDAR:
		/* XXX TODO */
		break;
	case SPRN_HDEC:
		*val = vcpu->arch.hdec_expires - mftb();
		rc = EMULATE_DONE;
		break;
	case SPRN_HRMOR:
		/* XXX TODO */
		break;
	case SPRN_HSRR0:
		*val = vcpu->arch.hv_regs.hsrr0;
		rc = EMULATE_DONE;
		break;
	case SPRN_HSRR1:
		/* XXX TODO */
		break;
	case SPRN_LPCR:
		*val = vcpu->arch.hv_regs.lpcr.inited ?
		       vcpu->arch.hv_regs.lpcr.val : vcpu->arch.vcore->lpcr;
		rc = EMULATE_DONE;
		break;
	case SPRN_LPID:
		*val = vcpu->arch.shadow_lpid;
		rc = EMULATE_DONE;
		break;
	case SPRN_HMER:
	case SPRN_HMEER:
		/* XXX TODO */
		break;
	case SPRN_PCR:
		*val = vcpu->arch.hv_regs.pcr.inited ?
		       vcpu->arch.hv_regs.pcr.val : vcpu->arch.vcore->pcr;
		rc = EMULATE_DONE;
		break;
	case SPRN_HEIR:
		/* XXX TODO */
		break;
	case SPRN_AMOR:
		*val = vcpu->arch.hv_regs.amor.inited ?
		       vcpu->arch.hv_regs.amor.val : vcpu->arch.amor;
		rc = EMULATE_DONE;
		break;
	case SPRN_PTCR:
		*val = vcpu->kvm->arch.ptcr;
		rc = EMULATE_DONE;
		break;
	case SPRN_ASDR:
		/* XXX TODO */
		break;
	case SPRN_PSSCR:
		*val = vcpu->arch.psscr & PSSCR_GUEST_VIS;
		rc = EMULATE_DONE;
		break;
	default:
		break;
	}

#ifdef DEBUG
	if (rc == EMULATE_FAIL)
		pr_info("%s: mfspr %d\n", __func__, sprn);
#endif

	return rc;
}

static int kvmppc_emulate_priv_op_31(struct kvm_run *run, struct kvm_vcpu *vcpu,
				     unsigned int instr)
{
	int rc = EMULATE_FAIL;

	switch (get_xop(instr)) {
	case OP_31_XOP_MSGSND:
	case OP_31_XOP_MSGCLR:
		/* XXX TODO */
		break;
	case OP_31_XOP_TLBIE:
		rc = kvmppc_emulate_priv_tlbie(vcpu, instr);
		break;
	case OP_31_XOP_LWZCIX:
	case OP_31_XOP_LHZCIX:
	case OP_31_XOP_LBZCIX:
	case OP_31_XOP_LDCIX:
	case OP_31_XOP_STWCIX:
	case OP_31_XOP_STHCIX:
	case OP_31_XOP_STBCIX:
	case OP_31_XOP_STDCIX:
		/* XXX TODO */
		break;
	case OP_31_XOP_TLBSYNC:
		/* XXX TODO - ONLY HV when GTSE == 0 */
		break;
	case OP_31_XOP_MSGSYNC:
		/* XXX TODO */
		break;
	default:
		break;
	}

#ifdef DEBUG
	if (rc == EMULATE_FAIL)
		pr_info("%s: op_31: 0x%.8x\n", __func__, get_xop(instr));
#endif

	return rc;
}

static int kvmppc_emulate_priv_op(struct kvm_run *run, struct kvm_vcpu *vcpu,
				  unsigned int instr)
{
	int rc = EMULATE_FAIL;

	switch (instr) {
	case PPC_INST_HRFID:
		/* XXX TODO */
		break;
	default:
		break;
	}

#ifdef DEBUG
	if (rc == EMULATE_FAIL)
		pr_info("%s: op: 0x%.8x\n", __func__, instr);
#endif

	return rc;
}

int kvmppc_emulate_priv(struct kvm_run *run, struct kvm_vcpu *vcpu,
			unsigned int instr)
{
	int rc = EMULATE_FAIL;

	switch (get_op(instr)) {
	case 31:
		switch (get_xop(instr)) {
		case OP_31_XOP_MTSPR:
			rc = kvmppc_emulate_priv_mtspr(run, vcpu, instr);
			break;
		case OP_31_XOP_MFSPR:
			rc = kvmppc_emulate_priv_mfspr(run, vcpu, instr);
			break;
		default:
			rc = kvmppc_emulate_priv_op_31(run, vcpu, instr);
			break;
		}

		if (rc == EMULATE_DONE) {
			vcpu->arch.pc += 4;
		}
		break;
	default:
		rc = kvmppc_emulate_priv_op(run, vcpu, instr);
		break;
	}

	return rc;
}

int kvmppc_handle_trap_nested(struct kvm_run *run, struct kvm_vcpu *vcpu,
			      struct task_struct *tsk)
{
	int rc = RESUME_HOST;

#ifdef DEBUG
	pr_info_ratelimited("KVM: Nested trap 0x%x\n", vcpu->arch.trap);
#endif

	switch (vcpu->arch.trap) {
	case BOOK3S_INTERRUPT_HV_DECREMENTER:
		/*
		 * Either the L0 host HDEC expired - we're good on these,
		 * or the L1 guest HDEC expired, in which case we need to inject
		 * an HDEC interrupt to that guest.
		 */
		{
			u64 tb = mftb();

			if (vcpu->arch.hdec_expires <= tb) {
				/* Inject HDEC to guest */
				/* XXX TODO */
			} else {
				vcpu->stat.dec_exits++;
			}
			rc = RESUME_GUEST;
			break;
		}
	case BOOK3S_INTERRUPT_SYSCALL:
	case BOOK3S_INTERRUPT_H_DATA_STORAGE:
	case BOOK3S_INTERRUPT_H_INST_STORAGE:
	case BOOK3S_INTERRUPT_H_DOORBELL:
	case BOOK3S_INTERRUPT_H_VIRT:
	case BOOK3S_INTERRUPT_SYSTEM_RESET:
	case BOOK3S_INTERRUPT_MACHINE_CHECK:
	case BOOK3S_INTERRUPT_EXTERNAL:
	case BOOK3S_INTERRUPT_PROGRAM:
	case BOOK3S_INTERRUPT_H_EMUL_ASSIST:
	case BOOK3S_INTERRUPT_HMI:
	case BOOK3S_INTERRUPT_PERFMON:
	case BOOK3S_INTERRUPT_H_FAC_UNAVAIL:
	case BOOK3S_INTERRUPT_HV_RM_HARD:
		/* XXX TODO */
	default:
		printk(KERN_EMERG "KVM: Unhandled trap in nested guest\n");
		kvmppc_dump_regs(vcpu);
		printk(KERN_EMERG "trap=0x%x | pc=0x%lx | msr=0x%llx\n",
		       vcpu->arch.trap, kvmppc_get_pc(vcpu),
		       vcpu->arch.shregs.msr);
		printk(KERN_EMERG "emul_inst=0x%x\n", vcpu->arch.emul_inst);
		run->hw.hardware_exit_reason = vcpu->arch.trap;
		rc = RESUME_HOST;
		break;
	}

	return rc;
}

void kvmppc_init_vm_hv_nest(struct kvm *kvm)
{
	INIT_LIST_HEAD(&kvm->arch.nested);
}

void kvmppc_destroy_vm_hv_nest(struct kvm *kvm)
{
}
