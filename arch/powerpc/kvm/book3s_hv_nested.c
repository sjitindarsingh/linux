// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Corporation, 2018
 * Authors Suraj Jitindar Singh <sjitindarsingh@gmail.com>
 *	   Paul Mackerras <paulus@ozlabs.org>
 *
 * Description: KVM functions specific to running nested KVM-HV guests
 * on Book3S processors (specifically POWER9 and later).
 */

#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/llist.h>

#include <asm/kvm_ppc.h>
#include <asm/kvm_book3s.h>
#include <asm/mmu.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/pte-walk.h>
#include <asm/reg.h>

static struct patb_entry *pseries_partition_tb;

static void kvmhv_update_ptbl_cache(struct kvm_nested_guest *gp);
static void kvmhv_remove_all_nested_rmap_lpid(struct kvm *kvm, int lpid);
static void kvmhv_free_memslot_nest_rmap(struct kvm_memory_slot *free);

void kvmhv_save_hv_regs(struct kvm_vcpu *vcpu, struct hv_guest_state *hr)
{
	struct kvmppc_vcore *vc = vcpu->arch.vcore;

	hr->pcr = vc->pcr;
	hr->dpdes = vc->dpdes;
	hr->hfscr = vcpu->arch.hfscr;
	hr->tb_offset = vc->tb_offset;
	hr->dawr0 = vcpu->arch.dawr;
	hr->dawrx0 = vcpu->arch.dawrx;
	hr->ciabr = vcpu->arch.ciabr;
	hr->purr = vcpu->arch.purr;
	hr->spurr = vcpu->arch.spurr;
	hr->ic = vcpu->arch.ic;
	hr->vtb = vc->vtb;
	hr->srr0 = vcpu->arch.shregs.srr0;
	hr->srr1 = vcpu->arch.shregs.srr1;
	hr->sprg[0] = vcpu->arch.shregs.sprg0;
	hr->sprg[1] = vcpu->arch.shregs.sprg1;
	hr->sprg[2] = vcpu->arch.shregs.sprg2;
	hr->sprg[3] = vcpu->arch.shregs.sprg3;
	hr->pidr = vcpu->arch.pid;
	hr->cfar = vcpu->arch.cfar;
	hr->ppr = vcpu->arch.ppr;
}

void kvmhv_save_guest_slb(struct kvm_vcpu *vcpu, struct guest_slb *slbp)
{
	int i;

	for (i = 0; i < 64; i++)
		slbp->slb[i] = vcpu->arch.slb[i];
	slbp->slb_max = vcpu->arch.slb_max;
	slbp->slb_nr = vcpu->arch.slb_nr;
}

static void byteswap_pt_regs(struct pt_regs *regs)
{
	unsigned long *addr = (unsigned long *) regs;

	for (; addr < ((unsigned long *) (regs + 1)); addr++)
		*addr = swab64(*addr);
}

static void byteswap_hv_regs(struct hv_guest_state *hr)
{
	hr->version = swab64(hr->version);
	hr->lpid = swab32(hr->lpid);
	hr->vcpu_token = swab32(hr->vcpu_token);
	hr->lpcr = swab64(hr->lpcr);
	hr->pcr = swab64(hr->pcr);
	hr->amor = swab64(hr->amor);
	hr->dpdes = swab64(hr->dpdes);
	hr->hfscr = swab64(hr->hfscr);
	hr->tb_offset = swab64(hr->tb_offset);
	hr->dawr0 = swab64(hr->dawr0);
	hr->dawrx0 = swab64(hr->dawrx0);
	hr->ciabr = swab64(hr->ciabr);
	hr->hdec_expiry = swab64(hr->hdec_expiry);
	hr->purr = swab64(hr->purr);
	hr->spurr = swab64(hr->spurr);
	hr->ic = swab64(hr->ic);
	hr->vtb = swab64(hr->vtb);
	hr->hdar = swab64(hr->hdar);
	hr->hdsisr = swab64(hr->hdsisr);
	hr->heir = swab64(hr->heir);
	hr->asdr = swab64(hr->asdr);
	hr->srr0 = swab64(hr->srr0);
	hr->srr1 = swab64(hr->srr1);
	hr->sprg[0] = swab64(hr->sprg[0]);
	hr->sprg[1] = swab64(hr->sprg[1]);
	hr->sprg[2] = swab64(hr->sprg[2]);
	hr->sprg[3] = swab64(hr->sprg[3]);
	hr->pidr = swab64(hr->pidr);
	hr->cfar = swab64(hr->cfar);
	hr->ppr = swab64(hr->ppr);
}

static void byteswap_guest_slb(struct guest_slb *slbp)
{
	int i;

	for (i = 0; i < 64; i++) {
		slbp->slb[i].esid = swab64(slbp->slb[i].esid);
		slbp->slb[i].vsid = swab64(slbp->slb[i].vsid);
		slbp->slb[i].orige = swab64(slbp->slb[i].orige);
		slbp->slb[i].origv = swab64(slbp->slb[i].origv);
		slbp->slb[i].valid = swab32(slbp->slb[i].valid);
		slbp->slb[i].Ks = swab32(slbp->slb[i].Ks);
		slbp->slb[i].Kp = swab32(slbp->slb[i].Kp);
		slbp->slb[i].nx = swab32(slbp->slb[i].nx);
		slbp->slb[i].large = swab32(slbp->slb[i].large);
		slbp->slb[i].tb = swab32(slbp->slb[i].tb);
		slbp->slb[i].class = swab32(slbp->slb[i].class);
		/* base_page_size is u8 thus no need to byteswap */
	}
	slbp->slb_max = swab64(slbp->slb_max);
	slbp->slb_nr = swab64(slbp->slb_nr);
}

static void save_hv_return_state(struct kvm_vcpu *vcpu, int trap,
				 struct hv_guest_state *hr)
{
	struct kvmppc_vcore *vc = vcpu->arch.vcore;

	hr->dpdes = vc->dpdes;
	hr->hfscr = vcpu->arch.hfscr;
	hr->purr = vcpu->arch.purr;
	hr->spurr = vcpu->arch.spurr;
	hr->ic = vcpu->arch.ic;
	hr->vtb = vc->vtb;
	hr->srr0 = vcpu->arch.shregs.srr0;
	hr->srr1 = vcpu->arch.shregs.srr1;
	hr->sprg[0] = vcpu->arch.shregs.sprg0;
	hr->sprg[1] = vcpu->arch.shregs.sprg1;
	hr->sprg[2] = vcpu->arch.shregs.sprg2;
	hr->sprg[3] = vcpu->arch.shregs.sprg3;
	hr->pidr = vcpu->arch.pid;
	hr->cfar = vcpu->arch.cfar;
	hr->ppr = vcpu->arch.ppr;
	switch (trap) {
	case BOOK3S_INTERRUPT_H_DATA_STORAGE:
		hr->hdar = vcpu->arch.fault_dar;
		hr->hdsisr = vcpu->arch.fault_dsisr;
		hr->asdr = vcpu->arch.fault_gpa;
		break;
	case BOOK3S_INTERRUPT_H_INST_STORAGE:
		hr->asdr = vcpu->arch.fault_gpa;
		break;
	case BOOK3S_INTERRUPT_H_EMUL_ASSIST:
		hr->heir = vcpu->arch.emul_inst;
		break;
	}
}

static void sanitise_hv_regs(struct kvm_vcpu *vcpu, struct hv_guest_state *hr)
{
	/*
	 * Don't let L1 enable features for L2 which we've disabled for L1,
	 * but preserve the interrupt cause field.
	 */
	hr->hfscr &= (HFSCR_INTR_CAUSE | vcpu->arch.hfscr);

	/* Don't let data address watchpoint match in hypervisor state */
	hr->dawrx0 &= ~DAWRX_HYP;

	/* Don't let completed instruction address breakpt match in HV state */
	if ((hr->ciabr & CIABR_PRIV) == CIABR_PRIV_HYPER)
		hr->ciabr &= ~CIABR_PRIV;
}

static void restore_hv_regs(struct kvm_vcpu *vcpu, struct hv_guest_state *hr)
{
	struct kvmppc_vcore *vc = vcpu->arch.vcore;

	vc->pcr = hr->pcr;
	vc->dpdes = hr->dpdes;
	vcpu->arch.hfscr = hr->hfscr;
	vcpu->arch.dawr = hr->dawr0;
	vcpu->arch.dawrx = hr->dawrx0;
	vcpu->arch.ciabr = hr->ciabr;
	vcpu->arch.purr = hr->purr;
	vcpu->arch.spurr = hr->spurr;
	vcpu->arch.ic = hr->ic;
	vc->vtb = hr->vtb;
	vcpu->arch.shregs.srr0 = hr->srr0;
	vcpu->arch.shregs.srr1 = hr->srr1;
	vcpu->arch.shregs.sprg0 = hr->sprg[0];
	vcpu->arch.shregs.sprg1 = hr->sprg[1];
	vcpu->arch.shregs.sprg2 = hr->sprg[2];
	vcpu->arch.shregs.sprg3 = hr->sprg[3];
	vcpu->arch.pid = hr->pidr;
	vcpu->arch.cfar = hr->cfar;
	vcpu->arch.ppr = hr->ppr;
}

void kvmhv_restore_guest_slb(struct kvm_vcpu *vcpu, struct guest_slb *slbp)
{
	int i;

	for (i = 0; i < 64; i++)
		vcpu->arch.slb[i] = slbp->slb[i];
	vcpu->arch.slb_max = slbp->slb_max;
	vcpu->arch.slb_nr = slbp->slb_nr;
}

void kvmhv_restore_hv_return_state(struct kvm_vcpu *vcpu,
				   struct hv_guest_state *hr)
{
	struct kvmppc_vcore *vc = vcpu->arch.vcore;

	vc->dpdes = hr->dpdes;
	vcpu->arch.hfscr = hr->hfscr;
	vcpu->arch.purr = hr->purr;
	vcpu->arch.spurr = hr->spurr;
	vcpu->arch.ic = hr->ic;
	vc->vtb = hr->vtb;
	vcpu->arch.fault_dar = hr->hdar;
	vcpu->arch.fault_dsisr = hr->hdsisr;
	vcpu->arch.fault_gpa = hr->asdr;
	vcpu->arch.emul_inst = hr->heir;
	vcpu->arch.shregs.srr0 = hr->srr0;
	vcpu->arch.shregs.srr1 = hr->srr1;
	vcpu->arch.shregs.sprg0 = hr->sprg[0];
	vcpu->arch.shregs.sprg1 = hr->sprg[1];
	vcpu->arch.shregs.sprg2 = hr->sprg[2];
	vcpu->arch.shregs.sprg3 = hr->sprg[3];
	vcpu->arch.pid = hr->pidr;
	vcpu->arch.cfar = hr->cfar;
	vcpu->arch.ppr = hr->ppr;
}

static void kvmhv_nested_mmio_needed(struct kvm_vcpu *vcpu, u64 regs_ptr)
{
	/* No need to reflect the page fault to L1, we've handled it */
	vcpu->arch.trap = 0;

	/*
	 * Since the L2 gprs have already been written back into L1 memory when
	 * we complete the mmio, store the L1 memory location of the L2 gpr
	 * being loaded into by the mmio so that the loaded value can be
	 * written there in kvmppc_complete_mmio_load()
	 */
	if (((vcpu->arch.io_gpr & KVM_MMIO_REG_EXT_MASK) == KVM_MMIO_REG_GPR)
	    && (vcpu->mmio_is_write == 0)) {
		vcpu->arch.nested_io_gpr = (gpa_t) regs_ptr +
					   offsetof(struct pt_regs,
						    gpr[vcpu->arch.io_gpr]);
		vcpu->arch.io_gpr = KVM_MMIO_REG_NESTED_GPR;
	}
}

static void kvmhv_update_intr_msr(struct kvm_vcpu *vcpu, unsigned long lpcr)
{
	if (lpcr & LPCR_ILE)
		vcpu->arch.intr_msr |= MSR_LE;
	else
		vcpu->arch.intr_msr &= ~MSR_LE;
}

long kvmhv_enter_nested_guest(struct kvm_vcpu *vcpu)
{
	long int err, r, ret = H_SUCCESS;
	struct kvm_nested_guest *l2;
	struct pt_regs l2_regs, saved_l1_regs;
	struct hv_guest_state l2_hv, saved_l1_hv;
	struct guest_slb *l2_slb = NULL, *saved_l1_slb = NULL;
	struct kvmppc_vcore *vc = vcpu->arch.vcore;
	u64 hv_ptr, regs_ptr, slb_ptr = 0UL;
	s64 delta_purr, delta_spurr, delta_ic, delta_vtb;
	u64 mask;
	unsigned long lpcr;
	u8 radix;

	if (vcpu->kvm->arch.l1_ptcr == 0)
		return H_NOT_AVAILABLE;

	/* copy parameters in */
	hv_ptr = kvmppc_get_gpr(vcpu, 4);
	err = kvm_vcpu_read_guest(vcpu, hv_ptr, &l2_hv,
				  sizeof(struct hv_guest_state));
	if (err)
		return H_PARAMETER;
	if (kvmppc_need_byteswap(vcpu))
		byteswap_hv_regs(&l2_hv);
	/* Do we support the guest version of the argument structures */
	if ((l2_hv.version > HV_GUEST_STATE_MAX_VERSION) ||
			(l2_hv.version < HV_GUEST_STATE_MIN_VERSION))
		return H_P2;

	regs_ptr = kvmppc_get_gpr(vcpu, 5);
	err = kvm_vcpu_read_guest(vcpu, regs_ptr, &l2_regs,
				  sizeof(struct pt_regs));
	if (err)
		return H_PARAMETER;
	if (kvmppc_need_byteswap(vcpu))
		byteswap_pt_regs(&l2_regs);
	if (l2_hv.vcpu_token >= NR_CPUS)
		return H_PARAMETER;

	/* translate lpid */
	l2 = kvmhv_get_nested(vcpu->kvm, l2_hv.lpid, true);
	if (!l2)
		return H_PARAMETER;
	if (!l2->l1_gr_to_hr) {
		mutex_lock(&l2->tlb_lock);
		kvmhv_update_ptbl_cache(l2);
		mutex_unlock(&l2->tlb_lock);
	}

	mutex_lock(&l2->tlb_lock);
	radix = l2->radix;
	mutex_unlock(&l2->tlb_lock);
	/* some lpcr sanity checking */
	if (radix) {
		/* radix requires gtse and uprt */
		if ((~l2_hv.lpcr & LPCR_HR) || (~l2_hv.lpcr & LPCR_GTSE) ||
					       (~l2_hv.lpcr & LPCR_UPRT) ||
					       (l2_hv.lpcr & LPCR_VPM1))
			return H_PARAMETER;
	} else {
		/* must be at least V2 to support hpt guest */
		if (l2_hv.version < 2)
			return H_PARAMETER;
		/* hpt doesn't support gtse or uprt and required vpm */
		if ((l2_hv.lpcr & LPCR_HR) || (l2_hv.lpcr & LPCR_GTSE) ||
					      (l2_hv.lpcr & LPCR_UPRT) ||
					      (~l2_hv.lpcr & LPCR_VPM1))
			return H_PARAMETER;
	}

	/* save l1 values of things */
	vcpu->arch.regs.msr = vcpu->arch.shregs.msr;
	saved_l1_regs = vcpu->arch.regs;
	kvmhv_save_hv_regs(vcpu, &saved_l1_hv);
	/* if running hpt then context switch the slb in the vcpu struct */
	if (!radix) {
		slb_ptr = kvmppc_get_gpr(vcpu, 6);
		l2_slb = kzalloc(sizeof(*l2_slb), GFP_KERNEL);
		saved_l1_slb = kzalloc(sizeof(*saved_l1_slb), GFP_KERNEL);

		if ((!l2_slb) || (!saved_l1_slb)) {
			ret = H_HARDWARE;
			goto out_free;
		}
		err = kvm_vcpu_read_guest(vcpu, slb_ptr, l2_slb,
					  sizeof(struct guest_slb));
		if (err) {
			ret = H_PARAMETER;
			goto out_free;
		}
		if (kvmppc_need_byteswap(vcpu))
			byteswap_guest_slb(l2_slb);
		kvmhv_save_guest_slb(vcpu, saved_l1_slb);
	}

	/* convert TB values/offsets to host (L0) values */
	vcpu->arch.hdec_exp = l2_hv.hdec_expiry - vc->tb_offset;
	vc->tb_offset += l2_hv.tb_offset;

	/* set L1 state to L2 state */
	vcpu->arch.nested = l2;
	vcpu->arch.nested_vcpu_id = l2_hv.vcpu_token;
	vcpu->arch.regs = l2_regs;
	vcpu->arch.shregs.msr = vcpu->arch.regs.msr;
	mask = LPCR_DPFD | LPCR_ILE | LPCR_TC | LPCR_AIL | LPCR_LD |
		LPCR_LPES | LPCR_MER | LPCR_HR | LPCR_GTSE | LPCR_UPRT |
		LPCR_VPM1;
	lpcr = (vc->lpcr & ~mask) | (l2_hv.lpcr & mask);
	kvmhv_update_intr_msr(vcpu, lpcr);
	sanitise_hv_regs(vcpu, &l2_hv);
	restore_hv_regs(vcpu, &l2_hv);
	if (!radix)
		kvmhv_restore_guest_slb(vcpu, l2_slb);

	vcpu->arch.ret = RESUME_GUEST;
	vcpu->arch.trap = 0;
	do {
		if (mftb() >= vcpu->arch.hdec_exp) {
			vcpu->arch.trap = BOOK3S_INTERRUPT_HV_DECREMENTER;
			r = RESUME_HOST;
			break;
		}
		/* update vcpu->arch.lpcr in case a previous loop modified it */
		vcpu->arch.lpcr = lpcr;
		if (radix)
			r = kvmhv_run_single_vcpu(vcpu->arch.kvm_run, vcpu);
		else
			r = kvmppc_run_vcpu(vcpu->arch.kvm_run, vcpu);
	} while (is_kvmppc_resume_guest(r));

	/* save L2 state for return */
	l2_regs = vcpu->arch.regs;
	l2_regs.msr = vcpu->arch.shregs.msr;
	delta_purr = vcpu->arch.purr - l2_hv.purr;
	delta_spurr = vcpu->arch.spurr - l2_hv.spurr;
	delta_ic = vcpu->arch.ic - l2_hv.ic;
	delta_vtb = vc->vtb - l2_hv.vtb;
	save_hv_return_state(vcpu, vcpu->arch.trap, &l2_hv);
	if (!radix)
		kvmhv_save_guest_slb(vcpu, l2_slb);

	/* restore L1 state */
	vcpu->arch.nested = NULL;
	vcpu->arch.regs = saved_l1_regs;
	vcpu->arch.shregs.msr = saved_l1_regs.msr & ~MSR_TS_MASK;
	/* set L1 MSR TS field according to L2 transaction state */
	if (l2_regs.msr & MSR_TS_MASK)
		vcpu->arch.shregs.msr |= MSR_TS_S;
	vc->tb_offset = saved_l1_hv.tb_offset;
	restore_hv_regs(vcpu, &saved_l1_hv);
	kvmhv_update_intr_msr(vcpu, vc->lpcr);
	if (!radix)
		kvmhv_restore_guest_slb(vcpu, saved_l1_slb);
	vcpu->arch.purr += delta_purr;
	vcpu->arch.spurr += delta_spurr;
	vcpu->arch.ic += delta_ic;
	vc->vtb += delta_vtb;

	kvmhv_put_nested(l2);

	/* copy l2_hv_state and regs back to guest */
	if (kvmppc_need_byteswap(vcpu)) {
		if (!radix)
			byteswap_guest_slb(l2_slb);
		byteswap_hv_regs(&l2_hv);
		byteswap_pt_regs(&l2_regs);
	}
	if (!radix) {
		err = kvm_vcpu_write_guest(vcpu, slb_ptr, l2_slb,
					   sizeof(struct guest_slb));
		if (err) {
			ret = H_AUTHORITY;
			goto out_free;
		}
		kfree(l2_slb);
		kfree(saved_l1_slb);
	}
	err = kvm_vcpu_write_guest(vcpu, hv_ptr, &l2_hv,
				   sizeof(struct hv_guest_state));
	if (err)
		return H_AUTHORITY;
	err = kvm_vcpu_write_guest(vcpu, regs_ptr, &l2_regs,
				   sizeof(struct pt_regs));
	if (err)
		return H_AUTHORITY;

	if (r == -EINTR)
		return H_INTERRUPT;

	if (vcpu->mmio_needed) {
		kvmhv_nested_mmio_needed(vcpu, regs_ptr);
		return H_TOO_HARD;
	}

	return vcpu->arch.trap;

out_free:
	kfree(l2_slb);
	kfree(saved_l1_slb);
	return ret;
}

long kvmhv_nested_init(void)
{
	long int ptb_order;
	unsigned long ptcr;
	long rc;

	if (!kvmhv_on_pseries())
		return 0;
	if (!radix_enabled())
		return -ENODEV;

	/* find log base 2 of KVMPPC_NR_LPIDS, rounding up */
	ptb_order = __ilog2(KVMPPC_NR_LPIDS - 1) + 1;
	if (ptb_order < 8)
		ptb_order = 8;
	pseries_partition_tb = kmalloc(sizeof(struct patb_entry) << ptb_order,
				       GFP_KERNEL);
	if (!pseries_partition_tb) {
		pr_err("kvm-hv: failed to allocated nested partition table\n");
		return -ENOMEM;
	}

	ptcr = __pa(pseries_partition_tb) | (ptb_order - 8);
	rc = plpar_hcall_norets(H_SET_PARTITION_TABLE, ptcr);
	if (rc != H_SUCCESS) {
		pr_err("kvm-hv: Parent hypervisor does not support nesting (rc=%ld)\n",
		       rc);
		kfree(pseries_partition_tb);
		pseries_partition_tb = NULL;
		return -ENODEV;
	}

	return 0;
}

void kvmhv_nested_exit(void)
{
	/*
	 * N.B. the kvmhv_on_pseries() test is there because it enables
	 * the compiler to remove the call to plpar_hcall_norets()
	 * when CONFIG_PPC_PSERIES=n.
	 */
	if (kvmhv_on_pseries() && pseries_partition_tb) {
		plpar_hcall_norets(H_SET_PARTITION_TABLE, 0);
		kfree(pseries_partition_tb);
		pseries_partition_tb = NULL;
	}
}

/*
 * Flushes the partition scoped translations of a given lpid.
 */
static void kvmhv_flush_lpid(unsigned int lpid, bool radix)
{
	long rc;

	if (!kvmhv_on_pseries()) {
		if (radix) {
			radix__flush_tlb_lpid(lpid);
		} else {
			asm volatile("ptesync": : :"memory");
			asm volatile(PPC_TLBIE_5(%0,%1,2,0,0) : :
				     "r" (TLBIEL_INVAL_SET_LPID), "r" (lpid));
			asm volatile("eieio; tlbsync; ptesync": : :"memory");
		}
		return;
	}

	rc = plpar_hcall_norets(H_TLB_INVALIDATE, H_TLBIE_P1_ENC(2, 0, radix),
				lpid, TLBIEL_INVAL_SET_LPID);
	if (rc)
		pr_err("KVM: TLB LPID invalidation hcall failed, rc=%ld\n", rc);
}

void kvmhv_set_ptbl_entry(unsigned int lpid, u64 dw0, u64 dw1)
{
	bool radix;

	if (!kvmhv_on_pseries()) {
		mmu_partition_table_set_entry(lpid, dw0, dw1);
		return;
	}

	/* radix flag based on old entry */
	radix = !!(be64_to_cpu(pseries_partition_tb[lpid].patb0) & PATB_HR);
	pseries_partition_tb[lpid].patb0 = cpu_to_be64(dw0);
	pseries_partition_tb[lpid].patb1 = cpu_to_be64(dw1);
	/* L0 will do the necessary barriers */
	kvmhv_flush_lpid(lpid, radix);
}

static inline int kvmhv_patb_get_hpt_order(u64 patb0)
{
	return (patb0 & PATB_HTABSIZE) + 18;
}

static inline u64 kvmhv_patb_get_htab_size(int order)
{
	return (order - 18) & PATB_HTABSIZE;
}

static void kvmhv_set_nested_ptbl(struct kvm_nested_guest *gp)
{
	unsigned long dw0;

	if (gp->radix) {
		dw0 = PATB_HR | radix__get_tree_size() |
			__pa(gp->shadow_pgtable) | RADIX_PGD_INDEX_SIZE;
	} else {
		dw0 = (PATB_HTABORG & __pa(gp->shadow_hpt.virt)) |
			(PATB_PS & gp->l1_gr_to_hr) |
			kvmhv_patb_get_htab_size(gp->shadow_hpt.order);
	}
	kvmhv_set_ptbl_entry(gp->shadow_lpid, dw0, gp->process_table);
}

void kvmhv_vm_nested_init(struct kvm *kvm)
{
	kvm->arch.max_nested_lpid = -1;
}

/*
 * Handle the H_SET_PARTITION_TABLE hcall.
 * r4 = guest real address of partition table + log_2(size) - 12
 * (formatted as for the PTCR).
 */
long kvmhv_set_partition_table(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned long ptcr = kvmppc_get_gpr(vcpu, 4);
	int srcu_idx;
	long ret = H_SUCCESS;

	srcu_idx = srcu_read_lock(&kvm->srcu);
	/*
	 * Limit the partition table to 4096 entries (because that's what
	 * hardware supports), and check the base address.
	 */
	if ((ptcr & PRTS_MASK) > 12 - 8 ||
	    !kvm_is_visible_gfn(vcpu->kvm, (ptcr & PRTB_MASK) >> PAGE_SHIFT))
		ret = H_PARAMETER;
	srcu_read_unlock(&kvm->srcu, srcu_idx);
	if (ret == H_SUCCESS)
		kvm->arch.l1_ptcr = ptcr;
	return ret;
}

/*
 * Handle the H_COPY_TOFROM_GUEST hcall.
 * r4 = L1 lpid of nested guest
 * r5 = pid
 * r6 = eaddr to access
 * r7 = to buffer (L1 gpa)
 * r8 = from buffer (L1 gpa)
 * r9 = n bytes to copy
 */
long kvmhv_copy_tofrom_guest_nested(struct kvm_vcpu *vcpu)
{
	struct kvm_nested_guest *gp;
	int l1_lpid = kvmppc_get_gpr(vcpu, 4);
	int pid = kvmppc_get_gpr(vcpu, 5);
	gva_t eaddr = kvmppc_get_gpr(vcpu, 6);
	gpa_t gp_to = (gpa_t) kvmppc_get_gpr(vcpu, 7);
	gpa_t gp_from = (gpa_t) kvmppc_get_gpr(vcpu, 8);
	void *buf;
	unsigned long n = kvmppc_get_gpr(vcpu, 9);
	bool is_load = !!gp_to;
	long rc;

	if (gp_to && gp_from) /* One must be NULL to determine the direction */
		return H_PARAMETER;

	if (eaddr & (0xFFFUL << 52))
		return H_PARAMETER;

	buf = kzalloc(n, GFP_KERNEL);
	if (!buf)
		return H_NO_MEM;

	gp = kvmhv_get_nested(vcpu->kvm, l1_lpid, false);
	if (!gp) {
		rc = H_PARAMETER;
		goto out_free;
	}

	mutex_lock(&gp->tlb_lock);

	if (!gp->radix) {
		/*
		 * Currently quadrants are the only way to read nested guest
		 * memory, which is only valid for a radix guest.
		 */
		rc = H_PARAMETER;
		goto out_unlock;
	}

	if (is_load) {
		/* Load from the nested guest into our buffer */
		rc = __kvmhv_copy_tofrom_guest_radix(gp->shadow_lpid, pid,
						     eaddr, buf, NULL, n);
		if (rc)
			goto not_found;

		/* Write what was loaded into our buffer back to the L1 guest */
		rc = kvm_vcpu_write_guest(vcpu, gp_to, buf, n);
		if (rc)
			goto not_found;
	} else {
		/* Load the data to be stored from the L1 guest into our buf */
		rc = kvm_vcpu_read_guest(vcpu, gp_from, buf, n);
		if (rc)
			goto not_found;

		/* Store from our buffer into the nested guest */
		rc = __kvmhv_copy_tofrom_guest_radix(gp->shadow_lpid, pid,
						     eaddr, NULL, buf, n);
		if (rc)
			goto not_found;
	}

out_unlock:
	mutex_unlock(&gp->tlb_lock);
	kvmhv_put_nested(gp);
out_free:
	kfree(buf);
	return rc;
not_found:
	rc = H_NOT_FOUND;
	goto out_unlock;
}

/* Caller must hold gp->tlb_lock */
static int kvmhv_switch_to_radix_nested(struct kvm_nested_guest *gp)
{
	struct kvm *kvm = gp->l1_host;
	pgd_t *pgtable;

	/* try to allocate a radix tree */
	pgtable = pgd_alloc(kvm->mm);
	if (!pgtable) {
		pr_err_ratelimited("KVM: Couldn't alloc nested radix tree\n");
		return -ENOMEM;
	}

	/* mmu_lock protects shadow_hpt & radix in nested guest struct */
	spin_lock(&kvm->mmu_lock);
	kvmppc_free_hpt(&gp->shadow_hpt);
	gp->radix = 1;
	gp->shadow_pgtable = pgtable;
	spin_unlock(&kvm->mmu_lock);

	/* remove all nested rmap entries and perform global invalidation */
	kvmhv_remove_all_nested_rmap_lpid(kvm, gp->l1_lpid);
	kvmhv_flush_lpid(gp->shadow_lpid, gp->radix);

	return 0;
}

/* Caller must hold gp->tlb_lock */
static int kvmhv_switch_to_hpt_nested(struct kvm_nested_guest *gp, int order)
{
	struct kvm *kvm = gp->l1_host;
	struct kvm_hpt_info info;
	int rc;

	/* try to allocate an hpt */
	rc = kvmppc_allocate_hpt(&info, order);
	if (rc) {
		pr_err_ratelimited("KVM: Couldn't alloc nested hpt\n");
		return rc;
	}

	/* mmu_lock protects shadow_pgtable & radix in nested guest struct */
	spin_lock(&kvm->mmu_lock);
	kvmppc_free_pgtable_radix(kvm, gp->shadow_pgtable, gp->shadow_lpid);
	pgd_free(kvm->mm, gp->shadow_pgtable);
	gp->shadow_pgtable = NULL;
	gp->radix = 0;
	gp->shadow_hpt = info;
	spin_unlock(&kvm->mmu_lock);

	/* remove all nested rmap entries and perform global invalidation */
	kvmhv_remove_all_nested_rmap_lpid(kvm, gp->l1_lpid);
	kvmhv_flush_lpid(gp->shadow_lpid, gp->radix);

	return 0;
}

static inline u64 kvmhv_patb_ps_to_slb_llp(u64 patb)
{
	return (((patb & PATB_PS_L) >> PATB_PS_L_SHIFT) << SLB_VSID_L_SHIFT) |
	       (((patb & PATB_PS_LP) >> PATB_PS_LP_SHIFT) << SLB_VSID_LP_SHIFT);
}

/*
 * Reload the partition table entry for a guest.
 * Caller must hold gp->tlb_lock.
 */
static void kvmhv_update_ptbl_cache(struct kvm_nested_guest *gp)
{
	int ret;
	struct patb_entry ptbl_entry;
	unsigned long ptbl_addr;
	struct kvm *kvm = gp->l1_host;

	gp->l1_gr_to_hr = 0;
	gp->process_table = 0;
	ret = -EFAULT;
	ptbl_addr = (kvm->arch.l1_ptcr & PRTB_MASK) + (gp->l1_lpid << 4);
	if (gp->l1_lpid < (1ul << ((kvm->arch.l1_ptcr & PRTS_MASK) + 8)))
		ret = kvm_read_guest(kvm, ptbl_addr,
				     &ptbl_entry, sizeof(ptbl_entry));
	if (!ret) {
		u64 patb0 = be64_to_cpu(ptbl_entry.patb0);
		u64 process_table = be64_to_cpu(ptbl_entry.patb1);

		if (patb0) {
			bool radix = !!(patb0 & PATB_HR);

			if (radix && !gp->radix)
				ret = kvmhv_switch_to_radix_nested(gp);
			else if (!radix && gp->radix)
				ret = kvmhv_switch_to_hpt_nested(gp,
					kvmhv_patb_get_hpt_order(patb0));
			if (!ret) {
				gp->l1_gr_to_hr = patb0;
				gp->process_table = process_table;
				if (!radix) { /* update vrma slb_v */
					u64 senc;

					senc = kvmhv_patb_ps_to_slb_llp(patb0);
					gp->vrma_slb_v = senc | SLB_VSID_B_1T |
						(VRMA_VSID << SLB_VSID_SHIFT_1T);
				}
			}
		}
	}
	kvmhv_set_nested_ptbl(gp);
}

struct kvm_nested_guest *kvmhv_alloc_nested(struct kvm *kvm, unsigned int lpid)
{
	/*
	 * Allocate the state for a nested guest.
	 * Note: assume radix to avoid allocating a hpt when not necessary as
	 * this can consume a large amount of contiguous memory in the host.
	 */
	struct kvm_nested_guest *gp;
	long shadow_lpid;

	gp = kzalloc(sizeof(*gp), GFP_KERNEL);
	if (!gp)
		return NULL;
	gp->l1_host = kvm;
	gp->l1_lpid = lpid;
	mutex_init(&gp->tlb_lock);
	gp->shadow_pgtable = pgd_alloc(kvm->mm);
	if (!gp->shadow_pgtable)
		goto out_free;
	shadow_lpid = kvmppc_alloc_lpid();
	if (shadow_lpid < 0)
		goto out_free2;
	gp->shadow_lpid = shadow_lpid;
	gp->radix = 1;

	memset(gp->prev_cpu, -1, sizeof(gp->prev_cpu));

	return gp;

 out_free2:
	pgd_free(kvm->mm, gp->shadow_pgtable);
 out_free:
	kfree(gp);
	return NULL;
}

/*
 * Free up any resources allocated for a nested guest.
 */
static void kvmhv_release_nested(struct kvm_nested_guest *gp)
{
	struct kvm *kvm = gp->l1_host;

	/*
	 * No vcpu is using this struct and no call to
	 * kvmhv_get_nested can find this struct,
	 * so we don't need to hold kvm->mmu_lock.
	 */
	if (gp->radix && gp->shadow_pgtable) {
		kvmppc_free_pgtable_radix(kvm, gp->shadow_pgtable,
					  gp->shadow_lpid);
		pgd_free(kvm->mm, gp->shadow_pgtable);
	} else if ((!gp->radix) && gp->shadow_hpt.virt) {
		kvmppc_free_hpt(&gp->shadow_hpt);
	}
	kvmhv_set_ptbl_entry(gp->shadow_lpid, 0, 0);
	kvmppc_free_lpid(gp->shadow_lpid);
	kfree(gp);
}

static void kvmhv_remove_nested(struct kvm_nested_guest *gp)
{
	struct kvm *kvm = gp->l1_host;
	int lpid = gp->l1_lpid;
	long ref;

	spin_lock(&kvm->mmu_lock);
	if (gp == kvm->arch.nested_guests[lpid]) {
		kvm->arch.nested_guests[lpid] = NULL;
		if (lpid == kvm->arch.max_nested_lpid) {
			while (--lpid >= 0 && !kvm->arch.nested_guests[lpid])
				;
			kvm->arch.max_nested_lpid = lpid;
		}
		--gp->refcnt;
	}
	ref = gp->refcnt;
	spin_unlock(&kvm->mmu_lock);
	if (ref == 0)
		kvmhv_release_nested(gp);
}

/*
 * Free up all nested resources allocated for this guest.
 * This is called with no vcpus of the guest running, when
 * switching the guest to HPT mode or when destroying the
 * guest.
 */
void kvmhv_release_all_nested(struct kvm *kvm)
{
	int i;
	struct kvm_nested_guest *gp;
	struct kvm_nested_guest *freelist = NULL;
	struct kvm_memory_slot *memslot;
	int srcu_idx;

	spin_lock(&kvm->mmu_lock);
	for (i = 0; i <= kvm->arch.max_nested_lpid; i++) {
		gp = kvm->arch.nested_guests[i];
		if (!gp)
			continue;
		kvm->arch.nested_guests[i] = NULL;
		if (--gp->refcnt == 0) {
			gp->next = freelist;
			freelist = gp;
		}
	}
	kvm->arch.max_nested_lpid = -1;
	spin_unlock(&kvm->mmu_lock);
	while ((gp = freelist) != NULL) {
		freelist = gp->next;
		kvmhv_release_nested(gp);
	}

	srcu_idx = srcu_read_lock(&kvm->srcu);
	kvm_for_each_memslot(memslot, kvm_memslots(kvm))
		kvmhv_free_memslot_nest_rmap(memslot);
	srcu_read_unlock(&kvm->srcu, srcu_idx);
}

/* caller must hold gp->tlb_lock */
static void kvmhv_flush_nested(struct kvm *kvm, struct kvm_nested_guest *gp,
			       bool invalidate_ptbl)
{
	/* Invalidate (zero) all entries in the shadow pgtable or shadow hpt */
	spin_lock(&kvm->mmu_lock);
	if (gp->radix) {
		kvmppc_free_pgtable_radix(kvm, gp->shadow_pgtable,
					  gp->shadow_lpid);
	} else {
		memset((void *) gp->shadow_hpt.virt, 0,
			1UL << gp->shadow_hpt.order);
		memset((void *) gp->shadow_hpt.rev, 0,
			(1UL << (gp->shadow_hpt.order - 4)) *
			sizeof(struct revmap_entry));
	}
	spin_unlock(&kvm->mmu_lock);
	/* remove all nested rmap entries and perform global invalidation */
	kvmhv_remove_all_nested_rmap_lpid(kvm, gp->l1_lpid);
	kvmhv_flush_lpid(gp->shadow_lpid, gp->radix);
	/* was caching of the partition table entries also invalidated? */
	if (invalidate_ptbl) {
		kvmhv_update_ptbl_cache(gp);
		if (gp->l1_gr_to_hr == 0)
			kvmhv_remove_nested(gp);
	}
}

struct kvm_nested_guest *kvmhv_get_nested(struct kvm *kvm, int l1_lpid,
					  bool create)
{
	struct kvm_nested_guest *gp, *newgp;

	if (l1_lpid >= KVM_MAX_NESTED_GUESTS ||
	    l1_lpid >= (1ul << ((kvm->arch.l1_ptcr & PRTS_MASK) + 12 - 4)))
		return NULL;

	spin_lock(&kvm->mmu_lock);
	gp = kvm->arch.nested_guests[l1_lpid];
	if (gp)
		++gp->refcnt;
	spin_unlock(&kvm->mmu_lock);

	if (gp || !create)
		return gp;

	newgp = kvmhv_alloc_nested(kvm, l1_lpid);
	if (!newgp)
		return NULL;
	spin_lock(&kvm->mmu_lock);
	if (kvm->arch.nested_guests[l1_lpid]) {
		/* someone else beat us to it */
		gp = kvm->arch.nested_guests[l1_lpid];
	} else {
		kvm->arch.nested_guests[l1_lpid] = newgp;
		++newgp->refcnt;
		gp = newgp;
		newgp = NULL;
		if (l1_lpid > kvm->arch.max_nested_lpid)
			kvm->arch.max_nested_lpid = l1_lpid;
	}
	++gp->refcnt;
	spin_unlock(&kvm->mmu_lock);

	if (newgp)
		kvmhv_release_nested(newgp);

	return gp;
}

void kvmhv_put_nested(struct kvm_nested_guest *gp)
{
	struct kvm *kvm = gp->l1_host;
	long ref;

	spin_lock(&kvm->mmu_lock);
	ref = --gp->refcnt;
	spin_unlock(&kvm->mmu_lock);
	if (ref == 0)
		kvmhv_release_nested(gp);
}

static struct kvm_nested_guest *kvmhv_find_nested(struct kvm *kvm, int lpid)
{
	if (lpid > kvm->arch.max_nested_lpid)
		return NULL;
	return kvm->arch.nested_guests[lpid];
}

static inline u64 n_rmap_to_gpa(u64 rmap)
{
	return ((rmap & RMAP_NESTED_GPA_MASK) >> RMAP_NESTED_GPA_SHIFT)
		<< PAGE_SHIFT;
}

static inline u64 gpa_to_n_rmap(u64 gpa)
{
	return ((gpa >> PAGE_SHIFT) << RMAP_NESTED_GPA_SHIFT) &
		RMAP_NESTED_GPA_MASK;
}

static inline u64 n_rmap_to_index(u64 rmap)
{
	return (rmap & RMAP_NESTED_GPA_MASK) >> RMAP_NESTED_GPA_SHIFT;
}

static inline u64 index_to_n_rmap(u64 index)
{
	return (index << RMAP_NESTED_GPA_SHIFT) & RMAP_NESTED_GPA_MASK;
}

static inline int n_rmap_to_lpid(u64 rmap)
{
	return (int) ((rmap & RMAP_NESTED_LPID_MASK) >> RMAP_NESTED_LPID_SHIFT);
}

static inline u64 lpid_to_n_rmap(int lpid)
{
	return (((u64) lpid) << RMAP_NESTED_LPID_SHIFT) & RMAP_NESTED_LPID_MASK;
}

static inline bool kvmhv_n_rmap_is_equal(u64 rmap_1, u64 rmap_2, u64 mask)
{
	return !((rmap_1 ^ rmap_2) & mask);
}

/* called with kvm->mmu_lock held */
void kvmhv_insert_nest_rmap(unsigned long *rmapp, struct rmap_nested **n_rmap)
{
	struct llist_head *head = (struct llist_head *) rmapp;
	struct rmap_nested *cursor;
	u64 new_rmap = (*n_rmap)->rmap;

	/* Do any existing entries match what we're trying to insert? */
	llist_for_each_entry(cursor, head->first, list) {
		if (kvmhv_n_rmap_is_equal(cursor->rmap, new_rmap,
					  RMAP_NESTED_LPID_MASK |
					  RMAP_NESTED_GPA_MASK))
			return;
	}

	/* Insert the new entry */
	llist_add(&((*n_rmap)->list), head);

	/* Set NULL so not freed by caller */
	*n_rmap = NULL;
}

/* called with kvm->mmu_lock held */
static void kvmhv_remove_nested_rmap_lpid(unsigned long *rmapp, int l1_lpid)
{
	struct llist_node **next = &(((struct llist_head *) rmapp)->first);
	u64 match = lpid_to_n_rmap(l1_lpid);

	while (*next) {
		struct llist_node *entry = (*next);
		struct rmap_nested *n_rmap = llist_entry(entry, typeof(*n_rmap),
							 list);

		if (kvmhv_n_rmap_is_equal(match, n_rmap->rmap,
					  RMAP_NESTED_LPID_MASK)) {
			*next = entry->next;
			kfree(n_rmap);
		} else {
			next = &(entry->next);
		}
	}
}

/*
 * caller must hold gp->tlb_lock
 * For a given nested lpid, remove all of the rmap entries which match that
 * nest lpid. Note that no invalidation/tlbie is done for the entries, it is
 * assumed that the caller will perform an lpid wide invalidation after calling
 * this function.
 */
static void kvmhv_remove_all_nested_rmap_lpid(struct kvm *kvm, int l1_lpid)
{
	struct kvm_memory_slot *memslot;

	kvm_for_each_memslot(memslot, kvm_memslots(kvm)) {
		unsigned long page;

		for (page = 0; page < memslot->npages; page++) {
			unsigned long *rmapp;

			spin_lock(&kvm->mmu_lock);
			rmapp = &memslot->arch.rmap[page];
			if (*rmapp) /* Are there any rmap entries? */
				kvmhv_remove_nested_rmap_lpid(rmapp, l1_lpid);
			spin_unlock(&kvm->mmu_lock);
		}
	}
}

/*
 * called with kvm->mmu_lock held
 * Given a single rmap entry, update the rc bits in the corresponding shadow
 * pte. Should only be used to clear rc bits.
 */
static void kvmhv_update_nest_rmap_rc(struct kvm *kvm, u64 n_rmap,
				      unsigned long clr, unsigned long set,
				      unsigned long hpa, unsigned long mask)
{
	struct kvm_nested_guest *gp;
	unsigned int lpid;

	lpid = n_rmap_to_lpid(n_rmap);;
	gp = kvmhv_find_nested(kvm, lpid);
	if (!gp)
		return;

	/*
	 * Find the pte, and ensure it's valid and still points to the same
	 * host page. If the pfn has changed then this is a stale rmap entry,
	 * the shadow pte actually points somewhere else now, and there is
	 * nothing to do. Otherwise clear the requested rc bits from the shadow
	 * pte and perform the appropriate cache invalidation.
	 * XXX A future optimisation would be to remove the rmap entry
	 */
	if (gp->radix) {
		unsigned long gpa = n_rmap_to_gpa(n_rmap);
		unsigned int shift;
		pte_t *ptep;

		ptep = __find_linux_pte(gp->shadow_pgtable, gpa, NULL, &shift);
		/* pte present and still points to the same host page? */
		if (ptep && pte_present(*ptep) && ((pte_val(*ptep) & mask) ==
						   hpa)) {
			__radix_pte_update(ptep, clr, set);
			kvmppc_radix_tlbie_page(kvm, gpa, shift, lpid);
		}
	 } else {
		unsigned long v, r, index = n_rmap_to_index(n_rmap);
		__be64 *hptep = (__be64 *)(gp->shadow_hpt.virt + (index << 4));

		preempt_disable();
		while (!try_lock_hpte(hptep, HPTE_V_HVLOCK))
			cpu_relax();
		v = be64_to_cpu(hptep[0]) & ~HPTE_V_HVLOCK;
		r = be64_to_cpu(hptep[1]);

		/*
		 * It's not enough to just clear the rc bits here since the
		 * hardware can just set them again transparently, we need to
		 * make the pte invalid so that an attempt to access the page
		 * will invoke the page fault handler and we can ensure
		 * consistency across the rc bits in the various ptes.
		 */
		if ((v & HPTE_V_VALID) && ((r & mask) == hpa)) {
			/* Invalidate existing pte */
			v = (v & ~HPTE_V_VALID) | HPTE_V_ABSENT;
			hptep[0] |= cpu_to_be64(HPTE_V_ABSENT);
			kvmppc_invalidate_hpte(gp->shadow_lpid, hptep, index);
			/* Zero second double word */
			hptep[1] = 0ULL;
			eieio();
		}
		__unlock_hpte(hptep, v);
		preempt_enable();
	}
}

/*
 * called with kvm->mmu_lock held
 * For a given list of rmap entries, update the rc bits in all ptes in shadow
 * page tables for nested guests which are referenced by the rmap list.
 * Should only be used to clear rc bits.
 */
void kvmhv_update_nest_rmap_rc_list(struct kvm *kvm, unsigned long *rmapp,
				    unsigned long clr, unsigned long set,
				    unsigned long hpa, unsigned long nbytes)
{
	struct llist_head *head = (struct llist_head *) rmapp;
	struct rmap_nested *cursor;
	unsigned long mask;

	if ((clr | set) & ~(_PAGE_DIRTY | _PAGE_ACCESSED))
		return;

	mask = HPTE_R_RPN_3_0 & ~(nbytes - 1);
	hpa &= mask;

	llist_for_each_entry(cursor, head->first, list)
		kvmhv_update_nest_rmap_rc(kvm, cursor->rmap, clr, set, hpa,
					  mask);
}

/*
 * called with kvm->mmu_lock held
 * Given a single rmap entry, invalidate the corresponding shadow pte.
 */
static void kvmhv_invalidate_nest_rmap(struct kvm *kvm, u64 n_rmap,
				       unsigned long hpa, unsigned long mask)
{
	struct kvm_nested_guest *gp;
	unsigned int lpid;

	lpid = n_rmap_to_lpid(n_rmap);;
	gp = kvmhv_find_nested(kvm, lpid);
	if (!gp)
		return;

	/*
	 * Find the pte, and ensure it's valid and still points to the same
	 * host page. If the pfn has changed then this is a stale rmap entry,
	 * the shadow pte actually points somewhere else now, and there is
	 * nothing to do. Otherwise invalidate the shadow pte and perform the
	 * appropriate cache invalidation.
	 */
	if (gp->radix) {
		unsigned long gpa = n_rmap_to_gpa(n_rmap);
		unsigned int shift;
		pte_t *ptep;

		ptep = __find_linux_pte(gp->shadow_pgtable, gpa, NULL, &shift);
		/* pte present and still points to the same host page? */
		if (ptep && pte_present(*ptep) && ((pte_val(*ptep) & mask) ==
						   hpa))
			kvmppc_unmap_pte(kvm, ptep, gpa, shift, NULL,
					 gp->shadow_lpid);
	} else {
		unsigned long v, r, index = n_rmap_to_index(n_rmap);
		__be64 *hptep = (__be64 *)(gp->shadow_hpt.virt + (index << 4));

		preempt_disable();
		while (!try_lock_hpte(hptep, HPTE_V_HVLOCK))
			cpu_relax();
		v = be64_to_cpu(hptep[0]) & ~HPTE_V_HVLOCK;
		r = be64_to_cpu(hptep[1]);

		/* Make pte absent if valid and host addr matches */
		if ((v & HPTE_V_VALID) && ((r & mask) == hpa)) {
			/* Invalidate existing pte */
			v = (v & ~HPTE_V_VALID) | HPTE_V_ABSENT;
			hptep[0] |= cpu_to_be64(HPTE_V_ABSENT);
			kvmppc_invalidate_hpte(gp->shadow_lpid, hptep, index);
			/* Zero second double word */
			hptep[1] = 0ULL;
			eieio();
		}
		__unlock_hpte(hptep, v);
		preempt_enable();
	}
}

/*
 * called with kvm->mmu_lock held
 * For a given list of rmap entries, invalidate the corresponding shadow ptes
 * for nested guests which are referenced by the rmap list.
 */
static void kvmhv_invalidate_nest_rmap_list(struct kvm *kvm,
					    unsigned long *rmapp,
					    unsigned long hpa,
					    unsigned long mask)
{
	struct llist_node *entry = llist_del_all((struct llist_head *) rmapp);
	struct rmap_nested *cursor, *next;

	llist_for_each_entry_safe(cursor, next, entry, list) {
		kvmhv_invalidate_nest_rmap(kvm, cursor->rmap, hpa, mask);
		kfree(cursor);
	}
}

/*
 * called with kvm->mmu_lock held
 * For a given memslot, invalidate all of the rmap entries which fall into the
 * given range.
 */
void kvmhv_invalidate_nest_rmap_range(struct kvm *kvm,
				      const struct kvm_memory_slot *memslot,
				      unsigned long gpa, unsigned long hpa,
				      unsigned long nbytes)
{
	unsigned long gfn, end_gfn;
	unsigned long addr_mask;

	if (!memslot)
		return;
	gfn = (gpa >> PAGE_SHIFT) - memslot->base_gfn;
	end_gfn = gfn + (nbytes >> PAGE_SHIFT);

	addr_mask = HPTE_R_RPN_3_0 & ~(nbytes - 1);
	hpa &= addr_mask;

	for (; gfn < end_gfn; gfn++) {
		unsigned long *rmap = &memslot->arch.rmap[gfn];
		kvmhv_invalidate_nest_rmap_list(kvm, rmap, hpa, addr_mask);
	}
}

/* Free the nest rmap structures for a given memslot */
static void kvmhv_free_memslot_nest_rmap(struct kvm_memory_slot *free)
{
	unsigned long page;

	for (page = 0; page < free->npages; page++) {
		unsigned long *rmapp = &free->arch.rmap[page];
		struct rmap_nested *cursor, *next;
		struct llist_node *entry;

		entry = llist_del_all((struct llist_head *) rmapp);
		llist_for_each_entry_safe(cursor, next, entry, list)
			kfree(cursor);
	}
}

static bool kvmhv_invalidate_shadow_pte_radix(struct kvm_vcpu *vcpu,
					      struct kvm_nested_guest *gp,
					      long gpa, int *shift_ret)
{
	struct kvm *kvm = vcpu->kvm;
	bool ret = false;
	pte_t *ptep;
	int shift;

	spin_lock(&kvm->mmu_lock);
	ptep = __find_linux_pte(gp->shadow_pgtable, gpa, NULL, &shift);
	if (!shift)
		shift = PAGE_SHIFT;
	if (ptep && pte_present(*ptep)) {
		kvmppc_unmap_pte(kvm, ptep, gpa, shift, NULL, gp->shadow_lpid);
		ret = true;
	}
	spin_unlock(&kvm->mmu_lock);

	if (shift_ret)
		*shift_ret = shift;
	return ret;
}

/* Called with the hpte locked */
static void kvmhv_invalidate_shadow_pte_hash(struct kvm_hpt_info *hpt,
					     unsigned int lpid, __be64 *hptep,
					     unsigned long index)
{
	hpt->rev[index].guest_rpte = 0UL;
	if (hptep[0] & cpu_to_be64(HPTE_V_VALID)) {
		/* HPTE was previously valid, so we need to invalidate it */
		hptep[0] |= cpu_to_be64(HPTE_V_ABSENT);
		kvmppc_invalidate_hpte(lpid, hptep, index);
	}
	hptep[1] = 0ULL;
	eieio();
	__unlock_hpte(hptep, 0UL);
}

/* Calculate hash given a virtual address, base page shift, and segment size */
static unsigned long kvmppc_hv_get_hash_value_va(struct kvm_hpt_info *hpt,
						 unsigned long va, int pshift,
						 unsigned long b)
{
	unsigned long hash, somask;

	if (b & HPTE_R_B_1T) {	/* 1T segment */
		somask = (1UL << 40) - 1;
		hash = va >> 40;
		hash ^= hash << 25;
	} else {		/* 256M segment */
		somask = (1UL << 28) - 1;
		hash = va >> 28;
	}
	hash ^= ((va & somask) >> pshift);
	hash &= kvmppc_hpt_mask(hpt);

	return hash;
}

/* called with gp->tlb_lock held */
static void kvmhv_tlbie_hpt_addr(struct kvm_nested_guest *gp, unsigned long va,
				 int base_pshift, int actual_pshift,
				 unsigned long b)
{
	unsigned long mask, hash_incr, num, i;
	struct kvm_hpt_info *hpt = &gp->shadow_hpt;
	__be64 *hptep;
	unsigned long hash, v, v_mask, v_match, r, r_mask, r_match;

	hash = kvmppc_hv_get_hash_value_va(hpt, va, base_pshift, b);

	/*
	 * The virtual address provided to us in the rb register for tlbie is
	 * bits 14:77 of the virtual address, however we support a 68 bit
	 * virtual address on P9. This means that we actually need bits 10:77 of
	 * the virtual address to calculate all possible hash values for a 68
	 * bit virtual address space. This means that dependant on the size of
	 * the hpt (and thus the number of hash bits we actually use to find
	 * the pteg index) we might have to search up to 16 ptegs (1TB segs) or
	 * 8 ptegs (256M segs) for a match.
	 */
	if (b & HPTE_R_B_1T) {	/* 1T segment */
		/*
		 * The hash when using 1T segments uses bits 0:37 of the VA.
		 * Thus to cover the missing bits of the VA (bits 0:13) we need
		 * to zero any of these bits being used (as determined by
		 * kvmppc_hpt_mask()) and then search all possible values.
		 */
		hash_incr = 1UL << 24;
		mask = (0x3ffUL << 24) & kvmppc_hpt_mask(hpt);
		hash &= ~mask;
		num = mask >> 24;
	} else {		/* 256M segment */
		/*
		 * The hash when using 256M segments uses bits 11:49 of the VA.
		 * Thus to cover the missing bits of the VA (bits 11:13) we need
		 * to zero any of these bits being used (as determined by
		 * kvmppc_hpt_mask()) and then search all possible values.
		 */
		hash_incr = 1UL << 36;
		mask = (0x7UL << 36) & kvmppc_hpt_mask(hpt);
		hash &= ~mask;
		num = mask >> 36;
	}

	/* Calculate what we're going to match the hpte on */
	v_match = va >> 16;	/* Align va to ava in the hpte */
	if (base_pshift >= 24)
		v_match &= ~((1UL << (base_pshift - 16)) - 1);
	else
		v_match &= ~0x7fUL;
	if (actual_pshift > 12)
		v_match |= HPTE_V_LARGE;
	r_match = b;
	/* We don't have the top 4 bits of the ava to match on */
	v_mask = (TLBIE_RB_AVA_4K >> 16) & HPTE_V_AVPN_3_0;
	v_mask |= HPTE_V_LARGE | HPTE_V_SECONDARY;
	r_mask = HPTE_R_B;

	/* Iterate through the ptegs which we have to search */
	for (i = 0; i <= num; i++, hash += hash_incr) {
		unsigned long pteg_addr = hash << 7;
		v_match &= ~HPTE_V_SECONDARY;

		/* Try both the primary and the secondary hash */
		while (true) {
			int j;
			hptep = (__be64 *)(hpt->virt + pteg_addr);

			/* There are 8 entries in the pteg to search */
			for (j = 0; j < 16; j += 2) {
				preempt_disable();
				/* Lock the pte */
				while (!try_lock_hpte(&hptep[j], HPTE_V_HVLOCK))
					cpu_relax();
				v = be64_to_cpu(hptep[j]) & ~HPTE_V_HVLOCK;
				r = be64_to_cpu(hptep[j + 1]);

				/*
				 * Check for a match under the lock
				 * NOTE: the entry might be valid or absent
				 */
				if ((v & (HPTE_V_VALID | HPTE_V_ABSENT)) &&
				    !((v ^ v_match) & v_mask) &&
				    !((r ^ r_match) & r_mask) &&
				    (kvmppc_hpte_base_page_shift(v, r) ==
				     base_pshift) &&
				    (kvmppc_hpte_actual_page_shift(v, r) ==
				     actual_pshift))
					kvmhv_invalidate_shadow_pte_hash(hpt,
						gp->shadow_lpid, &hptep[j],
						(pteg_addr >> 4) + (j >> 1));
				else
					__unlock_hpte(&hptep[j], v);
				preempt_enable();
				/*
				 * In theory there is a 1-to-1 mapping between
				 * entries in the L1 hpt and our shadow hpt,
				 * however since L1 can't exactly specify a
				 * hpte (since we're missing some va bits) we
				 * must invalidate any match which we find and
				 * continue the search.
				 */
			}

			if (v_match & HPTE_V_SECONDARY)
				break;
			/* try the secondary hash */
			v_match |= HPTE_V_SECONDARY;
			pteg_addr ^= (kvmppc_hpt_mask(hpt) << 7);
		}
	}
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

/* SLB[lp] encodings for base page shifts */
static int slb_base_page_shift[4] = {
	24,     /* 16M */
	16,     /* 64k */
	34,     /* 16G */
	20,     /* 1M, unsupported */
};

static int kvmhv_emulate_tlbie_tlb_addr(struct kvm_vcpu *vcpu, int lpid,
					bool radix, unsigned long rbval)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_nested_guest *gp;
	int rc = 0;

	gp = kvmhv_get_nested(kvm, lpid, false);
	if (!gp) /* No such guest -> nothing to do */
		return 0;
	mutex_lock(&gp->tlb_lock);

	if (radix) {	/* Radix Invalidation */
		int shift, shadow_shift;
		unsigned long addr;
		long npages;

		/* Radix invalidation but this is a hpt guest, nothing to do */
		if (!gp->radix)
			goto out_unlock;

		shift = ap_to_shift(get_ap(rbval));
		addr = get_epn(rbval) << 12;
		if (shift < 0) {	/* Invalid ap encoding */
			rc = -EINVAL;
			goto out_unlock;
		}

		addr &= ~((1UL << shift) - 1);
		npages = 1UL << (shift - PAGE_SHIFT);
		/* There may be more than one host page backing this single guest pte */
		do {
			kvmhv_invalidate_shadow_pte_radix(vcpu, gp, addr,
							  &shadow_shift);

			npages -= 1UL << (shadow_shift - PAGE_SHIFT);
			addr += 1UL << shadow_shift;
		} while (npages > 0);
	} else {	/* Hash Invalidation */
		int base_pshift = 12, actual_pshift = 12;
		unsigned long ava, b = (rbval & TLBIE_RB_B) << TLBIE_RB_B_SHIFT;

		/* HPT invalidation but this is a radix guest, nothing to do */
		if (gp->radix)
			goto out_unlock;

		/* Decode the rbval into ava, b, and base and actual pshifts */
		if (rbval & TLBIE_RB_L) {	/* large base page size */
			unsigned long lp = rbval & TLBIE_RB_LP;
			ava = (rbval & TLBIE_RB_AVA_L) |
			      ((rbval & TLBIE_RB_AVAL) << TLBIE_RB_AVAL_SHIFT);

			/* base and actual page size encoded in lp field */
			base_pshift = kvmppc_hpte_base_page_shift(HPTE_V_LARGE,
								  lp);
			actual_pshift = kvmppc_hpte_actual_page_shift(HPTE_V_LARGE,
								      lp);
		} else {			/* !large base page size */
			int ap = get_ap(rbval);
			ava = rbval & TLBIE_RB_AVA_4K;

			/* actual page size encoded in ap field */
			if (ap & 0x4)
				actual_pshift = slb_base_page_shift[ap & 0x3];
		}

		kvmhv_tlbie_hpt_addr(gp, ava, base_pshift, actual_pshift, b);
	}

out_unlock:
	mutex_unlock(&gp->tlb_lock);
	kvmhv_put_nested(gp);
	return rc;
}

static void kvmhv_emulate_tlbie_lpid(struct kvm_vcpu *vcpu,
				     struct kvm_nested_guest *gp, int ric)
{
	struct kvm *kvm = vcpu->kvm;

	mutex_lock(&gp->tlb_lock);
	switch (ric) {
	case 0:
		/* Invalidate TLB */
		kvmhv_flush_nested(kvm, gp, false);
		break;
	case 1:
		/*
		 * Invalidate PWC
		 * We don't cache this -> nothing to do
		 */
		break;
	case 2:
		/* Invalidate TLB, PWC and caching of partition table entries */
		kvmhv_flush_nested(kvm, gp, true);
		break;
	default:
		break;
	}
	mutex_unlock(&gp->tlb_lock);
}

static void kvmhv_emulate_tlbie_all_lpid(struct kvm_vcpu *vcpu, int ric)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_nested_guest *gp;
	int i;

	spin_lock(&kvm->mmu_lock);
	for (i = 0; i <= kvm->arch.max_nested_lpid; i++) {
		gp = kvm->arch.nested_guests[i];
		if (gp) {
			spin_unlock(&kvm->mmu_lock);
			kvmhv_emulate_tlbie_lpid(vcpu, gp, ric);
			spin_lock(&kvm->mmu_lock);
		}
	}
	spin_unlock(&kvm->mmu_lock);
}

static int kvmhv_emulate_priv_tlbie(struct kvm_vcpu *vcpu, unsigned int instr,
				    unsigned long rsval, unsigned long rbval)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_nested_guest *gp;
	int r, ric, prs, is;
	int lpid;
	int ret = 0;

	ric = get_ric(instr);
	prs = get_prs(instr);
	r = get_r(instr);
	lpid = get_lpid(rsval);
	is = get_is(rbval);

	/*
	 * These cases are invalid and are not handled:
	 *
	 * Radix:
	 * prs == 1 -> Not HV privileged
	 * ric == 3 -> No cluster bombs for radix
	 * is  == 1 -> Partition scoped translations not associated with pid
	 * (!is) && (ric == 1 || ric == 2) -> Not supported by ISA
	 *
	 * HPT:
	 * prs == 1 && ric != 2	-> Only process scoped caching is process table
	 * ric == 1		-> No page walk cache for HPT
	 * (!is) && ric == 2	-> Not supported by ISA
	 * ric == 3		-> Although cluster bombs are technically
	 * 			   supported for is == 0, their encoding is
	 * 			   implementation specific and linux doesn't
	 * 			   use them, so we don't handle them for now.
	 * is == 1		-> HPT translations not associated with pid
	 */
	if (r && ((prs) || (ric == 3) || (is == 1) ||
			   ((!is) && (ric == 1 || ric == 2))))
		return -EINVAL;
	else if (!r && ((prs && (ric != 2)) || (ric == 1) ||
			(!is && (ric == 2)) || (is == 1) || (ric == 3)))
		return -EINVAL;

	switch (is) {
	case 0:
		/*
		 * We know ric == 0
		 * Invalidate TLB for a given target address
		 */
		ret = kvmhv_emulate_tlbie_tlb_addr(vcpu, lpid, r, rbval);
		break;
	case 2:
		/* Invalidate matching LPID */
		gp = kvmhv_get_nested(kvm, lpid, false);
		if (gp) {
			kvmhv_emulate_tlbie_lpid(vcpu, gp, ric);
			kvmhv_put_nested(gp);
		}
		break;
	case 3:
		/* Invalidate ALL LPIDs */
		kvmhv_emulate_tlbie_all_lpid(vcpu, ric);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/*
 * This handles the H_TLB_INVALIDATE hcall.
 * Parameters are (r4) tlbie instruction code, (r5) rS contents,
 * (r6) rB contents.
 */
long kvmhv_do_nested_tlbie(struct kvm_vcpu *vcpu)
{
	int ret;

	ret = kvmhv_emulate_priv_tlbie(vcpu, kvmppc_get_gpr(vcpu, 4),
			kvmppc_get_gpr(vcpu, 5), kvmppc_get_gpr(vcpu, 6));
	if (ret)
		return H_PARAMETER;
	return H_SUCCESS;
}

/*
 * Inject a storage interrupt (instruction or data) to the nested guest.
 *
 * Normally don't inject interrupts to the nested guest directly but
 * instead let it's guest hypervisor handle injecting interrupts. However
 * there are cases where the guest hypervisor is providing access to a page
 * but the level 0 hypervisor is not, and in this case we need to inject an
 * interrupt directly.
 */
static void kvmhv_inject_nested_storage_int(struct kvm_vcpu *vcpu, bool data,
					    bool writing, u64 addr, u64 flags)
{
	int vec = BOOK3S_INTERRUPT_INST_STORAGE;

	if (writing)
		flags |= DSISR_ISSTORE;
	if (data) {
		vec = BOOK3S_INTERRUPT_DATA_STORAGE;
		kvmppc_set_dar(vcpu, addr);
		kvmppc_set_dsisr(vcpu, flags);
	}
	kvmppc_inject_interrupt(vcpu, vec, flags);
}

/* Used to convert a radix nested guest real addr to a L1 guest real address */
static int kvmhv_xlate_addr_nested_radix(struct kvm_vcpu *vcpu,
					 struct kvm_nested_guest *gp,
					 unsigned long n_gpa, bool data,
					 bool writing,
					 struct kvmppc_pte *gpte_p)
{
	u64 fault_addr, flags = writing ? DSISR_ISSTORE : 0ULL;
	int ret;

	ret = kvmppc_mmu_walk_radix_tree(vcpu, n_gpa, gpte_p, gp->l1_gr_to_hr,
					 &fault_addr);

	if (ret) {
		/* We didn't find a pte */
		if (ret == -EINVAL) {
			/* Unsupported mmu config */
			flags |= DSISR_UNSUPP_MMU;
		} else if (ret == -ENOENT) {
			/* No translation found */
			flags |= DSISR_NOHPTE;
		} else if (ret == -EFAULT) {
			/* Couldn't access L1 real address */
			flags |= DSISR_PRTABLE_FAULT;
			vcpu->arch.fault_gpa = fault_addr;
		} else {
			/* Unknown error */
			return ret;
		}
		goto forward_to_l1;
	} else {
		/* We found a pte -> check permissions */
		if (writing) {
			/* Can we write? */
			if (!gpte_p->may_write) {
				flags |= DSISR_PROTFAULT;
				goto forward_to_l1;
			}
		} else if (!data) {
			/* Can we execute? */
			if (!gpte_p->may_execute) {
				flags |= SRR1_ISI_N_OR_G;
				goto forward_to_l1;
			}
		} else {
			/* Can we read? */
			if (!gpte_p->may_read && !gpte_p->may_write) {
				flags |= DSISR_PROTFAULT;
				goto forward_to_l1;
			}
		}
	}

	return 0;

forward_to_l1:
	vcpu->arch.fault_dsisr = flags;
	if (!data) {
		vcpu->arch.shregs.msr &= ~0x783f0000ul;
		vcpu->arch.shregs.msr |= (flags & 0x783f0000ul);
	}
	return RESUME_HOST;
}

static long kvmhv_handle_nested_set_rc_radix(struct kvm_vcpu *vcpu,
					     struct kvm_nested_guest *gp,
					     unsigned long n_gpa,
					     struct kvmppc_pte gpte,
					     unsigned long dsisr)
{
	struct kvm *kvm = vcpu->kvm;
	bool writing = !!(dsisr & DSISR_ISSTORE);
	u64 pgflags;
	long ret;

	/* Are the rc bits set in the L1 partition scoped pte? */
	pgflags = _PAGE_ACCESSED;
	if (writing)
		pgflags |= _PAGE_DIRTY;
	if (pgflags & ~gpte.rc)
		return RESUME_HOST;

	spin_lock(&kvm->mmu_lock);
	/* Set the rc bit in the pte of our (L0) pgtable for the L1 guest */
	ret = kvmppc_hv_handle_set_rc(kvm, kvm->arch.pgtable, writing,
				     gpte.raddr, kvm->arch.lpid);
	if (!ret) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/* Set the rc bit in the pte of the shadow_pgtable for the nest guest */
	ret = kvmppc_hv_handle_set_rc(kvm, gp->shadow_pgtable, writing, n_gpa,
				      gp->shadow_lpid);
	if (!ret)
		ret = -EINVAL;
	else
		ret = 0;

out_unlock:
	spin_unlock(&kvm->mmu_lock);
	return ret;
}

static inline int kvmppc_radix_level_to_shift(int level)
{
	switch (level) {
	case 2:
		return PUD_SHIFT;
	case 1:
		return PMD_SHIFT;
	default:
		return PAGE_SHIFT;
	}
}

static inline int kvmppc_radix_shift_to_level(int shift)
{
	if (shift == PUD_SHIFT)
		return 2;
	if (shift == PMD_SHIFT)
		return 1;
	if (shift == PAGE_SHIFT)
		return 0;
	WARN_ON_ONCE(1);
	return 0;
}

/* called with gp->tlb_lock held */
static long int __kvmhv_nested_page_fault_radix(struct kvm_run *run,
						struct kvm_vcpu *vcpu,
						struct kvm_nested_guest *gp)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_memory_slot *memslot;
	struct rmap_nested *n_rmap;
	struct kvmppc_pte gpte;
	pte_t pte, *pte_p;
	unsigned long mmu_seq;
	unsigned long dsisr = vcpu->arch.fault_dsisr;
	unsigned long ea = vcpu->arch.fault_dar;
	unsigned long *rmapp;
	unsigned long n_gpa, gpa, gfn, perm = 0UL;
	unsigned int shift, l1_shift, level;
	bool data = vcpu->arch.trap == BOOK3S_INTERRUPT_H_DATA_STORAGE;
	bool writing = data && (dsisr & DSISR_ISSTORE);
	bool kvm_ro = false;
	long int ret;

	if (!gp->l1_gr_to_hr) {
		kvmhv_update_ptbl_cache(gp);
		if (!gp->l1_gr_to_hr)
			return RESUME_HOST;
	}

	/* Convert the nested guest real address into a L1 guest real address */

	n_gpa = vcpu->arch.fault_gpa & ~0xF000000000000FFFULL;
	if (!(dsisr & DSISR_PRTABLE_FAULT))
		n_gpa |= ea & 0xFFF;
	ret = kvmhv_xlate_addr_nested_radix(vcpu, gp, n_gpa, data, writing,
					    &gpte);

	/*
	 * If the hardware found a translation but we don't now have a usable
	 * translation in the l1 partition-scoped tree, remove the shadow pte
	 * and let the guest retry.
	 */
	if (ret == RESUME_HOST &&
	    (dsisr & (DSISR_PROTFAULT | DSISR_BADACCESS | DSISR_NOEXEC_OR_G |
		      DSISR_BAD_COPYPASTE)))
		goto inval;
	if (ret)
		return ret;

	/* Failed to set the reference/change bits */
	if (dsisr & DSISR_SET_RC) {
		ret = kvmhv_handle_nested_set_rc_radix(vcpu, gp, n_gpa, gpte,
						       dsisr);
		if (ret == RESUME_HOST)
			return ret;
		if (ret)
			goto inval;
		dsisr &= ~DSISR_SET_RC;
		if (!(dsisr & (DSISR_BAD_FAULT_64S | DSISR_NOHPTE |
			       DSISR_PROTFAULT)))
			return RESUME_GUEST;
	}

	/*
	 * We took an HISI or HDSI while we were running a nested guest which
	 * means we have no partition scoped translation for that. This means
	 * we need to insert a pte for the mapping into our shadow_pgtable.
	 */

	l1_shift = gpte.page_shift;
	if (l1_shift < PAGE_SHIFT) {
		/* We don't support l1 using a page size smaller than our own */
		pr_err("KVM: L1 guest page shift (%d) less than our own (%d)\n",
			l1_shift, PAGE_SHIFT);
		return -EINVAL;
	}
	gpa = gpte.raddr;
	gfn = gpa >> PAGE_SHIFT;

	/* 1. Get the corresponding host memslot */

	memslot = gfn_to_memslot(kvm, gfn);
	if (!memslot || (memslot->flags & KVM_MEMSLOT_INVALID)) {
		if (dsisr & (DSISR_PRTABLE_FAULT | DSISR_BADACCESS)) {
			/* unusual error -> reflect to the guest as a DSI */
			kvmhv_inject_nested_storage_int(vcpu, data, writing, ea,
							dsisr);
			return RESUME_GUEST;
		}

		/* passthrough of emulated MMIO case */
		return kvmppc_hv_emulate_mmio(run, vcpu, gpa, ea, writing);
	}
	if (memslot->flags & KVM_MEM_READONLY) {
		if (writing) {
			/* Give the guest a DSI */
			kvmhv_inject_nested_storage_int(vcpu, data, writing, ea,
							DSISR_PROTFAULT);
			return RESUME_GUEST;
		}
		kvm_ro = true;
	}

	/* 2. Find the host pte for this L1 guest real address */

	/* Used to check for invalidations in progress */
	mmu_seq = kvm->mmu_notifier_seq;
	smp_rmb();

	/* See if can find translation in our partition scoped tables for L1 */
	pte = __pte(0);
	spin_lock(&kvm->mmu_lock);
	pte_p = __find_linux_pte(kvm->arch.pgtable, gpa, NULL, &shift);
	if (!shift)
		shift = PAGE_SHIFT;
	if (pte_p)
		pte = *pte_p;
	spin_unlock(&kvm->mmu_lock);

	if (!pte_present(pte) || (writing && !(pte_val(pte) & _PAGE_WRITE))) {
		/* No suitable pte found -> try to insert a mapping */
		ret = kvmppc_book3s_instantiate_page(vcpu, gpa, memslot,
					writing, kvm_ro, &pte, &level);
		if (ret == -EAGAIN)
			return RESUME_GUEST;
		else if (ret)
			return ret;
		shift = kvmppc_radix_level_to_shift(level);
	}
	/* Align gfn to the start of the page */
	gfn = (gpa & ~((1UL << shift) - 1)) >> PAGE_SHIFT;

	/* 3. Compute the pte we need to insert for nest_gpa -> host r_addr */

	/* The permissions is the combination of the host and l1 guest ptes */
	perm |= gpte.may_read ? 0UL : _PAGE_READ;
	perm |= gpte.may_write ? 0UL : _PAGE_WRITE;
	perm |= gpte.may_execute ? 0UL : _PAGE_EXEC;
	/* Only set accessed/dirty (rc) bits if set in host and l1 guest ptes */
	perm |= (gpte.rc & _PAGE_ACCESSED) ? 0UL : _PAGE_ACCESSED;
	perm |= ((gpte.rc & _PAGE_DIRTY) && writing) ? 0UL : _PAGE_DIRTY;
	pte = __pte(pte_val(pte) & ~perm);

	/* What size pte can we insert? */
	if (shift > l1_shift) {
		u64 mask;
		unsigned int actual_shift = PAGE_SHIFT;
		if (PMD_SHIFT < l1_shift)
			actual_shift = PMD_SHIFT;
		mask = (1UL << shift) - (1UL << actual_shift);
		pte = __pte(pte_val(pte) | (gpa & mask));
		shift = actual_shift;
	}
	level = kvmppc_radix_shift_to_level(shift);
	n_gpa &= ~((1UL << shift) - 1);

	/* 4. Insert the pte into our shadow_pgtable */

	n_rmap = kzalloc(sizeof(*n_rmap), GFP_KERNEL);
	if (!n_rmap)
		return RESUME_GUEST; /* Let the guest try again */
	n_rmap->rmap = gpa_to_n_rmap(n_gpa) | lpid_to_n_rmap(gp->l1_lpid);
	rmapp = &memslot->arch.rmap[gfn - memslot->base_gfn];
	ret = kvmppc_create_pte(kvm, gp->shadow_pgtable, pte, n_gpa, level,
				mmu_seq, gp->shadow_lpid, rmapp, &n_rmap);
	if (n_rmap)
		kfree(n_rmap);
	if (ret == -EAGAIN)
		ret = RESUME_GUEST;	/* Let the guest try again */

	return ret;

 inval:
	kvmhv_invalidate_shadow_pte_radix(vcpu, gp, n_gpa, NULL);
	return RESUME_GUEST;
}

/*
 * Used to convert a hash nested guest virtual addr to a L1 guest real addr
 * Returns pte index of pte which provided the translation
 */
static long kvmhv_xlate_addr_nested_hash(struct kvm_vcpu *vcpu,
					 struct kvm_nested_guest *gp,
					 u64 eaddr, u64 slb_v, bool data,
					 bool writing, u64 *v_p, u64 *r_p)
{
	unsigned long v, v_mask, v_match, r, r_mask, r_match;
	u64 flags = writing ? DSISR_ISSTORE : 0ULL;
	int pshift, i, ret;
	u64 hash, pp, key;
	u64 pteg[16];

	/* NOTE: All handling done in new ISA V3.0 hpte format */

	/* Compute the hash */
	hash = kvmppc_hv_get_hash_value(&gp->shadow_hpt, eaddr, slb_v, &v_match,
					&pshift);
	/* Bits which must match */
	v_mask = HPTE_V_AVPN_3_0 | HPTE_V_SECONDARY | HPTE_V_VALID;
	v_match |= HPTE_V_VALID;
	if (slb_v & SLB_VSID_L) {
		v_mask |= HPTE_V_LARGE;
		v_match |= HPTE_V_LARGE;
	}
	r_mask = HPTE_R_B;
	r_match = (slb_v & SLB_VSID_B_1T) ? HPTE_R_B_1T : 0ULL;

	/*
	 * Read the pteg from L1 guest memory and search for a matching pte.
	 * Note: No need to lock the pte since we hold the tlb_lock meaning
	 * that L1 can't complete a tlbie and change the pte out from under us.
	 */
	while (true) {
		u64 pteg_addr = (gp->l1_gr_to_hr & PATB_HTABORG) + (hash << 7);

		ret = kvm_vcpu_read_guest(vcpu, pteg_addr, pteg, sizeof(pteg));
		if (ret) {
			flags |= DSISR_NOHPTE;
			goto forward_to_l1;
		}

		for (i = 0; i < 16; i += 2) {
			v = be64_to_cpu(pteg[i]) & ~HPTE_V_HVLOCK;
			r = be64_to_cpu(pteg[i + 1]);

			if (!((v ^ v_match) & v_mask) &&
					!((r ^ r_match) & r_mask) &&
					(kvmppc_hpte_base_page_shift(v, r) ==
					 pshift))
				goto match_found;
		}

		if (v_match & HPTE_V_SECONDARY) {
			flags |= DSISR_NOHPTE;
			goto forward_to_l1;
		}
		/* Try the secondary hash */
		v_match |= HPTE_V_SECONDARY;
		hash = hash ^ kvmppc_hpt_mask(&gp->shadow_hpt);
	}

match_found:
	/* Match found - check the permissions */
	pp = r & HPTE_R_PPP;
	key = slb_v & (vcpu->arch.shregs.msr & MSR_PR ? SLB_VSID_KP :
							SLB_VSID_KS);
	if (!data) {		/* check execute permissions */
		if (r & (HPTE_R_N | HPTE_R_G)) {
			flags |= SRR1_ISI_N_OR_G;
			goto forward_to_l1;
		}
		if (!hpte_read_permission(pp, key)) {
			flags |= SRR1_ISI_PROT;
			goto forward_to_l1;
		}
	} else if (writing) {	/* check write permissions */
		if (!hpte_write_permission(pp, key)) {
			flags |= DSISR_PROTFAULT;
			goto forward_to_l1;
		}
	} else {		/* check read permissions */
		if (!hpte_read_permission(pp, key)) {
			flags |= DSISR_PROTFAULT;
			goto forward_to_l1;
		}
	}

	*v_p = v & ~HPTE_V_HVLOCK;
	*r_p = r;
	return (hash << 3) + (i >> 1);

forward_to_l1:
	vcpu->arch.fault_dsisr = flags;
	if (!data) {
		vcpu->arch.shregs.msr &= ~0x783f0000ul;
		vcpu->arch.shregs.msr |= (flags & 0x783f0000ul);
	}
	return -1;
}

static long kvmhv_handle_nested_set_rc_hash(struct kvm_vcpu *vcpu,
					    struct kvm_nested_guest *gp,
					    unsigned long gpa, u64 index,
					    u64 *gr, u64 *hr, bool writing)
{
	struct kvm *kvm = vcpu->kvm;
	u64 pgflags;
	long ret;

	pgflags = _PAGE_ACCESSED;
	if (writing)
		pgflags |= _PAGE_DIRTY;

	/* Are the rc bits set in the L1 hash pte? */
	if (pgflags & ~(*gr)) {
		__be64 gr_be;
		u64 addr = (gp->l1_gr_to_hr & PATB_HTABORG) + (index << 4);
		addr += sizeof(*gr);	/* Writing second doubleword */

		/* Update rc in the L1 guest pte */
		(*gr) |= pgflags;
		gr_be = cpu_to_be64(*gr);
		ret = kvm_write_guest(kvm, addr, &gr_be, sizeof(gr_be));
		if (ret)	/* Let the guest try again */
			return -EINVAL;
	}

	/* Set the rc bit in the pte of our (L0) pgtable for the L1 guest */
	spin_lock(&kvm->mmu_lock);
	ret = kvmppc_hv_handle_set_rc(kvm, kvm->arch.pgtable, writing,
				      gpa, kvm->arch.lpid);
	spin_unlock(&kvm->mmu_lock);
	if (!ret)		/* Let the guest try again */
		return -EINVAL;

	/* Set the rc bit in the pte of the shadow_hpt for the nest guest */
	(*hr) |= pgflags;

	return 0;
}

/* called with gp->tlb_lock held */
static long int __kvmhv_nested_page_fault_hash(struct kvm_run *run,
					       struct kvm_vcpu *vcpu,
					       struct kvm_nested_guest *gp)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_memory_slot *memslot;
	struct rmap_nested *n_rmap;
	unsigned long hpte[3] = { 0UL };
	unsigned long mmu_seq;
	unsigned long dsisr = vcpu->arch.fault_dsisr;
	unsigned long ea = vcpu->arch.fault_dar;
	long index = vcpu->arch.pgfault_index;
	unsigned long psize, *rmapp;
	bool data = vcpu->arch.trap == BOOK3S_INTERRUPT_H_DATA_STORAGE;
	bool writing = data && (dsisr & DSISR_ISSTORE);
	bool kvm_ro = false;
	u64 gv = 0ULL, gr = 0ULL, hr = 0ULL;
	u64 gpa, gfn, hpa;
	int l1_shift, shift, req_perm, h_perm;
	pte_t pte, *pte_p;
	__be64 *hptep;
	long int ret;

	/*
	 * 1. Translate to a L1 Guest Real Addr
	 * If there was no existing entry (pgfault_index < 0) then we need to
	 * search for the guest hpte in l1 memory.
	 * If we found an entry in kvmppc_hpte_hv_fault() (pgfault_index >= 0)
	 * then lock the hpte and check it hasn't changed. If it has (because
	 * a tlbie has completed between then and now) let the guest try again.
	 * If the entry is valid then we are coming in here to upgrade the write
	 * permissions on an existing hpte which we mapped read only to avoid
	 * setting the change bit, and now the guest is writing to it.
	 * If the entry isn't valid (which means it's absent) then the
	 * guest_rpte is still valid, we just made it absent when the host
	 * paged out the underlying page which was used to back the guest memory
	 * NOTE: Since the shadow_hpt was allocated the same size as the l1 hpt
	 * the index is preserved giving a 1-to-1 mapping between the hash page
	 * tables, this could be changed in future.
	 */
	if (index >= 0) {
		hptep = (__be64 *)(gp->shadow_hpt.virt + (index << 4));

		preempt_disable();
		while (!try_lock_hpte(hptep, HPTE_V_HVLOCK))
			cpu_relax();
		hpte[0] = gv = be64_to_cpu(hptep[0]) & ~HPTE_V_HVLOCK;
		hpte[1] = hr = be64_to_cpu(hptep[1]);
		hpte[2] = gr = gp->shadow_hpt.rev[index].guest_rpte;
		unlock_hpte(hptep, hpte[0]);
		preempt_enable();

		/* hpt modified under us? */
		if (hpte[0] != hpte_old_to_new_v(vcpu->arch.pgfault_hpte[0]) ||
		    hpte[1] != hpte_old_to_new_r(vcpu->arch.pgfault_hpte[0],
						 vcpu->arch.pgfault_hpte[1]))
			return RESUME_GUEST;	/* Let the guest try again */
	} else {
		/* Note: fault_gpa was used to store the slb_v entry */
		index = kvmhv_xlate_addr_nested_hash(vcpu, gp, ea,
						     vcpu->arch.fault_gpa, data,
						     writing, &gv, &gr);
		if (index < 0)
			return RESUME_HOST;
		hptep = (__be64 *)(gp->shadow_hpt.virt + (index << 4));
	}
	l1_shift = kvmppc_hpte_actual_page_shift(gv, gr);
	psize = (1UL << l1_shift);
	gfn = (gr & HPTE_R_RPN_3_0 & ~(psize - 1)) >> PAGE_SHIFT;
	gpa = (gfn << PAGE_SHIFT) | (ea & (psize - 1));

	/* 2. Find the host memslot */

	memslot = gfn_to_memslot(kvm, gfn);
	if (!memslot || (memslot->flags & KVM_MEMSLOT_INVALID)) {
		/* passthrough of emulated MMIO case */
		pr_err("emulated MMIO passthrough?\n");
		return -EINVAL;
	}
	if (memslot->flags & KVM_MEM_READONLY) {
		if (writing) {
			/* Give the guest a DSI */
			kvmhv_inject_nested_storage_int(vcpu, data, ea, writing,
							DSISR_PROTFAULT);
			return RESUME_GUEST;
		}
		kvm_ro = true;
	}

	/* 3. Translate to a L0 Host Real Address through the L0 page table */

	/* Used to check for invalidations in progress */
	mmu_seq = kvm->mmu_notifier_seq;
	smp_rmb();

	/* See if can find translation in our partition scoped tables for L1 */
	if (!kvm->arch.radix) {
		/* only support nested hpt guest under radix l1 guest */
		pr_err("nested hpt guest only supported under radix guest\n");
		return -EINVAL;
	}
	pte = __pte(0);
	spin_lock(&kvm->mmu_lock);
	pte_p = __find_linux_pte(kvm->arch.pgtable, gpa, NULL, &shift);
	spin_unlock(&kvm->mmu_lock);

	if (!shift)
		shift = PAGE_SHIFT;
	if (pte_p)
		pte = *pte_p;

	if (!pte_present(pte) || (writing && !(pte_val(pte) & _PAGE_WRITE))) {
		int level;
		/* No suitable pte found -> try to insert a mapping */
		ret = kvmppc_book3s_instantiate_page(vcpu, gpa, memslot,
						writing, kvm_ro, &pte, &level);
		if (ret == -EAGAIN)
			return RESUME_GUEST;
		else if (ret)
			return ret;
		shift = kvmppc_radix_level_to_shift(level);
	}

	if (shift < l1_shift)	/* Don't support L1 using larger page than us */
		return -EINVAL;
	if (!hpte_cache_flags_ok(gr, pte_ci(pte)))
		return -EINVAL;
	hpa = pte_pfn(pte) << PAGE_SHIFT;
	/* Align gfn to the start of the page */
	gfn = (gpa & ~((1UL << shift) - 1)) >> PAGE_SHIFT;

	/* 4. Compute the PTE we're going to insert */

	if (!hr) {	/* Not an existing entry */
		hr = gr & ~HPTE_R_RPN_3_0;	/* Copy everything except rpn */
		hr |= ((psize - HPTE_R_KEY_BIT2) & gr);	/* psize encoding */
		hr |= (hpa & HPTE_R_RPN_3_0 & ~((1UL << shift) - 1));
		if (shift > l1_shift)	/* take some bits from the gpa */
			hr |= (gpa & ((1UL << shift) - psize));
	}

	/* Limit permissions based on the L0 pte */
	req_perm = data ? (writing ? (_PAGE_READ | _PAGE_WRITE) : _PAGE_READ)
			: _PAGE_EXEC;
	h_perm = (pte_val(pte) & _PAGE_READ) ? _PAGE_READ : 0;
	h_perm |= (pte_val(pte) & _PAGE_WRITE) ? (_PAGE_READ |
						 (kvm_ro ? 0 : _PAGE_WRITE))
					       : 0;
	h_perm |= (pte_val(pte) & _PAGE_EXEC) ? _PAGE_EXEC : 0;
	if (req_perm & ~h_perm) {
		/* host doesn't provide a required permission -> dsi to guest */
		kvmhv_inject_nested_storage_int(vcpu, data, ea, writing,
						DSISR_PROTFAULT);
		return RESUME_GUEST;
	}
	if (!(h_perm & _PAGE_EXEC))	/* Make page no execute */
		hr |= HPTE_R_N;
	if (!(h_perm & _PAGE_WRITE)) {	/* Make page no write */
		hr = hpte_make_readonly(hr);
		writing = 0;
	} else if (!writing) {
		/*
		 * Make page no write so we can defer setting the change bit.
		 * If the guest writes to the page we'll come back in to
		 * upgrade the permissions and set the change bit then.
		 */
		hr = hpte_make_readonly(hr);
	} else {	/* _PAGE_WRITE && writing */
		hr = hpte_make_writable(hr);
	}

	/* 5. Update rc bits if required */

	ret = kvmhv_handle_nested_set_rc_hash(vcpu, gp, gpa, index, &gr, &hr,
					      writing);
	if (ret)
		return RESUME_GUEST;		/* Let the guest try again */

	/* 6. Generate the nest rmap */

	n_rmap = kzalloc(sizeof(*n_rmap), GFP_KERNEL);
	if (!n_rmap)				/* Let the guest try again */
		return RESUME_GUEST;
	n_rmap->rmap = index_to_n_rmap(index) | lpid_to_n_rmap(gp->l1_lpid);
	rmapp = &memslot->arch.rmap[gfn - memslot->base_gfn];

	/* 7. Insert the PTE */

	/* Check if we might have been invalidated; let the guest retry if so */
	spin_lock(&kvm->mmu_lock);
	if (mmu_notifier_retry(kvm, mmu_seq))
		goto out_free;

	/* Lock the hpte */
	preempt_disable();
	while (!try_lock_hpte(hptep, HPTE_V_HVLOCK))
		cpu_relax();

	/* Check that the entry hasn't been changed out from under us */
	if ((be64_to_cpu(hptep[0]) & ~HPTE_V_HVLOCK) != hpte[0] ||
	     be64_to_cpu(hptep[1]) != hpte[1] ||
	     gp->shadow_hpt.rev[index].guest_rpte != hpte[2])
		goto out_unlock;		/* Let the guest try again */

	/* Ensure valid bit set in hpte */
	gv = (gv & ~HPTE_V_ABSENT) | HPTE_V_VALID;

	if (be64_to_cpu(hptep[0]) & HPTE_V_VALID) {
		/* HPTE was previously valid, so we need to invalidate it */
		hptep[0] |= cpu_to_be64(HPTE_V_ABSENT);
		kvmppc_invalidate_hpte(gp->shadow_lpid, hptep, index);
	}

	/* Insert the rmap entry */
	kvmhv_insert_nest_rmap(rmapp, &n_rmap);

	/* Always update guest_rpte in case we updated rc bits */
	gp->shadow_hpt.rev[index].guest_rpte = gr;

	hptep[1] = cpu_to_be64(hr);
	eieio();
	__unlock_hpte(hptep, gv);
	preempt_enable();

out_free:
	spin_unlock(&kvm->mmu_lock);
	if (n_rmap)
		kfree(n_rmap);
	return RESUME_GUEST;

out_unlock:
	__unlock_hpte(hptep, be64_to_cpu(hptep[0]));
	preempt_enable();
	goto out_free;
}

long int kvmhv_nested_page_fault(struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	struct kvm_nested_guest *gp = vcpu->arch.nested;
	long int ret;

	mutex_lock(&gp->tlb_lock);
	if (gp->radix)
		ret = __kvmhv_nested_page_fault_radix(run, vcpu, gp);
	else
		ret = __kvmhv_nested_page_fault_hash(run, vcpu, gp);
	mutex_unlock(&gp->tlb_lock);
	return ret;
}

int kvmhv_nested_next_lpid(struct kvm *kvm, int lpid)
{
	int ret = -1;

	spin_lock(&kvm->mmu_lock);
	while (++lpid <= kvm->arch.max_nested_lpid) {
		if (kvm->arch.nested_guests[lpid]) {
			ret = lpid;
			break;
		}
	}
	spin_unlock(&kvm->mmu_lock);
	return ret;
}
