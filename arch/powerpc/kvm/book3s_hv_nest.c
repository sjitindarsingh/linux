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
#include <asm/kvm_book3s.h>
#include <asm/kvm_book3s_hv_nest.h>
#include <asm/book3s/64/mmu.h>
#include <asm/pte-walk.h>

#undef DEBUG

static struct kvm_arch_nested *kvmppc_find_nested(struct kvm *kvm, int lpid);

unsigned long kvmppc_radix_remove_nest_pte(struct kvm *kvm, pte_t *ptep,
					   unsigned long addr,
					   unsigned int shift,
					   unsigned int lpid)
{
	unsigned long old;

	old = kvmppc_radix_update_pte(kvm, ptep, ~0UL, 0, addr, shift);
	if (lpid) {
		kvmppc_radix_tlbie_page_lpid(addr, shift, lpid);
	}

	return old;
}

/* Must be called with rmap lock held */
static int kvmppc_test_and_replace_nest_rmap(struct kvm_nest_rmap *old,
					     struct kvm_nest_rmap *new)
{
	/* Does this rmap entry belong to this guest? */
	if (old->lpid == new->lpid) {
		/* Same page could be mapped at multiple guest addrs */
		if (old->nest_gpa == new->nest_gpa) {
			old->pfn = new->pfn;
			old->npages = new->npages;
			return 1;
		}
	}

	return 0;
}

int kvmppc_insert_nest_rmap_entry(unsigned long *rmap,
				  struct kvm_nest_rmap *rmap_entry)
{
	int rc = 0;
	struct kvm_nest_rmap *nest_rmap;
	struct list_head *head;

	lock_rmap_nest(rmap);
	head = get_rmap_nest(rmap);
	if (!head) {
		/* List is empty -> create a head */
		head = kzalloc(sizeof(*head), GFP_KERNEL);
		if (!head) {
			rc = -ENOMEM;
			goto out_unlock;
		}
		INIT_LIST_HEAD(head);
		set_rmap_nest(rmap, head);
	} else {
		struct kvm_nest_rmap *cur, *n;

		/*
		 * Already a list, iterate over the list and try to reuse an
		 * entry, otherwise add a new entry.
		*/
		list_for_each_entry_safe(cur, n, head, list) {
			if (kvmppc_test_and_replace_nest_rmap(cur, rmap_entry)) {
				/* We replaced an existing entry */
				goto out_unlock;
			}
		}
	}

	nest_rmap = kzalloc(sizeof(*nest_rmap), GFP_KERNEL);
	if (!nest_rmap) {
		rc = -ENOMEM;
		goto out_free;
	}
	memcpy(nest_rmap, rmap_entry, sizeof(*nest_rmap));

	/* Add ourselves to the list */
	list_add(&nest_rmap->list, head);
	goto out_unlock;

out_free:
	set_rmap_nest(rmap, NULL);
	kfree(head);
out_unlock:
	unlock_rmap_nest(rmap);
	return rc;
}

/*
 * Remove an rmap entry, and invalidate and tlbie the pte if appropriate
 * Must be called with rmap lock held
 * NOTE: caller must free and NULL the head pointer if removing last entry
 */
static void kvmppc_remove_nest_rmap(struct kvm *kvm, struct kvm_nest_rmap *rmap)
{
	struct kvm_arch_nested *nested;
	pgd_t *pgtable;
	pte_t *ptep;
	unsigned int shift;

	nested = kvmppc_find_nested(kvm, rmap->lpid);
	if (!nested) {
		goto out;
	}

	mutex_lock(&nested->lock);
	pgtable = nested->shadow_pgtable;
	if (!pgtable) {
		goto out_unlock;
	}
	/* find the pte */
	ptep = __find_linux_pte(pgtable, rmap->nest_gpa, NULL, &shift);
	/* Don't spuriously invalidate ptes if the pfn has changed */
	if (ptep && pte_present(*ptep) && (pte_pfn(*ptep) == rmap->pfn)) {
		kvmppc_radix_remove_nest_pte(kvm, ptep, rmap->nest_gpa, shift,
					     nested->lpid);
	}

out_unlock:
	mutex_unlock(&nested->lock);
out:
	/* remove this from the list */
	list_del(&rmap->list);
	kfree(rmap);
}

/*
 * Walk the rmap list for the given gfn of the memslot and remove entries which
 * map a number of pages greater than or equal to npages.
 * Must be called with rmap lock held
 */
static void kvmppc_remove_nest_rmap_list(struct kvm *kvm,
					 struct kvm_memory_slot *memslot,
					 unsigned long gfn,
					 unsigned long npages)
{
	struct kvm_nest_rmap *cur, *n;
	struct list_head *head;
	unsigned long *rmap;

	if (gfn < memslot->base_gfn || gfn >= (memslot->base_gfn +
					       memslot->npages)) {
		pr_err("KVM: %s gfn: 0x%.16lx out of memslot range\n",
				__func__, gfn);
	}

	rmap = &memslot->arch.rmap[gfn - memslot->base_gfn];

	lock_rmap_nest(rmap);

	head = get_rmap_nest(rmap);
	if (!head) {
		goto continue_unlock;
	}

	/* Remove all relevant entries except the head */
	list_for_each_entry_safe(cur, n, head, list) {
		if (cur->npages >= npages) {
			kvmppc_remove_nest_rmap(kvm, cur);
		}
	}

	/* Is the list empty now? */
	if (list_empty(head)) {
		/* Remove the head pointer */
		set_rmap_nest(rmap, NULL);
		kfree(head);
	}

continue_unlock:
	unlock_rmap_nest(rmap);
}

/*
 * Clear the rmap from base_gfn -> base_gfn + npages for this memslot
 * This invalidates ptes and preforms any required tlbies
 */
void kvmppc_clear_nest_rmap(struct kvm *kvm,
			    struct kvm_memory_slot *memslot,
			    unsigned long base_gfn,
			    unsigned long npages)
{
	unsigned long mask, gfn, end_gfn = base_gfn + npages;

	for (gfn = base_gfn; gfn < end_gfn; gfn++) {
		kvmppc_remove_nest_rmap_list(kvm, memslot, gfn, 1);
	}

	/* We need to check for 1G or 2M pages which encompass us */
	/* Could there be 1G pages? */
	if (memslot->npages > (PUD_SHIFT - PAGE_SHIFT)) {
		mask = (1UL << (PUD_SHIFT - PAGE_SHIFT)) - 1;
		if (base_gfn & mask) {
			/* remove any 1G entries which encompass us */
			kvmppc_remove_nest_rmap_list(kvm, memslot,
						     base_gfn & ~mask,
						     PUD_SHIFT - PAGE_SHIFT);
		}
		/* else -> we were on a 1G boundary, nothing to do */
	}
	/* Could there be 2M pages? */
	if (memslot->npages > (PMD_SHIFT - PAGE_SHIFT)) {
		mask = (1UL << (PMD_SHIFT - PAGE_SHIFT)) - 1;
		if (base_gfn & mask) {
			/* remove any 2M entries which encompass us */
			kvmppc_remove_nest_rmap_list(kvm, memslot,
						     base_gfn & ~mask,
						     PMD_SHIFT - PAGE_SHIFT);
		}
		/* else -> we were on a 2M boundary, nothing to do */
	}
}

/*
 * Clear the whole rmap of this memslot
 * This invalidates ptes and preforms any required tlbies
 */
void kvmppc_clear_all_nest_rmap(struct kvm *kvm,
				struct kvm_memory_slot *memslot)
{
	kvmppc_clear_nest_rmap(kvm, memslot, memslot->base_gfn,
			       memslot->npages);
}

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

/* Must only be called with the kvm lock held */
static struct kvm_arch_nested *kvmppc_init_vm_nested(struct kvm *kvm,
						     int lpid)
{
	struct kvm_arch_nested *nested;

	if (lpid >= KVMPPC_NR_LPIDS) {
		pr_err("KVM: lpid (%d) exceeds n.o. supported lpids (%d)\n",
		       lpid, KVMPPC_NR_LPIDS);
		return NULL;
	}

	nested = kzalloc(sizeof(*nested), GFP_KERNEL);
	if (!nested) {
		pr_err("KVM_HV_NEST: Unable to allocate memory\n");
		return NULL; /* ENOMEM -> Not much we can do though */
	}

	mutex_init(&nested->lock);
	nested->lpid = 0;		/* Will be allocated on final entry */
	nested->host_lpid = kvm->arch.lpid;
	nested->shadow_lpid = lpid;
	nested->shadow_pgtable = NULL;
	nested->process_table = 0ULL;

	list_add(&nested->list, &kvm->arch.nested);

	return nested;
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

/*
 * For all memslots, clear the rmap of all entries (matching lpid if != 0)
 * This doesn't invalidate ptes or perform any tlbies
 */
static void kvmppc_clear_nest_rmap_lpid(struct kvm *kvm, int lpid)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int mem_slot;

	for (mem_slot = 0; mem_slot < slots->used_slots; mem_slot++) {
		struct kvm_memory_slot *memslot = &slots->memslots[mem_slot];
		unsigned long page;

		for (page = 0; page < memslot->npages; page++) {
			unsigned long *rmap = &memslot->arch.rmap[page];
			struct list_head *head;

			lock_rmap_nest(rmap);

			head = get_rmap_nest(rmap);

			if (head) {
				struct kvm_nest_rmap *cur, *n;

				list_for_each_entry_safe(cur, n, head, list) {
					/*
					 * If this rmap matches, remove it. No
					 * need to invalidate or tlbie the pte,
					 * this guest is going away so it's
					 * pgtable has been removed and we will
					 * do a global tlbie.
					 */
					if (cur->lpid == lpid || !lpid) {
						list_del(&cur->list);
						kfree(cur);
					}
				}

				if (list_empty(head)) {
					set_rmap_nest(rmap, NULL);
					kfree(head);
				}
			}

			unlock_rmap_nest(rmap);
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

static int kvmppc_emulate_priv_tlbie(struct kvm_vcpu *vcpu, unsigned int instr)
{
	int rc = 0;
	int rs, rb;
	int ric, prs, r, is, ap = 0;
	int lpid;
	long npages = 1;
	long epn = 0;

	rs = get_rs(instr);
	rb = get_rb(instr);

	ric = get_ric(instr);
	prs = get_prs(instr);
	r = get_r(instr);
	lpid = get_lpid(vcpu->arch.gpr[rs]);
	is = get_is(vcpu->arch.gpr[rb]);
	if (!is) {
		int shift;

		epn = get_epn(vcpu->arch.gpr[rb]);
		ap = get_ap(vcpu->arch.gpr[rb]);
		shift = ap_encoding_to_shift(ap);
		if (!shift) {
			pr_err("KVM: Invalid ap encoding (0x%x) in tlbie instr\n",
			       ap);
			return EMULATE_FAIL;
		}
		epn &= ~((1UL << shift) - 1);
		npages = 1ULL << (shift - PAGE_SHIFT);
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
		/*
		 * We never look at or cache entries from the lpid 0 partition
		 * table so only something to do if lpid != 0:
		 * - Invalidate the entry in our own shadow_pgtable
		 * - Perform the appropriate tlbie ourselves
		 * Note: there might be multiple host pages to invalidate for a
		 *       single guest tlbie
		 */
		if (lpid) {
			struct kvm_arch_nested *nested;
			pgd_t *pgtable;
			pte_t *ptep;
			int shift;

			nested = kvmppc_find_nested(vcpu->kvm, lpid);
			if (!nested) {
				break;
			}

			mutex_lock(&nested->lock);
			/* Nothing to do if haven't alloced pgtable */
			if (!nested->shadow_pgtable) {
				mutex_unlock(&nested->lock);
				break;
			}

			pgtable = nested->shadow_pgtable;
			lpid = nested->lpid;

			do {
				ptep = __find_linux_pte(pgtable, epn, NULL,
							&shift);
				if (ptep && pte_present(*ptep)) {
					kvmppc_radix_remove_nest_pte(vcpu->kvm,
								     ptep, epn,
								     shift,
								     lpid);
				}
				npages -= 1ULL << (shift - PAGE_SHIFT);
				epn += 1UL << shift;
			} while (npages > 0);
			/* We don't remove the rmaps, let other code do that */
			mutex_unlock(&nested->lock);
		}
		break;
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

				if (!nested) {
					goto no_nested;
				}

				mutex_lock(&nested->lock);
				/* Nothing to do if haven't alloced pgtable */
				if (!nested->shadow_pgtable) {
					goto unlock;
				}

				/* Free page table since global invalidate */
				kvmppc_free_pgtable_radix(vcpu->kvm,
							  &nested->shadow_pgtable);
				kvmppc_clear_nest_rmap_lpid(vcpu->kvm,
							    nested->shadow_lpid);

				if (!nested->lpid) {
					goto unlock;
				}

				/* Return the lpid to the pool */
				kvmppc_setup_partition_table_nested(nested);
				kvmppc_free_lpid(nested->lpid);
				nested->lpid = 0;
unlock:
				mutex_unlock(&nested->lock);
			}
no_nested:
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

static struct kvm_arch_nested *kvmppc_find_init_vm_nested(struct kvm_vcpu *vcpu,
							  unsigned int lpid)
{
	struct kvm_arch_nested *nested;

	mutex_lock(&vcpu->kvm->lock);

	nested = kvmppc_find_nested(vcpu->kvm, lpid);
	if (!nested) {
		nested = kvmppc_init_vm_nested(vcpu->kvm, lpid);
	}

	mutex_unlock(&vcpu->kvm->lock);
	return nested;
}

static int kvmppc_find_alloc_nest_lpid(struct kvm_vcpu *vcpu,
				       struct kvm_arch_nested *nested)
{
	long rc;

	/* We need an lpid - try to find a free one */
	rc = kvmppc_alloc_lpid();
	if (rc >= 0) {
		nested->lpid = rc;
		goto lpid_found;
	}

	/* For now we don't handle taking an LPID off someone else */
	pr_err("KVM: No free lpids available to run nested guest\n");
	return rc;

lpid_found:	/* New (or reused) lpid - setup the partition table entry */
#ifdef DEBUG
	pr_info("KVM: Allocated nested lpid %d\n", nested->lpid);
#endif
	kvmppc_setup_partition_table_nested(nested);
	return 0;
}

static inline void reg_switch(ulong *val1, ulong *val2)
{
	ulong tmp;

	tmp = *val1;
	*val1 = *val2;
	*val2 = tmp;
}

static void hv_reg_switch(struct hv_reg *hv_reg, ulong *reg)
{
	if (!hv_reg->inited) {
		hv_reg->inited = 1;
		hv_reg->val = *reg;
		return;
	}

	reg_switch(&hv_reg->val, reg);
}

static void kvmppc_nested_reg_entry_switch(struct kvm_vcpu *vcpu)
{
	hv_reg_switch(&vcpu->arch.hv_regs.dawr, &vcpu->arch.dawr);
	hv_reg_switch(&vcpu->arch.hv_regs.ciabr, &vcpu->arch.ciabr);
	hv_reg_switch(&vcpu->arch.hv_regs.dawrx, &vcpu->arch.dawrx);
	hv_reg_switch(&vcpu->arch.hv_regs.hfscr, &vcpu->arch.hfscr);
	/* Can do this since there's only one thread per vcore on P9 */
	if (vcpu->arch.hv_regs.lpcr.inited) {
		u64 mask = kvmppc_get_lpcr_mask();
		ulong tmp = vcpu->arch.vcore->lpcr;
		vcpu->arch.vcore->lpcr &= ~mask;
		vcpu->arch.vcore->lpcr |= vcpu->arch.hv_regs.lpcr.val & mask;
		vcpu->arch.hv_regs.lpcr.val = tmp;
	} else {
		vcpu->arch.hv_regs.lpcr.inited = 1;
		vcpu->arch.hv_regs.lpcr.val = vcpu->arch.vcore->lpcr;
	}
	hv_reg_switch(&vcpu->arch.hv_regs.pcr, &vcpu->arch.vcore->pcr);
	hv_reg_switch(&vcpu->arch.hv_regs.amor, &vcpu->arch.amor);

	if (vcpu->arch.vcore->dpdes) {
		/* There is still one pending for the L1 Guest */
		vcpu->arch.doorbell_request = 1;
	}
	vcpu->arch.vcore->dpdes = vcpu->arch.hv_regs.nested_dpdes;

	kvmppc_update_intr_msr(&vcpu->arch.intr_msr, vcpu->arch.vcore->lpcr);
}

/*
 * This is the final transition into the nested guest, we need to:
 * - Allocate an LPID if not already done
 * - Setup a partition table if not already done
 * - Update the nest state so the kvm entry code uses the nest lpid
 * - Perform the final switch of a few registers
 * - Update the vcpu pc and msr to that of the nested guest
 */
static int kvmppc_enter_nested(struct kvm_vcpu *vcpu)
{
	struct kvm_arch_nested *nested;
	int rc;

	if (vcpu->arch.hv_regs.hsrr1 & MSR_HV) {
		/*
		 * If hrfid to HV state then don't switch the regs which would
		 * only take effect in non-HV state.
		 */
		goto no_switch;
	}

	nested = kvmppc_find_init_vm_nested(vcpu, vcpu->arch.shadow_lpid);
	if (!nested) {
		/* ENOMEM -> not much we can do, let the guest try again... */
		return EMULATE_DONE;
	}

	mutex_lock(&nested->lock);

	/* Find the process table (if required) */
	if (!nested->process_table) {
		rc = kvmppc_find_update_process_table(vcpu->kvm, nested);
		if (rc) {
			goto fail_unlock;
		}
	}

	/* Init the shadow page table (if required) */
	if (!nested->shadow_pgtable) {
		rc = kvmppc_init_pgtable_radix(vcpu->kvm,
					       &nested->shadow_pgtable);
		if (rc) {
			goto fail_unlock;
		}
	}

	/* Find or allocate an lpid (if required) */
	if (!nested->lpid) {
		rc = kvmppc_find_alloc_nest_lpid(vcpu, nested);
		if (rc) {
			goto fail_unlock;
		}
	}

	nested->running_vcpus += 1;
	mutex_unlock(&nested->lock);

	kvmppc_nested_reg_entry_switch(vcpu);

	vcpu->arch.cur_nest = nested;

no_switch:
	vcpu->arch.pc = vcpu->arch.hv_regs.hsrr0;
	vcpu->arch.shregs.msr = vcpu->arch.hv_regs.hsrr1 & ~MSR_HV;

	return EMULATE_DONE;

fail_unlock:
	mutex_unlock(&nested->lock);
	return EMULATE_FAIL;
}

static void kvmppc_nested_reg_exit_switch(struct kvm_vcpu *vcpu)
{
	reg_switch(&vcpu->arch.hv_regs.dawr.val, &vcpu->arch.dawr);
	reg_switch(&vcpu->arch.hv_regs.ciabr.val, &vcpu->arch.ciabr);
	reg_switch(&vcpu->arch.hv_regs.dawrx.val, &vcpu->arch.dawrx);
	reg_switch(&vcpu->arch.hv_regs.hfscr.val, &vcpu->arch.hfscr);
	/* Can do this since there's only one thread per vcore on P9 */
	if (vcpu->arch.hv_regs.lpcr.inited) {
		u64 mask = kvmppc_get_lpcr_mask();
		ulong tmp = vcpu->arch.hv_regs.lpcr.val;
		vcpu->arch.hv_regs.lpcr.val &= ~mask;
		vcpu->arch.hv_regs.lpcr.val |= vcpu->arch.vcore->lpcr & mask;
		vcpu->arch.vcore->lpcr = tmp;
	}
	reg_switch(&vcpu->arch.hv_regs.pcr.val, &vcpu->arch.vcore->pcr);
	reg_switch(&vcpu->arch.hv_regs.amor.val, &vcpu->arch.amor);

	vcpu->arch.hv_regs.nested_dpdes = vcpu->arch.vcore->dpdes & 0x1ULL;
	vcpu->arch.vcore->dpdes = 0;

	kvmppc_update_intr_msr(&vcpu->arch.intr_msr, vcpu->arch.vcore->lpcr);
}

/*
 * This is to switch from the nested guest back to the L1 guest, we need to:
 * - Update the nest state so we use the L1 guest lpid on kvm entry
 * - Switch back any registers we switched on entry
 */
void kvmppc_exit_nested(struct kvm_vcpu *vcpu)
{
	struct kvm_arch_nested *nested = vcpu->arch.cur_nest;

	BUG_ON(!nested);

	mutex_lock(&nested->lock);
	nested->running_vcpus -= 1;
	mutex_unlock(&nested->lock);

	kvmppc_nested_reg_exit_switch(vcpu);

	vcpu->arch.cur_nest = NULL;
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
		vcpu->arch.hv_regs.hdsisr = val;
		rc = EMULATE_DONE;
		break;
	case SPRN_HDAR:
		vcpu->arch.hv_regs.hdar = val;
		rc = EMULATE_DONE;
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
		vcpu->arch.hv_regs.hsrr1 = val;
		rc = EMULATE_DONE;
		break;
	case SPRN_LPCR:
		{
			if (!(val & LPCR_HR)) {
				/* We only support radix nested guests */
				pr_err("KVM: nested HV running hpt guest\n");
				break;
			}

			vcpu->arch.hv_regs.lpcr.val = val;
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
		vcpu->arch.hv_regs.asdr = val;
		rc = EMULATE_DONE;
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
		*val = vcpu->arch.hv_regs.hdsisr;
		rc = EMULATE_DONE;
		break;
	case SPRN_HDAR:
		*val = vcpu->arch.hv_regs.hdar;
		rc = EMULATE_DONE;
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
		*val = vcpu->arch.hv_regs.hsrr1;
		rc = EMULATE_DONE;
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
		*val = vcpu->arch.hv_regs.asdr;
		rc = EMULATE_DONE;
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

	/* The instruction image isn't pulled out correctly, so mask it */
	switch (instr & 0xFF00FFFF) {
	case PPC_INST_HRFID:
		rc = kvmppc_enter_nested(vcpu);
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

void kvmppc_inject_hv_interrupt(struct kvm_vcpu *vcpu, int vec, u64 flags)
{
	if (vcpu->arch.cur_nest)
		kvmppc_exit_nested(vcpu);
#ifdef DEBUG
	pr_info("Injecting hv_int 0x%x (0x%.16llx)\n", vec, flags);
#endif
	vcpu->arch.hv_regs.hsrr0 = kvmppc_get_pc(vcpu);
	vcpu->arch.hv_regs.hsrr1 = kvmppc_get_msr(vcpu) | flags;
	kvmppc_set_pc(vcpu, vec);
	vcpu->arch.mmu.reset_msr(vcpu);
}

void kvmppc_inject_interrupt_hisi(struct kvm_vcpu *vcpu, u64 flags)
{
	vcpu->arch.hv_regs.asdr = vcpu->arch.fault_gpa;
	kvmppc_inject_hv_interrupt(vcpu, BOOK3S_INTERRUPT_H_INST_STORAGE,
				   flags);
}

void kvmppc_inject_interrupt_hdsi(struct kvm_vcpu *vcpu, u64 flags)
{
	vcpu->arch.hv_regs.hdsisr = flags;
	vcpu->arch.hv_regs.hdar = vcpu->arch.fault_dar;
	vcpu->arch.hv_regs.asdr = vcpu->arch.fault_gpa;
	kvmppc_inject_hv_interrupt(vcpu, BOOK3S_INTERRUPT_H_DATA_STORAGE, 0ULL);
}

/* Used to convert a nested guest real address to a L1 guest real address */
int kvmppc_book3s_translate_addr_nested(struct kvm_vcpu *vcpu,
					unsigned long gpa, unsigned long dsisr,
					struct kvmppc_pte *gpte)
{
	unsigned int lpid = vcpu->arch.cur_nest->shadow_lpid;
	u64 flags = 0ULL;
	int rc;

	rc = kvmppc_mmu_radix_translate_table(vcpu, gpa, gpte,
					      vcpu->kvm->arch.ptcr, lpid,
					      false);
	if (rc) {
		/* We didn't find a pte */
		if (rc == -EINVAL) {
			/* Unsupported mmu config */
			flags |= DSISR_UNSUPP_MMU;
		} else if (rc == -ENOENT) {
			/* No translation found */
			flags |= DSISR_NOHPTE;
		} else {
			/* Internal Error */
			return rc;
		}
		if (dsisr) {
			/* This was an HDSI -> Inject HDSI */
			goto inject_hdsi;
		} else {
			/* This was an HISI -> Inject HISI */
			goto inject_hisi;
		}
	}

	/* We found a pte -> check permissions */
	if (dsisr) {
		/* This was an HDSI */
		if (dsisr & DSISR_ISSTORE) {
			/* Can we write? */
			flags |= gpte->may_write ? 0 : DSISR_PROTFAULT;
		} else {
			/* Can we read? */
			flags |= gpte->may_read ? 0 : DSISR_PROTFAULT;
		}
		if (flags) {
			goto inject_hdsi;
		}
	} else {
		/* This was an HISI */
		if (!gpte->may_execute) {
			/* Can we execute? */
			flags |= SRR1_ISI_N_OR_G;
		}
		if (flags) {
			goto inject_hisi;
		}
	}

	/* All Good! */
	return 0;

inject_hdsi:
	flags |= (dsisr & DSISR_ISSTORE);
	kvmppc_inject_interrupt_hdsi(vcpu, flags);
	return 1;
inject_hisi:
	kvmppc_inject_interrupt_hisi(vcpu, flags);
	return 1;
}

int kvmppc_book3s_radix_page_fault_nested(struct kvm_run *run,
					  struct kvm_vcpu *vcpu,
					  unsigned long ea, unsigned long dsisr)
{
	struct kvm_arch_nested *nested = vcpu->arch.cur_nest;
	int p9_radix_level_shifts[4] = { PAGE_SHIFT,
					 PMD_SHIFT,
					 PUD_SHIFT,
					 PGDIR_SHIFT };
	struct kvm *kvm = vcpu->kvm;
	struct kvm_memory_slot *memslot;
	struct kvm_nest_rmap rmap_entry;
	unsigned long gpa, fault_gpa, gfn, mask, perm = 0UL;
	unsigned long mmu_seq;
	unsigned long npages, base_gfn;
	struct kvmppc_pte gpte;
	bool writing = !!(dsisr & DSISR_ISSTORE);
	bool kvm_ro = false;
	unsigned int shift, nested_shift, max_shift, level;
	pte_t pte, *ptep;
	int rc;

	WARN_ON(!nested);

	fault_gpa = vcpu->arch.fault_gpa & ~0xF000000000000FFFULL;
#ifdef DEBUG
	pr_info("gpa: 0x%.16lx\n", fault_gpa);
	pr_info("ea: 0x%.8lx\n", ea);
	pr_info("dsisr: 0x%.8lx\n", dsisr);
	pr_info("nested lpid: %u\n", nested->lpid);
	pr_info("pc: 0x%.16lx\n", vcpu->arch.pc);
	pr_info("msr: 0x%.16llx\n", vcpu->arch.shregs.msr);
#endif

	/* Failed to set the reference/change bits */
	if (dsisr & DSISR_SET_RC) {
		mutex_lock(&nested->lock);

		if (!nested->shadow_pgtable) {
			/* Someone has torn down the pgtable -> nothing to do */
			mutex_unlock(&nested->lock);
			return RESUME_GUEST;
		}

		kvmppc_hv_handle_set_rc(vcpu->kvm, nested->shadow_pgtable,
					&dsisr, fault_gpa);
		mutex_unlock(&nested->lock);
		/*
		 * XXX
		 * - Should we also set the bit in the L1 partition table in L0?
		 * - Should we reflect an interrupt to L1 to set the bit in the
		 *   L2 partition table in L1?
		 */

		if (!(dsisr & (DSISR_BAD_FAULT_64S | DSISR_NOHPTE |
			       DSISR_PROTFAULT | DSISR_SET_RC))) {
			return RESUME_GUEST;
		}
	}

	/*
	 * We took an HISI or an HDSI while we were running the nested guest
	 * which means our partition scoped translation for that guest failed.
	 * Thus we need to insert a pte for this mapping into our shadow
	 * partition table by:
	 * 1. Walking the L1 guest partition table for this guest to convert
	 *    the fault address into an L1 guest real address, or injecting
	 *    an interrupt into the L1 guest if this translation doesn't exist
	 * 2. Converting the L1 guest real address into a host real address
	 *    through our (host) partition scoped tables for the L1 guest
	 * 3. Inserting this translation into our (host) partition scoped
	 *    table for the nested guest (into the shadow_pgtable)
	 */

	rc = kvmppc_book3s_translate_addr_nested(vcpu, fault_gpa, dsisr, &gpte);
	if (rc < 0) {
		return rc;
	} else if (rc) {
		return RESUME_GUEST;
	}
	nested_shift = mmu_psize_to_shift(gpte.page_size);
	if (nested_shift < PAGE_SHIFT) {
		/* We don't support L1 using a size less than our page size */
		pr_err("KVM: Guest page shift (%d) < minimum supported (%d)\n",
			nested_shift, PAGE_SHIFT);
		return -EINVAL;
	}
	mask = (1UL << nested_shift) - PAGE_SIZE;
	gpa = gpte.raddr & ~(0xF000000000000000ULL | mask);
	/* Apply mask of fault_gpa to gpa incase backed by smaller page in L0 */
	gpa |= (fault_gpa & mask);
	gfn = gpa >> PAGE_SHIFT;
	if (!(dsisr & DSISR_PRTABLE_FAULT)) {
		gpa |= ea & 0xFFFULL;
	}

#ifdef DEBUG
	pr_info("KVM: Nest RA 0x%.16lx -> L1 RA 0x%.16lx\n", fault_gpa, gpa);
#endif

	/* Get the corresponding memslot */
	memslot = gfn_to_memslot(kvm, gfn);
	if (!memslot || (memslot->flags & KVM_MEMSLOT_INVALID)) {
		/*
		 * If this was emulated mmio the guest shouldn't have inserted
		 * a pte, some unusual error -> reflect to the guest as a DSI.
		 */
		pr_err("KVM: Invalid host memslot for nested guest pgfault 0x%.16lx\n",
			gfn);
		kvmppc_core_queue_data_storage(vcpu, ea, dsisr);
		return RESUME_GUEST;
	} else if (memslot->flags & KVM_MEM_READONLY) {
		kvm_ro = true;
	}

	/* used to check for invalidations in progress */
	mmu_seq = kvm->mmu_notifier_seq;
	smp_rmb();

	/* See if can find translation in L0 partition scoped tables for L1 */
	spin_lock(&kvm->mmu_lock);
	ptep = __find_linux_pte(kvm->arch.pgtable, gpa, NULL, &shift);
	spin_unlock(&kvm->mmu_lock);

	if (ptep && pte_present(*ptep)) {
		pte = *ptep;

#ifdef DEBUG
		pr_info("KVM: L1 RA 0x%.16lx -> PTE 0x%.16lx (existing)\n",
			gpa, pte_val(pte));
#endif

		if (writing && !(pte_val(pte) & _PAGE_WRITE)) {
			ptep = NULL;
		}
	}
	/* No pte found -> insert mapping in L0 partition table for L1 guest */
	if (!ptep || !pte_present(*ptep)) {
		rc = kvmppc_book3s_handle_radix_page_fault(vcpu, gpa, memslot,
							   writing, kvm_ro,
							   &pte, &level);
		if (rc == -EAGAIN) {
			return RESUME_GUEST;
		} else if (rc) {
			return rc;
		}
		shift = p9_radix_level_shifts[level];
#ifdef DEBUG
		pr_info("KVM: L1 RA 0x%.16lx -> PTE 0x%.16lx (new)\n",
			gpa, pte_val(pte));
#endif
	}

#ifdef DEBUG
	pr_info("KVM: nest shift: %d host shift: %d\n", nested_shift, shift);
#endif

	/* The permission is the combination of the host and L1 guest ptes */
	if (!gpte.may_read)
		perm |= _PAGE_READ;
	if (!gpte.may_write)
		perm |= _PAGE_WRITE;
	if (!gpte.may_execute)
		perm |= _PAGE_EXEC;
	pte = __pte(pte_val(pte) & ~perm);
	/* Compute the PTE that we need to insert */
	level = 0;
	/* What's the biggest pte we can insert? */
	max_shift = min(shift, nested_shift);
	if (max_shift >= PUD_SHIFT) {
		level = 2;
	} else if (max_shift >= PMD_SHIFT) {
		level = 1;
	}
	if (shift > nested_shift) {
		/*
		 * L0 page is larger than L1 page, apply the L1 index
		 * to the L0 pte since we will insert the smaller page.
		 */
		mask = (1UL << shift) - (1UL << nested_shift);
		pte = __pte(pte_val(pte) | (gpa & mask));
	}

	shift = p9_radix_level_shifts[level]; /* what size pte did we insert */
	mask = ~((1UL << shift) - 1);
	base_gfn = (gpa & mask) >> PAGE_SHIFT;
	fault_gpa &= mask;
	npages = 1ULL << (shift - PAGE_SHIFT);
	if (base_gfn < memslot->base_gfn) {
		pr_err("KVM: %s gfn 0x%.16lx out of memslot range\n",
				__func__, base_gfn);
	}

	/*
	 * The only way this can happen is if another thread freed the page
	 * table while we were running the nested guest, which shouldn't be
	 * possible.
	 */
	WARN_ON(!nested->shadow_pgtable);

	rmap_entry.lpid = nested->shadow_lpid;
	rmap_entry.pfn = pte_pfn(pte);
	rmap_entry.nest_gpa = fault_gpa;
	rmap_entry.npages = npages;
	/* Insert the pte into our shadow_pgtable */
	rc = kvmppc_create_pte(kvm, nested->shadow_pgtable, pte,
			       fault_gpa, level, mmu_seq, nested,
			       &memslot->arch.rmap[base_gfn - memslot->base_gfn]
			       , &rmap_entry);
	if (rc == -EAGAIN) {
		/* Go back to the guest so it can try again */
		rc = RESUME_GUEST;
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
	/*
	 * We get these two when the hardware was unable to perform partition
	 * scoped translation of the nested guest real address. This means we're
	 * lacking the translation in the shadow_pgtable for this nested guest.
	 * By returning RESUME_PAGE_FAULT we'll continue the exit path and call
	 * into kvmppc_book3s_radix_page_fault() where an entry will be inserted
	 */
	case BOOK3S_INTERRUPT_H_INST_STORAGE:
		vcpu->arch.fault_dar = kvmppc_get_pc(vcpu);
		vcpu->arch.fault_dsisr = 0;
	case BOOK3S_INTERRUPT_H_DATA_STORAGE:
		rc = RESUME_PAGE_FAULT;
#ifdef DEBUG
		pr_info("Page Fault in Nested Guest: 0x%x\n", vcpu->arch.trap);
#endif
		break;
	case BOOK3S_INTERRUPT_SYSCALL:
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
