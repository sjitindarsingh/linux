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

#undef DEBUG

void kvmppc_vcpu_nested_init(struct kvm_vcpu *vcpu)
{
}

static int kvmppc_emulate_priv_mtspr(struct kvm_run *run, struct kvm_vcpu *vcpu,
				     unsigned int instr)
{
	int rs, sprn, rc = EMULATE_FAIL;

	rs = get_rs(instr);
	sprn = get_sprn(instr);

	switch (sprn) {
	case SPRN_DPDES:
	case SPRN_DAWR:
	case SPRN_RPR:
	case SPRN_CIABR:
	case SPRN_DAWRX:
	case SPRN_HFSCR:
		/* XXX TODO */
		break;
	case SPRN_TBWL:
	case SPRN_TBWU:
	case SPRN_TBU40:
		/* XXX TODO */
		break;
	case SPRN_HSPRG0:
	case SPRN_HSPRG1:
	case SPRN_HDSISR:
	case SPRN_HDAR:
	case SPRN_SPURR:
	case SPRN_PURR:
	case SPRN_HDEC:
	case SPRN_HRMOR:
	case SPRN_HSRR0:
	case SPRN_HSRR1:
		/* XXX TODO */
		break;
	case SPRN_LPCR:
	case SPRN_LPID:
	case SPRN_HMER:
	case SPRN_HMEER:
	case SPRN_PCR:
	case SPRN_HEIR:
	case SPRN_AMOR:
	case SPRN_PTCR:
		/* XXX TODO */
		break;
	case SPRN_ASDR:
	case SPRN_IC:
	case SPRN_VTB:
	case SPRN_PSSCR:
		/* XXX TODO */
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

	rt = get_rt(instr);
	sprn = get_sprn(instr);

	switch (sprn) {
	case SPRN_DAWR:
	case SPRN_RPR:
	case SPRN_CIABR:
	case SPRN_DAWRX:
	case SPRN_HFSCR:
		/* XXX TODO */
		break;
	case SPRN_HSPRG0:
	case SPRN_HSPRG1:
	case SPRN_HDSISR:
	case SPRN_HDAR:
	case SPRN_HDEC:
	case SPRN_HRMOR:
	case SPRN_HSRR0:
	case SPRN_HSRR1:
		/* XXX TODO */
		break;
	case SPRN_LPCR:
	case SPRN_LPID:
	case SPRN_HMER:
	case SPRN_HMEER:
	case SPRN_PCR:
	case SPRN_HEIR:
	case SPRN_AMOR:
	case SPRN_PTCR:
		/* XXX TODO */
		break;
	case SPRN_ASDR:
	case SPRN_PSSCR:
		/* XXX TODO */
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
		/* XXX TODO */
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

void kvmppc_init_vm_hv_nest(struct kvm *kvm)
{
	INIT_LIST_HEAD(&kvm->arch.nested);
}

void kvmppc_destroy_vm_hv_nest(struct kvm *kvm)
{
}
