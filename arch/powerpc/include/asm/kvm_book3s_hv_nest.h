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
int kvmppc_emulate_priv(struct kvm_run *run, struct kvm_vcpu *vcpu,
			unsigned int instr);
#endif /* CONFIG_KVM_BOOK3S_HV_NEST_POSSIBLE */

#endif /* __POWERPC_KVM_BOOK3S_HV_NEST_H__ */
