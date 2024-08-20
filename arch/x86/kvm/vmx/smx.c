// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include "kvm_cache_regs.h"

#include "smx.h"

static int handle_getsec_capabilities(struct kvm_vcpu *vcpu)
{
    return 0;
}

static int handle_getsec_enteraccs(struct kvm_vcpu *vcpu)
{
    return 0;
}

static int handle_getsec_exitac(struct kvm_vcpu *vcpu)
{
    return 0;
}

int handle_getsec(struct kvm_vcpu *vcpu)
{
	unsigned long cr4 = kvm_read_cr4(vcpu);
    u32 eax = kvm_rax_read(vcpu);

	if (!(cr4 & X86_CR4_SMXE)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

    switch (eax) {
    case CAPABILITIES:
        handle_getsec_capabilities(vcpu);
        break;
    case ENTERACCS:
        handle_getsec_enteraccs(vcpu);
        break;
    case EXITAC:
        handle_getsec_exitac(vcpu);
        break;
    default:
        kvm_queue_exception(vcpu, UD_VECTOR);
        return 1;
    }

	return kvm_skip_emulated_instruction(vcpu);

}