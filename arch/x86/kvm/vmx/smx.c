// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include "kvm_cache_regs.h"

#include "x86.h"
#include "vmx.h"
#include "smx.h"

static int handle_getsec_capabilities(struct kvm_vcpu *vcpu)
{
    u32 eax;
    u32 ebx = kvm_rbx_read(vcpu);

#define CAPABILITIES_DEFAULT 0
    if (ebx == CAPABILITIES_DEFAULT) {
        eax = CAPABILITIES_CHIPSET_PRESENT | CAPABILITIES_ENTERACCS | CAPABILITIES_EXITAC;
        kvm_rax_write(vcpu, eax);
    } else {
        kvm_rax_write(vcpu, 0);
    }
    return 0;
}

static int handle_getsec_enteraccs(struct kvm_vcpu *vcpu)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    unsigned long acm_base = kvm_rbx_read(vcpu);
    unsigned long acm_size = kvm_rcx_read(vcpu);

    {
        /* Bunch of sanity checks go here.
         * See Intel SDM Volume 2D 7.3
         */
        if (!(is_protmode(vcpu) && (
                vmx_get_cpl(vcpu) == 0
                && !(vmx_get_rflags(vcpu) & X86_EFLAGS_VM)))) {
            return 1;
        }
        if (vmx->authenticated_code_execution_mode)
            return 1;
        if (is_smm(vcpu) || vmx->nested.vmxon)
            return 1;

#define ACMBASE_ALIGN 4096
#define ACMSIZE_ALIGN 64
#define ACMADDR_LIMIT 0xFFFFFFFF
        if (acm_base % ACMBASE_ALIGN != 0 || acm_size % ACMSIZE_ALIGN != 0 ||
            (acm_base + acm_size) > ACMADDR_LIMIT)
            return 1;

// TODO: Shut down TXT upon detecting memory for ACM is not WB

    }
// TODO: Mask external signals INIT#, A20M, NMI#, and SMI# asserted to ILPs

    vmx->authenticated_code_execution_mode = true;
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

    int err;

	if (!(cr4 & X86_CR4_SMXE)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

    switch (eax) {
    case CAPABILITIES:
        err = handle_getsec_capabilities(vcpu);
        break;
    case ENTERACCS:
        err = handle_getsec_enteraccs(vcpu);
        break;
    case EXITAC:
        err = handle_getsec_exitac(vcpu);
        break;
    default:
        kvm_queue_exception(vcpu, UD_VECTOR);
        return 1;
    }

	return kvm_complete_insn_gp(vcpu, err);

}