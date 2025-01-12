// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include "vmx.h"
#include "mktme.h"

int read_wbinvdp(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);

    if (!vmx->seam_mode)
        return 1;
// TODO: invoked from vmx loads/stores

    msr_info->data = NUM_CACHE_BLOCKS;
    return 0;
}

int write_wbinvdp(struct kvm_vcpu *vcpu)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    u64 rdx, rax, idx;
    rdx = kvm_rdx_read(vcpu);
    rax = kvm_rax_read(vcpu);

    if (!vmx->seam_mode)
        return 1;

    idx = (rdx << 32) | rax;
    if (idx > NUM_CACHE_BLOCKS)
        return 1;
// TODO: invoked from vmx loads/stores

    return kvm_emulate_wbinvd(vcpu);
}