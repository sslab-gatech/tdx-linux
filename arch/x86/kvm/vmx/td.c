// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include "vmx.h"
#include "nested.h"
#include "td.h"

bool is_from_tdcall(struct kvm_vcpu *vcpu, u32 intr_info)
{
    static const char tdcall_bytecode[] = { __TDCALL_BYTECODE };
    char inst[4];
    struct x86_exception e;

    if (!is_invalid_opcode(intr_info))
        return false;

    if (kvm_read_guest_virt(vcpu, kvm_rip_read(vcpu), inst, 
                     sizeof(inst), &e) == 0) {
        if (memcmp(inst, tdcall_bytecode, sizeof(tdcall_bytecode)) == 0)
            return true;
    }

    return false;
}

int handle_tdcall(struct kvm_vcpu *vcpu)
{
    struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
    u32 intr_info = (GP_VECTOR | INTR_TYPE_HARD_EXCEPTION | 
                     INTR_INFO_DELIVER_CODE_MASK | INTR_INFO_VALID_MASK);

    if (!is_guest_mode(vcpu)) {
        // TODO: even non-seam can tdcall?
        kvm_queue_exception(vcpu, UD_VECTOR);
        return 1;
    } else if (vmx_get_cpl(vcpu) > 0) {
        if (vmcs12->exception_bitmap & (1 << GP_VECTOR)) {
            nested_vmx_vmexit(vcpu, EXIT_REASON_EXCEPTION_NMI, intr_info, 0);
        } else {
            kvm_queue_exception_e(vcpu, GP_VECTOR, 0);
        }
        return 1;
    }

    nested_vmx_vmexit(vcpu, EXIT_REASON_TDCALL, 0, 0);
    return 1;
}