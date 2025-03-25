/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_VMX_VIRTUALIZATION_EXCEPTION_H
#define __KVM_X86_VMX_VIRTUALIZATION_EXCEPTION_H

/* Virtualization-Exception Information Area */
struct kvm_ve_info {
    u32 exit_reason;
    u32 reserved;
    u64 exit_qual;
    u64 guest_linear_address;
    u64 guest_physical_address;
    u16 eptp_index;
} __aligned(64);

#endif

