/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TD_H
#define __KVM_X86_TD_H

#include <linux/kvm_host.h>

#define __TDCALL_BYTECODE            0x66,0x0f,0x01,0xcc

bool is_from_tdcall(struct kvm_vcpu *vcpu, u32 intr_info);
int handle_tdcall(struct kvm_vcpu *vcpu);

#endif