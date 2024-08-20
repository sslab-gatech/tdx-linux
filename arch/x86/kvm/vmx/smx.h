/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_SMX_H
#define __KVM_X86_SMX_H

#include <linux/kvm_host.h>

enum smx_getsec_function {
    CAPABILITIES = 0x00,
    ENTERACCS    = 0x02,
    EXITAC       = 0x03,
    SENTER       = 0x04,
    SEXIT        = 0x05,
    PARAMETERS   = 0x06,
    SMCTRL       = 0x07,
    WAKEUP       = 0x08,
};

int handle_getsec(struct kvm_vcpu *vcpu);

#endif