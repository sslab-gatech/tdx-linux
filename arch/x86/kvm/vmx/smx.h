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

#define CAPABILITIES_CHIPSET_PRESENT    BIT(0)
#define CAPABILITIES_ENTERACCS          BIT(2)
#define CAPABILITIES_EXITAC             BIT(3)
#define CAPABILITIES_SENTER             BIT(4)
#define CAPABILITIES_SEXIT              BIT(5)
#define CAPABILITIES_PARAMETERS         BIT(6)
#define CAPABILITIES_SMCTRL             BIT(7)
#define CAPABILITIES_WAKEUP             BIT(8)
#define CAPABILITIES_EXTENDED_LEAFS     BIT(31)

int handle_getsec(struct kvm_vcpu *vcpu);

#endif