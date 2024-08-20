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

/* 
 * Intel Trusted Execution Technology (Intel TXT) SDM
 *   A.1.1 ACM Header Format   
 */
struct acm_header {
    // 00000000
    u16 module_type;
    u16 module_sub_type;
    u32 header_len;
    u32 header_version;
    u16 chipset_id;
    u16 flags;

    // 00000010
    u32 module_vendor;
    u32 date;
    u32 size;
    u16 txt_svn;
    u16 sgx_svn;

    // 00000020
    u32 code_control;
    u32 error_entry_point;
    u32 gdt_limit;
    u32 gdt_base_ptr;

    // 00000030
    u32 seg_sel;
    u32 entry_point;
    u8 reserved2[64];

    // 00000078
    u32 key_size;
    u32 scratch_size; // should be 208 in Version 3.0
    u8 rsa_pub_key[384]; // currently only Version 3.0 is allowed
    // u0 rsa_pub_exp;

    // 00000200
    u8 rsa_sig[384]; // Version 3.0
};

int handle_getsec(struct kvm_vcpu *vcpu);

#endif