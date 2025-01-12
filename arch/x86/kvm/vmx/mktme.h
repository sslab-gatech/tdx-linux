/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_MKTME_H
#define __KVM_X86_MKTME_H

#include <linux/bits.h>
#include <linux/kvm_host.h>

#define MSR_IA32_WBINVDP                0x98
#define MSR_IA32_WBNOINVDP              0x99
#define NUM_CACHE_BLOCKS                0x1

#define KEYID_BITS  6ULL

#define MSR_IA32_TME_CAPABILITY         0x981
#define TME_CAP_AES_128                 BIT(0)
#define TME_CAP_AES_128_INT             BIT(1)
#define TME_CAP_AES_256                 BIT(2)
#define TME_CAP_BYPASS_SUPPORTED        BIT(31)
#define TME_CAP_KEYID_BITS_OFFSET       32
#define TME_CAP_KEYID_NUM_OFFSET        36
#define TME_CAP_KEYID_BITS              (KEYID_BITS << TME_CAP_KEYID_BITS_OFFSET)
#define TME_CAP_KEYID_NUM               (((1ULL << KEYID_BITS) - 1) << TME_CAP_KEYID_NUM_OFFSET)

#define MSR_IA32_TME_ACTIVATE           0x982
#define TME_ACT_LOCKED                  BIT(0)
#define TME_ACT_ENC_ENABLED             BIT(1)
#define TME_ACT_KEY_SELECT              BIT(2)
#define TME_ACT_KEY_SAVE                BIT(3)
#define TME_ACT_ENC_ALG_OFFSET          4
#define TME_ACT_BYPASS_ENABLED          BIT(31)
#define TME_ACT_KEYID_BITS_OFFSET       32
#define TME_ACT_TDX_KEYID_BITS_OFFSET   36
#define TME_ACT_MKTME_ENC_ALG_OFFSET    48
#define TME_ACT_RESERVED1               0x7fffff00ULL
#define TME_ACT_RESERVED2               0xfff8000000000000ULL

static inline bool tme_locked(u64 data) {
    return !!(data & TME_ACT_LOCKED);
}

static inline bool tme_enabled(u64 data) {
    return !!(data & TME_ACT_ENC_ENABLED);
}

static inline u8 enc_alg(u64 data) {
    return 1 << ((data >> TME_ACT_ENC_ALG_OFFSET) & 0xf);
}

static inline u8 mktme_enc_alg(u64 data) {
	return 1 << ((data >> TME_ACT_MKTME_ENC_ALG_OFFSET) & 0xf);
}

static inline u8 keyid_bits(u64 data) {
    return (data >> TME_CAP_KEYID_BITS_OFFSET) & 0xf;
}

static inline u8 tdx_keyid_bits(u64 data) {
    return (data >> TME_ACT_TDX_KEYID_BITS_OFFSET) & 0xf;
}

static inline u32 num_keyids(u64 msr_tme_activate) {
    bool locked = tme_locked(msr_tme_activate);
    return locked ? 1 << (keyid_bits(msr_tme_activate) - tdx_keyid_bits(msr_tme_activate)) : 0;
}

static inline u64 num_tdx_keyids(u64 msr_tme_activate) {
    bool locked = tme_locked(msr_tme_activate);
    return locked ? (1 << (keyid_bits(msr_tme_activate))) - num_keyids(msr_tme_activate) : 0;
}

int read_wbinvdp(struct kvm_vcpu *vcpu, struct msr_data *msr_info);
int write_wbinvdp(struct kvm_vcpu *vcpu);

#endif