/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_MKTME_H
#define __KVM_X86_MKTME_H

#include <linux/bits.h>
#include <linux/kvm_host.h>

#define __PCONFIG_BYTECODE              0x0f,0x01,0xc5

#define MSR_IA32_WBINVDP                0x98
#define MSR_IA32_WBNOINVDP              0x99
#define NUM_CACHE_BLOCKS                0x1

#define KEYID_BITS  6ULL

#define MSR_IA32_TME_CAPABILITY         0x981
#define TME_CAP_AES_128                 BIT(0)
#define TME_CAP_AES_128_INT             BIT(1)
#define TME_CAP_AES_256                 BIT(2)
#define TME_CAP_AES_256_INT             BIT(3)
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
	return (data >> TME_ACT_MKTME_ENC_ALG_OFFSET) & 0xf;
}

static inline u8 keyid_bits(u64 data) {
    return (data >> TME_CAP_KEYID_BITS_OFFSET) & 0xf;
}

static inline u8 tdx_keyid_bits(u64 data) {
    return (data >> TME_ACT_TDX_KEYID_BITS_OFFSET) & 0xf;
}

static inline u32 keyid_mask(u64 data) {
    return (1 << keyid_bits(data)) - 1;
}

static inline u32 num_keyids(u64 msr_tme_activate) {
    bool locked = tme_locked(msr_tme_activate);
    return locked ? (1 << (keyid_bits(msr_tme_activate) - tdx_keyid_bits(msr_tme_activate))) - 1 : 0;
}

static inline u64 num_tdx_keyids(u64 msr_tme_activate) {
    bool locked = tme_locked(msr_tme_activate);
    return locked ? (1 << (keyid_bits(msr_tme_activate))) - num_keyids(msr_tme_activate) - 1: 0;
}

int read_wbinvdp(struct kvm_vcpu *vcpu, struct msr_data *msr_info);
int write_wbinvdp(struct kvm_vcpu *vcpu);

#define PCONFIG_MKTME_KEY_PROGRAM           0x0

// keyid_ctrl command types
#define MKTME_KEYID_SET_KEY_DIRECT 0
#define MKTME_KEYID_SET_KEY_RANDOM 1
#define MKTME_KEYID_CLEAR_KEY      2
#define MKTME_KEYID_NO_ENCRYPT     3

// key program return value
#define PROG_SUCCESS            0
#define INVALID_PROG_CMD        1
#define ENTROPY_ERR             2
#define INVALID_KEYID           3
#define INVALID_CRYPTO_ARG      4
#define DEVICE_BUSY             5 

#define MKTME_KP_RESERVED1_SIZE     (64 - sizeof(u16) - sizeof(mktme_keyid_ctrl_t))
#define MKTME_KP_KEY_FIELD_SIZE     64
#define MKTME_KP_RESERVED2_SIZE     (256 - 64 - MKTME_KP_KEY_FIELD_SIZE)

typedef union mktme_keyid_ctrl {
    struct {
        u32 command  : 8;
        u32 enc_algo : 16;
        u32 rsvd     : 8;
    };
    u32 raw;
} mktme_keyid_ctrl_t;

typedef struct mktme_key_program {
    u16 key_id;
    mktme_keyid_ctrl_t keyid_ctrl;
    u8 rsvd1[MKTME_KP_RESERVED1_SIZE];
    u8 key_field1[MKTME_KP_KEY_FIELD_SIZE];
    u8 key_field2[MKTME_KP_KEY_FIELD_SIZE];
    u8 rsvd2[MKTME_KP_RESERVED2_SIZE];
} __packed mktme_key_program_t;

typedef struct mktme_entry {
    u16 key_id;
    u8 key[32];
    u8 enc_mode;
    // TODO: we need metadata here to track all EPTE accessed with this key_id
} mktme_entry_t;

typedef struct keyid_of_page {
    u16 keyid;
    struct list_head page_list;
} keyid_of_page_t;

typedef struct sptep_of_page {
    u16 keyid;
    u64 *sptep;
    struct list_head node;
} sptep_of_page_t;

#define KEYID_EMPTY     0

u16 keyid_of(gpa_t gpa, struct kvm *kvm);
bool has_keyid(gpa_t gpa, struct kvm *kvm);
bool is_tdx_keyid(u16 keyid, struct kvm *kvm);
gpa_t gpa_without_keyid(gpa_t gpa, struct kvm *kvm);
gpa_t gpa_with_keyid(gpa_t gpa, u16 keyid, struct kvm *kvm);

int handle_pconfig(struct kvm_vcpu *vcpu);

int get_mktme_state(struct kvm_vcpu *vcpu, struct kvm_mktme_state __user *user_kvm_mktme_state);
int get_mktme_entries(struct kvm_vcpu *vcpu, struct kvm_mktme_entries __user *user_mktme_entries);
int get_page_keyids(struct kvm_vcpu *vcpu, struct kvm_page_keyids __user *user_page_keyids);

#endif