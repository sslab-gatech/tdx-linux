/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_SEAM_H
#define __KVM_X86_SEAM_H

#include <linux/kvm_host.h>

#define MTRR_SEAMRR_ENABLED             BIT(15)

#define MSR_IA32_SEAMRR_PHYS_BASE       0x1400
#define MSR_IA32_SEAMRR_PHYS_MASK       0x1401
#define MSR_IA32_SEAMEXTEND             0x1402

#define SEAMRR_BASE_CONFIGURE_OFFSET    3
#define SEAMRR_BASE_CONFIGURED          BIT(3)
#define SEAMRR_BASE_ALIGN               25
#define SEAMRR_BASE_BITS_MASK(maxphyaddr)   (((1ULL<<maxphyaddr) - 1) & ~((1ULL<<SEAMRR_BASE_ALIGN) - 1))
#define SEAMRR_MASK_LOCK_OFFSET             10
#define SEAMRR_MASK_LOCKED                  BIT(10)
#define SEAMRR_MASK_ENABLE_OFFSET           11
#define SEAMRR_MASK_ENABLED                 BIT(11)
#define SEAMRR_MASK_ALIGN               25
#define SEAMRR_MASK_BITS_MASK(maxphyaddr)   (((1ULL<<maxphyaddr) - 1) & ~((1ULL<<SEAMRR_MASK_ALIGN) - 1))

#define P_SEAMLDR_RANGE_SIZE            (1ULL << SEAMRR_MASK_ALIGN)

struct seam_range {
    u8 configured;
    u8 locked;
    u8 enabled;
    u64 base;
    u64 size;
};

struct mem_range {
    u64 base;
    u64 size;
};

#define SYS_INFO_TABLE_SOCKET_CPUID_TABLE_SIZE  8
#define SYS_INFO_TABLE_NUM_CMRS                 32

struct sys_info_table {
    u64 version;
    u32 tot_num_lps;
    u32 tot_num_sockets;
    u32 socket_cpuid_table[SYS_INFO_TABLE_SOCKET_CPUID_TABLE_SIZE];
    struct mem_range p_seamldr_range;
    u8 skip_smrr2_check;
    u8 tdx_ac;
    u8 reserved0[62];
    struct mem_range cmr[SYS_INFO_TABLE_NUM_CMRS];
    // u8 reserved1[1408]; // Commented due to frame size warning
};

struct msr_seam_extend {
    u64 valid;
    u8 tee_tcb_svn[16];
    u8 mr_seam[48];
    u8 mr_signer[48];
    u64 attributes;
    u8 seam_ready;
    u8 seam_under_debug;
    u8 p_seamldr_ready;
    u8 reserved[5];
};

void mcheck(struct kvm_vcpu *vcpu, gpa_t gpa);
void handle_seam_extend(struct kvm_vcpu *vcpu);

int handle_seamcall(struct kvm_vcpu *vcpu);

#endif