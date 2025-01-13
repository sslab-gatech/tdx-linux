/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_SEAM_H
#define __KVM_X86_SEAM_H

#include <linux/kvm_host.h>

#include "vmx_vmcs.h"

#define __SEAMCALL_BYTECODE             0x66,0x0f,0x01,0xcf
#define __SEAMRET_BYTECODE              0x66,0x0f,0x01,0xcd
#define __SEAMOPS_BYTECODE              0x66,0x0f,0x01,0xce

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
    u8 smrr2_not_supported;
    u8 tdx_without_integrity;
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

#define vmcs_read(field) \
    *((u64 *) ((u8 *) (vmcs + VMX_##field##_OFFSET))) & \
        (VMX_##field##_SIZE == 8 ? -1ULL : ((1ULL << (8 * VMX_##field##_SIZE)) - 1))
#define vmcs_write(field, value) \
    switch(VMX_##field##_SIZE) { \
    case 1: \
        *((u8 *) (vmcs + VMX_##field##_OFFSET)) = ((u8) value); \
        break; \
    case 2: \
        *((u16 *) ((u8 *) (vmcs + VMX_##field##_OFFSET))) = ((u16) value); \
        break; \
    case 4: \
        *((u32 *) ((u8 *) (vmcs + VMX_##field##_OFFSET))) = ((u32) value); \
        break; \
    case 8: \
        *((u64 *) ((u8 *) (vmcs + VMX_##field##_OFFSET))) = ((u64) value); \
        break; \
    default: \
        printk(KERN_WARNING "%s: unsupported size %d for vmcs_write\n", __func__, VMX_##field##_SIZE); \
    }

#define read_segment_helper(seg) \
static inline void read_segment_##seg(struct kvm_segment *var, u8 *vmcs)    \
{   \
    u32 ar; \
    var->base = vmcs_read(GUEST_##seg##_BASE);  \
    var->limit = vmcs_read(GUEST_##seg##_LIMIT);    \
    var->selector = vmcs_read(GUEST_##seg##_SELECTOR);  \
    ar = vmcs_read(GUEST_##seg##_ARBYTE);   \
    var->type = ar & 15;    \
    var->s = (ar >> 4) & 1; \
    var->dpl = (ar >> 5) & 3;   \
    var->present = (ar >> 7) & 1;  \
    var->avl = (ar >> 12) & 1;  \
    var->l = (ar >> 13) & 1;    \
    var->db = (ar >> 14) & 1;   \
    var->g = (ar >> 15) & 1;    \
    var->unusable = !var->present; \
}

read_segment_helper(CS)
read_segment_helper(SS)
read_segment_helper(DS)
read_segment_helper(ES)
read_segment_helper(FS)
read_segment_helper(GS)
read_segment_helper(LDTR)
read_segment_helper(TR)

#define CAPABILITIES_SEAMREPORT     BIT(1)
#define CAPABILITIES_SEAMDB_CLEAR   BIT(2)
#define CAPABILITIES_SEAMDB_INSERT  BIT(3)
#define CAPABILITIES_SEAMDB_GETREF  BIT(4)
#define CAPABILITIES_SEAMDB_REPORT  BIT(5)

void mcheck(struct kvm_vcpu *vcpu, gpa_t gpa);
void handle_seamextend(struct kvm_vcpu *vcpu);

int handle_seamcall(struct kvm_vcpu *vcpu);
int handle_seamret(struct kvm_vcpu *vcpu);
int handle_seamops(struct kvm_vcpu *vcpu);
__init int seam_vmx_hardware_setup(int (*exit_handlers[])(struct kvm_vcpu *));

#endif