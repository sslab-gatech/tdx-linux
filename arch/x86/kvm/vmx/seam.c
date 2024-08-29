// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include "kvm_cache_regs.h"

#include "vmx.h"
#include "seam.h"

#include <asm/asm.h>

void mcheck(struct kvm_vcpu *vcpu, gpa_t gpa)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    struct sys_info_table sys_info_table;
    u32 eax = 0x1, ebx, ecx, edx;
    int i;

    struct page *empty_page = alloc_page(GFP_KERNEL);
    // TODO: handle if alloc_page failed

    void *empty = page_address(empty_page);
    memset(empty, 0, PAGE_SIZE);

    sys_info_table.version = 0;
    sys_info_table.tot_num_lps = vcpu->kvm->created_vcpus;
    sys_info_table.tot_num_sockets = 1; // TODO: disable NUMA in QEMU

    kvm_cpuid(vcpu, &eax, &ebx, &ecx, &edx, false);
    for (i = 0; i < SYS_INFO_TABLE_SOCKET_CPUID_TABLE_SIZE; i++) {
        if (i < sys_info_table.tot_num_sockets) {
            sys_info_table.socket_cpuid_table[i] = eax;
        } else {
            sys_info_table.socket_cpuid_table[i] = 0;
        }
    }

    sys_info_table.p_seamldr_range.base = vmx->seamrr.base + vmx->seamrr.size - P_SEAMLDR_RANGE_SIZE;
    sys_info_table.p_seamldr_range.size = P_SEAMLDR_RANGE_SIZE;

    sys_info_table.skip_smrr2_check = 0;
    sys_info_table.tdx_ac = 0;

    // Allow entire physical memory over 4GB as CMR
#define _4GB    0x100000000
    sys_info_table.cmr[0].base = _4GB;
    sys_info_table.cmr[0].size = cpuid_maxphyaddr(vcpu) - _4GB;
    for (i = 1; i < SYS_INFO_TABLE_NUM_CMRS; i++) {
        sys_info_table.cmr[i].base = 0;
        sys_info_table.cmr[i].size = 0;
    }

    kvm_write_guest_page(vcpu->kvm, gpa_to_gfn(gpa), empty, 0, PAGE_SIZE);
    kvm_write_guest(vcpu->kvm, gpa, (void *) &sys_info_table, sizeof(sys_info_table));

    free_page((unsigned long) empty);
}
EXPORT_SYMBOL(mcheck);


void handle_seam_extend(struct kvm_vcpu *vcpu)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    u64 rdx, rax, value;
    rdx = kvm_rdx_read(vcpu);
    rax = kvm_rax_read(vcpu);
    value = (rdx << 32) | (rax & 0xFFFFFFFF);

    gpa_t gpa = value & ~0x1ULL;

    if (value & 1) {
        kvm_write_guest(vcpu->kvm, gpa, (void *) &vmx->seam_extend, sizeof(vmx->seam_extend));
    } else {
        kvm_read_guest(vcpu->kvm, gpa, (void *) &vmx->seam_extend, sizeof(vmx->seam_extend));
    }
    vmx->seam_extend.valid = 1;
}
EXPORT_SYMBOL(handle_seam_extend);

