// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include "kvm_cache_regs.h"

#include "vmx.h"
#include "seam.h"
#include "nested.h"

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

static void save_vmm_state(struct kvm_vcpu *vcpu, gpa_t vmcs)
{
}

static void load_seam_state(struct kvm_vcpu *vcpu, gpa_t vmcs)
{
}

int handle_seamcall(struct kvm_vcpu *vcpu)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    u64 efer, seam_cvp, rax, rflags;
    u32 eax, ebx, ecx, edx;
    struct kvm_segment cs;
    int err = 0;

    kvm_get_msr(vcpu, MSR_EFER, &efer);
    vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);

    eax = 0xb;
    ecx = ebx = edx = 0x0;
    kvm_cpuid(vcpu, &eax, &ebx, &ecx, &edx, false);

    
    if (!vmx->nested.vmxon || vmx->seam_mode || (!(efer & EFER_LMA) || !cs.l)) {
        kvm_queue_exception(vcpu, UD_VECTOR);
        return 1;
    } else if (is_guest_mode(vcpu)) {
        nested_vmx_vmexit(vcpu, EXIT_REASON_SEAMCALL, 0, 0);
        return 1;
    } else if (vmx_get_cpl(vcpu) > 0 || vmx->seamrr.enabled == 0) {
// TODO: events blocking by MOV-SS
        err = 1;
        goto exit;
    }

    seam_cvp = (vmx->seamrr.base + PAGE_SIZE) + (edx & 0xFFFFFFFF) * PAGE_SIZE;

    rax = kvm_rax_read(vcpu);

#define INVOKE_PSEAMLDR (1ULL << 63)
    if (rax & INVOKE_PSEAMLDR) {
// TODO: Acquire P_SEAMLDR_MUTEX
// TODO: Check P_SEAMLDR is loaded and enabled
        kvm_set_rflags(vcpu, X86_EFLAGS_CF);
        goto exit;

        vmx->in_pseamldr = true;
    } else {
// TODO: Check TDX Module is loaded
        kvm_set_rflags(vcpu, X86_EFLAGS_CF);
        goto exit;
    }

    rflags = kvm_get_rflags(vcpu);
    kvm_set_rflags(vcpu, rflags & 
        ~(X86_EFLAGS_CF | X86_EFLAGS_OF | X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF));

    vmx->seam_mode = true;

    if (vmx->nested.current_vmptr != INVALID_GPA)
        printk(KERN_WARNING "%s: Do not support current-VMCS on SEAMCALL\n", 
               __func__);

// TODO: Save event inhibits in VMM interruptability status
// TODO: Inhibit SMI and NMI
    save_vmm_state(vcpu, seam_cvp);
    load_seam_state(vcpu, seam_cvp);

exit:
    return kvm_complete_insn_gp(vcpu, 0);
}