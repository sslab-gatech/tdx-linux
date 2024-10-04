// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include "asm/msr-index.h"
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

static void save_vmm_state(struct kvm_vcpu *vcpu, u8 *vmcs)
{
#define ONLY_DEFINES
#include "vmx_vmcs.h"
    u32 exit_ctls = vmcs_read(VM_EXIT_CONTROL);

    /* 28.3 Saving Guest State */

    /* 28.3.1 Saving Control Registers, Debug Registers, and MSRs */

    vmcs_write(GUEST_CR0, vmcs_readl(GUEST_CR0));
    vmcs_write(GUEST_CR3, vmcs_readl(GUEST_CR3));
    vmcs_write(GUEST_CR4, vmcs_readl(GUEST_CR4));

    vmcs_write(GUEST_IA32_SYSENTER_CS, vmcs_read32(GUEST_SYSENTER_CS));
    vmcs_write(GUEST_IA32_SYSENTER_ESP, vmcs_readl(GUEST_SYSENTER_ESP));
    vmcs_write(GUEST_IA32_SYSENTER_EIP, vmcs_readl(GUEST_SYSENTER_EIP));

    if (exit_ctls & VM_EXIT_SAVE_DEBUG_CONTROLS) {
        vmcs_write(GUEST_DR7, vmcs_readl(GUEST_DR7));
        vmcs_write(GUEST_IA32_DEBUGCTLMSR_FULL, vmcs_read64(GUEST_IA32_DEBUGCTL));
    }
    if (exit_ctls & VM_EXIT_SAVE_IA32_PAT)
        vmcs_write(GUEST_IA32_PAT_FULL, vmcs_read64(GUEST_IA32_PAT));
    if (exit_ctls & VM_EXIT_SAVE_IA32_EFER)
        vmcs_write(GUEST_IA32_EFER_FULL, vmcs_read64(GUEST_IA32_EFER));
// TODO: IA32_BNDCFGS
    vmcs_write(GUEST_RTIT_CTL_FULL, vmcs_read64(GUEST_IA32_RTIT_CTL));
    vmcs_write(GUEST_IA32_S_CET, vmcs_readl(GUEST_S_CET));
    vmcs_write(GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR, vmcs_readl(GUEST_INTR_SSP_TABLE));
// TODO: IA32_LBR_CTL
// TODO: IA32_PKRS
// TODO: User interrupts
// TODO: IA32_PERF_GLOBAL_CTL

    /* 28.3.2 Saving Segment Registers and Descriptor-Table Registers */

    vmcs_write(GUEST_CS_SELECTOR, vmcs_read16(GUEST_CS_SELECTOR));
    vmcs_write(GUEST_CS_ARBYTE, vmcs_read32(GUEST_CS_AR_BYTES));
    vmcs_write(GUEST_CS_LIMIT, vmcs_read32(GUEST_CS_LIMIT));
    vmcs_write(GUEST_CS_BASE, vmcs_readl(GUEST_CS_BASE));

    vmcs_write(GUEST_SS_SELECTOR, vmcs_read16(GUEST_SS_SELECTOR));
    vmcs_write(GUEST_SS_ARBYTE, vmcs_read32(GUEST_SS_AR_BYTES));
    vmcs_write(GUEST_SS_LIMIT, vmcs_read32(GUEST_SS_LIMIT));
    vmcs_write(GUEST_SS_BASE, vmcs_readl(GUEST_SS_BASE));

    vmcs_write(GUEST_DS_SELECTOR, vmcs_read16(GUEST_DS_SELECTOR));
    vmcs_write(GUEST_DS_ARBYTE, vmcs_read32(GUEST_DS_AR_BYTES));
    vmcs_write(GUEST_DS_LIMIT, vmcs_read32(GUEST_DS_LIMIT));
    vmcs_write(GUEST_DS_BASE, vmcs_readl(GUEST_DS_BASE));

    vmcs_write(GUEST_ES_SELECTOR, vmcs_read16(GUEST_ES_SELECTOR));
    vmcs_write(GUEST_ES_ARBYTE, vmcs_read32(GUEST_ES_AR_BYTES));
    vmcs_write(GUEST_ES_LIMIT, vmcs_read32(GUEST_ES_LIMIT));
    vmcs_write(GUEST_ES_BASE, vmcs_readl(GUEST_ES_BASE));

    vmcs_write(GUEST_FS_SELECTOR, vmcs_read16(GUEST_FS_SELECTOR));
    vmcs_write(GUEST_FS_ARBYTE, vmcs_read32(GUEST_FS_AR_BYTES));
    vmcs_write(GUEST_FS_LIMIT, vmcs_read32(GUEST_FS_LIMIT));
    vmcs_write(GUEST_FS_BASE, vmcs_readl(GUEST_FS_BASE));

    vmcs_write(GUEST_GS_SELECTOR, vmcs_read16(GUEST_GS_SELECTOR));
    vmcs_write(GUEST_GS_ARBYTE, vmcs_read32(GUEST_GS_AR_BYTES));
    vmcs_write(GUEST_GS_LIMIT, vmcs_read32(GUEST_GS_LIMIT));
    vmcs_write(GUEST_GS_BASE, vmcs_readl(GUEST_GS_BASE));

    vmcs_write(GUEST_LDTR_SELECTOR, vmcs_read16(GUEST_LDTR_SELECTOR));
    vmcs_write(GUEST_LDTR_ARBYTE, vmcs_read32(GUEST_LDTR_AR_BYTES));
    vmcs_write(GUEST_LDTR_LIMIT, vmcs_read32(GUEST_LDTR_LIMIT));
    vmcs_write(GUEST_LDTR_BASE, vmcs_readl(GUEST_LDTR_BASE));

    vmcs_write(GUEST_TR_SELECTOR, vmcs_read16(GUEST_TR_SELECTOR));
    vmcs_write(GUEST_TR_ARBYTE, vmcs_read32(GUEST_TR_AR_BYTES));
    vmcs_write(GUEST_TR_LIMIT, vmcs_read32(GUEST_TR_LIMIT));
    vmcs_write(GUEST_TR_BASE, vmcs_readl(GUEST_TR_BASE));

    vmcs_write(GUEST_GDTR_BASE, vmcs_readl(GUEST_GDTR_BASE));
    vmcs_write(GUEST_GDTR_LIMIT, vmcs_read32(GUEST_GDTR_LIMIT));

    vmcs_write(GUEST_IDTR_BASE, vmcs_readl(GUEST_IDTR_BASE));
    vmcs_write(GUEST_IDTR_LIMIT, vmcs_read32(GUEST_IDTR_LIMIT));

    /* 28.3.3 Saving RIP, RSP, RFLAGS, and SSP */

    vmcs_write(GUEST_RSP, vmcs_readl(GUEST_RSP));
    vmcs_write(GUEST_RIP, vmcs_readl(GUEST_RIP));
    vmcs_write(GUEST_RFLAGS, vmcs_readl(GUEST_RFLAGS));
    vmcs_write(GUEST_SSP, vmcs_readl(GUEST_SSP));
// TODO: handling Resume Flag?

    /* 28.3.4 Saving Non-Register State */
    vmcs_write(GUEST_SLEEP_STATE, vmcs_read32(GUEST_ACTIVITY_STATE));
    vmcs_write(GUEST_INTERRUPTIBILITY, vmcs_read32(GUEST_INTERRUPTIBILITY_INFO)); // TODO
    vmcs_write(GUEST_PND_DEBUG_EXCEPTION, vmcs_readl(GUEST_PENDING_DBG_EXCEPTIONS)); // TODO
// TODO: VMX-preemption timer value
// NOTE: EPT is not used for SEAM VMCS

    /* 28.4 Saving MSRs */
    // NOTE: MSR Saving is not used for SEAM VMCS
}

static void load_seam_state(struct kvm_vcpu *vcpu, u8 *vmcs)
{
#define ONLY_DEFINES
#include "vmx_vmcs.h"
    u32 exit_ctls = vmcs_read(VM_EXIT_CONTROL);

    unsigned long cr0, cr3, cr4;
    u64 efer;
    struct kvm_segment cs, ss, ds, es, fs, gs, tr;
    struct kvm_segment ldtr;
    struct desc_ptr gdtr, idtr;
    unsigned long rip, rsp, rflags;
    u32 instr_len; 

    cr0 = vmcs_read(HOST_CR0);
    cr3 = vmcs_read(HOST_CR3);
    cr4 = vmcs_read(HOST_CR4);

    /* 28.5 Loading Host State */

    /* 28.5.1 Loading Host Control Registers, Debug Registers, MSRs */

// TODO: Check CR0, CR3, CR4
    kvm_set_cr0(vcpu, cr0);
    kvm_set_cr3(vcpu, cr3);

    if (exit_ctls & VM_EXIT_HOST_ADDR_SPACE_SIZE)
        cr4 |= X86_CR4_PAE;
    else
        cr4 &= ~X86_CR4_PCIDE;
    kvm_set_cr4(vcpu, cr4);

    kvm_set_dr(vcpu, 7, 0x400);
// TODO: Handle clear UINV

    kvm_emulate_msr_write(vcpu, MSR_IA32_DEBUGCTLMSR, 0x0);
    kvm_emulate_msr_write(vcpu, MSR_IA32_SYSENTER_CS, vmcs_read(HOST_IA32_SYSENTER_CS));
    kvm_emulate_msr_write(vcpu, MSR_IA32_SYSENTER_ESP, vmcs_read(HOST_IA32_SYSENTER_ESP));
    kvm_emulate_msr_write(vcpu, MSR_IA32_SYSENTER_EIP, vmcs_read(HOST_IA32_SYSENTER_EIP));

#ifdef CONFIG_X86_64
    kvm_emulate_msr_write(vcpu, MSR_FS_BASE, vmcs_read(HOST_FS_BASE));
    kvm_emulate_msr_write(vcpu, MSR_GS_BASE, vmcs_read(HOST_GS_BASE));
#endif

    if (exit_ctls & VM_EXIT_LOAD_IA32_EFER) {
        efer = vmcs_read(HOST_IA32_EFER_FULL);
        efer &= (exit_ctls & VM_EXIT_HOST_ADDR_SPACE_SIZE) ? -1ULL : ~(EFER_LMA | EFER_LME);

        kvm_emulate_msr_write(vcpu, MSR_EFER, efer);
    }
    if (exit_ctls & VM_EXIT_LOAD_IA32_PAT)
        kvm_emulate_msr_write(vcpu, MSR_IA32_CR_PAT, vmcs_read(HOST_IA32_PAT_FULL));
// TODO: IA32_PERF_GLOBAL_CTL
// TODO: IA32_BNDCFGS
    if (exit_ctls & VM_EXIT_CLEAR_IA32_RTIT_CTL)
        kvm_emulate_msr_write(vcpu, MSR_IA32_RTIT_CTL, 0x0);
    if (exit_ctls & VM_EXIT_LOAD_CET_STATE) {
        kvm_emulate_msr_write(vcpu, MSR_IA32_S_CET, vmcs_read(HOST_IA32_S_CET));
        kvm_emulate_msr_write(vcpu, MSR_IA32_INT_SSP_TAB, vmcs_read(HOST_IA32_INTERRUPT_SSP_TABLE_ADDR));
    }
// TODO: IA32_S_CET
// TODO: IA32_PKRS

    /* 28.5.2 Loading Host Segment and Descriptor-Table Registers */

    cs.base = 0;
    cs.limit = 0xFFFFFFFF;
    cs.type = 0xB;
    cs.s = 1;
    cs.dpl = 0;
    cs.present = 1;

    if (exit_ctls & VM_EXIT_HOST_ADDR_SPACE_SIZE) {
        cs.l = 1;
        cs.db = 0;
    } else
        cs.db = 1;
    cs.g = 1;

    ss.base = ds.base = es.base = 0;
    fs.base = vmcs_read(HOST_FS_BASE);
    gs.base = vmcs_read(HOST_GS_BASE);
    tr.base = vmcs_read(HOST_TR_BASE);

    ss.limit = ds.limit = es.limit = fs.limit = gs.limit = 0xFFFFFFFF;
    tr.limit = 0x67;
    ss.type = ds.type = es.type = fs.type = gs.type = 0x3;
    ss.s = ds.s = es.s = fs.s = gs.s = 1;
    tr.type = 0xb;
    tr.s = 0;

    ss.dpl = tr.dpl = 0;
    ds.dpl = es.dpl = fs.dpl = gs.dpl = 0;

    tr.present = 1;
    ss.present = ds.present = es.present = fs.present = gs.present = 1;

    ss.db = 1;
    ds.db = es.db = fs.db = gs.db = 1;
    tr.db = 0;

    ss.g = ds.g = es.g = fs.g = gs.g = 1;
    tr.g = 0;

    cs.selector = vmcs_read(HOST_CS_SELECTOR);
    ss.selector = vmcs_read(HOST_SS_SELECTOR);
    ds.selector = vmcs_read(HOST_DS_SELECTOR);
    es.selector = vmcs_read(HOST_ES_SELECTOR);
    fs.selector = vmcs_read(HOST_FS_SELECTOR);
    gs.selector = vmcs_read(HOST_GS_SELECTOR);
    tr.selector = vmcs_read(HOST_TR_SELECTOR);

    __vmx_set_segment(vcpu, &cs, VCPU_SREG_CS);
    __vmx_set_segment(vcpu, &ss, VCPU_SREG_SS);
    __vmx_set_segment(vcpu, &ds, VCPU_SREG_DS);
    __vmx_set_segment(vcpu, &es, VCPU_SREG_ES);
    __vmx_set_segment(vcpu, &fs, VCPU_SREG_FS);
    __vmx_set_segment(vcpu, &gs, VCPU_SREG_GS);
    __vmx_set_segment(vcpu, &tr, VCPU_SREG_TR);

    ldtr.selector = 0;
    ldtr.unusable = 1;
    __vmx_set_segment(vcpu, &ldtr, VCPU_SREG_LDTR);

    gdtr.address = vmcs_read(HOST_GDTR_BASE);
    gdtr.size = 0xFFFF;

    idtr.address = vmcs_read(HOST_IDTR_BASE);
    idtr.size = 0xFFFF;

    vmx_set_gdt(vcpu, &gdtr);
    vmx_set_idt(vcpu, &idtr);

    /* 28.5.3 Loading Host RIP, RSP, RFLAGS, and SSP */
    rip = vmcs_read(HOST_RIP);
    rsp = vmcs_read(HOST_RSP);
    rflags = X86_EFLAGS_FIXED;

    instr_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
    kvm_rip_write(vcpu, rip - instr_len);
    kvm_rsp_write(vcpu, rsp);
    kvm_set_rflags(vcpu, rflags);
    vmcs_writel(GUEST_SSP, vmcs_read(HOST_SSP));

    /* 28.5.4 Checking and Loading Host Page-Directory-Pointer-Table Entries */
    // NOTE: PAE paging is not supported

    /* 28.5.5 Updating Non-Register State */
    // TODO

    /* 28.5.6 Clearning Address-Range Monitoring */
    // TODO

    /* 28.6 Loading MSRs */
    // NOTE: MSR loading is not supported by SEAM VMCS
}

int handle_seamcall(struct kvm_vcpu *vcpu)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);

    u64 efer, seam_cvp, rax, rflags;
    u32 eax, ebx, ecx, edx;
    struct kvm_segment cs;
    int err = 0;

    struct page *vmcs_page = alloc_page(GFP_KERNEL);
    // TODO: handle if alloc_page failed

    void *vmcs = page_address(vmcs_page);

    kvm_emulate_msr_read(vcpu, MSR_EFER, &efer);
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
        if (!mutex_trylock(&kvm_vmx->p_seamldr_lock)) {
            kvm_set_rflags(vcpu, X86_EFLAGS_CF | X86_EFLAGS_FIXED);
            goto exit;
        } else if (vmx->in_pseamldr) {
            mutex_unlock(&kvm_vmx->p_seamldr_lock);
            // TODO: What happens if in_pseamldr already set
            goto exit;
        } else if (false) {
// TODO: Check P_SEAMLDR is loaded and enabled
            kvm_set_rflags(vcpu, X86_EFLAGS_CF | X86_EFLAGS_FIXED);
            goto exit;
        }
        seam_cvp = vmx->seamrr.base + vmx->seamrr.size - P_SEAMLDR_RANGE_SIZE + PAGE_SIZE;
        vmx->in_pseamldr = true;
    } else {
// TODO: Check TDX Module is loaded
        kvm_set_rflags(vcpu, X86_EFLAGS_CF | X86_EFLAGS_FIXED);
        goto exit;
    }

    rflags = kvm_get_rflags(vcpu);
    kvm_set_rflags(vcpu, rflags & 
        ~(X86_EFLAGS_CF | X86_EFLAGS_OF | X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF));

    vmx->seam_mode = true;

    if (vmx->nested.current_vmptr != INVALID_GPA)
        printk(KERN_WARNING "%s: Do not support current-VMCS on SEAMCALL\n", 
               __func__);

    kvm_read_guest_page(vcpu->kvm, gpa_to_gfn(seam_cvp), vmcs, 0, PAGE_SIZE);

// TODO: Save event inhibits in VMM interruptability status
// TODO: Inhibit SMI and NMI
    save_vmm_state(vcpu, (u8 *) vmcs);
    load_seam_state(vcpu, (u8 *) vmcs);

    kvm_write_guest_page(vcpu->kvm, gpa_to_gfn(seam_cvp), vmcs, 0, PAGE_SIZE);

exit:
    return kvm_complete_insn_gp(vcpu, 0);
}
