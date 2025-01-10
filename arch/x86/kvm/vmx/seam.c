// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include "asm/msr-index.h"
#include "kvm_cache_regs.h"

#include "vmx.h"
#include "seam.h"
#include "nested.h"

#include "x86.h"
#include <asm/asm.h>
#include <asm/segment.h>

enum seamops_function {
    CAPABILITIES    = 0x0,
    SEAMREPORT      = 0x1,
    SEAMDB_CLEAR    = 0x2,
    SEAMDB_INSERT   = 0x3,
    SEAMDB_GETREF   = 0x4,
    SEAMDB_REPORT   = 0x5,
};

void mcheck(struct kvm_vcpu *vcpu, gpa_t gpa)
{
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);
    struct sys_info_table sys_info_table = { 0, };
    u32 eax = 0x1, ebx, ecx, edx;
    int i;

    struct page *seaminfo_page = alloc_page(GFP_KERNEL);
    // TODO: handle if alloc_page failed

    void *seaminfo = page_address(seaminfo_page);

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

    sys_info_table.p_seamldr_range.base = kvm_vmx->seamrr.base + kvm_vmx->seamrr.size - P_SEAMLDR_RANGE_SIZE;
    sys_info_table.p_seamldr_range.size = P_SEAMLDR_RANGE_SIZE;

    sys_info_table.skip_smrr2_check = 0;
    sys_info_table.tdx_ac = 0;

    // Allow entire physical memory over 4GB as CMR
#define _4GB    0x100000000
    sys_info_table.cmr[0].base = _4GB;
    sys_info_table.cmr[0].size = (1ULL << cpuid_maxphyaddr(vcpu)) - _4GB;
    for (i = 1; i < SYS_INFO_TABLE_NUM_CMRS; i++) {
        sys_info_table.cmr[i].base = 0;
        sys_info_table.cmr[i].size = 0;
    }

    kvm_read_guest_page(vcpu->kvm, gpa_to_gfn(gpa), seaminfo, 0, PAGE_SIZE);
    memset(seaminfo, 0, PAGE_SIZE / 2);
    memcpy(seaminfo, &sys_info_table, sizeof(sys_info_table));
    kvm_write_guest_page(vcpu->kvm, gpa_to_gfn(gpa), seaminfo, 0, PAGE_SIZE);

    free_page((unsigned long) seaminfo);
}


void handle_seamextend(struct kvm_vcpu *vcpu)
{
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);
    u64 rdx, rax, value;
    rdx = kvm_rdx_read(vcpu);
    rax = kvm_rax_read(vcpu);
    value = (rdx << 32) | (rax & 0xFFFFFFFF);

    gpa_t gpa = value & ~0x1ULL;

    if (value & 1) {
        kvm_write_guest(vcpu->kvm, gpa, (void *) &kvm_vmx->seam_extend, sizeof(kvm_vmx->seam_extend));
    } else {
        kvm_read_guest(vcpu->kvm, gpa, (void *) &kvm_vmx->seam_extend, sizeof(kvm_vmx->seam_extend));
    }
    kvm_vmx->seam_extend.valid = 1;
}

static void save_guest_state(struct kvm_vcpu *vcpu, u8 *vmcs)
{
    u32 exit_ctls = vmcs_read(VM_EXIT_CONTROL);
    u64 efer;

    int has_cet = kvm_cpu_cap_has(X86_FEATURE_SHSTK) && kvm_cpu_cap_has(X86_FEATURE_IBT);

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
    if (exit_ctls & VM_EXIT_SAVE_IA32_EFER) {
        kvm_emulate_msr_read(vcpu, MSR_EFER, &efer);
        vmcs_write(GUEST_IA32_EFER_FULL, efer);
    }
// TODO: IA32_BNDCFGS
    printk(KERN_WARNING "[opentdx] do not support setting GUEST_IA32_RTIT_CTL");
    // vmcs_write(GUEST_RTIT_CTL_FULL, vmcs_read64(GUEST_IA32_RTIT_CTL));
    if (has_cet) {
        vmcs_write(GUEST_IA32_S_CET, vmcs_readl(GUEST_S_CET));
        vmcs_write(GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR, vmcs_readl(GUEST_INTR_SSP_TABLE));
    } else {
        printk(KERN_WARNING "[opentdx] do not support setting GUEST_S_CET, GUEST_INTR_SSP_TABLE");
    }
// TODO: IA32_LBR_CTL
// TODO: PKRS
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
    vmcs_write(GUEST_RFLAGS, kvm_get_rflags(vcpu));

    if (has_cet) {
        vmcs_write(GUEST_SSP, vmcs_readl(GUEST_SSP));
    } else {
        printk(KERN_WARNING "[opentdx] do not support setting GUEST_SSP");
    }
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

/*
 * Loading guest state should first check all the guest-state fields are correct,
 * and then, actually update the vcpu state. return 1 otherwise.
 */
static int load_guest_state(struct kvm_vcpu *vcpu, u8 *vmcs)
{
    u32 entry_ctls = vmcs_read(VM_ENTRY_CONTROL);

    unsigned long cr0, cr4, cr3;
    unsigned long s_cet, intr_ssp_table_addr;
    struct kvm_segment cs = {0,}, ss = {0,}, ds = {0,}, es = {0,}, fs = {0,}, gs = {0,}, tr = {0,};
    struct kvm_segment ldtr = {0,};
    struct desc_ptr gdtr, idtr;
    u64 efer, rflags;
    // bool ia32e_mode_guest;

    int has_cet = kvm_cpu_cap_has(X86_FEATURE_SHSTK) && kvm_cpu_cap_has(X86_FEATURE_IBT);

    cr0 = vmcs_read(GUEST_CR0);
    cr4 = vmcs_read(GUEST_CR4);
    cr3 = vmcs_read(GUEST_CR3);

    if (has_cet) {
        s_cet = vmcs_read(GUEST_IA32_S_CET);
        intr_ssp_table_addr = vmcs_read(GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR);
    }

    efer = vmcs_read(GUEST_IA32_EFER_FULL);

    /* 27.3 Checking and loading guest state */

    /* 27.3.1 Checks on the guest state area */
    if ((cr0 & vmcs_config.nested.cr0_fixed0) != vmcs_config.nested.cr0_fixed0 ||
        (cr0 | vmcs_config.nested.cr0_fixed1) != vmcs_config.nested.cr0_fixed1)
        return 1;

    if ((cr0 & X86_CR0_PG) && !(cr0 & X86_CR0_PE))
        return 1;

    if ((cr4 & vmcs_config.nested.cr4_fixed0) != vmcs_config.nested.cr4_fixed0 ||
        (cr4 | vmcs_config.nested.cr4_fixed1) != vmcs_config.nested.cr4_fixed1)
        return 1;

    if ((cr4 & X86_CR4_CET) && !(cr0 & X86_CR0_WP))
        return 1;

    if (entry_ctls & VM_ENTRY_IA32E_MODE) {
        if (!(cr0 & X86_CR0_PG) || !(cr4 & X86_CR4_PAE) || (cr4 & X86_CR4_PCIDE))
            return 1;
    }

    if (cr3 & vcpu->arch.reserved_gpa_bits)
        return 1;

    if (has_cet && (
        entry_ctls & VM_ENTRY_LOAD_CET_STATE) && (
        is_noncanonical_address(s_cet, vcpu) ||
        is_noncanonical_address(intr_ssp_table_addr, vcpu)))
        return 1;

// TODO: check IA32_PERF_GLOBAL_CTRL
// TODO: check IA32_PAT

    if (entry_ctls & VM_ENTRY_LOAD_IA32_EFER) {
        // NOTE: seamret does not check it?
        // ia32e_mode_guest = !!(entry_ctls & VM_ENTRY_IA32E_MODE);
        // if (!!(efer & EFER_LMA) != ia32e_mode_guest)
        //     return 1;

        if ((cr0 & X86_CR0_PG) &&
            (!!(efer & EFER_LMA) != !!(efer & EFER_LME)))
            return 1;
    }
// TODO: IA32_BNDCFGS
// TODO: IA32_RTIT_CTL

    if (has_cet && 
        (entry_ctls & VM_ENTRY_LOAD_CET_STATE) &&
        ((s_cet & CET_RESERVED) ||
         ((s_cet & CET_SUPPRESS) && (s_cet & CET_WAIT_ENDBR))))
        return 1;

// TODO: PKRS
// TODO: UINV

    rflags = vmcs_read(GUEST_RFLAGS);

    read_segment_CS(&cs, vmcs);
    read_segment_SS(&ss, vmcs);
    read_segment_DS(&ds, vmcs);
    read_segment_ES(&es, vmcs);
    read_segment_FS(&fs, vmcs);
    read_segment_GS(&gs, vmcs);
    read_segment_LDTR(&ldtr, vmcs);
    read_segment_TR(&tr, vmcs);

    gdtr.address = vmcs_read(GUEST_GDTR_BASE);
    gdtr.size = vmcs_read(GUEST_GDTR_LIMIT);

    idtr.address = vmcs_read(GUEST_IDTR_BASE);
    idtr.size = vmcs_read(GUEST_IDTR_LIMIT);

    if (rflags & X86_EFLAGS_VM) {
        printk(KERN_WARNING "[opentdx] does not allow entering guest with virtual 8086 mode");
        return 1;
    }

// Assumption, TDX module will not modify guest state
// TODO: 27.3.1.2 Checks on Guest Segment Registers
// TODO: 27.3.1.3 Checks on Guest Descriptor-Table Registers
// TODO: 27.3.1.4 Checks on Guest RIP, RFLAGS, and SSP

    /* 27.3.2 Loading Guest State */
    kvm_set_cr0(vcpu, cr0);
    kvm_set_cr3(vcpu, cr3);
    kvm_set_cr4(vcpu, cr4);

    if (entry_ctls & VM_ENTRY_LOAD_DEBUG_CONTROLS) {
        kvm_set_dr(vcpu, 7, vmcs_read(GUEST_DR7));
        kvm_emulate_msr_write(vcpu, MSR_IA32_DEBUGCTLMSR, vmcs_read(GUEST_IA32_DEBUGCTLMSR_FULL));
    }
    kvm_emulate_msr_write(vcpu, MSR_IA32_SYSENTER_CS, vmcs_read(GUEST_IA32_SYSENTER_CS));
    kvm_emulate_msr_write(vcpu, MSR_IA32_SYSENTER_ESP, vmcs_read(GUEST_IA32_SYSENTER_ESP));
    kvm_emulate_msr_write(vcpu, MSR_IA32_SYSENTER_EIP, vmcs_read(GUEST_IA32_SYSENTER_EIP));

    kvm_emulate_msr_write(vcpu, MSR_FS_BASE, vmcs_read(GUEST_FS_BASE));
    kvm_emulate_msr_write(vcpu, MSR_GS_BASE, vmcs_read(GUEST_GS_BASE));

    if (entry_ctls & VM_ENTRY_LOAD_DEBUG_CONTROLS) {
        vcpu->arch.dr7 = vmcs_read(GUEST_DR7);
        vmcs_write64(GUEST_IA32_DEBUGCTL, vmcs_read(GUEST_IA32_DEBUGCTLMSR_FULL));
    }

    if (entry_ctls & VM_ENTRY_LOAD_IA32_EFER) {
        kvm_emulate_msr_write(vcpu, MSR_EFER, efer);
    } else {
        printk(KERN_WARNING "[opentdx] does not allow unsetting load_ia32_efer entry ctls");
        return 1;
    }
// TODO: IA32_PERF_GLOBAL_CTL
    if (entry_ctls & VM_ENTRY_LOAD_IA32_PAT) {
        kvm_emulate_msr_write(vcpu, MSR_IA32_CR_PAT, vmcs_read(GUEST_IA32_PAT_FULL));
    }
// TODO: IA32_BNDCFGS
    if (entry_ctls & VM_ENTRY_LOAD_IA32_RTIT_CTL) {
        printk(KERN_WARNING "[opentdx] do not support loading ia32_rtit_ctl");
    }
    if (has_cet && (entry_ctls & VM_ENTRY_LOAD_CET_STATE)) {
        kvm_emulate_msr_write(vcpu, MSR_IA32_S_CET, vmcs_read(GUEST_IA32_S_CET));
        kvm_emulate_msr_write(vcpu, MSR_IA32_INT_SSP_TAB, vmcs_read(GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR));
    }
// TODO: PKRS
// TODO: UINV
// TODO: SMBASE

    __vmx_set_segment(vcpu, &cs, VCPU_SREG_CS);
    __vmx_set_segment(vcpu, &ss, VCPU_SREG_SS);
    __vmx_set_segment(vcpu, &ds, VCPU_SREG_DS);
    __vmx_set_segment(vcpu, &es, VCPU_SREG_ES);
    __vmx_set_segment(vcpu, &fs, VCPU_SREG_FS);
    __vmx_set_segment(vcpu, &gs, VCPU_SREG_GS);
    __vmx_set_segment(vcpu, &ldtr, VCPU_SREG_LDTR);
    __vmx_set_segment(vcpu, &tr, VCPU_SREG_TR);

    vmx_set_gdt(vcpu, &gdtr);
    vmx_set_idt(vcpu, &idtr);

    kvm_rsp_write(vcpu, vmcs_read(GUEST_RSP));
    kvm_rip_write(vcpu, vmcs_read(GUEST_RIP));
    kvm_set_rflags(vcpu, rflags);

    if (has_cet && (entry_ctls & VM_ENTRY_LOAD_CET_STATE)) {
        vmcs_writel(GUEST_SSP, vmcs_read(GUEST_SSP));
    }
// TODO: do not allow PAE paging

    /* 27.3.3 Clearing Address-Range Monitoring */

    /* 27.4 Loading MSRs */

    /* 27.5 Trace-Address Pre-Translation */

    /* 27.6 Event Injection */

    /* 27.7 Special Features of VM Entry */

    return 0;
}

static void load_host_state(struct kvm_vcpu *vcpu, u8 *vmcs)
{
    u32 exit_ctls = vmcs_read(VM_EXIT_CONTROL);

    unsigned long cr0, cr3, cr4;
    u64 efer, rflags;
    struct kvm_segment cs = {0,}, ss = {0,}, ds = {0,}, es = {0,}, fs = {0,}, gs = {0,}, tr = {0,};
    struct kvm_segment ldtr = {0,};
    struct desc_ptr gdtr, idtr;
    unsigned long rip, rsp;
    u32 instr_len; 

    int has_cet = kvm_cpu_cap_has(X86_FEATURE_SHSTK) && kvm_cpu_cap_has(X86_FEATURE_IBT);

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

    if (!has_cet)
        cr4 &= ~X86_CR4_CET;
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
    if (has_cet && (exit_ctls & VM_EXIT_LOAD_CET_STATE)) {
        kvm_emulate_msr_write(vcpu, MSR_IA32_S_CET, vmcs_read(HOST_IA32_S_CET));
        kvm_emulate_msr_write(vcpu, MSR_IA32_INT_SSP_TAB, vmcs_read(HOST_IA32_INTERRUPT_SSP_TABLE_ADDR));
    }
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
    rflags = vmx_get_rflags(vcpu) & ~(X86_EFLAGS_CF | X86_EFLAGS_OF | X86_EFLAGS_SF | 
                                      X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF);

    instr_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
    kvm_rip_write(vcpu, rip - instr_len);
    kvm_rsp_write(vcpu, rsp);
    vmx_set_rflags(vcpu, rflags);
    if (has_cet)
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

static void save_exit_info(struct kvm_vcpu *vcpu, u8 *vmcs)
{

    /* 28.2 Recording VM-Exit information and updating VM-Entry control fields */

    /* 28.2.1 Basic VM-Exit Information */
    vmcs_write(VM_EXIT_REASON, EXIT_REASON_SEAMCALL);

    // Guest linear address
    // Guest physical address

    /* 28.2.2 Information for VM Exits due to vectored events */

    // VM-exit interruption information
    // VM-exit interruption error code

    /* 28.2.3 Information about NMI unblocking due to IRET */

    /* 28.2.4 Information for VM Exits during event delivery */

    /* 28.2.5 Information for VM Exits due to instruction execution */

    vmcs_write(VM_EXIT_INSTRUCTION_LENGTH, 4);
    // VM-exit instruction information
    // IO-RCX, IO-RSI, IO-RDI, IO-RIP
}

static int check_entry_info(struct kvm_vcpu *vcpu, u8 *vmcs)
{
    /* 27.2 Checks on VMX controls and host-state area */

    /* 27.2.1 Checks on VMX controls */

    /* 27.2.2 Checks on host registers, MSRs, and SSP */

    /* 27.2.3 Checks on host segment and descriptor-table registers */

    /* 27.2.4 Checks related to address-space size */

    return 0;
}

static int vmx_succeed(struct kvm_vcpu *vcpu)
{
	vmx_set_rflags(vcpu, vmx_get_rflags(vcpu)
			& ~(X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF |
			    X86_EFLAGS_SF | X86_EFLAGS_OF));
	return kvm_skip_emulated_instruction(vcpu);
}

static int vmx_fail_invalid(struct kvm_vcpu *vcpu)
{
	vmx_set_rflags(vcpu, (vmx_get_rflags(vcpu)
			& ~(X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF |
			    X86_EFLAGS_SF | X86_EFLAGS_OF))
			| X86_EFLAGS_CF);
	return kvm_skip_emulated_instruction(vcpu);
}

int handle_seamcall(struct kvm_vcpu *vcpu)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);

    u64 efer, seam_cvp, rax, rflags;
    u32 eax, ebx, ecx, edx;
    struct kvm_segment cs = {0,};
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
        // TODO: set "VM exit from VMX root operation" 0
        nested_vmx_vmexit(vcpu, EXIT_REASON_SEAMCALL, 0, 0);
        return 1;
    } else if (vmx_get_cpl(vcpu) > 0 || kvm_vmx->seamrr.enabled == 0) {
// TODO: events blocking by MOV-SS
        err = 1;
        goto exit;
    }

    seam_cvp = (kvm_vmx->seamrr.base + PAGE_SIZE) + (edx & 0xFFFFFFFF) * PAGE_SIZE;

    rax = kvm_rax_read(vcpu);

#define INVOKE_PSEAMLDR (1ULL << 63)
    if (rax & INVOKE_PSEAMLDR) {
        if (!mutex_trylock(&kvm_vmx->p_seamldr_lock)) {
            return vmx_fail_invalid(vcpu);
        } else if (vmx->in_pseamldr) {
            mutex_unlock(&kvm_vmx->p_seamldr_lock);
            // TODO: What happens if in_pseamldr already set
            goto exit;
        } else if (false) {
// TODO: Check P_SEAMLDR is loaded and enabled
            return vmx_fail_invalid(vcpu);
        }
        seam_cvp = kvm_vmx->seamrr.base + kvm_vmx->seamrr.size - P_SEAMLDR_RANGE_SIZE + PAGE_SIZE;
        vmx->in_pseamldr = true;
    } else {
// TODO: Check TDX Module is loaded
        if (!kvm_vmx->seam_extend.seam_ready) {
            return vmx_fail_invalid(vcpu);
        }
    }

    rflags = vmx_get_rflags(vcpu);
    // TODO: single-step debugging should set Trap flag
    vmx_set_rflags(vcpu, rflags & 
        ~(X86_EFLAGS_CF | X86_EFLAGS_OF | X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF));

    if (vmx->nested.current_vmptr != INVALID_GPA)
        printk(KERN_WARNING "%s: do not support current-VMCS on SEAMCALL\n", 
               __func__);

    // TODO: nested.current_vmptr should be released here
    vmx->seam_mode = true;
    vmx->seam_vmptr = seam_cvp;

    kvm_read_guest_page(vcpu->kvm, gpa_to_gfn(vmx->seam_vmptr), vmcs, 0, PAGE_SIZE);

// TODO: Save event inhibits in VMM interruptability status
// TODO: Inhibit SMI and NMI
    save_exit_info(vcpu, (u8 *) vmcs);
    save_guest_state(vcpu, (u8 *) vmcs);
    load_host_state(vcpu, (u8 *) vmcs);

    vcpu->arch.apic->apicv_active = false;
    kvm_apic_update_apicv(vcpu);
    kvm_make_request(KVM_REQ_EVENT, vcpu);

    kvm_write_guest_page(vcpu->kvm, gpa_to_gfn(vmx->seam_vmptr), vmcs, 0, PAGE_SIZE);

exit:
    free_page((unsigned long) vmcs);

    return kvm_complete_insn_gp(vcpu, err);
}

int handle_seamret(struct kvm_vcpu *vcpu)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);
    u64 efer;
    struct kvm_segment cs = {0,};
    int err = 0;

    struct page *vmcs_page = alloc_page(GFP_KERNEL);

    void *vmcs = page_address(vmcs_page);

    kvm_emulate_msr_read(vcpu, MSR_EFER, &efer);
    vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);

    if (!vmx->seam_mode || (!(efer & EFER_LMA)) || !cs.l || is_guest_mode(vcpu)) {
        kvm_queue_exception(vcpu, UD_VECTOR);

        free_page((unsigned long) vmcs);
        return 1;
    } else if (vmx_get_cpl(vcpu) > 0) {
        err = 1;
        goto exit;
    }
    // TODO: Check current vmptr (i.e., vmx->seam_vmptr) is valid? Can it be invalid?

    kvm_read_guest_page(vcpu->kvm, gpa_to_gfn(vmx->seam_vmptr), vmcs, 0, PAGE_SIZE);

    if (check_entry_info(vcpu, vmcs)) {
        // TODO: Check settings of VMX controls and host-state area
        vmx_set_rflags(vcpu, X86_EFLAGS_ZF);

        vmcs_write(VM_INSTRUCTION_ERRORCODE, 0x7);

        free_page((unsigned long) vmcs);
        return 1;
    }

    if (load_guest_state(vcpu, vmcs)) {
        printk(KERN_WARNING "[opentdx] loading guest state returned 1");

        vmcs_write(VM_EXIT_REASON,
            VMX_EXIT_REASONS_FAILED_VMENTRY | EXIT_REASON_INVALID_STATE);
        vmcs_write(VM_EXIT_QUALIFICATION, 0);
        goto exit;
    }

    vmx->seam_vmptr = INVALID_GPA;
    vmx->seam_mode = false;

    if (vmx->in_pseamldr) {
        vmx->in_pseamldr = false;
        mutex_unlock(&kvm_vmx->p_seamldr_lock);
    }

    vcpu->arch.apic->apicv_active = true;
    kvm_make_request(KVM_REQ_APICV_UPDATE, vcpu);

exit:
    free_page((unsigned long) vmcs);

    if (err)
        kvm_inject_gp(vcpu, 0);

    return 1;
}

static int handle_seamops_capabilities(struct kvm_vcpu *vcpu)
{
// TODO
    kvm_rax_write(vcpu, 
        CAPABILITIES_SEAMDB_CLEAR | CAPABILITIES_SEAMDB_INSERT | 
        CAPABILITIES_SEAMDB_GETREF | 0x1);
    return 0;
}

static int handle_seamops_seamdb_clear(struct kvm_vcpu *vcpu)
{
    kvm_rax_write(vcpu, 0x0);
    return 0;
}

static int handle_seamops_seamdb_insert(struct kvm_vcpu *vcpu)
{
    kvm_rax_write(vcpu, 0x0);
    return 0;
}

static int handle_seamops_seamdb_getref(struct kvm_vcpu *vcpu)
{
// TODO
    kvm_rax_write(vcpu, 0x0);
    kvm_r10_write(vcpu, 0x0);
    kvm_r11_write(vcpu, 0x0);
    kvm_r12_write(vcpu, 0x0);
    kvm_r13_write(vcpu, 0x0);
    kvm_r14_write(vcpu, 0x0);
    kvm_r15_write(vcpu, 0x0);
    return 0;
}

int handle_seamops(struct kvm_vcpu *vcpu)
{
    static const char seamops_bytecode[] = { __SEAMOPS_BYTECODE };
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    u64 efer;
    struct kvm_segment cs = {0,};
    unsigned long rip = kvm_rip_read(vcpu);
    u32 eax = kvm_rax_read(vcpu);
    int err = 0;

    kvm_emulate_msr_read(vcpu, MSR_EFER, &efer);
    vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);

    if (!vmx->seam_mode || !(efer & EFER_LMA) || !cs.l || is_guest_mode(vcpu)) {
        kvm_queue_exception(vcpu, UD_VECTOR);
        return 1;
    } else if (vmx_get_cpl(vcpu) > 0) {
        err = 1;
        goto exit;
    }
// TODO: lock CRPL_CPUSVN and BIOS_SE_SVN

    switch (eax) {
    case CAPABILITIES:
        err = handle_seamops_capabilities(vcpu);
        break;
    case SEAMREPORT:
        err = 1;
        break;
    case SEAMDB_CLEAR:
        err = handle_seamops_seamdb_clear(vcpu);
        break;
    case SEAMDB_INSERT:
        err = handle_seamops_seamdb_insert(vcpu);
        break;
    case SEAMDB_GETREF:
        err = handle_seamops_seamdb_getref(vcpu);
        break;
    case SEAMDB_REPORT:
        err = 1;
        break;
    default:
        err = 1;
    }

    kvm_rip_write(vcpu, rip + sizeof(seamops_bytecode));

exit:
    if (err)
        kvm_inject_gp(vcpu, 0);

    return 1;
}

static struct nested_vmx_instruction_handlers {
    int (*vmread)(struct kvm_vcpu *);
    int (*vmwrite)(struct kvm_vcpu *);
} vmx_instruction_handlers;

/* TODO: if guest VM-root uses shadow VMCS, vmread will not be caught.
 *       So, we should disable using shadow VMCS when running SEAMCALL.
 *       Then, we should re-enable it when TDX-module creates TDs so that
 *       vmread/vmwrite should be correctly forwarded to the VMCS of TDs.
 */
static int handle_vmread(struct kvm_vcpu* vcpu)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    unsigned long exit_qualification;
    struct x86_exception e;
    u32 instr_info;
    unsigned long encode;
    u64 value;
    gva_t gva = 0;
    int len, r;

    if (vmx->seam_mode) {
        if (is_guest_mode(vcpu)) {
            printk(KERN_WARNING "[TODO] support vmread in L2");
            return vmx_fail_invalid(vcpu);
        }

        exit_qualification = vmx_get_exit_qual(vcpu);

        instr_info = vmcs_read32(VMX_INSTRUCTION_INFO);
        encode = kvm_register_read(vcpu, (((instr_info) >> 28) & 0xf));

#define macro(field)                                                        \
    case VMX_##field##_ENCODE:                                              \
    if (kvm_read_guest(vcpu->kvm, vmx->seam_vmptr + VMX_##field##_OFFSET,   \
                       &value, VMX_##field##_SIZE)) {                       \
        goto err;                                                           \
    }                                                                       \
    break;

        switch (encode) {
#include "vmx_vmcs_macro.h"
        default:
        printk(KERN_WARNING "%s: unknown encoding 0x%0lx", __func__, encode);
        return vmx_fail_invalid(vcpu);
        }
#undef macro

        if (instr_info & BIT(10)) {
            kvm_register_write(vcpu, (((instr_info) >> 3) & 0xf), value);
        } else {
            len = is_64_bit_mode(vcpu) ? 8 : 4;
            if (get_vmx_mem_address(vcpu, exit_qualification, 
                    instr_info, true, len, &gva))
                return 1;

            r = kvm_write_guest_virt_system(vcpu, gva, &value, len, &e);
            if (r != X86EMUL_CONTINUE)
                return kvm_handle_memory_failure(vcpu, r, &e);
        }

        return vmx_succeed(vcpu);

err:
        printk(KERN_WARNING "%s: error while handling vmread",
               __func__);
        return 1;
    } else {
        return vmx_instruction_handlers.vmread(vcpu);
    }
}

static int handle_vmwrite(struct kvm_vcpu* vcpu)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    unsigned long exit_qualification;
    struct x86_exception e;
    u32 instr_info;
    unsigned long encode;
    u64 value;
    gva_t gva = 0;
    int len, r;

    if (vmx->seam_mode) {
        if (is_guest_mode(vcpu)) {
            printk(KERN_WARNING "[TODO] support vmwrite in L2");
            return vmx_fail_invalid(vcpu);
        }

        exit_qualification = vmx_get_exit_qual(vcpu);

        instr_info = vmcs_read32(VMX_INSTRUCTION_INFO);

        if (instr_info & BIT(10)) {
            value = kvm_register_read(vcpu, (((instr_info) >> 3) & 0xf));
        } else {
            len = is_64_bit_mode(vcpu) ? 8 : 4;
            if (get_vmx_mem_address(vcpu, exit_qualification,
                    instr_info, false, len, &gva))
                return 1;
            r = kvm_read_guest_virt(vcpu, gva, &value, len, &e);
            if (r != X86EMUL_CONTINUE)
                return kvm_handle_memory_failure(vcpu, r, &e);
        }

        encode = kvm_register_read(vcpu, (((instr_info) >> 28) & 0xf));

#define macro(field)                                                        \
    case VMX_##field##_ENCODE:                                              \
    if (kvm_write_guest(vcpu->kvm, vmx->seam_vmptr + VMX_##field##_OFFSET,  \
                        &value, VMX_##field##_SIZE)) {                      \
        goto err;                                                           \
    }                                                                       \
    break;

        switch (encode) {
#include "vmx_vmcs_macro.h"
        default:
        printk(KERN_WARNING "%s: unknown encoding 0x%0lx", __func__, encode);
        return vmx_fail_invalid(vcpu);
        }
#undef macro

        return vmx_succeed(vcpu);

err:
        printk(KERN_WARNING "%s: error while handling vmwrite",
               __func__);
        return 1;
    } else {
        return vmx_instruction_handlers.vmwrite(vcpu);
    }
}

__init int seam_vmx_hardware_setup(int (*exit_handler[])(struct kvm_vcpu *))
{
    vmx_instruction_handlers.vmread = exit_handler[EXIT_REASON_VMREAD];
    vmx_instruction_handlers.vmwrite = exit_handler[EXIT_REASON_VMWRITE];

    exit_handler[EXIT_REASON_VMREAD] = handle_vmread;
    exit_handler[EXIT_REASON_VMWRITE] = handle_vmwrite;

    return 0;
} 

