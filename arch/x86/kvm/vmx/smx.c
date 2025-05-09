// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include "kvm_cache_regs.h"

#include "x86.h"
#include "vmx.h"
#include "smx.h"

#include <asm/asm.h>

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

static void dump_acm_header(struct acm_header *acm_header);
static int authenticate_acm(struct acm_header *acm_header);
static void dump_post_enteraccs(struct kvm_vcpu *vcpu);


static int handle_getsec_capabilities(struct kvm_vcpu *vcpu)
{
    u32 eax;
    u32 ebx = kvm_rbx_read(vcpu);

#define CAPABILITIES_DEFAULT 0
    if (ebx == CAPABILITIES_DEFAULT) {
        eax = CAPABILITIES_CHIPSET_PRESENT | CAPABILITIES_ENTERACCS | CAPABILITIES_EXITAC;
        kvm_rax_write(vcpu, eax);
    } else {
        kvm_rax_write(vcpu, 0);
    }
    return 0;
}

static int handle_getsec_enteraccs(struct kvm_vcpu *vcpu)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    unsigned long acm_base = kvm_rbx_read(vcpu);
    unsigned long acm_size = kvm_rcx_read(vcpu);

    struct acm_header *acm_header;
    int ret;

    unsigned long cr0, cr4;
    u32 entry_point, eip, next_eip, instr_len;
    struct desc_ptr old_gdt, gdt;
    struct kvm_segment old_cs = {0,}, cs = {0,}, ds = {0,};

    {
        /* Bunch of sanity checks go here.
         * See Intel SDM Volume 2D 7.3
         */
        if (!(is_protmode(vcpu) && (
                vmx_get_cpl(vcpu) == 0
                && !(vmx_get_rflags(vcpu) & X86_EFLAGS_VM)))) {
            return 1;
        }
        if (vmx->authenticated_code_execution_mode)
            return 1;
        if (is_smm(vcpu) || vmx->nested.vmxon)
            return 1;

#define ACMBASE_ALIGN 4096
#define ACMSIZE_ALIGN 64
#define ACMADDR_LIMIT 0xFFFFFFFF
        if (acm_base % ACMBASE_ALIGN != 0 || acm_size % ACMSIZE_ALIGN != 0 ||
            (acm_base + acm_size) > ACMADDR_LIMIT)
            return 1;

// TODO: Mask external signals INIT#, A20M, NMI#, and SMI# asserted to ILPs

        vmx_flush_tlb_guest(vcpu);
        vmx->authenticated_code_execution_mode = true;

// TODO: Shut down TXT upon detecting memory for ACM is not WB

        acm_header = (struct acm_header *) kmalloc(sizeof(struct acm_header), GFP_KERNEL);
        ret = kvm_vcpu_read_guest(vcpu, acm_base, (void *) acm_header, sizeof(struct acm_header));
        if (ret)
            goto err;

        dump_acm_header(acm_header);

#define ACM_HEADER_VERSION  0x30000
#define ACM_MODULE_TYPE     2
        if (acm_header->header_version != ACM_HEADER_VERSION || acm_header->module_type != ACM_MODULE_TYPE)
            goto shutdown;

        if (authenticate_acm(acm_header))
            goto shutdown;

// TODO: Check CodeControl

        if ((acm_header->gdt_base_ptr < acm_header->header_len * 4 + acm_header->scratch_size) ||
            (acm_header->gdt_base_ptr + acm_header->gdt_limit > acm_size))
            goto shutdown;

        if (acm_header->code_control)
            goto err;
        entry_point = acm_base + acm_header->entry_point;

        if ((acm_header->entry_point >= acm_size) ||
            (acm_header->entry_point < acm_header->header_len * 4 + acm_header->scratch_size))
            goto shutdown;

        if (acm_header->gdt_limit & 0xFFFF0000)
            goto shutdown;

        if ((acm_header->seg_sel > acm_header->gdt_limit - 15) ||
            (acm_header->seg_sel < 8))
            goto shutdown;

        if ((acm_header->seg_sel & SEGMENT_TI_MASK) || (acm_header->seg_sel & SEGMENT_RPL_MASK))
            goto shutdown;
    }

    if (kvm_emulate_msr_write(vcpu, MSR_IA32_MISC_ENABLE, 0))
        goto err;

    vmx_set_rflags(vcpu, 0x2);

    eip = kvm_rip_read(vcpu);
    instr_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
    next_eip = eip + instr_len;
    kvm_rbx_write(vcpu, next_eip);

    vmx_get_gdt(vcpu, &old_gdt);
    vmx_get_segment(vcpu, &old_cs, VCPU_SREG_CS);
    kvm_rcx_write(vcpu, old_gdt.size << 16 | old_cs.selector);
    kvm_rdx_write(vcpu, (u32) old_gdt.address);

    kvm_rbp_write(vcpu, acm_base);

    gdt.address = (unsigned long) (acm_base + acm_header->gdt_base_ptr);
    gdt.size = acm_header->gdt_limit;
    vmx_set_gdt(vcpu, &gdt);

    cs.selector = (u16) acm_header->seg_sel;
    cs.base = 0;
    cs.limit = 0xFFFFFFFF;
    cs.g = 1;
    cs.db = 1;
    cs.present = 1;
    cs.s = 1;
    cs.type = 0xB;
    __vmx_set_segment(vcpu, &cs, VCPU_SREG_CS);

    ds.selector = (u16) acm_header->seg_sel + 8;
    ds.base = 0;
    ds.limit = 0xFFFFFFFF;
    ds.g = 1;
    ds.db = 1;
    ds.present = 1;
    ds.s = 1;
    ds.type = 0x3;
    __vmx_set_segment(vcpu, &ds, VCPU_SREG_DS);

    cr0 = kvm_read_cr0(vcpu);
    cr0 = cr0 & ~(X86_CR0_WP | X86_CR0_AM | X86_CR0_PG);
    if (kvm_set_cr0(vcpu, cr0))
        goto err;

    cr4 = kvm_read_cr4(vcpu);
    cr4 = cr4 & ~(X86_CR4_MCE | X86_CR4_CET | X86_CR4_PCIDE);
    if (kvm_set_cr4(vcpu, cr4))
        goto err;

    if (kvm_emulate_msr_write(vcpu, MSR_EFER, 0x0))
        goto err;

    if (kvm_set_dr(vcpu, 7, 0x400))
        goto err;

    if (kvm_emulate_msr_write(vcpu, MSR_IA32_DEBUGCTLMSR, 0))
        goto err;

    // NOTE: kvm_complete_insn_gp forwards rip by instr_len as it skips the emulated instruction.
    //       Subtract it beforehand to place rip in correct location.
    kvm_rip_write(vcpu, entry_point - instr_len);

    dump_post_enteraccs(vcpu);

    return 0;

shutdown:
    kfree(acm_header);
    printk(KERN_WARNING "TXT shutdown\n");
// TODO: Emulate TXT shutdown
    return 1;

err:
    kfree(acm_header);
    printk(KERN_ERR "Error while GETSEC[ENTERACCS]\n");
// TODO: Handle internal KVM error
    return 1;
}

static void dump_acm_header(struct acm_header *acm_header)
{
    printk(KERN_WARNING \
"""ACM Header\n\
\tModuleType: %d\n\
\tModuleSubType: %d\n\
\tHeaderLen: %d\n\
\tHeaderVersion: 0x%05X\n\
\tChipsetID: 0x%04X\n\
\tFlags: 0x%04X\n\
\tModuleVendor: 0x%08X\n\
\tDate: %08X\n\
\tSize: %d\n\
\tTXT SVN: %d\n\
\tSGX SVN: %d\n\
\tCodeControl: 0x%08X\n\
\tErrorEntryPoint: 0x%08x\n\
\tGDTLimit: 0x%08X\n\
\tGDTBasePtr: 0x%08X\n\
\tSegSel: 0x%08X\n\
\tEntryPoint: 0x%08X\n\
\tKeySize: %d\n\
\tScratchSize: %d\n\
""", acm_header->module_type, acm_header->module_sub_type, 
     acm_header->header_len, acm_header->header_version,
     acm_header->chipset_id, acm_header->flags,
     acm_header->module_vendor, acm_header->date, 
     acm_header->size, acm_header->txt_svn, 
     acm_header->sgx_svn, acm_header->code_control,
     acm_header->error_entry_point, acm_header->gdt_limit,
     acm_header->gdt_base_ptr, acm_header->seg_sel,
     acm_header->entry_point, acm_header->key_size, 
     acm_header->scratch_size);
}

static int authenticate_acm(struct acm_header *acm_header)
{
    return 0;
}

static void dump_post_enteraccs(struct kvm_vcpu *vcpu)
{
    unsigned long cr0, cr4;
    u32 eip, eflags, ebx, ecx, edx, ebp;
    struct desc_ptr gdt;
    struct kvm_segment cs = {0,}, ds = {0,};

    cr0 = kvm_read_cr0(vcpu);
    cr4 = kvm_read_cr4(vcpu);
    eflags = vmx_get_rflags(vcpu);
    eip = kvm_rip_read(vcpu);
    ebp = kvm_rbp_read(vcpu);
    ebx = kvm_rbx_read(vcpu);
    ecx = kvm_rcx_read(vcpu);
    edx = kvm_rdx_read(vcpu);
    vmx_get_gdt(vcpu, &gdt);
    vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
    vmx_get_segment(vcpu, &ds, VCPU_SREG_DS);

    printk(KERN_WARNING \
"""Post ENTERACCS State\n\
\tCR0: 0x%08X\n\
\tCR4: 0x%08X\n\
\tEFLAGS: 0x%08X\n\
\tEIP: 0x%08X\n\
\tEBP: 0x%08X\n\
\tEBX: 0x%08X\n\
\tECX: 0x%08X\n\
\tEDX: 0x%08X\n\
\tCS: 0x%08X.0x%08X | sel: 0x%04X | g: %d | db: %d | p: %d | s:%d | type: 0x%1X\n\
\tDS: 0x%08X.0x%08X | sel: 0x%04X | g: %d | db: %d | p: %d | s:%d | type: 0x%1X\n\
\tGDT: 0x%08X.0x%08X\n\
""", (u32) cr0, (u32) cr4, eflags, eip, ebp, ebx, ecx, edx,
     (u32) cs.base, cs.limit, cs.selector, cs.g, cs.db, cs.present, cs.s, cs.type,
     (u32) ds.base, ds.limit, ds.selector, ds.g, ds.db, ds.present, ds.s, ds.type,
     (u32) gdt.address, gdt.size);
}

static int handle_getsec_exitac(struct kvm_vcpu *vcpu)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    u64 efer;
    u32 ebx, edx, r8, instr_len;
    struct kvm_segment old_cs = {0,};

    ebx = kvm_rbx_read(vcpu);
    edx = kvm_rdx_read(vcpu);
    vmx_get_segment(vcpu, &old_cs, VCPU_SREG_CS);

    {
        /* Bunch of sanity checks go here.
         * See Intel SDM Volume 2D 7.3
         */

        if (!(is_protmode(vcpu) && (vmx_get_cpl(vcpu) == 0) &&
              !(vmx_get_rflags(vcpu) & X86_EFLAGS_VM) &&
              vmx->authenticated_code_execution_mode &&
              (edx == 0))) {
                return 1;
            }

        if (ebx > (old_cs.base + old_cs.limit))
            return 1;

    }

    vmx->authenticated_code_execution_mode = false;
    kvm_emulate_msr_read(vcpu, MSR_EFER, &efer);
    if (efer & EFER_LMA) {
        r8 = kvm_r8_read(vcpu);
        kvm_set_cr3(vcpu, r8);
    }

    instr_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
    kvm_rip_write(vcpu, ebx - instr_len);

    return 0;
}

int handle_getsec(struct kvm_vcpu *vcpu)
{
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);
	unsigned long cr4 = kvm_read_cr4(vcpu);
    u32 eax = kvm_rax_read(vcpu);

    int err;

	if (!(cr4 & X86_CR4_SMXE)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

    switch (eax) {
    case CAPABILITIES:
        err = handle_getsec_capabilities(vcpu);
        if (!err)
            kvm_rip_write(vcpu, kvm_rip_read(vcpu) + 0x2);
        break;
    case ENTERACCS:
        if (!kvm_vmx->seamrr.enabled)
            err = 1;
        else
            err = handle_getsec_enteraccs(vcpu);
        break;
    case EXITAC:
        err = handle_getsec_exitac(vcpu);
        break;
    default:
        kvm_queue_exception(vcpu, UD_VECTOR);
        return 1;
    }

	return kvm_complete_insn_gp(vcpu, err);

}
EXPORT_SYMBOL(handle_getsec);
