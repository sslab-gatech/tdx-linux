// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include "kvm_cache_regs.h"

#include "x86.h"
#include "vmx.h"
#include "smx.h"

static void dump_acm_header(struct acm_header *acm_header);
static int authenticate_acm(struct acm_header *acm_header);

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
    }
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

    return 0;

shutdown:
    kfree(acm_header);
// TODO: Emulate TXT shutdown
    return 1;

err:
    kfree(acm_header);
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

static int handle_getsec_exitac(struct kvm_vcpu *vcpu)
{
    return 0;
}

int handle_getsec(struct kvm_vcpu *vcpu)
{
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
        break;
    case ENTERACCS:
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