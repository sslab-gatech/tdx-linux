// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include "vmx.h"
#include "mktme.h"

#include "x86.h"

int read_wbinvdp(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);

    if (!vmx->seam_mode)
        return 1;
// TODO: invoked from vmx loads/stores

    msr_info->data = NUM_CACHE_BLOCKS;
    return 0;
}

int write_wbinvdp(struct kvm_vcpu *vcpu)
{
    struct vcpu_vmx *vmx = to_vmx(vcpu);
    u64 rdx, rax, idx;
    rdx = kvm_rdx_read(vcpu);
    rax = kvm_rax_read(vcpu);

    if (!vmx->seam_mode)
        return 1;

    idx = (rdx << 32) | rax;
    if (idx > NUM_CACHE_BLOCKS)
        return 1;
// TODO: invoked from vmx loads/stores

    return kvm_emulate_wbinvd(vcpu);
}

static int handle_pconfig_mktme_key_program(struct kvm_vcpu *vcpu, gva_t rbx)
{
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);
    struct x86_exception e;
    mktme_key_program_t key_program = { 0, };
    mktme_entry_t *mktme_entry;
    u8 buf[64] = { 0, }, enc_alg;
    int key_size;

    if (kvm_read_guest_virt(vcpu, rbx, &key_program, sizeof(key_program), &e) != 0) {
        printk(KERN_WARNING "failed to read MKTME key program");
        return -EINVAL;
    }

    if (key_program.key_id == 0 || 
        key_program.key_id >= (1 << keyid_bits(kvm_vmx->msr_ia32_tme_activate))) {
        return INVALID_KEYID;
    }

    if (key_program.keyid_ctrl.command > MKTME_KEYID_NO_ENCRYPT)
        return INVALID_PROG_CMD;

    if (key_program.keyid_ctrl.command <= MKTME_KEYID_SET_KEY_RANDOM && 
        (!is_power_of_2(key_program.keyid_ctrl.enc_algo) ||
         !(mktme_enc_alg(kvm_vmx->msr_ia32_tme_activate) & key_program.keyid_ctrl.enc_algo))) {
        return INVALID_CRYPTO_ARG;
    }

    enc_alg = key_program.keyid_ctrl.enc_algo;
    key_size = (enc_alg & TME_CAP_AES_128 || enc_alg & TME_CAP_AES_128_INT) ? 16 : 32;

    if ((memcmp(&key_program.key_field1[key_size], buf, 64 - key_size) != 0 ||
         memcmp(&key_program.key_field2[key_size], buf, 64 - key_size) != 0)) {
        return INVALID_PROG_CMD;
    }

    mktme_entry = &kvm_vmx->mktme_table[key_program.key_id];
    mktme_entry->key_id = key_program.key_id;

    if (key_program.keyid_ctrl.command == MKTME_KEYID_SET_KEY_RANDOM) {
        get_random_bytes(buf, key_size);
    }
    for (int i = 0; i < key_size; i++) {
        buf[i] ^= key_program.key_field1[i] ^ key_program.key_field2[i];
    }

    memcpy(mktme_entry->key, buf, key_size);
    mktme_entry->enc_mode = enc_alg;

    // printk(KERN_WARNING "MKTME key program:\n");
    // printk(KERN_WARNING "keyid: 0x%x\n", mktme_entry->key_id);
    // printk(KERN_WARNING "key: 0x%x %x %x ... %x %x %x\n", 
    //     mktme_entry->key[0], mktme_entry->key[1], mktme_entry->key[2],
    //     mktme_entry->key[29], mktme_entry->key[30], mktme_entry->key[31]);
    // printk(KERN_WARNING "enc_mode: 0x%x\n", mktme_entry->enc_mode);

    return 0;
}

int handle_pconfig(struct kvm_vcpu *vcpu)
{
    static const char pconfig_bytecode[] = { __PCONFIG_BYTECODE };
    unsigned long rip = kvm_rip_read(vcpu);
    u64 rflags, rbx;
    u32 eax;
    int err = 0;

    rflags = vmx_get_rflags(vcpu);
    rbx = kvm_rbx_read(vcpu);
    eax = kvm_rax_read(vcpu);

    switch (eax) {
    case PCONFIG_MKTME_KEY_PROGRAM:
        err = handle_pconfig_mktme_key_program(vcpu, rbx);
        break;
    default:
        kvm_inject_gp(vcpu, 0);
    }

    kvm_rip_write(vcpu, rip + sizeof(pconfig_bytecode));

    rflags &= ~(X86_EFLAGS_ZF | X86_EFLAGS_CF | X86_EFLAGS_PF |
                X86_EFLAGS_AF | X86_EFLAGS_OF | X86_EFLAGS_SF);

    if (err < 0) {
        // TODO
    } else if (err > PROG_SUCCESS) {
        rflags |= X86_EFLAGS_ZF;
        kvm_rax_write(vcpu, err);
    }

    return 1;
}
EXPORT_SYMBOL_GPL(handle_pconfig);