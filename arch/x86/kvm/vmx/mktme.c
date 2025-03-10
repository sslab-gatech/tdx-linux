// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2021 Intel Corporation. */

#include "vmx.h"
#include "mktme.h"

#include "x86.h"

extern int max_phyaddr_bits;

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

    return kvm_emulate_wbinvd_noskip(vcpu);
}

u16 keyid_of(gpa_t gpa, struct kvm *kvm)
{
    u64 tme_activate = to_kvm_vmx(kvm)->msr_ia32_tme_activate;
    if (!tme_locked(tme_activate))
        return 0;

    return (gpa >> (max_phyaddr_bits - keyid_bits(tme_activate))
            & keyid_mask(tme_activate));
}

bool has_keyid(gpa_t gpa, struct kvm *kvm)
{
    return !!keyid_of(gpa, kvm);
}

bool is_tdx_keyid(u16 keyid, struct kvm *kvm)
{
    u64 tme_activate = to_kvm_vmx(kvm)->msr_ia32_tme_activate;
    if (!tme_locked(tme_activate))
        return false;

    return keyid >= (1 << (keyid_bits(tme_activate) - tdx_keyid_bits(tme_activate)));
}

gpa_t gpa_without_keyid(gpa_t gpa, struct kvm *kvm)
{
    u64 tme_activate = to_kvm_vmx(kvm)->msr_ia32_tme_activate;
    if (!tme_locked(tme_activate))
        return gpa;

    gpa_t mask = (1ULL << (max_phyaddr_bits - keyid_bits(tme_activate))) - 1;
    return gpa & mask;
}

gpa_t gpa_with_keyid(gpa_t gpa, u16 keyid, struct kvm *kvm)
{
    u64 tme_activate = to_kvm_vmx(kvm)->msr_ia32_tme_activate;
    if (keyid != 0 && !tme_locked(tme_activate)) {
        pr_err("[opentdx] tried to get keyid|gpa without tme activated\n");

        BUG();
    }

    gpa_t mask = (((u64) keyid) << (max_phyaddr_bits - keyid_bits(tme_activate)));
    return gpa | mask;
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

int get_mktme_state(struct kvm_vcpu *vcpu, struct kvm_mktme_state __user *user_kvm_mktme_state)
{
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);

    struct kvm_mktme_state mktme_state = {
        .msr_ia32_tme_capability = kvm_vmx->msr_ia32_tme_capability,
        .msr_ia32_tme_activate = kvm_vmx->msr_ia32_tme_activate,

        .num_mktme_keys = (1 << KEYID_BITS),
        .mktme_entries = NULL,

        .num_page_keyids = atomic_read(&kvm_vmx->num_keyed_pages),
        .page_keyids = NULL,
    };

    if (copy_to_user(user_kvm_mktme_state, &mktme_state, sizeof(mktme_state)))
        return -EFAULT;

    return 0;
}

int get_mktme_entries(struct kvm_vcpu *vcpu, struct kvm_mktme_entries __user *user_mktme_entries)
{
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);
    struct kvm_mktme_entries mktme_entries;
    struct kvm_mktme_entry *entries;
    int i;

    mktme_entry_t *mktme_table = kvm_vmx->mktme_table;

    if (copy_from_user(&mktme_entries, user_mktme_entries, sizeof(struct kvm_mktme_entries)))
        return -EFAULT;

    if (mktme_entries.num_entries != (1 << KEYID_BITS))
        return -EINVAL;

    entries = kzalloc(sizeof(struct kvm_mktme_entries) * mktme_entries.num_entries, GFP_KERNEL);
    if (!entries)
        return -ENOMEM;

    for (i = 0; i < mktme_entries.num_entries; i++) {
        entries[i].key_id = mktme_table[i].key_id;
        memcpy(&entries[i].key, &mktme_table[i].key, 32);
        entries[i].enc_mode = mktme_table[i].enc_mode;
    }

    if (copy_to_user(mktme_entries.entries, entries, sizeof(struct kvm_mktme_entries) * mktme_entries.num_entries)) {
        kfree(entries);
        return -EFAULT;
    }

    kfree(entries);

    return 0;
}

int get_page_keyids(struct kvm_vcpu *vcpu, struct kvm_page_keyids __user *user_page_keyids)
{
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);
    struct kvm_page_keyids page_keyids;

    keyid_of_page_t *keyid_of_page;
    struct kvm_page_keyid *pages;
    unsigned long idx, real_gfn;

    if (copy_from_user(&page_keyids, user_page_keyids, sizeof(struct kvm_page_keyids)))
        return -EFAULT;

    if (atomic_read(&kvm_vmx->num_keyed_pages) != page_keyids.num_pages)
        return -EINVAL;

    pages = kzalloc(sizeof(struct kvm_page_keyid) * page_keyids.num_pages, GFP_KERNEL);
    if (!pages)
        return -ENOMEM;

    idx = 0;
    xa_for_each_range(&kvm_vmx->keyid_of_pages, real_gfn, keyid_of_page, 0,
            atomic_read(&kvm_vmx->num_keyed_pages) - 1) {
    
        pages[idx].gfn = real_gfn;
        pages[idx].key_id = keyid_of_page->keyid;
        idx++;
    }

    if (copy_to_user(page_keyids.pages, pages, sizeof(struct kvm_page_keyid) * page_keyids.num_pages)) {
        kfree(pages);
        return -EFAULT;
    }

    kfree(pages);

    return 0;
}