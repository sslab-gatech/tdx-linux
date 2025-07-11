/* Copyright(c) 2021 Intel Corporation. */

#include "opentdx.h"

#include "vmx.h"
#include "x86.h"

static int register_pci_config(struct kvm_vcpu *vcpu)
{
    return 0;
}

static int register_pci_region(struct kvm_vcpu *vcpu)
{
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);
    pci_region_t *region, *tmp;

    pci_resource_type_t type = (pci_resource_type_t) kvm_rcx_read(vcpu);
    u64 base = kvm_rdx_read(vcpu);
    u64 length = kvm_r8_read(vcpu);
    u64 end = base + length - 1, tmp_end;

    if (type >= MaxType)
        return 1;
    if (end <= base)
        return 1;

    region = kzalloc(sizeof(*region), GFP_KERNEL);
    if (!region)
        return -ENOMEM;

    region->type = type;
    region->base = base;
    region->length = length;

    list_for_each_entry(tmp, &kvm_vmx->pci_regions, node) {
        tmp_end = tmp->base + tmp->length - 1;
        if (!(end < tmp->base || base > tmp_end)) {
            printk(KERN_WARNING "opentdx: pci regions overlap\n");
            kfree(region);
            return 1;
        }
    }

    list_add(&region->node, &kvm_vmx->pci_regions);

    return 0;
}

static int register_pci_bar(struct kvm_vcpu *vcpu)
{
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);
    pci_bar_t *bar, *tmp;
    u64 type_owner = kvm_rcx_read(vcpu);
    u64 base = kvm_rdx_read(vcpu);
    u64 length = kvm_r8_read(vcpu);

    pci_resource_type_t type = (pci_resource_type_t) (type_owner >> 32);
    u8 bus = (type_owner >> 8) & 0xFF;
    u8 device = (type_owner >> 3) & 0x1F;
    u8 function = (type_owner) & 0x7;

    int bkt;

    if (type >= MaxType)
        return 1;

    bar = kzalloc(sizeof(*bar), GFP_KERNEL);
    if (!bar)
        return -ENOMEM;

    bar->type = type;
    bar->owner.bus = bus;
    bar->owner.device = device;
    bar->owner.function = function;

    bar->base = base;
    bar->length = length;

    hash_for_each(kvm_vmx->pci_bars, bkt, tmp, node) {
        if (bar->base == tmp->base) {
            printk(KERN_WARNING "opentdx: duplicate PCI bar\n");
            kfree(bar);
            return 1;
        }
    }

    hash_add(kvm_vmx->pci_bars, &bar->node, bar->base);

    return 0;
}

int handle_tdcall(struct kvm_vcpu *vcpu)
{
    u64 rax = kvm_rax_read(vcpu);
    int err = 0;

    switch (rax) {
    case TDCALL_TD_PCI_CONFIG_REGISTER:
        rax = register_pci_config(vcpu);

        break;
    case TDCALL_TD_PCI_REGION_REGISTER:
        rax = register_pci_region(vcpu);

        break;
    case TDCALL_TD_PCI_BAR_REGISTER:
        rax = register_pci_bar(vcpu);

        break;
    default:
        kvm_rax_write(vcpu, 0x1);
    }

    kvm_rax_write(vcpu, rax);

    return kvm_complete_insn_gp(vcpu, err);
}

