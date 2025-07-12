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
    u64 start = kvm_rdx_read(vcpu);
    u64 length = kvm_r8_read(vcpu);
    u64 end = start + length - 1;

    if (type >= MaxType)
        return 1;
    if (end <= start)
        return 1;

    region = kzalloc(sizeof(*region), GFP_KERNEL);
    if (!region)
        return -ENOMEM;

    region->type = type;
    region->start = start;
    region->end = end;

    list_for_each_entry(tmp, &kvm_vmx->pci_regions, node) {
        if (!(end < tmp->start || start > tmp->end)) {
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
    pci_bar_t *bar;
    u64 type_owner = kvm_rcx_read(vcpu);
    u64 start = kvm_rdx_read(vcpu);
    u64 length = kvm_r8_read(vcpu);
    u64 end = start + length - 1;

    pci_resource_type_t type = (pci_resource_type_t) (type_owner >> 32);
    u8 bus = (type_owner >> 8) & 0xFF;
    u8 device = (type_owner >> 3) & 0x1F;
    u8 function = (type_owner) & 0x7;

    struct interval_tree_span_iter iter;

    if (type >= MaxType)
        return 1;
    if (end <= start)
        return 1;

    bar = kzalloc(sizeof(*bar), GFP_KERNEL);
    if (!bar)
        return -ENOMEM;

    bar->type = type;
    bar->owner.bus = bus;
    bar->owner.device = device;
    bar->owner.function = function;

    bar->start = start;
    bar->end = end;

    bar->node.start = start;
    bar->node.last = end;

    interval_tree_for_each_span(&iter, &kvm_vmx->pci_bars, start, end) {
        if (!iter.is_hole) {
            printk(KERN_WARNING "opentdx: requsted pci bar (0x%llx, 0x%llx) overlaps (0x%llx, 0x%llx)\n",
                    start, end, (unsigned long long) iter.start_used, (unsigned long long) iter.last_used);
            
            kfree(bar);
            return 1;
        }
    }

    interval_tree_insert(&bar->node, &kvm_vmx->pci_bars);

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

void hook_mmio(struct kvm_vcpu *vcpu, gpa_t gpa)
{
    struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);
    pci_region_t *region = NULL;
    pci_bar_t *bar = NULL;
    struct interval_tree_node *iter;

    list_for_each_entry(region, &kvm_vmx->pci_regions, node) {
        if (region->start <= gpa && region->end >= gpa)
            break;
    }

    if (region->start > gpa || region->end < gpa) {
        return;
    }

    for (iter = interval_tree_iter_first(&kvm_vmx->pci_bars, region->start, region->end);
        iter; iter = interval_tree_iter_next(iter, region->start, region->end)) {
        if (iter->start <= gpa && iter->last >= gpa) {
            bar = container_of(iter, pci_bar_t, node);
            break;
        }
    }

    if (bar == NULL) {
        printk(KERN_WARNING "opentdx: cannot find pci bar for 0x%llx\n", gpa);
        return;
    }

    // TODO: get PCI BAR offset and write payload of GPU devices

    return;
}