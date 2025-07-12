/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ARCH_X86_OPENTDX_H
#define _ARCH_X86_OPENTDX_H

#include <linux/kvm_host.h>

#define __TDCALL_BYTECODE       0x66,0x0f,0x01,0xcc

#define TDCALL_TD_PCI_CONFIG_REGISTER   30
#define TDCALL_TD_PCI_REGION_REGISTER   31
#define TDCALL_TD_PCI_BAR_REGISTER      32

typedef enum {
    Unknown = 0,
    Io16,
    Io32,
    Mem32,
    PMem32,
    Mem64,
    PMem64,
    OpRom,
    Io,
    Mem,
    MaxType
} pci_resource_type_t;

typedef struct {
    pci_resource_type_t type;
    u64 start;
    u64 end;
    struct list_head node;
} pci_region_t;

typedef struct {
    u8 bus;
    u8 device;
    u8 function;
} pci_owner_t;

typedef struct {
    pci_resource_type_t type;
    pci_owner_t owner;

    u64 start;
    u64 end;

    struct interval_tree_node node;
} pci_bar_t;

int handle_tdcall(struct kvm_vcpu *vcpu);
void hook_mmio(struct kvm_vcpu *vcpu, gpa_t gpa);

#endif