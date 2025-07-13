/* Copyright(c) 2021 Intel Corporation. */

#include <linux/kvm_host.h>

#include "opentdx.h"

#include "vmx.h"
#include "x86.h"

const char* reg8_names[16] = {
    "al", "cx", "dxl", "bxl",
    "spl", "bpl", "sil", "dil",
    "r8l",  "r9l",  "r10l", "r11l",
    "r12l", "r13l", "r14l", "r15l"
};

const char* reg16_names[16] = {
    "ax", "cx", "dx", "bx",
    "sp", "bp", "si", "di",
    "r8w",  "r9w",  "r10w", "r11w",
    "r12w", "r13w", "r14w", "r15w"
};

const char* reg32_names[16] = {
    "eax", "ecx", "edx", "ebx",
    "esp", "ebp", "esi", "edi",
    "r8d",  "r9d",  "r10d", "r11d",
    "r12d", "r13d", "r14d", "r15d"
};

const char* reg64_names[16] = {
    "rax", "rcx", "rdx", "rbx",
    "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11",
    "r12", "r13", "r14", "r15"
};

static unsigned long (*read_reg[])(struct kvm_vcpu *vcpu) = {
    [VCPU_REGS_RAX] = kvm_rax_read,
    [VCPU_REGS_RCX] = kvm_rcx_read,
    [VCPU_REGS_RDX] = kvm_rdx_read,
    [VCPU_REGS_RBX] = kvm_rbx_read,
    [VCPU_REGS_RSP] = kvm_rsp_read,
    [VCPU_REGS_RBP] = kvm_rbp_read,
    [VCPU_REGS_RSI] = kvm_rsi_read,
    [VCPU_REGS_RDI] = kvm_rdi_read,
    [VCPU_REGS_R8] = kvm_r8_read,
    [VCPU_REGS_R9] = kvm_r9_read,
    [VCPU_REGS_R10] = kvm_r10_read,
    [VCPU_REGS_R11] = kvm_r11_read,
    [VCPU_REGS_R12] = kvm_r12_read,
    [VCPU_REGS_R13] = kvm_r13_read,
    [VCPU_REGS_R14] = kvm_r14_read,
    [VCPU_REGS_R15] = kvm_r15_read
};

static char *instr_to_str(u8 *instr, u32 instr_len)
{
    char *str = (char *) kzalloc(sizeof(char) * instr_len * 3 + 1, GFP_KERNEL);

    for (int i = 0; i < instr_len; i++)
        sprintf(str + i * 3, "%02X ", instr[i]);

    return str;
}

static int get_dest_and_payload(struct kvm_vcpu *vcpu, u8 *instr, u32 instr_len,
                                 gpa_t *dst_gpa, u64 *payload)
{
    char *instr_str = instr_to_str(instr, instr_len);
    u32 i = 0;
    u8 pfx = 0, rex = 0, opcode = 0, sib = 0;
    u8 modrm, mod, reg, rm;
    u8 ss, base, idx;
    u32 displacement = 0;
    u64 mask = 0;

    gva_t dst_gva;
    int err = 0;

    if (instr_len < 2) {
        printk(KERN_WARNING "opentdx: instruction (%s) too short\n", instr_str);
        err = -1;
        goto out;
    }

    // Optional instruction prefix
    if ((instr[i] == 0xF0) ||                                        // LOCK
        (instr[i] == 0xF2 || instr[i] == 0xF3) ||                     // REPEAT & BND
        (instr[i] == 0x2E || instr[i] == 0x36 || instr[i] == 0x3E ||   // Segment override & branch hint
        (instr[i] == 0x26 || instr[i] == 0x64 || instr[i] == 0x65) ||
        (instr[i] == 0x67))) {                                       // Address size override
        printk(KERN_WARNING "opentdx: instruction (%s) unsupported prefix\n", instr_str);
        err = -1;
        goto out;
    } else if (instr[i] == 0x66) { // Operand-size override
        pfx = instr[i++];
    }

    // Optional REX prefix
    if ((instr[i] & 0xF0) == 0x40)
        rex = instr[i++];

    opcode = instr[i++];

    // 88: mov r/m8, r8
    // 89: mov r/m16, r16 | mov r/m32, r32 | mov r/m64, r64
    if (opcode == 0x88 || opcode == 0x89) {
        modrm = instr[i++];
        mod = (modrm >> 6) & 0x3;
        reg = (modrm >> 3) & 0x7;
        rm = modrm & 0x7;

        if (mod == 0x03) {
            printk(KERN_WARNING "opentdx: instruction (%s) reg-to-reg mov\n", instr_str);
            err = -1;
            goto out;
        }

        if (rm == 0x4) {
            sib = instr[i++];
            ss = (sib >> 6) & 0x3;
            idx = (sib >> 3) & 0x7;
            base = sib & 0x7;

            /*
            If idx == 0x4, ss and idx are not used.
            Only base is used as if normal mov with displacement = 0
            */
            if (idx != 0x4) {
                // TODO: This may not true
                printk(KERN_WARNING "opentdx: instruction (%s) SIB with idx !=0x4\n", instr_str);
                err = -1;
                goto out;
            }

            reg += rex & 0x4 ? 8 : 0;
            base += rex & 0x1 ? 8 : 0;
        } else {
            reg += rex & 0x4 ? 8 : 0;
            rm += rex & 0x1 ? 8 : 0;
        }

        if (mod == 0x0 && rm == 0x05) {
            printk(KERN_WARNING "opentdx: instruction (%s) RIP related addressing\n", instr_str);
            err = -1;
            goto out;
        } else if (mod == 0x1) {
            displacement = instr[i++];
        } else if (mod == 0x2) {
            displacement = instr[i+3] << 24 | instr[i+2] << 16 | instr[i+1] << 8 | instr[i];
            i += 4;
        }
    } else if (opcode == 0x8A || opcode == 0x8B) {
        err = 1;
        goto out;
    } else {
        printk(KERN_WARNING "opentdx: instruction (%s) not parsed\n", instr_str);
        err = -1;
        goto out;
    }

    if (i != instr_len) {
        printk(KERN_WARNING "opentdx: instruction (%s) not correctly parsed\n", instr_str);
        err = -1;
        goto out;
    }

    mask = (opcode == 0x88) ? 0xFF : 
           (rex & 0x8) ? ~0x0ULL : 
           (pfx == 0x66) ? 0xFFFF : 0xFFFFFFFF;

    *payload = mask & read_reg[reg](vcpu);
    dst_gva = read_reg[rm == 0x4 ? base : rm](vcpu) + displacement;
    *dst_gpa = kvm_mmu_gva_to_gpa_system(vcpu, dst_gva, NULL);

    // printk(KERN_WARNING "instr: %s\n", instr_str);
    // printk(KERN_WARNING "mov [%s + 0x%x], %s: 0x%llx <== 0x%llx", 
    //         reg64_names[rm == 0x4 ? base : rm], displacement,
    //         opcode == 0x88 ? reg8_names[reg] : 
    //         rex & 0x8 ? reg64_names[reg] :
    //         pfx == 0x66 ? reg16_names[reg] : reg32_names[reg],
    //         *dst_gpa, *payload);

out:
    kfree(instr_str);
    return err;
}

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

    u32 instr_len;
#define MAX_INSTR_LEN 12
    char instr[MAX_INSTR_LEN];
    struct x86_exception e;

    u64 payload;
    gpa_t dst_gpa;
    int ret;

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

    instr_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
    if (instr_len > MAX_INSTR_LEN) {
        printk(KERN_WARNING "opentdx: instr_len (%d) > MAX_INSTR_LEN\n", instr_len);
        return;
    }
    if (kvm_read_guest_virt(vcpu, kvm_rip_read(vcpu), 
                instr, instr_len, &e) == 0) {
        ret = get_dest_and_payload(vcpu, instr, instr_len, &dst_gpa, &payload);
        if (ret == 0)
            printk(KERN_WARNING "0x%llx <== 0x%llx\n", dst_gpa, payload);
        else if (ret < 0)
            BUG();
    }

    // TODO: get PCI BAR offset and write payload of GPU devices

    return;
}