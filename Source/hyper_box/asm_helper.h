/*
 *                   Hyper-Box of Alcatraz
 *                   ---------------------
 *      A Practical Hypervisor Sandbox to Prevent Escapes 
 *
 *               Copyright (C) 2021 Seunghun Han
 *             at The Affiliated Institute of ETRI
 */

/*
 * This software has GPL v2+ license. See the GPL_LICENSE file.
 */
#ifndef __ASM_HELPER_H__
#define __ASM_HELPER_H__

/*
 * Functions.
 */
extern void hb_enable_vmx(void);
extern void hb_disable_vmx(void);
extern u64 hb_get_cr0(void);
extern void hb_set_cr0(u64 cr0);
extern u64 hb_get_cr2(void);
extern u64 hb_get_cr3(void);
extern void hb_set_cr3(u64);
extern u64 hb_get_cr4(void);
extern u64 hb_get_cr8(void);
extern u64 hb_get_cs(void);
extern u64 hb_get_ss(void);
extern u64 hb_get_ds(void);
extern u64 hb_get_es(void);
extern u64 hb_get_fs(void);
extern u64 hb_get_gs(void);
extern u64 hb_get_tr(void);
extern u64 hb_get_dr7(void);
extern u64 hb_get_rflags(void);
extern u64 hb_get_ldtr(void);
extern void hb_set_cr4(u64 cr4);
extern int hb_start_vmx(void* vmcs);
extern int hb_clear_vmcs(void* guest_vmcs);
extern int hb_load_vmcs(void* guest_vmcs);
extern int hb_store_vmcs(void* guest_vmcs);
extern int hb_write_vmcs(u64 reg_index, u64 value);
extern int hb_read_vmcs(u64 reg_index, u64* value);
extern void hb_stop_vmx(void);
extern u64 hb_rdmsr(u64 msr_index);
extern void hb_wrmsr(u64 msr_index, u64 value);
extern void hb_invept(u64 inv_type, u64* desc_ptr);
extern void hb_invvpid(u64 inv_type, u64* desc_ptr);
extern void hb_invpcid(u64 inv_type, u64* desc_ptr);
extern void hb_xsetbv(u64 index, u64 value);
extern int hb_vm_launch(void);
extern int hb_vm_launch_other(void);
extern int hb_vm_resume(void);
extern u64 hb_get_rip(void);
extern u64 hb_calc_vm_exit_callback_addr(u64 error);
extern void hb_vm_exit_callback_stub(void);
extern void hb_invd(void);
extern void hb_flush_gdtr(void);
extern void hb_gen_int(void);
extern void hb_pause_loop(void);
extern void* hb_vm_call(u64 svr_num, void* arg);
extern void hb_restore_context_from_stack(u64 stack_addr);

/* Special stub for interrupt handling. */
extern void hb_int_callback_stub(void);
extern void hb_int_with_error_callback_stub(void);
extern void hb_int_nmi_callback_stub(void);

#endif /* __ASM_HELPER_H__ */
