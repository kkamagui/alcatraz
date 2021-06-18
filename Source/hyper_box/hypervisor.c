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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/getcpu.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <asm/desc.h>
#include <linux/kallsyms.h>
#include <asm/reboot.h>
#include <linux/reboot.h>
#include <asm/cacheflush.h>
#include <linux/hardirq.h>
#include <asm/processor.h>
#include <asm/pgtable_64.h>
#include <asm/hw_breakpoint.h>
#include <asm/debugreg.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/utsname.h>
#include <linux/mmzone.h>
#include <linux/jiffies.h>
#include <linux/tboot.h>
#include <linux/log2.h>
#include <linux/version.h>
#include <linux/kfifo.h>
#include <asm/uaccess.h>
#include <linux/suspend.h>
#include <asm/tlbflush.h>
#include <linux/acpi.h>
#include <acpi/acpi_bus.h>
#include <linux/kprobes.h>
#include <linux/nmi.h>
#include "asm_helper.h"
#include "hyper_box.h"
#include "monitor.h"
#include "mmu.h"
#include "asm_helper.h"
#include "workaround.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/vmalloc.h>
#endif

/*
 * Variables.
 */
/* Variables for supporting multi-core environment. */
struct task_struct *g_vm_start_thread_id[MAX_PROCESSOR_COUNT]= {NULL, };
int g_thread_result = 0;
struct task_struct *g_vm_shutdown_thread_id[MAX_PROCESSOR_COUNT]= {NULL, };
struct desc_ptr g_gdtr_array[MAX_PROCESSOR_COUNT];
void* g_vmx_on_vmcs_log_addr[MAX_PROCESSOR_COUNT] = {NULL, };
void* g_guest_vmcs_log_addr[MAX_PROCESSOR_COUNT] = {NULL, };
u64 g_guest_vmcs_phy_addr[MAX_PROCESSOR_COUNT] = {0, };
void* g_vm_exit_stack_addr[MAX_PROCESSOR_COUNT] = {NULL, };
void* g_io_bitmap_addrA[MAX_PROCESSOR_COUNT] = {NULL, };
void* g_io_bitmap_addrB[MAX_PROCESSOR_COUNT] = {NULL, };
void* g_msr_bitmap_addr[MAX_PROCESSOR_COUNT] = {NULL, };
void* g_vmread_bitmap_addr[MAX_PROCESSOR_COUNT] = {NULL, };
void* g_vmwrite_bitmap_addr[MAX_PROCESSOR_COUNT] = {NULL, };
void* g_virt_apic_page_addr[MAX_PROCESSOR_COUNT] = {NULL, };
int g_vmx_root_mode[MAX_PROCESSOR_COUNT] = {0, };

u64 g_nested_vmcs_ptr[MAX_PROCESSOR_COUNT] = {0, };
u64 g_nested_vm_exit_reason[100] = {0, };
u64 g_test_dr[MAX_PROCESSOR_COUNT][8] = {0, };

u64 g_stack_size = MAX_HB_STACK_SIZE;
u64 g_vm_host_phy_pml4 = 0;
u64 g_vm_init_phy_pml4 = 0;
struct module* g_hyper_box_module = NULL;
static int g_support_smx = 0;
static int g_support_xsave = 0;
static struct desc_ptr g_host_idtr;

#if HYPERBOX_USE_VMCS_SHADOWING
static int g_support_vmcs_shadowing = 0;
#endif /*HYPERBOX_USE_VMCS_SHADOWING */

#if HYPERBOX_USE_VPID
static int g_support_vpid = 0;
#endif /* HYPERBOX_USE_VPID */

atomic_t g_need_init_in_secure = {1};
volatile int g_allow_hyper_box_hide = 0;
volatile u64 g_init_in_secure_jiffies = 0;
atomic_t g_thread_run_flags;
atomic_t g_thread_entry_count;
atomic_t g_thread_rcu_sync_count;
atomic_t g_sync_flags;
atomic_t g_complete_flags;
atomic_t g_framework_init_start_flags;
atomic_t g_enter_count;
atomic_t g_first;
//atomic_t g_framework_init_flags;
atomic_t g_iommu_complete_flags;
atomic_t g_mutex_lock_flags;
u64 g_vm_pri_proc_based_ctrl_default = 0;
static spinlock_t g_mem_pool_lock;
static spinlock_t g_mem_sync_lock;

/* Variables for checking dynamic kernel objects. */
struct list_head* g_modules_ptr = NULL;
struct file* g_root_file_ptr = NULL;
struct file* g_proc_file_ptr = NULL;
struct file* g_tcp_file_ptr = NULL;
struct file* g_tcp6_file_ptr = NULL;
struct file* g_udp_file_ptr = NULL;
struct file* g_udp6_file_ptr = NULL;
struct socket* g_tcp_sock = NULL;
struct socket* g_udp_sock = NULL;
rwlock_t* g_tasklist_lock;

/* Variables for operating. */
u64 g_max_ram_size = 0;
struct hb_memory_pool_struct g_memory_pool = {0, };
int g_ro_array_count = 0;
struct ro_addr_struct g_ro_array[MAX_RO_ARRAY_COUNT] = {0, };
struct hb_workaround g_workaround = {{0, }, {0, }};
struct hb_share_context* g_share_context = NULL;
atomic_t g_is_shutdown_trigger_set = {0, };
volatile u64 g_shutdown_jiffies = 0;
static struct kfifo* g_log_info = NULL;
static spinlock_t g_log_lock;

volatile u64 g_dump_jiffies = 0;
u64 g_dump_count[MAX_VM_EXIT_DUMP_COUNT] = {0, };

/* Nested VMCS structrue. */
struct hb_nested_vmcs_struct g_nested_vmcs_array[MAX_NESTED_VMCS] = {0, };

/*
 * Static functions.
 */
static int hb_start(u64 reinitialize);
static void hb_alloc_vmcs_memory(void);
static void hb_setup_workaround(void);
static int hb_setup_memory_pool(void);
void * hb_get_memory(void);
static int hb_is_workaround_addr(u64 addr);
static int hb_init_vmx(int cpu_id);
#if HYPERBOX_USE_MSR_PROTECTION
static void hb_vm_set_msr_write_bitmap(struct hb_vm_control_register*
	hb_vm_control_register, u64 msr_number);
#endif /* HYPERBOX_USE_MSR_PROTECTION */
static void hb_vm_set_vmread_vmwrite_bitmap(struct hb_vm_control_register*
	hb_vm_control_register, u64 field_number);
static void hb_setup_vm_host_register(struct hb_vm_host_register* pstVMHost);
static void hb_setup_vm_guest_register(struct hb_vm_guest_register* pstVMGuest,
	const struct hb_vm_host_register* pstVMHost);
static void hb_setup_vm_control_register(struct hb_vm_control_register*
	pstVMControl, int iCPUID);
static void hb_setup_vmcs(const struct hb_vm_host_register* pstVMHost, const
	struct hb_vm_guest_register* pstVMGuest, const struct hb_vm_control_register*
	pstVMControl);
static void hb_dump_vm_host_register(struct hb_vm_host_register* pstVMHost);
static void hb_dump_vm_guest_register(struct hb_vm_guest_register* pstVMHost);
static void hb_dump_vm_control_register(struct hb_vm_control_register*
	pstVMControl);
static u64 hb_get_desc_base(u64 qwOffset);
static u64 hb_get_desc_access(u64 qwOffset);
static void hb_remove_int_exception_from_vm(int vector);
static void hb_print_vm_result(const char* pcData, int iResult);
static void hb_disable_and_change_machine_check_timer(int reinitialize);
static int hb_vm_thread(void* pvArgument);
static void hb_dup_page_table_for_host(int reinitialize);
static void hb_protect_kernel_ro_area(void);
#if HYPERBOX_USE_MODULE_PROTECTION
static void hb_protect_module_list_ro_area(int reinitialize);
#endif /* HYPERBOX_USE_MODULE_PROTECTION */
static void hb_protect_vmcs(void);
static void hb_protect_gdt(int cpu_id);
static void hb_setup_host_idt_and_protect(void);
static void hb_protect_hyper_box_module(int protect_mode);
static void hb_advance_vm_guest_rip(void);
static u64 hb_calc_vm_pre_timer_value(void);
static unsigned long hb_encode_dr7(int dr_num, unsigned int len, unsigned int type);
static void hb_print_hyper_box_logo(void);
static int hb_prepare_log_buffer(void);
#if HYPERBOX_USE_SHUTDOWN
static int hb_vm_thread_shutdown(void* argument);
static void hb_shutdown_vm_this_core(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context);
static void hb_fill_context_from_vm_guest(struct hb_vm_exit_guest_register*
	guest_context, struct hb_vm_full_context* full_context);
static void hb_restore_context_from_vm_guest(int cpu_id, struct hb_vm_full_context*
	full_context, u64 guest_rsp);
#endif /* HYPERBOX_USE_SHUTDOWN */
static void hb_lock_range(u64 start_addr, u64 end_addr, int alloc_type);
static int hb_get_function_pointers(void);
static int hb_is_system_shutdowning(void);
#if HYPERBOX_USE_SLEEP
static void hb_disable_desc_monitor(void);
static inline __attribute__((always_inline))
void hb_trigger_shutdown_timer(void);
static int hb_is_shutdown_timer_expired(void);
#endif /* HYPERBOX_USE_SLEEP */
static void hb_sync_page_table_flag(struct hb_pagetable* vm, struct hb_pagetable*
	init, int index, u64 addr);
static void hb_set_reg_value_from_index(struct hb_vm_exit_guest_register*
	guest_context, int index, u64 reg_value);
static u64 hb_get_reg_value_from_index(struct hb_vm_exit_guest_register*
	guest_context, int index);

static inline __attribute__((always_inline))
void hb_handle_systemcall_breakpoints(int cpu_id, u64 dr6,
    struct hb_vm_exit_guest_register* guest_context);

/* Functions for vm exit. */
static inline __attribute__((always_inline))
void hb_vm_exit_callback_int(int cpu_id, unsigned long dr6, struct
	hb_vm_exit_guest_register* guest_context);
static void hb_vm_exit_callback_init_signal(int cpu_id);
static void hb_vm_exit_callback_start_up_signal(int cpu_id);
static void hb_vm_exit_callback_access_cr(int cpu_id, struct
	hb_vm_exit_guest_register* guest_context, u64 exit_reason, u64 exit_qual);
static void hb_vm_exit_callback_vmcall(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context);
#if HYPERBOX_USE_MSR_PROTECTION
static void hb_vm_exit_callback_wrmsr(int cpu_id);
#endif /* HYPERBOX_USE_MSR_PROTECTION */
static void hb_vm_exit_callback_gdtr_idtr(int cpu_id, struct
	hb_vm_exit_guest_register* guest_context);
static void hb_vm_exit_callback_ldtr_tr(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context);
static void hb_vm_exit_callback_vmx_inst_type1(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context, u64 exit_reason);
static void hb_vm_exit_callback_vmx_inst_type2(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context, u64 exit_reason);
static void hb_vm_exit_callback_ept_violation(int cpu_id, struct
	hb_vm_exit_guest_register* guest_context, u64 exit_reason, u64 exit_qual,
	u64 guest_linear, u64 guest_physical);
static void hb_vm_exit_callback_cpuid(struct hb_vm_exit_guest_register*
	guest_context);
static void hb_vm_exit_callback_invd(void);
static void hb_vm_exit_callback_pre_timer_expired(int cpu_id);

#if HYPERBOX_USE_SHUTDOWN
static int hb_system_reboot_notify(struct notifier_block *nb, unsigned long code,
	void *unused);

static struct notifier_block* g_vm_reboot_nb_ptr = NULL;
static struct notifier_block g_vm_reboot_nb = {
	.notifier_call = hb_system_reboot_notify,
};
#endif /* HYPERBOX_USE_SHUTDOWN*/

#if HYPERBOX_USE_SLEEP
static int hb_system_sleep_notify(struct notifier_block* nb, unsigned long val, void* unused);
static struct notifier_block* g_hb_sleep_nb_ptr = NULL;
#endif

typedef unsigned long (*kallsyms_lookup_name_t) (const char* name);
kallsyms_lookup_name_t g_kallsyms_lookup_name_fp = NULL;

typedef void (*watchdog_nmi_disable_t) (unsigned int cpu);
watchdog_nmi_disable_t g_watchdog_nmi_disable_fp = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
typedef void (*flush_tlb_one_kernel_t) (unsigned long addr);
flush_tlb_one_kernel_t g_flush_tlb_one_kernel_fp = NULL;
#endif

/* Get or allocate VMCS pointer. */
inline __attribute__((always_inline))
struct hb_nested_vmcs_struct* hb_find_nested_vmcs_struct(u64 vmcs_ptr)
{
	int i;

	for (i = 0 ; i < MAX_NESTED_VMCS ; i++)
	{
		if ((g_nested_vmcs_array[i].vmcs_ptr == vmcs_ptr) ||
		    (g_nested_vmcs_array[i].vmcs_ptr == 0))
		{
			return &(g_nested_vmcs_array[i]);
		}
	}

	hb_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] No nested VMCS structure is selected\n");

	return NULL;
}

/*
 * Clear VMX-related result flags.
 */
static void hb_clear_vmx_inst_flags(void)
{
	u64 temp;

	hb_read_vmcs(VM_GUEST_RFLAGS, &temp);
	temp &= ~(RFLAGS_BIT_CF | RFLAGS_BIT_ZF);
	hb_write_vmcs(VM_GUEST_RFLAGS, temp);
}

/*
 * Start function of Hyper-box module
 */
static int __init hyper_box_init(void)
{
	int cpu_count;
	int cpu_id;
	struct kfifo* fifo;
	u32 eax, ebx, ecx, edx;
	u64 msr;

	hb_print_hyper_box_logo();

	/* Check VMX support. */
	cpuid_count(1, 0, &eax, &ebx, &ecx, &edx);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Initialize VMX\n");
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check virtualization, %08X, "
		"%08X, %08X, %08X\n", eax, ebx, ecx, edx);
	if (ecx & CPUID_1_ECX_VMX)
	{
		hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] VMX support\n");
	}
	else
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] VMX not support\n");
		hb_error_log(ERROR_HW_NOT_SUPPORT);
		return -1;
	}

	if (ecx & CPUID_1_ECX_SMX)
	{
		hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] SMX support\n");
		g_support_smx = 1;
	}
	else
	{
		hb_printf(LOG_LEVEL_DETAIL, LOG_ERROR "    [*] SMX not support\n");
	}

	/* Check BIOS locked feature. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
	msr = hb_rdmsr(MSR_IA32_FEATURE_CONTROL);
#else /* LINUX_VERSION_CODE */
	msr = hb_rdmsr(MSR_IA32_FEAT_CTL);
#endif /* LINUX_VERSION_CODE */
	if (msr & MSR_IA32_FEATURE_CONTROL_BIT_CONTROL_LOCKED)
	{
		if (!(msr & MSR_IA32_FEATURE_CONTROL_BIT_VMXON_ENABLED_OUTPUTSIDE_SMX))
		{
			hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] VMX is disabled by BIOS\n");
			hb_error_log(ERROR_HW_NOT_SUPPORT);
			return -1;
		}
	}

#if HYPERBOX_USE_VMCS_SHADOWING
	/* Check VMCS Shadowing featrue. */
	if (!((hb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) &
		VM_BIT_VM_SEC_PROC_CTRL_VMCS_SHADOWING))
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] CPU does not support VMCS Shadowing\n",
			cpu_id);
	}
#endif /* HYPERBOX_USE_VMCS_SHADOWING */

#if HYPERBOX_USE_VPID
	if (!((hb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) &
		VM_BIT_VM_SEC_PROC_CTRL_ENABLE_VPID))
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] CPU does not support VPID\n",
			cpu_id);
	}
#endif /* HYPERBOX_USE_VPID */

	if (hb_get_function_pointers() != 0)
	{
		hb_error_log(ERROR_KERNEL_VERSION_MISMATCH);
		goto ERROR_HANDLE;
	}

	/* Check XSAVES, XRSTORS support. */
	cpuid_count(0x0D, 1, &eax, &ebx, &ecx, &edx);

	if (eax & CPUID_D_EAX_XSAVES)
	{
		hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] XSAVES/XRSTORES support\n");
		g_support_xsave = 1;
	}
	else
	{
		hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] XSAVES/XRSTORES not support\n");
	}

#if HYPERBOX_USE_SHUTDOWN
	/* Add callback function for checking system shutdown. */
	g_vm_reboot_nb_ptr = kmalloc(sizeof(struct notifier_block), GFP_KERNEL);
	memcpy(g_vm_reboot_nb_ptr, &g_vm_reboot_nb, sizeof(struct notifier_block));
	register_reboot_notifier(g_vm_reboot_nb_ptr);

	/* Create shared context for system shutdown. */
	g_share_context = (struct hb_share_context*) kmalloc(sizeof(struct
		hb_share_context), GFP_KERNEL);
	atomic_set(&(g_share_context->shutdown_complete_count), 0);
	atomic_set(&(g_share_context->shutdown_flag), 0);
#endif /* HYPERBOX_USE_SHUTDOWN */

#if HYPERBOX_USE_SLEEP
	/* Add callback function for checking system sleep. */
	g_hb_sleep_nb_ptr = kmalloc(sizeof(struct notifier_block), GFP_KERNEL);
	g_hb_sleep_nb_ptr->notifier_call = hb_system_sleep_notify;
	g_hb_sleep_nb_ptr->priority = 0;
	register_pm_notifier(g_hb_sleep_nb_ptr);
#endif

	memset(&g_nested_vmcs_array, 0, sizeof(g_nested_vmcs_array));

	/*
	 * Check total RAM size.
	 * To cover system reserved area (3GB ~ 4GB), if system has under 4GB RAM,
	 * Hyper-box sets 4GB RAM to the variable. If system RAM has upper 4GB RAM,
	 * Hyper-box sets 1GB more than original size to the variable.
	 */
	g_max_ram_size = hb_get_max_ram_size();

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "totalram_pages %ld, size %ld, "
		"g_max_ram_size %ld\n", totalram_pages, totalram_pages * VAL_4KB,
		g_max_ram_size);
#else /* LINUX_VERSION_CODE */
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "totalram_pages %ld, size %ld, "
		"g_max_ram_size %ld\n", totalram_pages(), totalram_pages() * VAL_4KB,
		g_max_ram_size);
#endif /* LINUX_VERSION_CODE */

	/* Ceiling to 1GBs and adding a buffer. */
	if (g_max_ram_size < VAL_4GB)
	{
		g_max_ram_size = VAL_4GB;
	}
	else
	{
		g_max_ram_size = CEIL(g_max_ram_size, VAL_1GB) * VAL_1GB;
	}
	g_max_ram_size = g_max_ram_size + VAL_1GB;

	cpu_id = smp_processor_id();
	cpu_count = num_online_cpus();

	hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "CPU Count %d\n", cpu_count);
	hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Booting CPU ID %d\n", cpu_id);

	hb_alloc_vmcs_memory();

#if HYPERBOX_USE_EPT
	if (hb_alloc_ept_pages() != 0)
	{
		hb_error_log(ERROR_MEMORY_ALLOC_FAIL);
		goto ERROR_HANDLE;
	}
	hb_setup_ept_pagetable_4KB();
#endif /* HYPERBOX_USE_EPT */

	hb_protect_kernel_ro_area();
	hb_setup_host_idt_and_protect();

#if HYPERBOX_USE_EPT
	hb_protect_ept_pages();
	hb_protect_vmcs();
#endif /* HYPERBOX_USE_EPT */

	/* Prepare the monitor */
	if (hb_prepare_monitor() != 0)
	{
		hb_error_log(ERROR_MEMORY_ALLOC_FAIL);
		return -1;
	}

	hb_setup_workaround();

	if (hb_setup_memory_pool() != 0)
	{
		hb_error_log(ERROR_MEMORY_ALLOC_FAIL);
		return -1;
	}

	if (hb_prepare_log_buffer() != 0)
	{
		hb_error_log(ERROR_MEMORY_ALLOC_FAIL);
		return -1;
	}
	fifo = g_log_info;

	g_tasklist_lock = (rwlock_t*) hb_get_symbol_address("tasklist_lock");

	/* Start Hyper-box. */
	if (hb_start(START_MODE_INITIALIZE) == 0)
	{
		return 0;
	}

ERROR_HANDLE:
	hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Execution Fail\n");

	hb_free_ept_pages();
	return -1;
}

/*
 * Start Hyper-box.
 */
static int hb_start(u64 reinitialize)
{
	int cpu_count;
	int cpu_id;
	int i;

	cpu_count = num_online_cpus();
	cpu_id = smp_processor_id();
	g_thread_result = 0;
	g_need_init_in_secure.counter = 1;
	g_allow_hyper_box_hide = 0;

	atomic_set(&g_thread_run_flags, cpu_count);
	atomic_set(&g_thread_entry_count, cpu_count);
	atomic_set(&g_thread_rcu_sync_count, cpu_count);
	atomic_set(&g_sync_flags, cpu_count);
	atomic_set(&g_complete_flags, cpu_count);
	atomic_set(&g_framework_init_start_flags, cpu_count);
	atomic_set(&g_first, 1);
	atomic_set(&g_enter_count, 0);
	//atomic_set(&g_framework_init_flags, cpu_count);
	atomic_set(&g_iommu_complete_flags, 0);
	atomic_set(&(g_mutex_lock_flags), 0);

	/* Create thread for each core. */
	for (i = 0 ; i < cpu_count ; i++)
	{
		g_vm_start_thread_id[i] = (struct task_struct *)kthread_create_on_node(
			hb_vm_thread, (void*) reinitialize, cpu_to_node(i), "vm_thread");
		if (g_vm_start_thread_id[i] != NULL)
		{
			kthread_bind(g_vm_start_thread_id[i], i);
		}
		else
		{
			hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] Thread run fail\n", i);
		}

#if HYPERBOX_USE_SHUTDOWN
		g_vm_shutdown_thread_id[i] = (struct task_struct *)kthread_create_on_node(
			hb_vm_thread_shutdown, NULL, cpu_to_node(i), "vm_shutdown_thread");
		if (g_vm_shutdown_thread_id[i] != NULL)
		{
			kthread_bind(g_vm_shutdown_thread_id[i], i);
		}
		else
		{
			hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] Thread run fail\n", i);
		}
#endif /* HYPERBOX_USE_SHUTDOWN */
	}

	/*
	 * Execute thread for each core except this core.
	 * If hb_vm_thread() is executed, task scheduling is prohibited. So,
	 * If task switching is occured when this core run loop below, some core could
	 * not run hb_vm_thread().
	 */
	for (i = 0 ; i < cpu_count ; i++)
	{
		if (i != cpu_id) {
			wake_up_process(g_vm_start_thread_id[i]);
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Thread Run Success\n", i);
		}

#if HYPERBOX_USE_SHUTDOWN
		wake_up_process(g_vm_shutdown_thread_id[i]);
#endif /* HYPERBOX_USE_SHUTDOWN */
	}

	/* Execute thread for this core */
	wake_up_process(g_vm_start_thread_id[cpu_id]);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Thread Run Success\n", cpu_id);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Waiting for complete\n", i);

	/* Check complete flags */
	while(atomic_read(&g_complete_flags) > 0)
	{
		msleep(100);
	}

	if (g_thread_result != 0)
	{
		hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Execution Fail [%d]\n", g_thread_result);
		hb_error_log(ERROR_NOT_START);
		return -1;
	}

	hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Execution Complete\n");
	hb_error_log(ERROR_SUCCESS);

	/* Set hide flag and time. */
	g_init_in_secure_jiffies = jiffies;
	g_allow_hyper_box_hide = 1;

	return 0;
}


/*
 * End function of Hyper-box module.
 *
 * Hyper-box should not be terminated.
 */
static void __exit hyper_box_exit(void)
{
	int cpu_id;

	cpu_id = smp_processor_id();
	hb_print_hyper_box_logo();
	hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "VMX [%d] Stop Hyper-box\n", cpu_id);
}

/*
 * Print Hyper-box logo.
 */
static void hb_print_hyper_box_logo(void)
{
 	hb_printf(LOG_LEVEL_ERROR, "        __    _     __     __   _____  ___    __   ____       \n");
  	hb_printf(LOG_LEVEL_ERROR, "       / /\\  | |   / /`   / /\\   | |  | |_)  / /\\   / /    \n");
  	hb_printf(LOG_LEVEL_ERROR, "      /_/--\\ |_|__ \\_\\_, /_/--\\  |_|  |_| \\ /_/--\\ /_/_ \n");
 	hb_printf(LOG_LEVEL_ERROR, "                                                             \n");
  	hb_printf(LOG_LEVEL_ERROR, "               /=[-----]                                    \n");
  	hb_printf(LOG_LEVEL_ERROR, "              [| |  [] |                                    \n");
  	hb_printf(LOG_LEVEL_ERROR, "             /||.|     |_ _    _       _. -._               \n");
  	hb_printf(LOG_LEVEL_ERROR, "            | \\| |  '` '-' '--''---`'-' | U |      /\\       \n");
  	hb_printf(LOG_LEVEL_ERROR, "     .      |  Y |  []   --   [}   --  {} ..|    ,'Y \\ /\\   \n");
  	hb_printf(LOG_LEVEL_ERROR, "    / \\     | [] |       []    '   {} '   {}|   /. / .Y '\\  \n");
  	hb_printf(LOG_LEVEL_ERROR, "   / Y '\\   |.   |  []    `   [} `     {} ..|._,', Y /_,._/ \n");
  	hb_printf(LOG_LEVEL_ERROR, " _'\\.__,.-.-(  []|       [}        {}       || /`-,        \n");
  	hb_printf(LOG_LEVEL_ERROR, "          ;`~T . |  [] '    ` [}    _,'-_,.-(^) ,-'@@#   ~~ \n");
  	hb_printf(LOG_LEVEL_ERROR, "         #;'~~l {|       [}    ,.-'`'~~~'~ -` @@a@@#      \n");
  	hb_printf(LOG_LEVEL_ERROR, "    ^^^  #;\\~~/\\{|  []     _,'-~~~~~ '~~_.,` @@@aa@@#     \n");
  	hb_printf(LOG_LEVEL_ERROR, "        #a;\\~~~/\\|  _,.-'`~~~~~~_..-'' aaa@@@&&&@@##      \n");
  	hb_printf(LOG_LEVEL_ERROR, "  ~~    ##a; \\~~( Y``~~ Y~~~~ / `,  aaaa@@@@aa@@@##  ^^^^ \n");
  	hb_printf(LOG_LEVEL_ERROR, "       #aa `._~ /~ L~\\~~_./'` aaa@@@@$$@@@&&@##           \n");
  	hb_printf(LOG_LEVEL_ERROR, "      #a@@@Aaaa'--..,-'`aa@@@@@&&@@@aa@@@@#    ~~         \n");
  	hb_printf(LOG_LEVEL_ERROR, "       ##@@&&@@@AA@@@@@@@@@@&&@@@@A@@@@@##                \n");
  	hb_printf(LOG_LEVEL_ERROR, "         #@@@@@$$@@@AA@@@a@@@&&@@@@@##                    \n");
  	hb_printf(LOG_LEVEL_ERROR, "            ##@aaAAA@@AAAa####        ^^^                 \n");
  	hb_printf(LOG_LEVEL_ERROR, "       ^^^       #aaAAaa@                                 \n"); 
  	hb_printf(LOG_LEVEL_ERROR, "                    ~~                                    \n");
 	hb_printf(LOG_LEVEL_ERROR, "                                                          \n");
  	hb_printf(LOG_LEVEL_ERROR, "  A Practical Hypervisor Sandbox to Prevent Escapes from\n");
	hb_printf(LOG_LEVEL_ERROR, "       the KVM/QEMU and KVM-based MicroVMs v%s          \n", HYPERBOX_VERSION);
 	hb_printf(LOG_LEVEL_ERROR, "                                                          \n");
}

/*
 * Prepare Hyper-box log buffer.
 */
static int hb_prepare_log_buffer(void)
{
	int ret;

	spin_lock_init(&g_log_lock);
	g_log_info = (struct kfifo*) kmalloc(sizeof(struct kfifo), GFP_KERNEL | __GFP_COLD);
	if (g_log_info == NULL)
	{
		return -1;
	}

	ret = kfifo_alloc(g_log_info, MAX_LOG_BUFFER_SIZE, GFP_KERNEL | __GFP_COLD);
	if (ret != 0)
	{
		return -1;
	}

	return 0;
}

/*
 * Check and return shutdown status.
 */
static int hb_is_system_shutdowning(void)
{
	if (system_state <= SYSTEM_RUNNING)
	{
		if (acpi_target_system_state() < ACPI_STATE_S3)
		{
			return 0;
		}
	}

	return 1;
}

#if HYPERBOX_USE_SLEEP

/*
 * Disable descriptor (GDT, LDT, IDT) monitoring function.
 */
static void hb_disable_desc_monitor(void)
{
	u64 reg_value;

	hb_read_vmcs(VM_CTRL_SEC_PROC_BASED_EXE_CTRL, &reg_value);
	reg_value &= ~((u64)(VM_BIT_VM_SEC_PROC_CTRL_DESC_TABLE));
	reg_value &= 0xFFFFFFFF;
	hb_write_vmcs(VM_CTRL_SEC_PROC_BASED_EXE_CTRL, reg_value);
}

/*
 * Trigger shutdown timer if the system is shutdowning.
 */
static void hb_trigger_shutdown_timer(void)
{
	if (hb_is_system_shutdowning() == 0)
	{
		return ;
	}

	if (atomic_cmpxchg(&g_is_shutdown_trigger_set, 0, 1) == 0)
	{
		g_shutdown_jiffies = jiffies;
	}

	return ;
}

/*
 * Check time is over after the shutdown timer is triggered.
 */
static inline __attribute__((always_inline))
int hb_is_shutdown_timer_expired(void)
{
	u64 value;

	if (g_is_shutdown_trigger_set.counter == 0)
	{
		return 0;
	}

	value = jiffies - g_shutdown_jiffies;

	if (jiffies_to_msecs(value) >= SHUTDOWN_TIME_LIMIT_MS)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM[%d] Shutdown timer is expired\n",
			smp_processor_id());
		hb_error_log(ERROR_SHUTDOWN_TIME_OUT);
		g_shutdown_jiffies = jiffies;
		return 1;
	}

	return 0;
}

#endif /* HYPERBOX_USE_SLEEP */

/*
 * Process VM resume fail.
 */
void hb_vm_resume_fail_callback(u64 error)
{
	u64 value;
	u64 value2;
	u64 value3;
	u64 prev_vmcs;
	int cpu_id;

	cpu_id = smp_processor_id();
	hb_store_vmcs((void*)&prev_vmcs);
	hb_read_vmcs(VM_GUEST_EFER, &value);
	hb_read_vmcs(VM_CTRL_VM_ENTRY_CTRLS, &value2);
	hb_read_vmcs(VM_GUEST_CR0, &value3);

	if (value & EFER_BIT_LME)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] is in 64bit mode, cur VMCS [%016lX], S.B [%016lX] GUEST_EFER [%016lX], VM_ENTRY_CTRLS [%016lX] GUEST_CR0 [%016lX]\n",
			cpu_id, prev_vmcs, virt_to_phys(g_guest_vmcs_log_addr[cpu_id]), value, value2, value3);
	}
	else
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] is not in 64bit mode, cur VMCS [%016lX], S.B [%016lX] GUEST_EFER [%016lX], VM_ENTRY_CTRLS [%016lX] GUEST_CR0 [%016lX]\n",
			cpu_id, prev_vmcs, virt_to_phys(g_guest_vmcs_log_addr[cpu_id]), value, value2, value3);
	}


	hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM_RESUME fail %d\n", error);
	hb_print_hyper_box_logo();

	hb_error_log(ERROR_LAUNCH_FAIL);
}

/*
 * Get address of kernel symbol.
 * kallsyms_lookup_name() does not have all symbol address which are in System.map.
 * So, if the symbol is not found in kallsyms_lookup_name(), this function finds
 * symbol address in predefined symbal table address.
 */
u64 hb_get_symbol_address(char* symbol)
{
	u64 log_addr = 0;

	log_addr = g_kallsyms_lookup_name_fp(symbol);
	if (log_addr == 0)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "hb_get_symbol_address [%s] is NULL\n", symbol);
		hb_hang("Error SYMBOL_NULL\n");
	}

	return log_addr;
}


/*
 * Convert DR7 data from debug register index, length, type.
 */
static unsigned long hb_encode_dr7(int index, unsigned int len, unsigned int type)
{
	unsigned long value;

	value = (len | type) & 0xf;
	value <<= (DR_CONTROL_SHIFT + index * DR_CONTROL_SIZE);
	value |= (DR_GLOBAL_ENABLE << (index * DR_ENABLE_SIZE));

	return value;
}


/*
 * Dump memory in hex format.
 */
void vm_dump_memory(u8* addr, int size)
{
	char buffer[200];
	char temp[20];
	int i;
	int j;

	for (j = 0 ; j < size / 16 ; j++)
	{
		memset(buffer, 0, sizeof(buffer));
		snprintf(buffer, sizeof(buffer), "[%04X] ", j * 16);
		for (i = 0 ; i < 16 ; i++)
		{
			snprintf(temp, sizeof(temp), "%02X ", addr[j * 16 + i]);
			strlcat(buffer, temp, sizeof(buffer));
		}

		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "%s\n", buffer);
	}
}

/*
 * Allocate memory for VMCS.
 */
static void hb_alloc_vmcs_memory(void)
{
 	int cpu_count;
 	int i;

	cpu_count = num_online_cpus();

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Alloc VMCS Memory\n");

	for (i = 0 ; i < cpu_count ; i++)
	{
		g_vmx_on_vmcs_log_addr[i] = (void*)__get_free_pages(GFP_KERNEL | __GFP_COLD,
			VMCS_SIZE_ORDER);
		g_guest_vmcs_log_addr[i] = (void*)__get_free_pages(GFP_KERNEL | __GFP_COLD,
			VMCS_SIZE_ORDER);
		g_guest_vmcs_phy_addr[i] = (u64) virt_to_phys(g_guest_vmcs_log_addr[i]);

		g_vm_exit_stack_addr[i] = (void*)vmalloc(g_stack_size);

		g_io_bitmap_addrA[i] = (void*)__get_free_page(GFP_KERNEL | __GFP_COLD);
		g_io_bitmap_addrB[i] = (void*)__get_free_page(GFP_KERNEL | __GFP_COLD);
		g_msr_bitmap_addr[i] = (void*)__get_free_page(GFP_KERNEL | __GFP_COLD);
		g_vmread_bitmap_addr[i] = (void*)__get_free_page(GFP_KERNEL | __GFP_COLD);
		g_vmwrite_bitmap_addr[i] = (void*)__get_free_page(GFP_KERNEL | __GFP_COLD);
		g_virt_apic_page_addr[i] = (void*)__get_free_page(GFP_KERNEL | __GFP_COLD);

		if ((g_vmx_on_vmcs_log_addr[i] == NULL) || (g_guest_vmcs_log_addr[i] == NULL) ||
			(g_vm_exit_stack_addr[i] == NULL) || (g_io_bitmap_addrA[i] == NULL) ||
			(g_io_bitmap_addrB[i] == NULL) || (g_msr_bitmap_addr[i] == NULL) ||
			(g_vmread_bitmap_addr[i] == NULL) || (g_vmwrite_bitmap_addr[i] == NULL) ||
			(g_virt_apic_page_addr[i] == NULL))
		{
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "hb_alloc_vmcs_memory alloc fail\n");
			goto error;
		}
		else
		{
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] Alloc Host VMCS"
				" %016lX\n", i, g_vmx_on_vmcs_log_addr[i]);
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] Alloc Guest VMCS"
				" %016lX\n", i, g_guest_vmcs_log_addr[i]);
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] Stack Addr %016lX\n",
				i, g_vm_exit_stack_addr[i]);
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] IO bitmapA Addr"
				" %016lX\n", i, g_io_bitmap_addrA[i]);
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] IO bitmapB Addr"
				" %016lX\n", i, g_io_bitmap_addrB[i]);
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] MSR Bitmap Addr"
				" %016lX\n", i, g_msr_bitmap_addr[i]);
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] VMREAD bitmap Addr"
				" %016lX\n", i, g_vmread_bitmap_addr[i]);
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] VMWRITE bitmap Addr"
				" %016lX\n", i, g_vmwrite_bitmap_addr[i]);
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] Virt APIC Page "
				"Addr %016lX\n", i, g_virt_apic_page_addr[i]);
		}
	}

	return ;

error:
	for (i = 0 ; i < cpu_count ; i++)
	{
		__free_pages(g_vmx_on_vmcs_log_addr[i], VMCS_SIZE_ORDER);
		__free_pages(g_guest_vmcs_log_addr[i], VMCS_SIZE_ORDER);
		vfree(g_vm_exit_stack_addr[i]);

		__free_pages(g_io_bitmap_addrA[i], 0);
		__free_pages(g_io_bitmap_addrB[i], 0);
		__free_pages(g_msr_bitmap_addr[i], 0);
		__free_pages(g_vmread_bitmap_addr[i], 0);
		__free_pages(g_vmwrite_bitmap_addr[i], 0);
		__free_pages(g_virt_apic_page_addr[i], 0);
	}
}

/*
 * Setup data for kernel patch workaround.
 * If you use CONIG_JUMP_LABEL,kernel patches itself during runtime.
 * This function adds exceptional case to allow runtime patch.
 */
static void hb_setup_workaround(void)
{
#if HYPERBOX_USE_WORKAROUND
	char* function_list[WORK_AROUND_MAX_COUNT] = {
		"__netif_hash_nolisten", "__ip_select_ident",
		"secure_dccpv6_sequence_number", "secure_ipv4_port_ephemeral",
		"netif_receive_skb_internal", "__netif_receive_skb_core",
		"netif_rx_internal", "inet6_ehashfn.isra.6", "inet_ehashfn", };
	u64 log_addr;
	u64 phy_addr;
	int i;
	int index = 0;

	memset(&g_workaround, 0, sizeof(g_workaround));
	hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Setup Workaround Address\n");

	for (i = 0 ; i < WORK_AROUND_MAX_COUNT ; i++)
	{
		if (function_list[i] == 0)
		{
			break;
		}

		log_addr = hb_get_symbol_address(function_list[i]);
		if (log_addr <= 0)
		{
			hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] %s log %016lX is not"
				" found\n", function_list[i], log_addr);
			continue;
		}
		phy_addr = virt_to_phys((void*)(log_addr & MASK_PAGEADDR));

		hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] %s log %016lX %016lX\n",
			function_list[i], log_addr, phy_addr);
		g_workaround.addr_array[index] = phy_addr;
		g_workaround.count_array[index] = 0;

		index++;
	}
#endif /* HYPERBOX_USE_WORKAROUND */
}

/*
 * Check if the address is in workaround address.
 */
static int hb_is_workaround_addr(u64 addr)
{
#if HYPERBOX_USE_WORKAROUND
	int i;

	for (i = 0 ; i < WORK_AROUND_MAX_COUNT ; i++)
	{
		if (g_workaround.addr_array[i] == (addr & MASK_PAGEADDR))
		{
			return 1;
		}
	}
#endif /* HYPERBOX_USE_WORKAROUND */

	return 0;
}

/*
 * Allocate memory for Hyper-box.
 * After Hyper-box is loaded and two world are separated, Hyper-box uses own
 * memory pool to prevent interference of the guest.
 */
static int hb_setup_memory_pool(void)
{
	u64 i;

	spin_lock_init(&g_mem_pool_lock);
	spin_lock_init(&g_mem_sync_lock);

	/* Allocate 2 page per 2MB. */
	g_memory_pool.max_count = g_max_ram_size / VAL_2MB * 2;
	g_memory_pool.pool = (u64 *)vzalloc(g_memory_pool.max_count * sizeof(u64));
	if (g_memory_pool.pool == NULL)
	{
		goto ERROR;
	}

	for (i = 0 ; i < g_memory_pool.max_count ; i++)
	{
		g_memory_pool.pool[i] = (u64)__get_free_page(GFP_KERNEL | __GFP_COLD);
		if (g_memory_pool.pool[i] == 0)
		{
			goto ERROR;
		}
#if HYPERBOX_USE_EPT
		hb_hide_range((u64)g_memory_pool.pool[i], (u64)g_memory_pool.pool[i] + VAL_4KB,
			ALLOC_KMALLOC);
#endif /* HYPERBOX_USE_EPT */
	}

	g_memory_pool.pop_index = 0;

	return 0;

ERROR:
	if (g_memory_pool.pool != NULL)
	{
		for (i = 0 ; i < g_memory_pool.max_count ; i++)
		{
			if (g_memory_pool.pool[i] != 0)
			{
#if HYPERBOX_USE_EPT
				hb_set_all_access_range((u64)g_memory_pool.pool[i], (u64)g_memory_pool.pool[i] + 
					VAL_4KB, ALLOC_KMALLOC);
#endif /* HYPERBOX_USE_EPT */
				free_page(g_memory_pool.pool[i]);
			}
		}

		vfree(g_memory_pool.pool);
	}

	return -1;
}

/*
 * Allocate memory from memory pool of Hyper-box.
 */
void * hb_get_memory(void)
{
	void *memory;

	spin_lock(&g_mem_pool_lock);

	if (g_memory_pool.pop_index >= g_memory_pool.max_count)
	{
		spin_unlock(&g_mem_pool_lock);
		return NULL;
	}

	memory = (void *)g_memory_pool.pool[g_memory_pool.pop_index];

	g_memory_pool.pop_index++;
	spin_unlock(&g_mem_pool_lock);

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Get Memory Index %d Addr %016lX\n",
		g_memory_pool.pop_index, memory);

	return memory;
}

/*
 * Lock memory range from the guest.
 */
static void hb_lock_range(u64 start_addr, u64 end_addr, int alloc_type)
{
	u64 i;
	u64 phy_addr;
	u64 align_end_addr;

	align_end_addr = (end_addr + PAGE_SIZE - 1) & MASK_PAGEADDR;

	for (i = (start_addr & MASK_PAGEADDR) ; i < align_end_addr ; i += VAL_4KB)
	{
		if (alloc_type == ALLOC_KMALLOC)
		{
			phy_addr = virt_to_phys((void*)i);
		}
		else
		{
			phy_addr = PFN_PHYS(vmalloc_to_pfn((void*)i));
		}

		hb_set_ept_lock_page(phy_addr);
	}
}

/*
 * Set permissions to memory range.
 */
void hb_set_all_access_range(u64 start_addr, u64 end_addr, int alloc_type)
{
	u64 i;
	u64 phy_addr;
	u64 align_end_addr;

	align_end_addr = (end_addr + PAGE_SIZE - 1) & MASK_PAGEADDR;

	for (i = (start_addr & MASK_PAGEADDR) ; i < align_end_addr ; i += VAL_4KB)
	{
		if (alloc_type == ALLOC_KMALLOC)
		{
			phy_addr = virt_to_phys((void*)i);
		}
		else
		{
			phy_addr = PFN_PHYS(vmalloc_to_pfn((void*)i));
		}

		hb_set_ept_all_access_page(phy_addr);
	}
}

/*
 * Hiding memory range from the guest.
 */
void hb_hide_range(u64 start_addr, u64 end_addr, int alloc_type)
{
	u64 i;
	u64 phy_addr;
	u64 align_end_addr;

	/* Round up the end address */
	align_end_addr = (end_addr + PAGE_SIZE - 1) & MASK_PAGEADDR;

	for (i = (start_addr & MASK_PAGEADDR) ; i < align_end_addr ; i += VAL_4KB)
	{
		if (alloc_type == ALLOC_KMALLOC)
		{
			phy_addr = virt_to_phys((void*)i);
		}
		else
		{
			phy_addr = PFN_PHYS(vmalloc_to_pfn((void*)i));
		}
#if HYPERBOX_USE_EPT
		hb_set_ept_hide_page(phy_addr);
#endif
	}
}

/*
 * Protect static kernel object of Linux kernel using locking and hiding.
 */
static void hb_protect_kernel_ro_area(void)
{
	char* sym_list[] = {
		"_text", "_etext",
		"__start___ex_table", "__stop___ex_table",
		"__start_rodata", "__end_rodata",
	};
	u64 start_log_addr;
	u64 end_log_addr;
	u64 start_phy_addr;
	u64 end_phy_addr;
	u64 i;

	hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Protect Kernel Code Area\n");
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Setup RO Area\n");
	for (i = 0 ; i < sizeof(sym_list)/ sizeof(char*) ; i+=2)
	{
		start_log_addr = hb_get_symbol_address(sym_list[i]);
		end_log_addr = hb_get_symbol_address(sym_list[i + 1]);

		start_phy_addr = virt_to_phys((void*)start_log_addr);
		end_phy_addr = virt_to_phys((void*)end_log_addr);

		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] %s Log %016lX, Phy %016lX\n",
			sym_list[i], start_log_addr, start_phy_addr);
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] %s Log %016lX, Phy %016lX\n",
			sym_list[i + 1], end_log_addr, end_phy_addr);

#if HYPERBOX_USE_EPT
		hb_lock_range(start_log_addr, end_log_addr, ALLOC_KMALLOC);
#endif
		hb_add_ro_area(start_log_addr, end_log_addr, RO_KERNEL);

		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] %d Pages\n",
			(end_log_addr - start_log_addr) / EPT_PAGE_SIZE);
	}

	hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Complete\n");
}
/*
 *	Get module data from a module structure.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
u64 hb_get_module_init_base(struct module *mod)
{
	return (u64)mod->module_init;
}

u64 hb_get_module_init_size(struct module *mod)
{
	return (u64)mod->init_size;
}

u64 hb_get_module_init_text_size(struct module *mod)
{
	return (u64)mod->init_text_size;
}

u64 hb_get_module_init_ro_size(struct module *mod)
{
	return (u64)mod->init_ro_size;
}

u64 hb_get_module_core_base(struct module *mod)
{
	return (u64)mod->module_core;
}

u64 hb_get_module_core_size(struct module *mod)
{
	return (u64)mod->core_size;
}

u64 hb_get_module_core_text_size(struct module *mod)
{
	return (u64)mod->core_text_size;
}

u64 hb_get_module_core_ro_size(struct module *mod)
{
	return (u64)mod->core_ro_size;
}
#else
u64 hb_get_module_init_base(struct module *mod)
{
	return (u64)(mod->init_layout.base);
}

u64 hb_get_module_init_size(struct module *mod)
{
	return (u64)(mod->init_layout.size);
}

u64 hb_get_module_init_text_size(struct module *mod)
{
	return (u64)(mod->init_layout.text_size);
}

u64 hb_get_module_init_ro_size(struct module *mod)
{
	return (u64)(mod->init_layout.ro_size);
}

u64 hb_get_module_core_base(struct module *mod)
{
	return (u64)(mod->core_layout.base);
}

u64 hb_get_module_core_size(struct module *mod)
{
	return (u64)(mod->core_layout.size);
}

u64 hb_get_module_core_text_size(struct module *mod)
{
	return (u64)(mod->core_layout.text_size);
}

u64 hb_get_module_core_ro_size(struct module *mod)
{
	return (u64)(mod->core_layout.ro_size);
}
#endif /* LINUX_VERSION_CODE */

/*
 * Protect static kernel object of the module using locking and hiding.
 */
void hb_add_and_protect_module_ro(struct module* mod)
{
	u64 mod_init_base;
	u64 mod_init_size;
	u64 mod_init_text_size;
	u64 mod_init_ro_size;
	u64 mod_core_base;
	u64 mod_core_size;
	u64 mod_core_text_size;
	u64 mod_core_ro_size;

	mod_init_base = hb_get_module_init_base(mod);
	mod_init_size = hb_get_module_init_size(mod);
	mod_init_text_size = hb_get_module_init_text_size(mod);
	mod_init_ro_size = hb_get_module_init_ro_size(mod);
	mod_core_base = hb_get_module_core_base(mod);
	mod_core_size = hb_get_module_core_size(mod);
	mod_core_text_size = hb_get_module_core_text_size(mod);
	mod_core_ro_size = hb_get_module_core_ro_size(mod);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] mod:0x%016lX [%s], sizeof mod [%d]", mod, mod->name, sizeof(struct module));
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init:0x%16lX module_init:0x%16lX"
		" module_core:0x%016lX\n", mod->init, mod_init_base, mod_core_base);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init_size:0x%ld core_size:%ld",
		mod_init_size, mod_core_size);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] init_text_size:%ld "
		"core_text_size:%ld\n", mod_init_text_size, mod_core_text_size);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] init_ro_size:%ld core_ro_size:"
		"%ld", mod_init_ro_size, mod_core_ro_size);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "\n");

	if ((mod_core_base != 0) && (mod_core_ro_size != 0))
	{
#if HYPERBOX_USE_EPT
		hb_lock_range(mod_core_base, mod_core_base + mod_core_ro_size, ALLOC_VMALLOC);

		/* Module list can be chagned, so make a module structure mutable. */
		hb_set_all_access_range((u64)mod, (u64)mod + sizeof(struct module), ALLOC_VMALLOC);
#endif
		hb_add_ro_area(mod_core_base, mod_core_base + mod_core_ro_size, RO_MODULE);
	}
}

/*
 * Unprotect static kernel object of the module.
 */
void hb_delete_and_unprotect_module_ro(u64 mod_core_base, u64 mod_core_ro_size)
{
	int result;

	if ((mod_core_base != 0) && (mod_core_ro_size != 0))
	{
		result = hb_delete_ro_area(mod_core_base, mod_core_base + mod_core_ro_size);
		if (result == 0)
		{
#if HYPERBOX_USE_EPT
			hb_set_all_access_range(mod_core_base, mod_core_base + mod_core_ro_size, ALLOC_VMALLOC);
#endif
		}
	}
}

#if HYPERBOX_USE_MODULE_PROTECTION

/*
 * Protect static kernel object of modules using hb_add_and_protect_module_ro.
 */
static void hb_protect_module_list_ro_area(int reinitialize)
{
	struct module *mod;
	struct list_head *pos, *node;
	unsigned long mod_head_node;
	u64 mod_core_size;

	hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Protect Module Code Area\n");
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Setup RO Area\n");

	/* If reinitialization, Hyper-box module should be unhide. */
	if (reinitialize == 1)
	{
		hb_protect_hyper_box_module(PROTECT_MODE_LOCK);
		return ;
	}

	g_hyper_box_module = THIS_MODULE;
	mod = THIS_MODULE;
	pos = &THIS_MODULE->list;

	hb_add_and_protect_module_ro(mod);

	node = &THIS_MODULE->list;
	mod_head_node = hb_get_symbol_address("modules");
	/* For later use */
	g_modules_ptr = (struct list_head*)mod_head_node;

	list_for_each(pos, node)
	{
		if(mod_head_node == (unsigned long)pos)
			break;

		mod = container_of(pos, struct module, list);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		mod_core_size = mod->core_size;
#else
		mod_core_size = mod->core_layout.size;
#endif
		if (mod_core_size == 0)
		{
			continue;
		}

		if (strcmp(mod->name, HELPER_MODULE_NAME) == 0)
		{
			hb_add_and_protect_module_ro(mod);
		}
	}
}

#endif /* HYPERBOX_USE_MODULE_PROTECTION */

/*
 * Protect Hyper-box module
 */
static void hb_protect_hyper_box_module(int protect_mode)
{
	struct module *mod;
	u64 mod_init_base;
	u64 mod_init_size;
	u64 mod_init_text_size;
	u64 mod_init_ro_size;
	u64 mod_core_base;
	u64 mod_core_size;
	u64 mod_core_text_size;
	u64 mod_core_ro_size;

	mod = g_hyper_box_module;

	mod_init_base = hb_get_module_init_base(mod);
	mod_init_size = hb_get_module_init_size(mod);
	mod_init_text_size = hb_get_module_init_text_size(mod);
	mod_init_ro_size = hb_get_module_init_ro_size(mod);
	mod_core_base = hb_get_module_core_base(mod);
	mod_core_size = hb_get_module_core_size(mod);
	mod_core_text_size = hb_get_module_core_text_size(mod);
	mod_core_ro_size = hb_get_module_core_ro_size(mod);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Protect Hyper-box Area, mode [%d]\n", protect_mode);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] mod:0x%016lX [%s], size of module"
		" struct %d", mod, mod->name, sizeof(struct module));
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init:0x%016lX module_init:0x%016lX "
		"module_core:0x%08lX\n", mod->init, mod_init_base, mod_core_base);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init_size:0x%ld core_size:%ld",
		mod_init_size, mod_core_size);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init_text_size:%ld "
		"core_text_size:%ld\n", mod_init_text_size, mod_core_text_size);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init_ro_size:%ld core_ro_size:%ld",
		mod_init_ro_size, mod_core_ro_size);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "\n");

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] protection start:%016lX end:%016lX",
		mod_core_base, mod_core_base + mod_core_size);

#if HYPERBOX_USE_SHUTDOWN
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] hb_system_reboot_notify:%016lX,"
		" g_vm_reboot_nb:%016lX", (u64)hb_system_reboot_notify,
		(u64)g_vm_reboot_nb_ptr);
#endif
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Complete\n");

#if HYPERBOX_USE_EPT
	if (protect_mode == PROTECT_MODE_HIDE)
	{
		hb_hide_range(mod_core_base, mod_core_base + mod_core_size, ALLOC_VMALLOC);
	}
	else
	{
		hb_lock_range(mod_core_base, mod_core_base + mod_core_ro_size, ALLOC_VMALLOC);
		hb_set_all_access_range(mod_core_base + mod_core_ro_size, mod_core_base +
			mod_core_size, ALLOC_VMALLOC);
	}

	/*
	 * Module structure is included in module core range, so give full access
	 * to module structure.
	 */
	hb_set_all_access_range((u64)g_hyper_box_module, (u64)g_hyper_box_module +
		sizeof(struct module), ALLOC_VMALLOC);
#endif
}

/*
 * Protect guest's GDT and IDT.
 */
static void hb_protect_gdt(int cpu_id)
{
	struct desc_ptr idtr;

	native_store_gdt(&(g_gdtr_array[cpu_id]));
	store_idt(&idtr);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM[%d] Protect GDT IDT\n", cpu_id);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM[%d]    [*] GDTR Base %16lX, Size %d\n",
		cpu_id, g_gdtr_array[cpu_id].address, g_gdtr_array[cpu_id].size);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM[%d]    [*] IDTR Base %16lX, Size %d\n", cpu_id, idtr.address, idtr.size);

	/* Fix the size of IDT because of KVM. */
	if (idtr.size > 0xFFF)
	{
		idtr.size = 0xFFF;
	}

#if HYPERBOX_USE_EPT
	hb_lock_range(idtr.address, (idtr.address + idtr.size) & MASK_PAGEADDR, ALLOC_VMALLOC);
#endif
}

/*
 * Allocate host's IDT and protect it.
 */
static void hb_setup_host_idt_and_protect(void)
{
	struct desc_ptr idtr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	struct gate_struct* idt;
#else
	struct gate_struct64* idt;
#endif
	int idt_size;
	int i;
	u64 handler;
	void* handlers[22] =
	{
		hb_int_callback_stub, hb_int_callback_stub, hb_int_nmi_callback_stub,
		hb_int_callback_stub, hb_int_callback_stub, hb_int_callback_stub,
		hb_int_callback_stub, hb_int_callback_stub, hb_int_with_error_callback_stub,
		hb_int_callback_stub, hb_int_with_error_callback_stub, hb_int_with_error_callback_stub,
		hb_int_with_error_callback_stub, hb_int_with_error_callback_stub, hb_int_with_error_callback_stub,
		hb_int_callback_stub, hb_int_callback_stub, hb_int_with_error_callback_stub,
		hb_int_callback_stub, hb_int_callback_stub, hb_int_callback_stub,
		hb_int_with_error_callback_stub
	};

	/* Allocate and setup new handlers. */
	store_idt(&idtr);
	memcpy(&g_host_idtr, &idtr, sizeof(struct desc_ptr));
	g_host_idtr.address = __get_free_page(GFP_KERNEL | GFP_ATOMIC | __GFP_COLD | __GFP_ZERO);

	/* Fix the size of IDT because of KVM. */
	if (g_host_idtr.size > 0xFFF)
	{
		g_host_idtr.size = 0xFFF;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	idt = (struct gate_struct *) g_host_idtr.address;
	idt_size = sizeof(struct gate_struct);
#else
	idt = (struct gate_struct64 *) g_host_idtr.address;
	idt_size = sizeof(struct gate_struct64);
#endif
	for (i = 0 ; i < VAL_4KB / idt_size ; i++)
	{
		if (i < 22)
		{
			handler = (u64)handlers[i];
		}
		else
		{
			handler = (u64)hb_int_callback_stub;
		}

		idt->offset_low = (u16)(handler);
		idt->segment = __KERNEL_CS;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
        idt->bits.ist = IST_INDEX_DB;
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0) */
        idt->bits.ist = DEBUG_STACK;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0) */
        idt->bits.type = GATE_INTERRUPT;
        idt->bits.dpl = 0;
        idt->bits.p = 1;
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) */
        idt->ist = DEBUG_STACK;
        idt->type = GATE_INTERRUPT;
        idt->dpl = 0;
        idt->p = 1;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) */
		idt->offset_middle = (u16)(handler >> 16);
		idt->offset_high = (u32)(handler >> 32);

		idt++;
	}

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Setup host's IDT and protect\n");
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IDTR Base %16lX, Size %d\n",
		g_host_idtr.address, g_host_idtr.size);

#if HYPERBOX_USE_EPT
	hb_hide_range(g_host_idtr.address,
		(g_host_idtr.address + g_host_idtr.size) & MASK_PAGEADDR, ALLOC_KMALLOC);
#endif
}

/*
 * Internal printf
 */
static void hb_internal_printf(char* format, va_list arg_list)
{
	char buffer[MAX_LOG_LINE];
	int remain;
	int len;
	int ret;
	int index;

	/* Make buffer and add newline at the end of line. */
	len = vscnprintf(buffer, sizeof(buffer) - 1, format, arg_list);
	if (buffer[len - 1] != '\n')
	{
		if (len >= MAX_LOG_LINE)
		{
			buffer[len - 1] = '\n';
		}
		else
		{
			buffer[len] = '\n';
			len++;
		}
	}

	remain = len;
	index = 0;
	do
	{
		/* When fifo is full, skip this message. */
		if (kfifo_is_full(g_log_info))
		{
			break;
		}

		ret = kfifo_in(g_log_info, buffer + index, remain);
		index += ret;
		remain -= ret;
	} while (remain > 0);
}

/*
 * Print Hyper-box log.
 */
void hb_printf(int level, char* format, ...)
{
	va_list arg_list;

	int cpu_id;
	cpu_id = smp_processor_id();
	if (level <= LOG_LEVEL)
	{
		/* Normal mode or vmx non-root mode. */
		if (g_vmx_root_mode[cpu_id] == 0)
		{
			va_start(arg_list, format);
			vprintk(format, arg_list);
			va_end(arg_list);
		}
		/* Vmx root mode. */
		else
		{
			spin_lock(&g_log_lock);

			va_start(arg_list, format);
			hb_internal_printf(format, arg_list);
			va_end(arg_list);

			spin_unlock(&g_log_lock);
		}
	}
}

/*
 * Print Hyper-box error.
 */
void hb_error_log(int error_code)
{
	hb_printf(LOG_LEVEL_ERROR, LOG_INFO "Error=%06d\n", error_code);
}

/*
 * Expand page table entry.
 */
void vm_expand_page_table_entry(u64 phy_table_addr, u64 start_entry_and_flags,
	u64 entry_size, u64 dummy)
{
	u64 i;
	struct hb_pagetable* log_addr;

	log_addr = (struct hb_pagetable*)phys_to_virt((u64)phy_table_addr & ~(MASK_PAGEFLAG));

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Expand page table entry. Start entry "
		"%016lX, size %016lX, phy table %016lX\n", start_entry_and_flags,
		entry_size, phy_table_addr);

	for (i = 0 ; i < 512 ; i++)
	{
		if (entry_size == VAL_4KB)
		{
			log_addr->entry[i] = (start_entry_and_flags & ~(MASK_PAGE_SIZE_FLAG)) +
				(i * entry_size);
		}
		else
		{
			log_addr->entry[i] = ((start_entry_and_flags & ~(entry_size - 1)) | MASK_PAGE_SIZE_FLAG) +
				(i * entry_size);
		}
	}
}

/*
 * Check and allocate page table.
 */
u64 vm_check_alloc_page_table(struct hb_pagetable* pagetable, int index)
{
	u64 value;

	if ((pagetable->entry[index] == 0) ||
		(pagetable->entry[index] & MASK_PAGE_SIZE_FLAG))
	{
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "PageTable %016lX Index %d is null\n",
			pagetable, index);

		value = (u64)hb_get_memory();
		if (value == 0)
		{
			hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "vm_check_alloc_page fail \n");
			hb_error_log(ERROR_MEMORY_ALLOC_FAIL);
		}

		memset((void*)value, 0, VAL_4KB);

		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "vm_check_alloc_page log %lX, phy %lX \n",
			value, virt_to_phys((void*)value));
		value = virt_to_phys((void*)value);
	}
	else
	{
		value = pagetable->entry[index];
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "PageTable %016lX Index %d is not null"
			" %016lX\n", pagetable, index, value);
	}

	return value;
}

/*
 * Syncronize page table flags.
 */
static void hb_sync_page_table_flag(struct hb_pagetable* vm, struct hb_pagetable* init,
	int index, u64 addr)
{
	u64 value;

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "SyncPage %016lX %016lX Index %d %016lX\n",
		vm->entry[index], init->entry[index], index, addr);

	value = addr & ~(MASK_PAGEFLAG);
	value |= init->entry[index] & MASK_PAGEFLAG;

	vm->entry[index] = value;
}

/*
 * Check if page table flags are same or page size is set.
 */
int vm_is_same_page_table_flag_or_size_flag_set(struct hb_pagetable* vm,
	struct hb_pagetable* init, int index)
{
	u64 vm_value;
	u64 init_value;

	if (init->entry[index] & MASK_PAGE_SIZE_FLAG)
	{
		return 1;
	}

	vm_value = vm->entry[index] & MASK_PAGEFLAG_WO_DA;
	init_value = init->entry[index] & MASK_PAGEFLAG_WO_DA;

	if (vm_value == init_value)
	{
		return 1;
	}

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Index not same %d\n", index);
	return 0;
}

/*
 * Check if new page table is needed.
 * If page table entry is in page table or page size flag is set, new page table
 * is needed.
 */
int vm_is_new_page_table_needed(struct hb_pagetable* vm, struct hb_pagetable* init,
	int index)
{
	if ((vm->entry[index] == 0) || ((vm->entry[index] & MASK_PAGE_SIZE_FLAG)))
	{
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Index not present %d\n", index);
		return 1;
	}

	return 0;
}

/*
 * Get physical address from logical address.
 */
void hb_get_phy_from_log(u64 pml4_phy_addr, u64 addr, struct vm_page_entry_struct*
	out_data)
{
	struct hb_pagetable* pml4;
	struct hb_pagetable* pdpte_pd;
	struct hb_pagetable* pdept;
	struct hb_pagetable* pte;
	u64 pml4_index;
	u64 pdpte_pd_index;
	u64 pdept_index;
	u64 pte_index;
	u64 value;
	u64 addr_value;

	pml4_index = (addr / VAL_512GB) % 512;
	pdpte_pd_index = (addr / VAL_1GB) %  512;
	pdept_index = (addr / VAL_2MB) %  512;
	pte_index = (addr / VAL_4KB) %  512;

	memset(out_data, 0, sizeof(struct vm_page_entry_struct));

	/* PML4 */
	pml4 = phys_to_virt((u64)pml4_phy_addr);
	value = pml4->entry[pml4_index];
	addr_value = GET_ADDR(value);
	out_data->phy_addr[0] = value;

	if (!IS_PRESENT(value))
	{
		return ;
	}

	if (IS_SIZE_FLAG_SET(value))
	{
		addr_value += pdpte_pd_index * VAL_1GB + pdept_index * VAL_2MB +
			pte_index * VAL_4KB;
		out_data->phy_addr[3] = addr_value | (value & MASK_PAGEFLAG_WO_SIZE);
		return ;
	}

	/* PDPTE_PD */
	pdpte_pd = phys_to_virt((u64)addr_value);
	value = pdpte_pd->entry[pdpte_pd_index];
	addr_value = GET_ADDR(value);
	out_data->phy_addr[1] = value;

	if (!IS_PRESENT(value))
	{
		return ;
	}

	if (IS_SIZE_FLAG_SET(value))
	{
		addr_value += pdept_index * VAL_2MB + pte_index * VAL_4KB;
		out_data->phy_addr[3] = addr_value | (value & MASK_PAGEFLAG_WO_SIZE);
		return ;
	}

	/* PDEPT */
	pdept = phys_to_virt((u64)addr_value);
	value = pdept->entry[pdept_index];
	addr_value = GET_ADDR(value);
	out_data->phy_addr[2] = value;

	if (!IS_PRESENT(value))
	{
		return ;
	}

	if (IS_SIZE_FLAG_SET(value))
	{
		addr_value += pte_index * VAL_4KB;
		out_data->phy_addr[3] = addr_value | (value & MASK_PAGEFLAG_WO_SIZE);
		return ;
	}

	/* PTE */
	pte = phys_to_virt((u64)addr_value);
	value = pte->entry[pte_index];
	out_data->phy_addr[3] = value;
}

/*
 * Syncronize page table with the guest to introspect it. V1
 * PML4 -> PDPTE_PD -> PDEPT -> PTE -> 4KB
 */
u64 hb_sync_page_table(u64 addr, u64 org_target_phy_pml4, int sync_direct_mapping)
{
	struct hb_pagetable* init_pml4;
	struct hb_pagetable* init_pdpte_pd;
	struct hb_pagetable* init_pdept;
	struct hb_pagetable* init_pte;
	struct hb_pagetable* vm_pml4;
	struct hb_pagetable* vm_pdpte_pd;
	struct hb_pagetable* vm_pdept;
	struct hb_pagetable* vm_pte;
	struct vm_page_entry_struct phy_entry;
	struct vm_page_entry_struct phy_entry2;

	u64 pml4_index;
	u64 pdpte_pd_index;
	u64 pdept_index;
	u64 pte_index;
	u64 value;
	u64 target_phy_pml4;
	u64 expand_value = 0;

	target_phy_pml4 = GET_ADDR(org_target_phy_pml4);

	/* Skip direct mapping area except host and target are different. */
	/* KVM maps new areas in the direct mapping area. */
	if (((u64)page_offset_base <= addr) && (addr < (u64)page_offset_base + (64 * VAL_1TB)))
	{
		if (sync_direct_mapping == 0)
		{
			return 0;
		}

		hb_get_phy_from_log(target_phy_pml4, addr, &phy_entry);
		if (!IS_PRESENT(phy_entry.phy_addr[3]))
		{
			return 0;
		}

		hb_get_phy_from_log(g_vm_host_phy_pml4, addr, &phy_entry2);
		if (IS_PRESENT(phy_entry2.phy_addr[3]))
		{
			if (GET_ADDR(phy_entry.phy_addr[3]) == GET_ADDR(phy_entry2.phy_addr[3]))
			{
				return 0;
			}
		}
	}

	/* Skip static kernel object area */
	if (hb_is_addr_in_kernel_ro_area((void*)addr))
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] The address is in kernel RO area.\n");
		return 0;
	}

	/* Get physical page by traversing page table of the guest. */
	hb_get_phy_from_log(target_phy_pml4, addr, &phy_entry);
	if (!IS_PRESENT(phy_entry.phy_addr[3]))
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] phy_entry.phy_addr[3] is not present.\n");
		return 0;
	}

	hb_get_phy_from_log(g_vm_host_phy_pml4, addr, &phy_entry2);
	if (GET_ADDR(phy_entry.phy_addr[3]) == GET_ADDR(phy_entry2.phy_addr[3]))
	{
		return 0;
	}

	init_pml4 = (struct hb_pagetable*)target_phy_pml4;
	init_pml4 = phys_to_virt((u64)init_pml4);
	vm_pml4 = phys_to_virt(g_vm_host_phy_pml4);

	pml4_index = (addr / VAL_512GB) % 512;
	pdpte_pd_index = (addr / VAL_1GB) %  512;
	pdept_index = (addr / VAL_2MB) %  512;
	pte_index = (addr / VAL_4KB) %  512;

	spin_lock(&g_mem_sync_lock);

	/*
	 * Get PDPTE_PD from PML4
	 */
	init_pdpte_pd = (struct hb_pagetable*)(init_pml4->entry[pml4_index]);
	if ((init_pdpte_pd == 0) || ((u64)init_pdpte_pd & MASK_PAGE_SIZE_FLAG))
	{
		vm_pml4->entry[pml4_index] = (u64)init_pdpte_pd;

		goto EXIT;
	}

	if (vm_is_new_page_table_needed(vm_pml4, init_pml4, pml4_index) == 1)
	{
		value = vm_check_alloc_page_table(vm_pml4, pml4_index);
		vm_expand_page_table_entry(value, phy_entry.phy_addr[3], VAL_1GB,
			init_pml4->entry[pml4_index]);
		hb_sync_page_table_flag(vm_pml4, init_pml4, pml4_index, value);

		if (expand_value == 0)
		{
			expand_value = VAL_1GB;
		}
	}

	init_pdpte_pd = phys_to_virt((u64)init_pdpte_pd & ~(MASK_PAGEFLAG));
	vm_pdpte_pd = (struct hb_pagetable*)(vm_pml4->entry[pml4_index]);
	vm_pdpte_pd = phys_to_virt((u64)vm_pdpte_pd & ~(MASK_PAGEFLAG));

	/*
	 * Get PDEPT from PDPTE_PD.
	 */
	init_pdept = (struct hb_pagetable*)(init_pdpte_pd->entry[pdpte_pd_index]);

	if ((init_pdept == 0) || ((u64)init_pdept & MASK_PAGE_SIZE_FLAG))
	{
		if (vm_pdpte_pd->entry[pdpte_pd_index] != (u64)init_pdept)
		{
			vm_pdpte_pd->entry[pdpte_pd_index] = (u64)init_pdept;

		}
		goto EXIT;
	}

	/* If PDEPT exist, syncronize the flag. */
	if (vm_is_new_page_table_needed(vm_pdpte_pd, init_pdpte_pd, pdpte_pd_index) == 1)
	{
		value = vm_check_alloc_page_table(vm_pdpte_pd, pdpte_pd_index);
		vm_expand_page_table_entry(value, phy_entry.phy_addr[3],
			VAL_2MB, init_pdpte_pd->entry[pdpte_pd_index]);
		hb_sync_page_table_flag(vm_pdpte_pd, init_pdpte_pd, pdpte_pd_index, value);
		if (expand_value == 0)
		{
			expand_value = VAL_2MB;
		}
	}

	init_pdept = phys_to_virt((u64)init_pdept & ~(MASK_PAGEFLAG));
	vm_pdept = (struct hb_pagetable*)(vm_pdpte_pd->entry[pdpte_pd_index]);
	vm_pdept = phys_to_virt((u64)vm_pdept & ~(MASK_PAGEFLAG));

	/*
	 * Get PTE from PDPTE_PD.
	 */
	init_pte = (struct hb_pagetable*)(init_pdept->entry[pdept_index]);

	if ((init_pte == 0) || ((u64)init_pte & MASK_PAGE_SIZE_FLAG))
	{
		if (vm_pdept->entry[pdept_index] != (u64)init_pte)
		{
			vm_pdept->entry[pdept_index] = (u64)init_pte;
		}
		goto EXIT;
	}

	/* If PTE exist, syncronize the flag. */
	if (vm_is_new_page_table_needed(vm_pdept, init_pdept, pdept_index) == 1)
	{
		value = vm_check_alloc_page_table(vm_pdept, pdept_index);
		vm_expand_page_table_entry(value, phy_entry.phy_addr[3], VAL_4KB,
			init_pdept->entry[pdept_index]);
		hb_sync_page_table_flag(vm_pdept, init_pdept, pdept_index, value);

		if (expand_value == 0)
		{
			expand_value = VAL_4KB;
		}
	}

	init_pte = phys_to_virt((u64)init_pte & ~(MASK_PAGEFLAG));
	vm_pte = (struct hb_pagetable*)(vm_pdept->entry[pdept_index]);

	vm_pte = phys_to_virt((u64)vm_pte & ~(MASK_PAGEFLAG));

	/* Copy PTE from the guest. */
	vm_pte->entry[pte_index] = init_pte->entry[pte_index];

EXIT:
	spin_unlock(&g_mem_sync_lock);

	/* Update page table to CPU. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	g_flush_tlb_one_kernel_fp(addr);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 20)
	__flush_tlb_one_kernel(addr);
#else
	__flush_tlb_one(addr);
#endif

	return expand_value;
}

/*
 * Duplicate page tabel for the host.
 *
 * Memory space of Linux kernel is as follows.
 * 0000000000000000 - 00007fffffffffff (=47 bits) user space, different per mm
 * ffff800000000000 - ffff80ffffffffff (=40 bits) guard hole
 * ffff880000000000 - ffffc7ffffffffff (=64 TB) direct mapping of all phys. memory
 * ffffc80000000000 - ffffc8ffffffffff (=40 bits) hole
 * ffffc90000000000 - ffffe8ffffffffff (=45 bits) vmalloc/ioremap space
 * ffffe90000000000 - ffffe9ffffffffff (=40 bits) hole
 * ffffea0000000000 - ffffeaffffffffff (=40 bits) virtual memory map (1TB)
 * ffffffff80000000 - ffffffffa0000000 (=512 MB)  kernel text mapping, from phys 0
 * ffffffffa0000000 - fffffffffff00000 (=1536 MB) module mapping space
 */
static void hb_dup_page_table_for_host(int reinitialize)
{
	struct hb_pagetable* org_pml4;
	struct hb_pagetable* org_pdpte_pd;
	struct hb_pagetable* org_pdept;
	struct hb_pagetable* org_pte;
	struct hb_pagetable* vm_pml4;
	struct hb_pagetable* vm_pdpte_pd;
	struct hb_pagetable* vm_pdept;
	struct hb_pagetable* vm_pte;
	int i;
	int j;
	int k;
	struct mm_struct* swapper_mm;
	u64 cur_addr;

	if (reinitialize != 0)
	{
		return ;
	}

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Duplicate page tables\n");

	org_pml4 = (struct hb_pagetable*)hb_get_symbol_address(INIT_LEVEL4_PGT);
	g_vm_init_phy_pml4 = virt_to_phys(org_pml4);
	swapper_mm = (struct mm_struct*)hb_get_symbol_address("init_mm");
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "init_mm %016lX, %s %016lX\n",
		swapper_mm->pgd, INIT_LEVEL4_PGT, org_pml4);

	vm_pml4 =  (struct hb_pagetable*)__get_free_pages(GFP_KERNEL_ACCOUNT |
		__GFP_ZERO, PGD_ALLOCATION_ORDER);
#if HYPERBOX_USE_EPT
	hb_hide_range((u64)vm_pml4, (u64)vm_pml4 + PAGE_SIZE * (0x1 << PGD_ALLOCATION_ORDER),
		ALLOC_KMALLOC);
#endif /* HYPERBOX_USE_EPT */

	g_vm_host_phy_pml4 = virt_to_phys(vm_pml4);

	/* Create page tables. */
	for (i = 0 ; i < 512 ; i++)
	{
		cur_addr = i * VAL_512GB;

		if ((org_pml4->entry[i] == 0) ||
			((org_pml4->entry[i] & MASK_PAGE_SIZE_FLAG)))
		{
			vm_pml4->entry[i] = org_pml4->entry[i];
			continue;
		}

		/* Allocate PDPTE_PD and copy. */
		vm_pml4->entry[i] = (u64)__get_free_page(GFP_KERNEL | GFP_ATOMIC |
			__GFP_COLD | __GFP_ZERO);
#if HYPERBOX_USE_EPT
		hb_hide_range((u64)vm_pml4->entry[i], (u64)(vm_pml4->entry[i]) + PAGE_SIZE,
			ALLOC_KMALLOC);
#endif /* HYPERBOX_USE_EPT */
		vm_pml4->entry[i] = virt_to_phys((void*)(vm_pml4->entry[i]));
		vm_pml4->entry[i] |= org_pml4->entry[i] & MASK_PAGEFLAG;

		/* Run loop to copy PDEPT. */
		org_pdpte_pd = (struct hb_pagetable*)(org_pml4->entry[i] & ~(MASK_PAGEFLAG));
		vm_pdpte_pd = (struct hb_pagetable*)(vm_pml4->entry[i] & ~(MASK_PAGEFLAG));
		org_pdpte_pd = phys_to_virt((u64)org_pdpte_pd);
		vm_pdpte_pd = phys_to_virt((u64)vm_pdpte_pd);

		for (j = 0 ; j < 512 ; j++)
		{
			if ((org_pdpte_pd->entry[j] == 0) ||
				((org_pdpte_pd->entry[j] & MASK_PAGE_SIZE_FLAG)))
			{
				vm_pdpte_pd->entry[j] = org_pdpte_pd->entry[j];
				continue;
			}

			/* Allocate PDEPT and copy. */
			vm_pdpte_pd->entry[j] = (u64)__get_free_page(GFP_KERNEL | GFP_ATOMIC |
				__GFP_COLD | __GFP_ZERO);
#if HYPERBOX_USE_EPT
			hb_hide_range((u64)vm_pdpte_pd->entry[j], (u64)(vm_pdpte_pd->entry[j]) +
				PAGE_SIZE, ALLOC_KMALLOC);
#endif /* HYPERBOX_USE_EPT */
			vm_pdpte_pd->entry[j] = virt_to_phys((void*)(vm_pdpte_pd->entry[j]));
			vm_pdpte_pd->entry[j] |= org_pdpte_pd->entry[j] & MASK_PAGEFLAG;

			/* Run loop to copy PDEPT. */
			org_pdept = (struct hb_pagetable*)(org_pdpte_pd->entry[j] & ~(MASK_PAGEFLAG));
			vm_pdept = (struct hb_pagetable*)(vm_pdpte_pd->entry[j] & ~(MASK_PAGEFLAG));
			org_pdept = phys_to_virt((u64)org_pdept);
			vm_pdept = phys_to_virt((u64)vm_pdept);

			for (k = 0 ; k < 512 ; k++)
			{
				if ((org_pdept->entry[k] == 0) ||
					((org_pdept->entry[k] & MASK_PAGE_SIZE_FLAG)))
				{
					vm_pdept->entry[k] = org_pdept->entry[k];
					continue;
				}

				/* Allocate PTE and copy. */
				vm_pdept->entry[k] = (u64)__get_free_page(GFP_KERNEL | GFP_ATOMIC |
					__GFP_COLD | __GFP_ZERO);
#if HYPERBOX_USE_EPT
				hb_hide_range((u64)vm_pdept->entry[k], (u64)(vm_pdept->entry[k]) + PAGE_SIZE,
					ALLOC_KMALLOC);
#endif /* HYPERBOX_USE_EPT */
				vm_pdept->entry[k] = virt_to_phys((void*)(vm_pdept->entry[k]));
				vm_pdept->entry[k] |= org_pdept->entry[k] & MASK_PAGEFLAG;

				/* Run loop to copy PTE */
				org_pte = (struct hb_pagetable*)(org_pdept->entry[k] & ~(MASK_PAGEFLAG));
				vm_pte = (struct hb_pagetable*)(vm_pdept->entry[k] & ~(MASK_PAGEFLAG));
				org_pte = phys_to_virt((u64)org_pte);
				vm_pte = phys_to_virt((u64)vm_pte);

				memcpy(vm_pte, org_pte, VAL_4KB);
			}
		}
	}
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] complete\n");
}


/*
 * Protect VMCS structure.
 */
static void hb_protect_vmcs(void)
{
	int i;
	int cpu_count;

	cpu_count = num_online_cpus();
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Protect VMCS\n");

	for (i = 0 ; i < cpu_count ; i++)
	{
		hb_hide_range((u64)g_vmx_on_vmcs_log_addr[i],
			(u64)g_vmx_on_vmcs_log_addr[i] + VMCS_SIZE, ALLOC_KMALLOC);
		hb_hide_range((u64)g_guest_vmcs_log_addr[i],
			(u64)g_guest_vmcs_log_addr[i] + VMCS_SIZE, ALLOC_KMALLOC);
		hb_hide_range((u64)g_vm_exit_stack_addr[i],
			(u64)g_vm_exit_stack_addr[i] + g_stack_size, ALLOC_VMALLOC);
		hb_hide_range((u64)g_io_bitmap_addrA[i],
			(u64)g_io_bitmap_addrA[i] + IO_BITMAP_SIZE, ALLOC_KMALLOC);
		hb_hide_range((u64)g_io_bitmap_addrB[i],
			(u64)g_io_bitmap_addrB[i] + IO_BITMAP_SIZE, ALLOC_KMALLOC);
		hb_hide_range((u64)g_msr_bitmap_addr[i],
			(u64)g_msr_bitmap_addr[i] + MSR_BITMAP_SIZE, ALLOC_KMALLOC);
		hb_hide_range((u64)g_vmread_bitmap_addr[i],
			(u64)g_vmread_bitmap_addr[i] + VMREAD_BITMAP_SIZE, ALLOC_KMALLOC);
		hb_hide_range((u64)g_vmwrite_bitmap_addr[i],
			(u64)g_vmwrite_bitmap_addr[i] + VMWRITE_BITMAP_SIZE, ALLOC_KMALLOC);
		hb_hide_range((u64)g_virt_apic_page_addr[i],
			(u64)g_virt_apic_page_addr[i] + VIRT_APIC_PAGE_SIZE, ALLOC_KMALLOC);
	}
}

/*
 * Hang system.
 * This function should be called in emergency situation.
 */
void hb_hang(char* string)
{
	do
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "===============================\n");
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "===============================\n");
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "HANG %s\n", string);
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "===============================\n");
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "===============================\n");

		msleep(5000);
	} while(hb_is_system_shutdowning() == 0);
}

/*
 * Disable machine check exception and change the check interval.
 */
static void hb_disable_and_change_machine_check_timer(int reinitialize)
{
	typedef void (*mce_timer_delete_all) (void);
	typedef void (*mce_cpu_restart) (void *data);
	unsigned long *check_interval;
	mce_timer_delete_all delete_timer_fp;
	mce_cpu_restart restart_cpu_fp;

	/* Disable MCE event. */
	cr4_clear_bits(CR4_BIT_MCE);
	disable_irq(VM_INT_MACHINE_CHECK);

	if (reinitialize != 0)
	{
		return ;
	}

	/* Change MCE polling timer. */
	if (smp_processor_id() == 0)
	{
		check_interval = (unsigned long *)hb_get_symbol_address("check_interval");
		delete_timer_fp = (mce_timer_delete_all)hb_get_symbol_address("mce_timer_delete_all");
		restart_cpu_fp = (mce_cpu_restart)hb_get_symbol_address("mce_cpu_restart");

		/* Set seconds for timer interval and restart timer. */
		*check_interval = VM_MCE_TIMER_VALUE;

		delete_timer_fp();
		on_each_cpu(restart_cpu_fp, NULL, 1);
	}
}

/*
 * Enable VT-x and run Hyper-box.
 * This thread function runs on each core.
 */
static int hb_vm_thread(void* argument)
{
	struct hb_vm_host_register* host_register;
	struct hb_vm_guest_register* guest_register;
	struct hb_vm_control_register* control_register;
	u64 vm_err_number;
	unsigned long irqs;
	int result;
	int cpu_id;
	int reinitialize;

	cpu_id = smp_processor_id();
	reinitialize = (u64) argument;

	/* Disable MCE exception. */
	hb_disable_and_change_machine_check_timer(reinitialize);

	/* Disable Watchdog. */
	g_watchdog_nmi_disable_fp(cpu_id);

	/* Synchronize processors. */
	atomic_dec(&g_thread_entry_count);
	while(atomic_read(&g_thread_entry_count) > 0)
	{
		schedule();
	}

	host_register = kmalloc(sizeof(struct hb_vm_host_register), GFP_KERNEL | __GFP_COLD);
	guest_register = kmalloc(sizeof(struct hb_vm_guest_register), GFP_KERNEL | __GFP_COLD);
	control_register = kmalloc(sizeof(struct hb_vm_control_register), GFP_KERNEL | __GFP_COLD);
	if ((host_register == NULL) || (guest_register == NULL) ||
			(control_register == NULL))
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Host or Guest or Control "
			"Register alloc fail\n", cpu_id);
		g_thread_result = -1;
		return -1;
	}

	memset(host_register, 0, sizeof(struct hb_vm_host_register));
	memset(guest_register, 0, sizeof(struct hb_vm_guest_register));
	memset(control_register, 0, sizeof(struct hb_vm_control_register));

	/* Lock module_mutex, and protect module RO area, and syncronize all core. */
	if (cpu_id == 0)
	{
		synchronize_rcu();
	}

	/* Synchronize processors. */
	atomic_dec(&g_thread_rcu_sync_count);
	while(atomic_read(&g_thread_rcu_sync_count) > 0)
	{
		msleep(0);
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] wait for synchronize_rcu %d\n",
			cpu_id, g_thread_rcu_sync_count);
	}

	if (cpu_id == 0)
	{
		mutex_lock(&module_mutex);

#if HYPERBOX_USE_MODULE_PROTECTION
		hb_protect_module_list_ro_area(reinitialize);
#endif /* HYPERBOX_USE_MODULE_PROTECTION */

		atomic_set(&g_mutex_lock_flags, 1);
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] module mutex lock complete\n",
			cpu_id);
	}
	else
	{
		while (atomic_read(&g_mutex_lock_flags) == 0)
		{
			msleep(0);
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] wait for mutex_lock %d\n",
				cpu_id, g_mutex_lock_flags);
		}
	}

	/* Disable preemption and hold processors. */
	preempt_disable();

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Wait until thread executed\n",
		cpu_id);

	/* Synchronize processors. */
	atomic_dec(&g_thread_run_flags);
	while(atomic_read(&g_thread_run_flags) > 0)
	{
		;
	}
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Complete to wait until thread "
		"executed\n", cpu_id);

	/* Lock tasklist_lock and initialize the monitor. */
	if (cpu_id == 0)
	{
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Dup talbe Initialize \n",
			cpu_id);

		/* Duplicate page table for the host and Hyper-box. */
		hb_dup_page_table_for_host(reinitialize);

		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Dup talbe Initialize Complete\n",
			cpu_id);

		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Monitor Initialize \n",
			cpu_id);

		/* Initialize monitor. */
		hb_init_monitor(reinitialize);

		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Monitor Initialize Complete \n",
			cpu_id);
	}

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Monitor Initialize Waiting\n",
		cpu_id);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM [%d] Complete\n", cpu_id);

	/* Synchronize processors. */
	atomic_dec(&g_sync_flags);
	while(atomic_read(&g_sync_flags) > 0)
	{
		;
	}
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Ready to go!!\n", cpu_id);

	/* Initialize VMX. */
	if (hb_init_vmx(cpu_id) < 0)
	{
		atomic_inc(&g_enter_count);
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] hb_init_vmx fail\n", cpu_id);

		result = -1;
		goto ERROR;
	}

	hb_protect_gdt(cpu_id);

	hb_setup_vm_host_register(host_register);
	hb_setup_vm_guest_register(guest_register, host_register);
	hb_setup_vm_control_register(control_register, cpu_id);
	hb_setup_vmcs(host_register, guest_register, control_register);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Launch Start\n", cpu_id);

	/* Disable interrupts before launch and enable again. */
	local_irq_save(irqs);
	result = hb_vm_launch();
	local_irq_restore(irqs);

	atomic_inc(&g_enter_count);

	if (result == -2)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] VM [%d] Launch Valid Fail\n",
			cpu_id);
		hb_read_vmcs(VM_DATA_INST_ERROR, &vm_err_number);
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] VM [%d] Error Number [%d]\n",
			cpu_id, (int)vm_err_number);
		hb_error_log(ERROR_LAUNCH_FAIL);

		result = -1;
		goto ERROR;
	}
	else if (result == -1)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] VM [%d] Launch Invalid Fail\n",
			cpu_id);
		hb_error_log(ERROR_LAUNCH_FAIL);

		result = -1;
		goto ERROR;
	}
	else
	{
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM [%d] Launch Success\n",
			cpu_id);
	}

	result = 0;

/* Handle errors. */
ERROR:
	if (result != 0)
	{
		g_thread_result = -1;
	}

	preempt_enable();

	if (cpu_id == 0)
	{
		mutex_unlock(&module_mutex);
	}
	atomic_dec(&g_complete_flags);

	kfree(host_register);
	kfree(guest_register);
	kfree(control_register);

	return result;
}

/*
 * Initialize VMX context (VMCS)
 */
static int hb_init_vmx(int cpu_id)
{
	u64 vmx_msr;
	u64 msr;
	u64 cr4;
	u64 cr0;
	u32* vmx_VMCS_log_addr;
	u32* vmx_VMCS_phy_addr;
	u32* guest_VMCS_log_addr;
	u32* guest_VMCS_phy_addr;
	u64 value;
	int result;

	cr4 = hb_get_cr4();
	cr4 |= CR4_BIT_VMXE;

	/* To handle the SMXE exception. */
	if (g_support_smx)
	{
		cr4 |= CR4_BIT_SMXE;
	}

	hb_set_cr4(cr4);

	vmx_msr = hb_rdmsr(MSR_IA32_VM_BASIC);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_VMX_BASIC MSR Value %016lX\n",
		vmx_msr);

	value = hb_rdmsr(MSR_IA32_VMX_ENTRY_CTRLS);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_VMX_ENTRY_CTRLS MSR Value "
		"%016lX\n", value);

	value = hb_rdmsr(MSR_IA32_VMX_EXIT_CTRLS);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_VMX_EXIT_CTRLS MSR Value "
		"%016lX\n", value);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
	msr = hb_rdmsr(MSR_IA32_FEATURE_CONTROL);
#else /* LINUX_VERSION_CODE */
	msr = hb_rdmsr(MSR_IA32_FEAT_CTL);
#endif /* LINUX_VERSION_CODE */

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_FEATURE_CONTROL MSR Value "
		"%016lX\n", msr);

	msr = hb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_IA32_VMX_PROCBASED_CTRLS "
		"MSR Value %016lX\n", msr);

	msr = hb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_IA32_VMX_PROCBASED_CTRLS2 "
		"MSR Value %016lX\n", msr);

	msr = hb_rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_IA32_VMX_EPT_VPID MSR Value "
		"%016lX\n", msr);


	msr = hb_rdmsr(MSR_IA32_EFER);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_EFER MSR Value %016lX\n",
		msr);

	cr0 = hb_get_cr0();
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] CR0 %016lX\n", cr0);

	cr4 = hb_get_cr4();
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Before Enable VMX CR4 %016lX\n",
		cr4);

	hb_enable_vmx();
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Enable VMX CR4\n");

	cr4 = hb_get_cr4();
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] After Enable VMX CR4 %016lX\n",
		cr4);

	vmx_VMCS_log_addr = (u32*)(g_vmx_on_vmcs_log_addr[cpu_id]);
	vmx_VMCS_phy_addr = (u32*)virt_to_phys(vmx_VMCS_log_addr);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Alloc Physical VMCS %016lX\n",
		vmx_VMCS_phy_addr);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Start VMX\n");

	/* First data of VMCS should be VMX revision number */
	vmx_VMCS_log_addr[0] = (u32)vmx_msr;
	result = hb_start_vmx(&vmx_VMCS_phy_addr);
	if (result == 0)
	{
		hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] VMXON Success\n");
	}
	else
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] VMXON Fail\n");
		hb_error_log(ERROR_LAUNCH_FAIL);
		return -1;
	}

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Preparing Geust\n");

	/* Allocate kernel memory for Guest VMCS. */
	guest_VMCS_log_addr = (u32*)(g_guest_vmcs_log_addr[cpu_id]);
	guest_VMCS_phy_addr = (u32*)virt_to_phys(guest_VMCS_log_addr);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Alloc Physical Guest VMCS %016lX\n",
		guest_VMCS_phy_addr);

	/* First data of VMCS should be VMX revision number */
	guest_VMCS_log_addr[0] = (u32) vmx_msr;
	result = hb_clear_vmcs(&guest_VMCS_phy_addr);
	if (result == 0)
	{
		hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Guest VMCS Clear Success\n");
	}
	else
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] Guest VMCS Clear Fail\n");
		hb_error_log(ERROR_LAUNCH_FAIL);
		return -1;
	}

	result = hb_load_vmcs((void*)&guest_VMCS_phy_addr);
	if (result == 0)
	{
		hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Guest VMCS Load Success\n");
	}
	else
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] Guest VMCS Load Fail\n");
		hb_error_log(ERROR_LAUNCH_FAIL);
		return -1;
	}

	return 0;
}

/*
 * Skip guest instruction
 */
static void hb_advance_vm_guest_rip(void)
{
	u64 inst_delta;
	u64 rip;

	hb_read_vmcs(VM_DATA_VM_EXIT_INST_LENGTH, &inst_delta);
	hb_read_vmcs(VM_GUEST_RIP, &rip);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM_DATA_VM_EXIT_INST_LENGTH: %016lX, "
		"VM_GUEST_RIP: %016lX\n", inst_delta, rip);
	hb_write_vmcs(VM_GUEST_RIP, rip + inst_delta);
}

/*
 * Calculate preemption timer value
 */
static u64 hb_calc_vm_pre_timer_value(void)
{
	u64 scale;

	scale = hb_rdmsr(MSR_IA32_VMX_MISC);
	scale &= 0x1F;

	return (VM_PRE_TIMER_VALUE >> scale);
}

/*
 * Dump vm_exit event data
 */
void hb_dump_vm_exit_data(void)
{
	u64 value;
	int i;
	u64 total = 0;

	value = jiffies - g_dump_jiffies;
	if (jiffies_to_msecs(value) >= 1000)
	{
		for (i = 0 ; i < MAX_VM_EXIT_DUMP_COUNT ; i++)
		{
			total += g_dump_count[i];
		}

		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ====== %ld =======\n", total);
		for (i = 0 ; i < MAX_VM_EXIT_DUMP_COUNT / 16 ; i++)
		{
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] %ld %ld %ld %ld %ld %ld "
				"%ld % ld %ld %ld %ld %ld %ld %ld %ld %ld\n", i * 16,
				g_dump_count[i * 16], g_dump_count[i * 16 + 1],
				g_dump_count[i * 16 + 2], g_dump_count[i * 16 + 3],
				g_dump_count[i * 16 + 4], g_dump_count[i * 16 + 5],
				g_dump_count[i * 16 + 6], g_dump_count[i * 16 + 7],
				g_dump_count[i * 16 + 8], g_dump_count[i * 16 + 9],
				g_dump_count[i * 16 + 10], g_dump_count[i * 16 + 11],
				g_dump_count[i * 16 + 12], g_dump_count[i * 16 + 13],
				g_dump_count[i * 16 + 14], g_dump_count[i * 16 + 15]);
		}

		memset(g_dump_count, 0, sizeof(g_dump_count));

		g_dump_jiffies = jiffies;
	}
}


/* Backup host registers. */
static inline __attribute__((always_inline))
void hb_backup_host_register(struct hb_vm_host_register* regs,
	struct hb_nested_vmcs_struct* nested_vmcs)
{
	regs->cr3 = nested_vmcs->cr3;

	hb_read_vmcs(VM_HOST_FS_BASE, &(regs->fs_base_addr));
	hb_read_vmcs(VM_HOST_GS_BASE, &(regs->gs_base_addr));
}

/* Copy host registers to guest vm. */
static inline __attribute__((always_inline))
void hb_copy_host_reg_to_guest(struct hb_vm_host_register* regs)
{
	hb_write_vmcs(VM_GUEST_CR3, regs->cr3);

	hb_write_vmcs(VM_GUEST_FS_BASE, regs->fs_base_addr);
	hb_write_vmcs(VM_GUEST_GS_BASE, regs->gs_base_addr);
}

#if HYPERBOX_USE_VMEXIT_PROFILE
/*
 * Profiling VMExit info of nested vmm.
 */
void hb_vm_profiling_nest_vmm(int cpu_id)
{
	int i;
	u64 exit_reason;
	static u64 exit_counter = 0;

	hb_read_vmcs(VM_DATA_EXIT_REASON, &exit_reason);
	g_nested_vm_exit_reason[exit_reason & 0xFFFF]++;

	if ((exit_counter % 10000) == 0)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Profiling...\n", cpu_id);

		for (i = 0 ; i < 100 ; i++)
		{
			if (g_nested_vm_exit_reason[i] != 0)
			{
				hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d]     [*] VM_EXIT_REASON[%d] Count [%d]\n",
					cpu_id, i, g_nested_vm_exit_reason[i]);
			}
		}
	}

	exit_reason++;
}
#endif /* HYPERBOX_USE_VMEXIT_PROFILE */

#if HYPERBOX_USE_VMCS_SHADOWING
/*
 *	Set VMCS shadowing.
 */
void hb_vm_set_vmcs_shadowing_to_current(u64 shadow_vmcs_phy_addr)
{
	u32* revision;

	if (g_support_vmcs_shadowing == 0)
	{
		return ;
	}

	/* Set bit 31 to make shadow VMCS. */
	hb_clear_vmcs(&shadow_vmcs_phy_addr);
	revision = (u32*)phys_to_virt(shadow_vmcs_phy_addr);
	revision[0] |= VM_BIT_REVISION_SHADOW_VMCS;

	hb_write_vmcs(VM_VMCS_LINK_PTR, shadow_vmcs_phy_addr);
}

/*
 *	Clear VMCS shadowing.
 */
void hb_vm_clear_vmcs_shadowing_to_current(void)
{
	u32* revision;
	u64 shadow_vmcs_phy_addr;

	if (g_support_vmcs_shadowing == 0)
	{
		return ;
	}

	hb_read_vmcs(VM_VMCS_LINK_PTR, &shadow_vmcs_phy_addr);

	/* No VMCS shadowing or no nested vmcs ptr are skipped. */
	if (shadow_vmcs_phy_addr == 0xFFFFFFFFFFFFFFFF)
	{
		return ;
	}

	hb_write_vmcs(VM_VMCS_LINK_PTR, 0xFFFFFFFFFFFFFFFF);

	/* Clear bit 31 to make shadow VMCS. */
	hb_clear_vmcs(&shadow_vmcs_phy_addr);
	revision = (u32*)phys_to_virt(shadow_vmcs_phy_addr);
	revision[0] &= ~((u32)VM_BIT_REVISION_SHADOW_VMCS);
}
#endif /* HYPERBOX_USE_VMCS_SHADOWING */

/*
 * Process vm_exit event.
 */
void hb_vm_exit_callback(struct hb_vm_exit_guest_register* guest_context)
{
	u64 exit_reason;
	u64 exit_qual;
	u64 guest_linear;
	u64 guest_physical;
	int cpu_id;
	u64 prev_vmcs;
	u64 temp_value;
	u64 guest_vmcs_phy_addr;
	struct hb_vm_host_register kvm_host_regs;
	struct hb_nested_vmcs_struct* nested_vmcs;
	int exit_from_vm = 0;
#if HYPERBOX_USE_VMCS_SHADOWING
	int is_back_to_vm = 0;
#endif /* HYPERBOX_USE_VMCS_SHADOWING */

	preempt_disable();

	cpu_id = smp_processor_id();

	/* Update currnt cpu mode. */
	g_vmx_root_mode[cpu_id] = 1;

	hb_store_vmcs((void*)&prev_vmcs);
	guest_vmcs_phy_addr = g_guest_vmcs_phy_addr[cpu_id];

	/* Check if exit from VMs of nested hypervisor. */
	if (prev_vmcs != guest_vmcs_phy_addr)
	{
#if HYPERBOX_USE_VMEXIT_PROFILE
		/* Profiling. */
		hb_vm_profiling_nest_vmm(cpu_id);
#endif /* HYPERBOX_USE_VMEXIT_PROFILE */

		exit_from_vm = 1;
		nested_vmcs = hb_find_nested_vmcs_struct(prev_vmcs);
		if (nested_vmcs == NULL)
		{
			goto skip_all;
		}

		hb_backup_host_register(&kvm_host_regs, nested_vmcs);
		hb_load_vmcs((void*)&guest_vmcs_phy_addr);
		hb_copy_host_reg_to_guest(&kvm_host_regs);

		hb_write_vmcs(VM_GUEST_RIP, nested_vmcs->rip);
		hb_write_vmcs(VM_GUEST_RSP, nested_vmcs->rsp);

		/* Clear IF for disabling interrupts and processing vm_exit in nested KVM. */
		temp_value = 0x02;
		hb_write_vmcs(VM_GUEST_RFLAGS, temp_value);

#if HYPERBOX_USE_VMCS_SHADOWING
		hb_vm_set_vmcs_shadowing_to_current(prev_vmcs);
#endif

#if HYPERBOX_USE_HW_BREAKPOINT
		/* Recover Debug Register. */
		set_debugreg(g_test_dr[cpu_id][0], 0);
		set_debugreg(g_test_dr[cpu_id][1], 1);
		set_debugreg(g_test_dr[cpu_id][2], 2);
		set_debugreg(g_test_dr[cpu_id][3], 3);
		get_debugreg(g_test_dr[cpu_id][6], 6);
		set_debugreg(g_test_dr[cpu_id][6] & 0xfffffffffffffff0, 6);
#endif

		goto skip_all;
	}
	/* Exit from guest. */
	else
	{
		/* Do nothing. */
	}

	hb_read_vmcs(VM_DATA_EXIT_REASON, &exit_reason);
	hb_read_vmcs(VM_DATA_EXIT_QUALIFICATION, &exit_qual);

#if HYPERBOX_USE_SLEEP
	/* Check system is shutdowning and shutdown timer is expired */
	hb_is_shutdown_timer_expired();
#endif /* HYPERBOX_USE_SLEEP */

	hb_write_vmcs(VM_CTRL_VM_ENTRY_INST_LENGTH, 0);

	if ((g_allow_hyper_box_hide == 1) &&
		(jiffies_to_msecs(jiffies - g_init_in_secure_jiffies) >= HYPER_BOX_HIDE_TIME_BUFFER_MS))
	{
		if (atomic_cmpxchg(&g_need_init_in_secure, 1, 0))
		{
#if HYPERBOX_USE_EPT
			/* Hide Hyper-box module here after all vm thread are terminated */
			hb_protect_hyper_box_module(PROTECT_MODE_HIDE);
			hb_protect_monitor_data();
#endif /* HYPERBOX_USE_EPT */

			g_allow_hyper_box_hide = 0;
		}
	}

#if HYPERBOX_USE_VMEXIT_DEBUG
	g_dump_count[exit_reason & 0xFFFF] += 1;
	hb_dump_vm_exit_data();
#endif /* HYPERBOX_USE_VMEXIT_DEBUG */

	switch((exit_reason & 0xFFFF))
	{
		case VM_EXIT_REASON_EXCEPT_OR_NMI:
			hb_vm_exit_callback_int(cpu_id, exit_qual, guest_context);
			break;

		case VM_EXIT_REASON_EXT_INTTERUPT:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] External Interrupt \n",
				cpu_id);
			break;

		case VM_EXIT_REASON_TRIPLE_FAULT:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Triple fault \n", cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_INIT_SIGNAL:
			hb_vm_exit_callback_init_signal(cpu_id);
			break;

		case VM_EXIT_REASON_START_UP_IPI:
			hb_vm_exit_callback_start_up_signal(cpu_id);
			break;

		case VM_EXIT_REASON_IO_SMI:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_IO_SMI\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_OTHER_SMI:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_OTHER_SMI\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_INT_WINDOW:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_INT_WINDOW\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_NMI_WINDOW:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_NMI_WINDOW\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_TASK_SWITCH:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_TASK_SWITCH\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		/* Unconditional VM exit event */
		case VM_EXIT_REASON_CPUID:
			hb_vm_exit_callback_cpuid(guest_context);
			break;

		/* For tboot interoperation*/
		case VM_EXIT_REASON_GETSEC:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_GETSEC\n", cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_HLT:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_HLT\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		/* Unconditional VM exit event */
		case VM_EXIT_REASON_INVD:
			hb_vm_exit_callback_invd();
			break;

		case VM_EXIT_REASON_INVLPG:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_INVLPG\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_RDPMC:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_RDPMC\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_RDTSC:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_RDTSC\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_RSM:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_RSM\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_VMCLEAR:
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] VM_EXIT_REASON_VMCLEAR\n",
				cpu_id);
			hb_vm_exit_callback_vmx_inst_type1(cpu_id, guest_context, VM_EXIT_REASON_VMCLEAR);
			break;

		case VM_EXIT_REASON_VMLAUNCH:
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] VM_EXIT_REASON_VMLAUNCH\n",
				cpu_id);
			hb_advance_vm_guest_rip();

#if HYPERBOX_USE_VMCS_SHADOWING
			is_back_to_vm = 1;

			hb_vm_clear_vmcs_shadowing_to_current();
#endif /* HYPERBOX_USE_VMCS_SHADOWING */

			/* Clear CF, ZF for making success result. */
			hb_clear_vmx_inst_flags();

			if (hb_load_vmcs((void*)&(g_nested_vmcs_ptr[cpu_id])) == 0)
			{
				hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Launch VMCS [%016lX] and go!, Magic [%016lX]\n",
					cpu_id, g_nested_vmcs_ptr[cpu_id], guest_context->vm_launch);

				/* Execute VMLAUNCH instead of VMRESUME. */
				guest_context->vm_launch = 1;
			}
			else
			{
				hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Launch VMCS [%016lX] failed!!!!\n",
					cpu_id, g_nested_vmcs_ptr[cpu_id]);

			}

			/* HOST RSP is set. */
			hb_write_vmcs(VM_HOST_RSP, (u64)(g_vm_exit_stack_addr[cpu_id]) + g_stack_size - VAL_4KB);
			break;

		case VM_EXIT_REASON_VMPTRLD:
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] VM_EXIT_REASON_VMPTRLD\n",
				cpu_id);
			hb_vm_exit_callback_vmx_inst_type1(cpu_id, guest_context, VM_EXIT_REASON_VMPTRLD);
			break;

		case VM_EXIT_REASON_VMPTRST:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_VMPTRST\n",
				cpu_id);
			hb_vm_exit_callback_vmx_inst_type1(cpu_id, guest_context, VM_EXIT_REASON_VMPTRST);
			break;

		case VM_EXIT_REASON_VMREAD:
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] VM_EXIT_REASON_VMREAD\n",
				cpu_id);
			hb_vm_exit_callback_vmx_inst_type2(cpu_id, guest_context, VM_EXIT_REASON_VMREAD);
			break;

		case VM_EXIT_REASON_VMRESUME:
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] VM_EXIT_REASON_VMRESUME\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			
#if HYPERBOX_USE_VMCS_SHADOWING
			is_back_to_vm = 1;

			hb_vm_clear_vmcs_shadowing_to_current();
#endif /* HYPERBOX_USE_VMCS_SHADOWING */

			/* Clear CF, ZF for making success result. */
			hb_clear_vmx_inst_flags();

			if (hb_load_vmcs((void*)&(g_nested_vmcs_ptr[cpu_id])) == 0)
			{
				hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Resume VMCS [%016lX] and go!, Magic [%016lX]\n",
					cpu_id, g_nested_vmcs_ptr[cpu_id], guest_context->vm_launch);
			}
			else
			{
				hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Resume VMCS [%016lX] failed!!!!\n",
					cpu_id, g_nested_vmcs_ptr[cpu_id]);
			}

			/* HOST RSP is set. */
			hb_write_vmcs(VM_HOST_RSP, (u64)(g_vm_exit_stack_addr[cpu_id]) + g_stack_size - VAL_4KB);

#if HYPERBOX_USE_VMCS_SHADOWING
			if (g_support_vmcs_shadowing == 1)
			{
				/* Execute VMLAUNCH instead of VMRESUME. */
				guest_context->vm_launch = 1;
			}
#endif /* HYPERBOX_USE_VMCS_SHADOWING */
			break;

		case VM_EXIT_REASON_VMWRITE:
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] VM_EXIT_REASON_VMWRITE\n",
				cpu_id);
			hb_vm_exit_callback_vmx_inst_type2(cpu_id, guest_context, VM_EXIT_REASON_VMWRITE);
			break;

		case VM_EXIT_REASON_VMXON:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_VMXON is called. PID [%d], TGID [%d] \n",
				cpu_id, get_current()->pid, get_current()->tgid);
			hb_vm_exit_callback_vmx_inst_type1(cpu_id, guest_context, VM_EXIT_REASON_VMXON);

			break;

		case VM_EXIT_REASON_VMXOFF:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_VMXOFF is called. PID [%d], TGID [%d]\n",
				cpu_id, get_current()->pid, get_current()->tgid);
			g_nested_vmcs_ptr[cpu_id] = 0x00;
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_VMCALL:
			hb_vm_exit_callback_vmcall(cpu_id, guest_context);
			break;

		/* Unconditional VM exit event (move fron reg_value) */
		case VM_EXIT_REASON_CTRL_REG_ACCESS:
			hb_vm_exit_callback_access_cr(cpu_id, guest_context, exit_reason, exit_qual);
			break;

		case VM_EXIT_REASON_MOV_DR:
			hb_printf(LOG_LEVEL_DETAIL, LOG_ERROR "VM [%d] MOVE DR is executed",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_IO_INST:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_IO_INST\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_RDMSR:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_RDMSR RCX %016lX\n",
				cpu_id, guest_context->rcx);

			temp_value = hb_rdmsr(guest_context->rcx);
			guest_context->rdx = temp_value >> 32;
			guest_context->rax = temp_value & 0xFFFFFFFF;

			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_WRMSR:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_WRMSR RCX %016lX, RAX %016lX, RDX %016lX\n",
				cpu_id, guest_context->rcx, guest_context->rax, guest_context->rdx);

			temp_value = guest_context->rdx;
			temp_value = temp_value << 32;
			temp_value |= guest_context->rax & 0xFFFFFFFF;
			hb_wrmsr(guest_context->rcx, temp_value);

			hb_advance_vm_guest_rip();
			//hb_vm_exit_callback_wrmsr(cpu_id);
			break;

		case VM_EXIT_REASON_VM_ENTRY_FAILURE_INV_GUEST:
		case VM_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOAD:
		case VM_EXIT_REASON_MWAIT:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_VM_ENTRY_"
				"FAILURE_INV_GUEST, MSR_LOAD\n", cpu_id);
			hb_advance_vm_guest_rip();
			break;

		/* For hardware breakpoint interoperation */
		case VM_EXIT_REASON_MONITOR_TRAP_FLAG:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_TRAP_FLAG\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_MONITOR:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_MONITOR\n",
				 cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_PAUSE:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_PAUSE\n",
				 cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK\n",
				 cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_TRP_BELOW_THRESHOLD:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_TRP_BELOW_THRESHOLD\n",
				 cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_APIC_ACCESS:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_APIC_ACCESS\n",
				 cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_VIRTUALIZED_EOI:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_VIRTUALIZED_EOI\n",
				 cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_ACCESS_GDTR_OR_IDTR:
			hb_vm_exit_callback_gdtr_idtr(cpu_id, guest_context);
			break;

		case VM_EXIT_REASON_ACCESS_LDTR_OR_TR:
			hb_vm_exit_callback_ldtr_tr(cpu_id, guest_context);
			break;

		case VM_EXIT_REASON_EPT_VIOLATION:
			hb_read_vmcs(VM_DATA_GUEST_LINEAR_ADDR, &guest_linear);
			hb_read_vmcs(VM_DATA_GUEST_PHY_ADDR, &guest_physical);

			hb_vm_exit_callback_ept_violation(cpu_id, guest_context, exit_reason,
				exit_qual, guest_linear, guest_physical);
			break;

		case VM_EXIT_REASON_EPT_MISCONFIGURATION:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_EPT_MISCONFIG\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;
	
		case VM_EXIT_REASON_INVEPT:
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] VM_EXIT_REASON_INVEPT is called\n",
				cpu_id);
			hb_vm_exit_callback_vmx_inst_type2(cpu_id, guest_context, VM_EXIT_REASON_INVEPT);
			break;

		case VM_EXIT_REASON_RDTSCP:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_RDTSCP\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_VMX_PREEMP_TIMER_EXPIRED:
			hb_vm_exit_callback_pre_timer_expired(cpu_id);
			break;

		case VM_EXIT_REASON_INVVPID:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_INVVPID is called\n",
				cpu_id);
			hb_vm_exit_callback_vmx_inst_type2(cpu_id, guest_context, VM_EXIT_REASON_INVVPID);
			break;

		case VM_EXIT_REASON_WBINVD:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_WBINVD\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_XSETBV:
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] VM_EXIT_REASON_XSETBV\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			temp_value = guest_context->rdx;
			temp_value = temp_value << 32;
			temp_value |= guest_context->rax;
			hb_xsetbv(guest_context->rcx, temp_value);
			break;

		case VM_EXIT_REASON_APIC_WRITE:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_APIC_WRITE\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_RDRAND:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_RDRAND\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_INVPCID:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_INVPCID\n",
				cpu_id);
			hb_vm_exit_callback_vmx_inst_type2(cpu_id, guest_context, VM_EXIT_REASON_INVPCID);
			break;

		case VM_EXIT_REASON_VMFUNC:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_VMFUNC\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_RDSEED:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_RDSEED\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_XSAVES:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_XSAVES\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_XRSTORS:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_XRSTORS\n",
				cpu_id);
			hb_advance_vm_guest_rip();
			break;

		default:
			hb_read_vmcs(VM_DATA_GUEST_LINEAR_ADDR, &guest_linear);
			hb_read_vmcs(VM_DATA_GUEST_PHY_ADDR, &guest_physical);
			hb_advance_vm_guest_rip();

			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_DEFAULT\n",
				cpu_id);
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Exit Reason: %016lX, %016lX\n",
				cpu_id, (u32)exit_reason, exit_reason);
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Exit Qualification: %016lX, %016lX\n",
				cpu_id, (u32)exit_qual, exit_qual);
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Guest Linear: %016lX, %016lX\n",
				cpu_id, (u32)guest_linear, guest_linear);
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Guest Physical: %016lX, %016lX\n",
				cpu_id, (u32)guest_physical, guest_physical);
			break;
	}

skip_all:

#if HYPERBOX_USE_VMCS_SHADOWING
	if ((g_support_vmcs_shadowing == 1) && (exit_from_vm == 0))
	{
		if ((is_back_to_vm == 0) && (g_nested_vmcs_ptr[cpu_id] != 0))
		{
			hb_vm_set_vmcs_shadowing_to_current(g_nested_vmcs_ptr[cpu_id]);
		}
	}
#endif /* HYPERBOX_USE_VMCS_SHADOWING */

	/* Update currnt cpu mode. */
	g_vmx_root_mode[cpu_id] = 0;

	preempt_enable();
}

/*
 * Handle systemcall monitor breakpoints.
 */
static inline __attribute__((always_inline))
void hb_handle_systemcall_breakpoints(int cpu_id, u64 dr6,
    struct hb_vm_exit_guest_register* guest_context)
{
	u64 syscall_number;
	struct task_struct* task;

	if (dr6 & DR_BIT_SYSCALL_64)
	{
		syscall_number = (int) guest_context->rax;

		/* If cred is changed anbornally or should be killed, change syscall
		number to __NR_exit. */
		if (hb_callback_check_cred_update_syscall(cpu_id, current,
		syscall_number) != 0)
		{
			guest_context->rax = __NR_exit;
			guest_context->rdx = -1;
		}
	}
	/* Create process. */
	else if (dr6 & DR_BIT_ADD_TASK)
	{
		hb_callback_add_task(cpu_id, guest_context);

		task = (struct task_struct*)guest_context->rdi;
	}
	/* Terminate process. */
	else if (dr6 & DR_BIT_DEL_TASK)
	{
		hb_callback_del_task(cpu_id, guest_context);
	}
	/* Change cred. */
	else if (dr6 & DR_BIT_COMMIT_CREDS)
	{
		hb_callback_update_cred(cpu_id, current, (struct cred*)(guest_context->rdi));
	}
	else
	{
		/* Do nothing. */
	}
}

/*
 * Process interrupt callback.
 */
static inline __attribute__((always_inline))
void hb_vm_exit_callback_int(int cpu_id, unsigned long dr6, struct
	hb_vm_exit_guest_register* guest_context)
{
	unsigned long rflags;
	u64 info_field;
	int vector;
	int type;

	// 8:10 bit is NMI
	hb_read_vmcs(VM_DATA_VM_EXIT_INT_INFO, &info_field);
	vector = VM_EXIT_INT_INFO_VECTOR(info_field);
	type = VM_EXIT_INT_INFO_INT_TYPE(info_field);

	if (type == VM_EXIT_INT_TYPE_NMI)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ===================WARNING======================\n",
			cpu_id);
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] NMI Interrupt Occured\n", cpu_id);
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ===================WARNING======================\n",
			cpu_id);
	}
	else if (vector != VM_INT_DEBUG_EXCEPTION)
	{
		return ;
	}

	/* For stable shutdown, skip processing if system is shutdowning. */
	if (hb_is_system_shutdowning() == 0)
	{
        	hb_handle_systemcall_breakpoints(cpu_id, dr6, guest_context);
	}

	dr6 &= 0xfffffffffffffff0;
	set_debugreg(dr6, 6);

	/* When the guest is resumed, Let the guest skip hardware breakpoint. */
	hb_read_vmcs(VM_GUEST_RFLAGS, (u64*)&rflags);
	rflags |= RFLAGS_BIT_RF;
	hb_write_vmcs(VM_GUEST_RFLAGS, rflags);

	hb_remove_int_exception_from_vm(vector);
}

/*
 * Process INIT IPI.
 */
static void hb_vm_exit_callback_init_signal(int cpu_id)
{
	u64 status;
	struct desc_ptr idt = { .address = 0, .size = 0 };

	hb_read_vmcs(VM_GUEST_ACTIVITY_STATE, &status);
	hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ===================WARNING======================\n",
		cpu_id);
	hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Activity Status %016lX\n", cpu_id,
		status);
	hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ===================WARNING======================\n",
		cpu_id);

	while(system_state == SYSTEM_RESTART)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Wait for system.\n", cpu_id);
		/* Wait 3 seconds for giving time to the system. */
		mdelay(3000);

		/* Force generate interrupt without IDT. */
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Invalidate IDT and generate Interrupt.\n", cpu_id);

		load_idt(&idt);
		hb_stop_vmx();
		hb_gen_int();
		hb_pause_loop();
	}
}

/*
 * Process Startup IPI.
 */
static void hb_vm_exit_callback_start_up_signal(int cpu_id)
{
	u64 status;

	hb_read_vmcs(VM_GUEST_ACTIVITY_STATE, &status);
	hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ===================WARNING======================\n",
		cpu_id);
	hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Change Activity Status to Active, %016lX\n",
		cpu_id, status);
	hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ===================WARNING======================\n",
		cpu_id);
}

/*
 * Process  read and write event of control register.
 */
static void hb_vm_exit_callback_access_cr(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context, u64 exit_reason, u64 exit_qual)
{
	u64 reg_value = 0;
		
	if (VM_EXIT_QUAL_CTRL_REG_ACC_GET_ACC_TYPE(exit_qual) ==
		VM_EXIT_QUAL_CTRL_REG_ACC_MOVE_FROM_CR)
	{

		switch(VM_EXIT_QUAL_CTRL_REG_ACC_GET_CTRL_REG_NUMBER(exit_qual))
		{
			case REG_NUM_CR0:
				hb_read_vmcs(VM_GUEST_CR0, &reg_value);
				break;

			case REG_NUM_CR2:
				reg_value = hb_get_cr2();
				break;

			case REG_NUM_CR3:
				hb_read_vmcs(VM_GUEST_CR3, &reg_value);
				break;

			case REG_NUM_CR4:
				hb_read_vmcs(VM_GUEST_CR4, &reg_value);
				break;

			case REG_NUM_CR8:
				reg_value = hb_get_cr8();
				break;
		}

		hb_set_reg_value_from_index(guest_context,
			VM_EXIT_QUAL_CTRL_REG_ACC_GET_GP_REG_NUMBER(exit_qual), reg_value);
	}
	else if (VM_EXIT_QUAL_CTRL_REG_ACC_GET_ACC_TYPE(exit_qual) ==
			 VM_EXIT_QUAL_CTRL_REG_ACC_MOVE_TO_CR)
	{
		reg_value = hb_get_reg_value_from_index(guest_context,
			VM_EXIT_QUAL_CTRL_REG_ACC_GET_GP_REG_NUMBER(exit_qual));
	
		switch(VM_EXIT_QUAL_CTRL_REG_ACC_GET_CTRL_REG_NUMBER(exit_qual))
		{
			case REG_NUM_CR0:
				/* WP bit should be set! */
				reg_value |= CR0_BIT_WP;
				hb_write_vmcs(VM_GUEST_CR0, reg_value);
				break;

			case REG_NUM_CR2:
				/* hb_write_vmcs(VM_GUEST_CR2, reg_value); */
				break;

			case REG_NUM_CR3:
				hb_write_vmcs(VM_GUEST_CR3, reg_value);
				break;

			case REG_NUM_CR4:
				/* VMXE, SMEP bit should be set! for unrestricted guest. */
				reg_value |= CR4_BIT_VMXE | CR4_BIT_SMEP;
				reg_value &= ~CR4_BIT_MCE;
				hb_write_vmcs(VM_GUEST_CR4, reg_value);
				break;

			case REG_NUM_CR8:
				/* hb_write_vmcs(VM_GUEST_CR8, reg_value); */
				break;
		}
	}
	else
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] VM_EXIT_QUAL_CTRL_REG is "
			"not move from reg_value: %d\n", cpu_id,
			(int)VM_EXIT_QUAL_CTRL_REG_ACC_GET_ACC_TYPE(exit_qual));
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] VM_EXIT_QUAL_CTRL_REG is "
			"not move from reg_value\n", cpu_id);
	}

	hb_advance_vm_guest_rip();
}

/*
 * Get register value of index in guest context.
 */
static u64 hb_get_reg_value_from_index(struct hb_vm_exit_guest_register* guest_context, int index)
{
	u64 reg_value = 0;

	switch(index)
	{
		case REG_NUM_RAX:
			reg_value = guest_context->rax;
			break;

		case REG_NUM_RCX:
			reg_value = guest_context->rcx;
			break;

		case REG_NUM_RDX:
			reg_value = guest_context->rdx;
			break;

		case REG_NUM_RBX:
			reg_value = guest_context->rbx;
			break;

		case REG_NUM_RSP:
			hb_read_vmcs(VM_GUEST_RSP, &reg_value);
			break;

		case REG_NUM_RBP:
			reg_value = guest_context->rbp;
			break;

		case REG_NUM_RSI:
			reg_value = guest_context->rsi;
			break;

		case REG_NUM_RDI:
			reg_value = guest_context->rdi;
			break;

		case REG_NUM_R8:
			reg_value = guest_context->r8;
			break;

		case REG_NUM_R9:
			reg_value = guest_context->r9;
			break;

		case REG_NUM_R10:
			reg_value = guest_context->r10;
			break;

		case REG_NUM_R11:
			reg_value = guest_context->r11;
			break;

		case REG_NUM_R12:
			reg_value = guest_context->r12;
			break;

		case REG_NUM_R13:
			reg_value = guest_context->r13;
			break;

		case REG_NUM_R14:
			reg_value = guest_context->r14;
			break;

		case REG_NUM_R15:
			reg_value = guest_context->r15;
			break;
	}

	return reg_value;
}

/*
 * Set value to register of index in guest context.
 */
static void hb_set_reg_value_from_index(struct hb_vm_exit_guest_register*
	guest_context, int index, u64 reg_value)
{
	switch(index)
	{
		case REG_NUM_RAX:
			guest_context->rax = reg_value;
			break;

		case REG_NUM_RCX:
			guest_context->rcx = reg_value;
			break;

		case REG_NUM_RDX:
			guest_context->rdx = reg_value;
			break;

		case REG_NUM_RBX:
			guest_context->rbx = reg_value;
			break;

		case REG_NUM_RSP:
			hb_write_vmcs(VM_GUEST_RSP, reg_value);
			break;

		case REG_NUM_RBP:
			guest_context->rbp = reg_value;
			break;

		case REG_NUM_RSI:
			guest_context->rsi = reg_value;
			break;

		case REG_NUM_RDI:
			guest_context->rdi = reg_value;
			break;

		case REG_NUM_R8:
			guest_context->r8 = reg_value;
			break;

		case REG_NUM_R9:
			guest_context->r9 = reg_value;
			break;

		case REG_NUM_R10:
			guest_context->r10 = reg_value;
			break;

		case REG_NUM_R11:
			guest_context->r11 = reg_value;
			break;

		case REG_NUM_R12:
			guest_context->r12 = reg_value;
			break;

		case REG_NUM_R13:
			guest_context->r13 = reg_value;
			break;

		case REG_NUM_R14:
			guest_context->r14 = reg_value;
			break;

		case REG_NUM_R15:
			guest_context->r15 = reg_value;
			break;
	}
}

/*
 * Calculate destination memory address from instruction information in guest
 * context.
 */
static u64 hb_calc_dest_mem_addr(struct hb_vm_exit_guest_register* guest_context,
	u64 inst_info)
{
	u64 dest_addr = 0;

	if (!(inst_info & VM_INST_INFO_IDX_REG_INVALID))
	{
		dest_addr += hb_get_reg_value_from_index(guest_context,
			VM_INST_INFO_IDX_REG(inst_info));

		dest_addr = dest_addr << VM_INST_INFO_SCALE(inst_info);
	}

	if (!(inst_info & VM_INST_INFO_BASE_REG_INVALID))
	{
		dest_addr += hb_get_reg_value_from_index(guest_context,
			VM_INST_INFO_BASE_REG(inst_info));
	}

	return dest_addr;
}

/*
 * Set value to memory.
 */
static void hb_set_value_to_memory(u64 inst_info, u64 addr, u64 value)
{
	switch(VM_INST_INFO_ADDR_SIZE(inst_info))
	{
		case VM_INST_INFO_ADDR_SIZE_16BIT:
			*(u16*)addr = (u16)value;
			break;

		case VM_INST_INFO_ADDR_SIZE_32BIT:
			*(u32*)addr = (u64)value;
			break;

		case VM_INST_INFO_ADDR_SIZE_64BIT:
			*(u64*)addr = (u64)value;
			break;
	}
}

/**
 * Get value from memory.
 */
static u64 hb_get_value_from_memory(u64 inst_info, u64 addr)
{
	u64 value = 0;

	switch(VM_INST_INFO_ADDR_SIZE(inst_info))
	{
		case VM_INST_INFO_ADDR_SIZE_16BIT:
			value = *(u16*)addr;
			break;

		case VM_INST_INFO_ADDR_SIZE_32BIT:
			value = *(u32*)addr;
			break;

		case VM_INST_INFO_ADDR_SIZE_64BIT:
			value = *(u64*)addr;
			break;
	}

	return value;
}

/*
 * Process VM call.
 */
static void hb_vm_exit_callback_vmcall(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context)
{
	u64 svr_num;
	void* arg;
	u64 cs_selector;

	svr_num = guest_context->rax;
	arg = (void*)guest_context->rbx;

	/* Set return value. */
	guest_context->rax = 0;

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] VMCALL index[%ld], arg_in[%016lX]\n",
		cpu_id, svr_num, arg);

	/* Clear CF, ZF for making success result. */
	hb_clear_vmx_inst_flags();

	/* Only kernel call vmcall (CPL=0) */
	hb_read_vmcs(VM_GUEST_CS_SELECTOR, &cs_selector);
	if ((cs_selector & MASK_GDT_ACCESS) != 0)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VMCALL index[%ld] is not allowed\n",
			cpu_id);
		hb_insert_ud_exception_to_vm();
		hb_advance_vm_guest_rip();
		return ;
	}

	/* Move RIP to next instruction. */
	hb_advance_vm_guest_rip();

	switch(svr_num)
	{
		/* Return log info structure. */
		case VM_SERVICE_GET_LOGINFO:
			guest_context->rax = (u64)g_log_info;
			break;

#if HYPERBOX_USE_SHUTDOWN
		case VM_SERVICE_SHUTDOWN:
			atomic_set(&(g_share_context->shutdown_flag), 1);
			break;

		case VM_SERVICE_SHUTDOWN_THIS_CORE:
			hb_shutdown_vm_this_core(cpu_id, guest_context);
			break;
#endif /* HYPERBOX_USE_SHUTDOWN */

		default:
			break;
	}
}

#if HYPERBOX_USE_SHUTDOWN
/**
 *	Shutdown Hyper-box
 */
static void hb_shutdown_vm_this_core(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context)
{
	struct hb_vm_full_context full_context;
	u64 guest_VMCS_log_addr;
	u64 guest_VMCS_phy_addr;
	u64 guest_rsp;

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] hb_shutdown_vm_this_core is called\n",
		cpu_id);

	hb_read_vmcs(VM_GUEST_RSP, &guest_rsp);
	hb_fill_context_from_vm_guest(guest_context, &full_context);

	guest_VMCS_log_addr = (u64)(g_guest_vmcs_log_addr[cpu_id]);
	guest_VMCS_phy_addr = (u64)virt_to_phys((void*)guest_VMCS_log_addr);
	hb_clear_vmcs(&guest_VMCS_phy_addr);
	hb_stop_vmx();

	hb_disable_vmx();

	hb_restore_context_from_vm_guest(cpu_id, &full_context, guest_rsp);
}

/*
 * Fill guest context from the guest VMCS.
 */
static void hb_fill_context_from_vm_guest(struct hb_vm_exit_guest_register*
	guest_context, struct hb_vm_full_context* full_context)
{
	memcpy(&(full_context->gp_register), guest_context,
		sizeof(struct hb_vm_exit_guest_register));

	hb_read_vmcs(VM_GUEST_CS_SELECTOR, &(full_context->cs_selector));
	hb_read_vmcs(VM_GUEST_DS_SELECTOR, &(full_context->ds_selector));
	hb_read_vmcs(VM_GUEST_ES_SELECTOR, &(full_context->es_selector));
	hb_read_vmcs(VM_GUEST_FS_SELECTOR, &(full_context->fs_selector));
	hb_read_vmcs(VM_GUEST_GS_SELECTOR, &(full_context->gs_selector));

	hb_read_vmcs(VM_GUEST_LDTR_SELECTOR, &(full_context->ldtr_selector));
	hb_read_vmcs(VM_GUEST_TR_SELECTOR, &(full_context->tr_selector));

	hb_read_vmcs(VM_GUEST_CR0, &(full_context->cr0));
	hb_read_vmcs(VM_GUEST_CR3, &(full_context->cr3));
	hb_read_vmcs(VM_GUEST_CR4, &(full_context->cr4));
	hb_read_vmcs(VM_GUEST_RIP, &(full_context->rip));
	hb_read_vmcs(VM_GUEST_RFLAGS, &(full_context->rflags));
}

/*
 * Restore the guest VMCS from the full context.
 * When Hyper-box is shutdown, return to hb_vm_call() function in the guest.
 */
static void hb_restore_context_from_vm_guest(int cpu_id, struct hb_vm_full_context*
	full_context, u64 guest_rsp)
{
	u64 target_addr;

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] guest_rsp %016lX\n", cpu_id,
		guest_rsp);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] cr4 %016lX, %016lX\n", cpu_id,
		full_context->cr4, hb_get_cr4());
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] cr3 %016lX, %016lX\n", cpu_id,
		full_context->cr3, hb_get_cr3());
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] cr0 %016lX, %016lX\n", cpu_id,
		full_context->cr0, hb_get_cr0());

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] tr %016lX\n", cpu_id,
		full_context->tr_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] ldtr %016lX\n", cpu_id,
		full_context->ldtr_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] gs %016lX\n", cpu_id,
		full_context->gs_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] fs %016lX\n", cpu_id,
		full_context->fs_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] es %016lX\n", cpu_id,
		full_context->es_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] ds %016lX\n", cpu_id,
		full_context->ds_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] cs %016lX\n", cpu_id,
		full_context->cs_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] r15 %016lX\n", cpu_id,
		full_context->gp_register.r15);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] rbp %016lX\n", cpu_id,
		full_context->gp_register.rbp);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] rflags %016lX, %016lX\n", cpu_id,
		full_context->rflags, hb_get_rflags());
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] rip %016lX, %016lX\n", cpu_id,
		full_context->rip, hb_vm_thread_shutdown);

	/* Copy context to stack and restore. */
	target_addr = guest_rsp - sizeof(struct hb_vm_full_context);
	memcpy((void*)target_addr, full_context, sizeof(struct hb_vm_full_context));

	hb_restore_context_from_stack(target_addr);
}

/*
 * Process system reboot notification event.
 */
static int hb_system_reboot_notify(struct notifier_block *nb, unsigned long code,
	void *unused)
{
	int cpu_count;

	/* Call Hyper-box shutdown function. */
	hb_vm_call(VM_SERVICE_SHUTDOWN, NULL);

	cpu_count = num_online_cpus();
	hb_printf(LOG_LEVEL_ERROR, LOG_INFO "Shutdown start, cpu count %d\n", cpu_count);

	while(1)
	{
		if (atomic_read(&(g_share_context->shutdown_complete_count)) == cpu_count)
		{
			break;
		}

		ssleep(1);
	}

	return NOTIFY_DONE;
}

/*
 * Disable VT-x and terminate Hyper-box.
 * This thread function runs on each core.
 */
static int hb_vm_thread_shutdown(void* argument)
{
	int cpu_id;

	cpu_id = smp_processor_id();

	while(atomic_read(&(g_share_context->shutdown_flag)) == 0)
	{
		ssleep(1);
	}

	hb_vm_call(VM_SERVICE_SHUTDOWN_THIS_CORE, NULL);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Shutdown complete\n", cpu_id);

	atomic_inc(&(g_share_context->shutdown_complete_count));
	return 0;
}

#endif /* HYPERBOX_USE_SHUTDOWN */

#if HYPERBOX_USE_SLEEP
/*
 *	Process system sleep notification event.
 */
static int hb_system_sleep_notify(struct notifier_block* nb, unsigned long val,
	void* unused)
{
	int cpu_id;

	cpu_id = smp_processor_id();

	switch(val)
	{
		case PM_POST_HIBERNATION:
		case PM_POST_SUSPEND:
			hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] Start restoring from sleep\n", cpu_id);
			/* Start with reinitialize flag. */
			hb_start(START_MODE_REINITIALIZE);
			break;
	}

	return NOTIFY_OK;
}
#endif /* HYPERBOX_USE_SLEEP */

/*
 * Insert exception to the guest.
 */
void hb_insert_ud_exception_to_vm(void)
{
	u64 info_field;

	info_field = VM_ENTRY_INT_INFO_UD;

	hb_write_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, info_field);
	hb_write_vmcs(VM_CTRL_VM_ENTRY_EXCEPT_ERR_CODE, 0);
}

/*
 * Insert exception to the guest.
 */
void hb_insert_nmi_exception_to_vm(void)
{
	u64 info_field;

	info_field = VM_ENTRY_INT_INFO_NMI;

	hb_write_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, info_field);
	hb_write_vmcs(VM_CTRL_VM_ENTRY_EXCEPT_ERR_CODE, 0);
}

/*
 * Remove exception from the guest.
 */
static void hb_remove_int_exception_from_vm(int vector)
{
	u64 info_field;

	hb_read_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, &info_field);
	info_field &= ~((u64) 0x01 << vector);
	hb_write_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, info_field);
}

#if HYPERBOX_USE_MSR_PROTECTION
/*
 * Process write MSR callback.
 */
static void hb_vm_exit_callback_wrmsr(int cpu_id)
{
	hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] hb_vm_exit_callback_wrmsr\n", cpu_id);
	hb_insert_ud_exception_to_vm();
}
#endif /* HYPERBOX_USE_MSR_PROTECTION */

/*
 * Process GDTR, IDTR modification callback.
 */
static void hb_vm_exit_callback_gdtr_idtr(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context)
{
	struct desc_ptr* gdtr;
	u64 inst_info;
	u64 dest_addr = 0;
	u64 value;
	int memory = 0;
	u64 guest_cr3;
	u64 exit_qual;

	if (hb_is_system_shutdowning() != 0)
	{
#if HYPERBOX_USE_SLEEP
		hb_disable_desc_monitor();
#endif /* HYPERBOX_USE_SLEEP */
		return ;
	}

	hb_advance_vm_guest_rip();
	hb_read_vmcs(VM_DATA_VM_EXIT_INST_INFO, &inst_info);
	hb_read_vmcs(VM_DATA_EXIT_QUALIFICATION, &exit_qual);

	/* Check destination type. */
	if (!VM_INST_INFO_MEM_REG(inst_info))
	{
		dest_addr = hb_calc_dest_mem_addr(guest_context, inst_info);
		memory = 1;
	}
	else
	{
		dest_addr = hb_get_reg_value_from_index(guest_context,
			VM_INST_INFO_REG1(inst_info));
	}
	dest_addr += exit_qual;

	/* Sync and reach it. */
	hb_read_vmcs(VM_GUEST_CR3, &guest_cr3);
	hb_sync_page_table(dest_addr, guest_cr3, 1);

	switch(VM_INST_INFO_INST_IDENTITY(inst_info))
	{
		case VM_INST_INFO_SGDT:
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] SGDT is allowed, Value[%016lX]\n",
				cpu_id, dest_addr);
			gdtr = (struct desc_ptr*) dest_addr;
			hb_read_vmcs(VM_GUEST_GDTR_BASE, &value);
			gdtr->address = value;
			hb_read_vmcs(VM_GUEST_GDTR_LIMIT, &value);
			gdtr->size = value;

			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] SGDT is allowed, Value[%016lX], gdtr->base[%016lX], limit[%08lX]\n",
				cpu_id, dest_addr, gdtr->address, gdtr->size);
			break;

		case VM_INST_INFO_SIDT:
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] SIDT is allowed, Value[%016lX], exit_qual[%016lX]\n",
				cpu_id, dest_addr, exit_qual);
			gdtr = (struct desc_ptr*) dest_addr;
			hb_read_vmcs(VM_GUEST_IDTR_BASE, &value);
			gdtr->address = value;
			hb_read_vmcs(VM_GUEST_IDTR_LIMIT, &value);
			gdtr->size = value;

			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] SIDT is allowed, Value[%016lX], idtr->base[%016lX], limit[%08lX]\n",
				cpu_id, dest_addr, gdtr->address, gdtr->size);
			break;

		case VM_INST_INFO_LGDT:
			gdtr = (struct desc_ptr*) dest_addr;
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] LGDT is allowed, Value[%016lX], gdtr->base[%016lX], limit[%08lX]\n",
				cpu_id, dest_addr, gdtr->address, gdtr->size);
			hb_write_vmcs(VM_GUEST_GDTR_BASE, gdtr->address);
			hb_write_vmcs(VM_GUEST_GDTR_LIMIT, gdtr->size);
			break;

		case VM_INST_INFO_LIDT:
			gdtr = (struct desc_ptr*) dest_addr;
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] LIDT is allowed, Value[%016lX], idtr->base[%016lX], limit[%08lX]\n",
				cpu_id, dest_addr, gdtr->address, gdtr->size);
			hb_write_vmcs(VM_GUEST_IDTR_BASE, gdtr->address);
			hb_write_vmcs(VM_GUEST_IDTR_LIMIT, gdtr->size);
			break;

		default:
			break;
	}
}

/*
 * Process LDTR, TR modification callback.
 * Linux set 0 to LLDT, so this function allows only 0 value setting.
 */
static void hb_vm_exit_callback_ldtr_tr(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context)
{
	u64 inst_info;
	u64 dest_addr = 0;
	u64 value;
	int memory = 0;
	u64 guest_cr3;
	u64 exit_qual;

	hb_read_vmcs(VM_DATA_VM_EXIT_INST_INFO, &inst_info);
	hb_read_vmcs(VM_DATA_EXIT_QUALIFICATION, &exit_qual);

	/* Check destination type. */
	if (!VM_INST_INFO_MEM_REG(inst_info))
	{
		dest_addr = hb_calc_dest_mem_addr(guest_context, inst_info);
		dest_addr += exit_qual;

		/* Sync and reach it. */
		hb_read_vmcs(VM_GUEST_CR3, &guest_cr3);
		hb_sync_page_table(dest_addr, guest_cr3, 1);

		memory = 1;
	}
	else
	{
		dest_addr = hb_get_reg_value_from_index(guest_context,
			VM_INST_INFO_REG1(inst_info));
		dest_addr += exit_qual;
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Reg Info [%d] Value[%016lX]\n",
			cpu_id, VM_INST_INFO_REG1(inst_info), dest_addr);
	}

	switch(VM_INST_INFO_INST_IDENTITY(inst_info))
	{
		/* SLDT. KVM uses it. */
		case VM_INST_INFO_SLDT:
			hb_read_vmcs(VM_GUEST_LDTR_SELECTOR, &value);
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] SLDT is allowed, Memory [%d], dest_addr [%016lX], ldtr[%016lX]\n",
				cpu_id, memory, dest_addr, value);
			if (memory == 1)
			{
				hb_set_value_to_memory(inst_info, dest_addr, value);
			}
			else
			{
				hb_set_reg_value_from_index(guest_context, VM_INST_INFO_REG1(inst_info),
					value);
			}
			break;

		/* STR. VirtualBox uses it every context switching. */
		case VM_INST_INFO_STR:
			hb_read_vmcs(VM_GUEST_TR_SELECTOR, &value);
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] STR is allowed, Memory [%d], dest_addr [%016lX], ldtr[%016lX]\n",
				cpu_id, memory, dest_addr, value);
			if (memory == 1)
			{
				hb_set_value_to_memory(inst_info, dest_addr, value);
			}
			else
			{
				hb_set_reg_value_from_index(guest_context, VM_INST_INFO_REG1(inst_info),
					value);
			}
			break;

		/* LLDT */
		case VM_INST_INFO_LLDT:
			hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] LLDT is allowed, value[%016lX]\n",
				cpu_id, dest_addr);
			if (memory == 1)
			{
				value = hb_get_value_from_memory(inst_info, dest_addr);
			}
			else
			{
				value = dest_addr;
			}

			/* Linux sets LDT to 0.*/
			if (value == 0)
			{
				hb_write_vmcs(VM_GUEST_LDTR_SELECTOR, value);
			}
			else
			{
				hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] LLDT Value is not 0, "
					"%016lX\n", cpu_id, dest_addr);
				hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] hb_vm_exit_callback_"
					"ldtr_tr LLDT 2\n", cpu_id);
				hb_insert_ud_exception_to_vm();
			}
			break;

		/* LTR. VirtualBox uses it every context swithcing. */
		case VM_INST_INFO_LTR:
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] LTR is allowed, value[%016lX]\n",
				cpu_id, dest_addr);

			if (memory == 1)
			{
				value = hb_get_value_from_memory(inst_info, dest_addr);
			}
			else
			{
				value = dest_addr;
			}

			hb_write_vmcs(VM_GUEST_TR_SELECTOR, value);
			break;
	}

	hb_advance_vm_guest_rip();
}

/*
 * Process VMXON, VMCLEAR, VMPTRLD, VMPTRST, XRSTORS, XSAVES callback.
 *	This type of instructions has only one register-based operand.
 *	ex) vmxon [rdi], vmclear [rdi] ...
 */
static void hb_vm_exit_callback_vmx_inst_type1(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context, u64 exit_reason)
{
	u64 inst_info;
	u64 dest_addr = 0;
	u64 data = 0;
	u64 guest_cr3;
	u64 exit_qual;

	hb_read_vmcs(VM_DATA_VM_EXIT_INST_INFO, &inst_info);
	hb_read_vmcs(VM_DATA_EXIT_QUALIFICATION, &exit_qual);

	dest_addr = hb_calc_dest_mem_addr(guest_context, inst_info);
	dest_addr += exit_qual;

	hb_read_vmcs(VM_GUEST_CR3, &guest_cr3);

	/* Sync and reach it. */
	hb_sync_page_table(dest_addr, guest_cr3, 1);

	data = *((u64*)dest_addr);
	hb_advance_vm_guest_rip();

	/* Clear CF, ZF for making success result. */
	hb_clear_vmx_inst_flags();

	switch (exit_reason)
	{
		case VM_EXIT_REASON_VMCLEAR:
			if (hb_clear_vmcs(&data) != 0)
			{
				hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d]     [*] address [%016lX], data [%016lX] clear fail\n",
					cpu_id, dest_addr, data);
			}

			if (g_nested_vmcs_ptr[cpu_id] == data)
			{
				g_nested_vmcs_ptr[cpu_id] = 0;
#if HYPERBOX_USE_VMCS_SHADOWING
				hb_vm_clear_vmcs_shadowing_to_current();
#endif /* HYPERBOX_USE_VMCS_SHADOWING */
			}
			break;

		case VM_EXIT_REASON_VMXON:
			/* Do nothing. */
			break;

		case VM_EXIT_REASON_VMPTRLD:
			g_nested_vmcs_ptr[cpu_id] = data;
#if HYPERBOX_USE_VMCS_SHADOWING
			hb_vm_set_vmcs_shadowing_to_current(data);
#endif /* HYPERBOX_USE_VMCS_SHADOWING */
			break;

		default:
			break;
	}
}

/*
 * Process VMXREAD, VMXWRITE, INVEPT callback.
 *	This type of instructions has two operands.
 *	ex) vmread [rsi], rdi, vmwrite rdi, rsi, invept rdi, [rsi]
 */
static void hb_vm_exit_callback_vmx_inst_type2(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context, u64 exit_reason)
{
	u64 inst_info;
	u64 dest_addr = 0;
	u64 reg_field = 0;
	int memory = 0;
	u64 temp_value = 0;
	struct hb_nested_vmcs_struct* nested_vmcs;
	u64 exit_qual;
	u64 prev_vmcs;

	hb_read_vmcs(VM_DATA_VM_EXIT_INST_INFO, &inst_info);
	hb_read_vmcs(VM_DATA_EXIT_QUALIFICATION, &exit_qual);

	/* Check destination type. */
	if (!VM_INST_INFO_MEM_REG(inst_info))
	{
		dest_addr = hb_calc_dest_mem_addr(guest_context, inst_info);
		memory = 1;
	}
	else
	{
		dest_addr = hb_get_reg_value_from_index(guest_context,
			VM_INST_INFO_REG1(inst_info));
	}
	dest_addr += exit_qual;

	/* Get VMCS field value from register 2. */
	reg_field = hb_get_reg_value_from_index(guest_context,
		VM_INST_INFO_REG2(inst_info));

	hb_advance_vm_guest_rip();

	/* Clear CF, ZF for making success result. */
	hb_clear_vmx_inst_flags();

	/* Find or allocate nested VMCS slot. */
	hb_store_vmcs((void*)&prev_vmcs);
	nested_vmcs = hb_find_nested_vmcs_struct(g_nested_vmcs_ptr[cpu_id]);
	if (nested_vmcs == NULL)
	{
		return ;
	}
	nested_vmcs->vmcs_ptr = g_nested_vmcs_ptr[cpu_id];

	switch (exit_reason)
	{
		case VM_EXIT_REASON_VMWRITE:
			switch(reg_field)
			{
				case VM_HOST_RIP:
					nested_vmcs->rip = dest_addr;
					dest_addr = (u64)hb_vm_exit_callback_stub;
					break;
			
				case VM_HOST_RSP:
					nested_vmcs->rsp = dest_addr;
					dest_addr = (u64)(g_vm_exit_stack_addr[cpu_id]) + g_stack_size - VAL_4KB;
					break;

				case VM_HOST_CR3:
					nested_vmcs->cr3 = dest_addr;
					dest_addr = g_vm_host_phy_pml4;
					break;

				default:
					/* Do nothing. */
					break;

			}

			if (hb_load_vmcs((void*)&(g_nested_vmcs_ptr[cpu_id])) == 0)
			{
				hb_write_vmcs(reg_field, dest_addr);
				hb_load_vmcs((void*)&prev_vmcs);
			}
			else
			{
				hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d]     [*] VMWRITE Prev VMCS [%016lX] SB VMCS [%016lX], nested [%016lX] load fail\n",
					cpu_id, prev_vmcs, virt_to_phys(g_guest_vmcs_log_addr[cpu_id]), g_nested_vmcs_ptr[cpu_id]);
			}
			break;

		case VM_EXIT_REASON_VMREAD:
			if (hb_load_vmcs((void*)&(g_nested_vmcs_ptr[cpu_id])) != 0)
			{
				hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d]     [*] VMREAD Prev VMCS [%016lX] SB VMCS [%016lX], nested [%016lX] load fail\n",
					cpu_id, prev_vmcs, virt_to_phys(g_guest_vmcs_log_addr[cpu_id]), g_nested_vmcs_ptr[cpu_id]);
				break;
			}

			switch (reg_field)
			{
				case VM_HOST_RIP:
					temp_value = nested_vmcs->rip;
					break;

				case VM_HOST_RSP:
					temp_value = nested_vmcs->rsp;
					break;

				case VM_HOST_CR3:
					temp_value = nested_vmcs->cr3;
					break;

				default:
					hb_read_vmcs(reg_field, &temp_value);
					break;
			}

			if (memory == 1)
			{
				hb_set_value_to_memory(inst_info, dest_addr, temp_value);
			}
			else
			{
				hb_set_reg_value_from_index(guest_context, VM_INST_INFO_REG1(inst_info),
					temp_value);
			}
			hb_load_vmcs((void*)&prev_vmcs);

			break;

		case VM_EXIT_REASON_INVEPT:
			hb_invept(reg_field, (u64*)dest_addr);
			break;

		case VM_EXIT_REASON_INVVPID:
			hb_invvpid(reg_field, (u64*)dest_addr);
			break;

		case VM_EXIT_REASON_INVPCID:
			hb_invpcid(reg_field, (u64*)dest_addr);
			break;

		default:
			break;
	}
}

/*
 * Process EPT violation.
 */
static void hb_vm_exit_callback_ept_violation(int cpu_id, struct hb_vm_exit_guest_register*
	guest_context, u64 exit_reason, u64 exit_qual, u64 guest_linear, u64 guest_physical)
{
	u64 cr0;

#if HYPERBOX_USE_SLEEP
	/* Support suspend and hibernation. */
	if (guest_linear == (u64) hb_system_sleep_notify)
	{
		hb_set_ept_lock_page(guest_physical);
		hb_trigger_shutdown_timer();
		return ;
	}
#endif /* HYPERBOX_USE_SLEEP */

	if (hb_is_system_shutdowning() == 0)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Error=%06d Memory attack is detected, "
			"guest linear=$(%016lX) guest physical=%016X virt_to_phys=%016lX\n",
			cpu_id, ERROR_KERNEL_MEMORY_MODIFICATION, guest_linear, guest_physical, virt_to_phys((void*)guest_linear));

		/* If the address is in workaround area, set all permission to the page */
		if (hb_is_workaround_addr(guest_physical) == 1)
		{
			hb_set_ept_all_access_page(guest_physical);
			hb_printf(LOG_LEVEL_ERROR,
				LOG_ERROR "VM [%d] === %016lX is Workaround Address ===\n\n",
				cpu_id, guest_physical);
		}
		else
		{
			/* Insert exception to the guest */
			hb_insert_ud_exception_to_vm();
			hb_read_vmcs(VM_GUEST_CR0, &cr0);

			/* If malware turns WP bit off, recover it again */
			if ((cr0 & CR0_BIT_PG) && !(cr0 & CR0_BIT_WP))
			{
				hb_write_vmcs(VM_GUEST_CR0, cr0 | CR0_BIT_WP);
			}

			hb_error_log(ERROR_KERNEL_MODIFICATION);
		}
	}
	else
	{
#if HYPERBOX_USE_SLEEP
		if (hb_is_addr_in_kernel_ro_area((void*)guest_linear) == 0)
		{
			hb_set_ept_read_only_page(guest_physical);
		}
#else
		hb_advance_vm_guest_rip();
#endif /* HYPERBOX_USE_SLEEP */
	}
}

/*
 * Process CPUID callback.
 */
static void hb_vm_exit_callback_cpuid(struct hb_vm_exit_guest_register* guest_context)
{
	cpuid_count(guest_context->rax, guest_context->rcx, (u32*)&guest_context->rax, (u32*)&guest_context->rbx,
		(u32*)&guest_context->rcx, (u32*)&guest_context->rdx);

	hb_advance_vm_guest_rip();
}

/*
 * Process INVD callback.
 */
static void hb_vm_exit_callback_invd(void)
{
	hb_invd();
	hb_advance_vm_guest_rip();
}

/*
 * Process VT-timer expire callback.
 */
static void hb_vm_exit_callback_pre_timer_expired(int cpu_id)
{
	u64 value;

        if (hb_is_system_shutdowning() == 0)
        {
		/* Call the function of Shadow-watcher. */
		hb_callback_vm_timer(cpu_id);
	}

	/* Reset VM timer. */
	value = hb_calc_vm_pre_timer_value();
	hb_write_vmcs(VM_GUEST_VMX_PRE_TIMER_VALUE, value);
}

/*
 * Process interrupts without an error code.
 *	Do nothing because the guest have to handle these interrupts.
 */
void hb_int_callback(void)
{
	int cpu_id;

	cpu_id = smp_processor_id();

	/* Update currnt cpu mode. */
	g_vmx_root_mode[cpu_id] = 1;

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] INT callback without an error code\n",
		cpu_id);

	/* Update currnt cpu mode. */
	g_vmx_root_mode[cpu_id] = 0;
}

/*
 * Process interrupts without an error code.
 *	Do nothing because the guest have to handle these interrupts.
 */
void hb_int_with_error_callback(void)
{
	int cpu_id;

	cpu_id = smp_processor_id();

	/* Update currnt cpu mode. */
	g_vmx_root_mode[cpu_id] = 1;

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] INT callback with an error code\n",
		cpu_id);

	/* Update currnt cpu mode. */
	g_vmx_root_mode[cpu_id] = 0;
}

/*
 * Process interrupts without an error code.
 *	Do nothing because the guest have to handle these interrupts.
 */
void hb_int_nmi_callback(void)
{
	int cpu_id;

	cpu_id = smp_processor_id();

	/* Update currnt cpu mode. */
	g_vmx_root_mode[cpu_id] = 1;

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] INT NMI callback\n", cpu_id);

	/* Update currnt cpu mode. */
	g_vmx_root_mode[cpu_id] = 0;
}

/*
 * Setup the host registers.
 */
static void hb_setup_vm_host_register(struct hb_vm_host_register* hb_vm_host_register)
{
	struct desc_ptr gdtr;
	struct desc_ptr idtr;
	struct desc_struct* gdt;
	LDTTSS_DESC* tss;
	u64 base0 = 0;
	u64 base1 = 0;
	u64 base2 = 0;
	u64 base3 = 0;
	int i;
	char* vm_exit_stack;
	u64 stack_size = g_stack_size;
	int cpu_id;

	cpu_id = smp_processor_id();

	/* Allocate kernel stack for VM exit */
	vm_exit_stack = (char*)(g_vm_exit_stack_addr[cpu_id]);
	memset(vm_exit_stack, 0, stack_size);

	native_store_gdt(&gdtr);
	store_idt(&idtr);

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Setup Host Register\n", cpu_id);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] GDTR Address %016lX\n",
		gdtr.address);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] GDTR Size %d\n", gdtr.size);

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IDTR Address %016lX\n",
		idtr.address);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IDTR Size %d\n", idtr.size);

	for (i = 0 ; i < (gdtr.size + 7) / 8 ; i++)
	{
		gdt = (struct desc_struct*)(gdtr.address + i * 8);
		hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] GDT Index %d\n", i);
		hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] GDT High %08X, Low %08X\n",
			*((u32*)gdt + 1), *((u32*)gdt));
	}

	hb_vm_host_register->cr0 = hb_get_cr0();

	/* Using Shaodow CR3 for world separation in host*/
	hb_vm_host_register->cr3 = g_vm_host_phy_pml4;
	hb_vm_host_register->cr4 = hb_get_cr4();

	hb_vm_host_register->rsp = (u64)vm_exit_stack + stack_size - VAL_4KB;
	hb_vm_host_register->rip = (u64)hb_vm_exit_callback_stub;

	hb_vm_host_register->cs_selector = __KERNEL_CS;
	hb_vm_host_register->ss_selector = __KERNEL_DS;
	hb_vm_host_register->ds_selector = __KERNEL_DS;
	hb_vm_host_register->es_selector = __KERNEL_DS;
	hb_vm_host_register->fs_selector = __KERNEL_DS;
	hb_vm_host_register->gs_selector = __KERNEL_DS;
	hb_vm_host_register->tr_selector = hb_get_tr();

	hb_vm_host_register->fs_base_addr = hb_rdmsr(MSR_FS_BASE_ADDR);
	hb_vm_host_register->gs_base_addr = hb_rdmsr(MSR_GS_BASE_ADDR);

	tss = (LDTTSS_DESC*)(gdtr.address +
		(hb_vm_host_register->tr_selector & ~MASK_GDT_ACCESS));
	base0 = tss->base0;
	base1 = tss->base1;
	base2 = tss->base2;
	base3 = tss->base3;
	hb_vm_host_register->tr_base_addr = base0 | (base1 << 16) | (base2 << 24) |
		(base3 << 32);

	hb_vm_host_register->gdtr_base_addr = gdtr.address;
	hb_vm_host_register->idtr_base_addr = g_host_idtr.address;

	hb_vm_host_register->ia32_sys_enter_cs = hb_rdmsr(MSR_IA32_SYSENTER_CS);
	hb_vm_host_register->ia32_sys_enter_esp = hb_rdmsr(MSR_IA32_SYSENTER_ESP);
	hb_vm_host_register->ia32_sys_enter_eip = hb_rdmsr(MSR_IA32_SYSENTER_EIP);

	hb_vm_host_register->ia32_perf_global_ctrl = hb_rdmsr(MSR_IA32_PERF_GLOBAL_CTRL);
	hb_vm_host_register->ia32_pat = hb_rdmsr(MSR_IA32_PAT);
	hb_vm_host_register->ia32_efer = hb_rdmsr(MSR_IA32_EFER);

	hb_dump_vm_host_register(hb_vm_host_register);
}

/*
 * Setup the guest register.
 */
static void hb_setup_vm_guest_register(struct hb_vm_guest_register*
	hb_vm_guest_register, const struct hb_vm_host_register* hb_vm_host_register)
{
	struct desc_ptr gdtr;
	struct desc_ptr idtr;
	struct desc_struct* gdt;
	LDTTSS_DESC* ldt;
	LDTTSS_DESC* tss;
	u64 base0 = 0;
	u64 base1 = 0;
	u64 base2 = 0;
	u64 base3 = 0;
	u64 access = 0;
	u64 qwLimit0 = 0;
	u64 qwLimit1 = 0;
	int cpu_id;
#if HYPERBOX_USE_HW_BREAKPOINT
	unsigned long dr6;
#endif
	unsigned long dr7 = 0;
	cpu_id = smp_processor_id();

	native_store_gdt(&gdtr);
	store_idt(&idtr);

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Setup Guest Register\n", cpu_id);

	hb_vm_guest_register->cr0 = hb_vm_host_register->cr0;
	hb_vm_guest_register->cr3 = hb_get_cr3();
	hb_vm_guest_register->cr4 = hb_vm_host_register->cr4;

#if HYPERBOX_USE_HW_BREAKPOINT
	set_debugreg(hb_get_symbol_address("wake_up_new_task"), 0);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
	set_debugreg(hb_get_symbol_address("proc_flush_task"), 1);
#else /* LINUX_VERSION_CODE */
	set_debugreg(hb_get_symbol_address("cgroup_release"), 1);
#endif /* LINUX_VERSION_CODE */

	set_debugreg(hb_get_symbol_address("entry_SYSCALL_64"), 2);
	set_debugreg(hb_get_symbol_address("commit_creds"), 3);

	dr7 = hb_encode_dr7(0, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= hb_encode_dr7(1, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= hb_encode_dr7(2, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= hb_encode_dr7(3, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= (0x01 << 10);

	hb_vm_guest_register->dr7 = dr7;

	get_debugreg(dr6, 6);
	dr6 &= 0xfffffffffffffff0;
	set_debugreg(dr6, 6);

	get_debugreg(g_test_dr[cpu_id][0], 0);
	get_debugreg(g_test_dr[cpu_id][1], 1);
	get_debugreg(g_test_dr[cpu_id][2], 2);
	get_debugreg(g_test_dr[cpu_id][3], 3);
	get_debugreg(g_test_dr[cpu_id][6], 6);
	get_debugreg(g_test_dr[cpu_id][7], 7);

#else /* HYPERBOX_USE_HW_BREAKPOINT */
	hb_vm_guest_register->dr7 = hb_get_dr7();
#endif /* HYPERBOX_USE_HW_BREAKPOINT */

	get_debugreg(dr7, 6);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "ORG DB6 = %lx", dr7);
	get_debugreg(dr7, 7);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "ORG DB7 = %lx", hb_vm_guest_register->dr7);

	hb_vm_guest_register->rflags = hb_get_rflags();
	/* Under two registers are set when VM launch. */
	hb_vm_guest_register->rsp = 0xFFFFFFFFFFFFFFFF;
	hb_vm_guest_register->rip = 0xFFFFFFFFFFFFFFFF;

	hb_vm_guest_register->cs_selector = hb_get_cs();
	hb_vm_guest_register->ss_selector = hb_get_ss();
	hb_vm_guest_register->ds_selector = hb_get_ds();
	hb_vm_guest_register->es_selector = hb_get_es();
	hb_vm_guest_register->fs_selector = hb_get_fs();
	hb_vm_guest_register->gs_selector = hb_get_gs();
	hb_vm_guest_register->ldtr_selector = hb_get_ldtr();
	hb_vm_guest_register->tr_selector = hb_get_tr();

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "LDTR Selector %08X\n",
		(u32)hb_vm_guest_register->ldtr_selector);

	hb_vm_guest_register->cs_base_addr =
		hb_get_desc_base(hb_vm_guest_register->cs_selector);
	hb_vm_guest_register->ss_base_addr =
		hb_get_desc_base(hb_vm_guest_register->ss_selector);
	hb_vm_guest_register->ds_base_addr =
		hb_get_desc_base(hb_vm_guest_register->ds_selector);
	hb_vm_guest_register->es_base_addr =
		hb_get_desc_base(hb_vm_guest_register->es_selector);
	hb_vm_guest_register->fs_base_addr = hb_rdmsr(MSR_FS_BASE_ADDR);
	hb_vm_guest_register->gs_base_addr = hb_rdmsr(MSR_GS_BASE_ADDR);

	if (hb_vm_guest_register->ldtr_selector == 0)
	{
		hb_vm_guest_register->ldtr_base_addr = 0;
	}
	else
	{
		ldt = (LDTTSS_DESC*)(gdtr.address +
			(hb_vm_guest_register->ldtr_selector & ~MASK_GDT_ACCESS));
		base0 = ldt->base0;
		base1 = ldt->base1;
		base2 = ldt->base2;
		base3 = ldt->base3;
		hb_vm_guest_register->ldtr_base_addr = base0 | (base1 << 16) |
			(base2 << 24) | (base3 << 32);
	}

	if (hb_vm_guest_register->tr_selector == 0)
	{
		hb_vm_guest_register->tr_base_addr = 0x00;
	}
	else
	{
		tss = (LDTTSS_DESC*)(gdtr.address +
			(hb_vm_guest_register->tr_selector & ~MASK_GDT_ACCESS));
		base0 = tss->base0;
		base1 = tss->base1;
		base2 = tss->base2;
		base3 = tss->base3;
		hb_vm_guest_register->tr_base_addr = base0 | (base1 << 16) |
			(base2 << 24) | (base3 << 32);
	}

	hb_vm_guest_register->cs_limit = 0xFFFFFFFF;
	hb_vm_guest_register->ss_limit = 0xFFFFFFFF;
	hb_vm_guest_register->ds_limit = 0xFFFFFFFF;
	hb_vm_guest_register->es_limit = 0xFFFFFFFF;
	hb_vm_guest_register->fs_limit = 0xFFFFFFFF;
	hb_vm_guest_register->gs_limit = 0xFFFFFFFF;

	if (hb_vm_guest_register->ldtr_selector == 0)
	{
		hb_vm_guest_register->ldtr_limit = 0;
	}
	else
	{
		ldt = (LDTTSS_DESC*)(gdtr.address +
			(hb_vm_guest_register->ldtr_selector & ~MASK_GDT_ACCESS));
		qwLimit0 = ldt->limit0;
		qwLimit1 = ldt->limit1;
		hb_vm_guest_register->ldtr_limit = qwLimit0 | (qwLimit1 << 16);
	}

	if (hb_vm_guest_register->tr_selector == 0)
	{
		hb_vm_guest_register->tr_limit = 0;
	}
	else
	{
		tss = (LDTTSS_DESC*)(gdtr.address +
			(hb_vm_guest_register->tr_selector & ~MASK_GDT_ACCESS));
		qwLimit0 = tss->limit0;
		qwLimit1 = tss->limit1;
		hb_vm_guest_register->tr_limit = qwLimit0 | (qwLimit1 << 16);
	}

	hb_vm_guest_register->cs_access =
		hb_get_desc_access(hb_vm_guest_register->cs_selector);
	hb_vm_guest_register->ss_access =
		hb_get_desc_access(hb_vm_guest_register->ss_selector);
	hb_vm_guest_register->ds_access =
		hb_get_desc_access(hb_vm_guest_register->ds_selector);
	hb_vm_guest_register->es_access =
		hb_get_desc_access(hb_vm_guest_register->es_selector);
	hb_vm_guest_register->fs_access =
		hb_get_desc_access(hb_vm_guest_register->fs_selector);
	hb_vm_guest_register->gs_access =
		hb_get_desc_access(hb_vm_guest_register->gs_selector);

	if (hb_vm_guest_register->ldtr_selector == 0)
	{
		hb_vm_guest_register->ldtr_access = 0x10000;
	}
	else
	{
		ldt = (LDTTSS_DESC*)(gdtr.address +
			(hb_vm_guest_register->ldtr_selector & ~MASK_GDT_ACCESS));
		gdt = (struct desc_struct*)ldt;
		access = *((u32*)gdt + 1) >> 8;

		/* type: 4, s: 1, dpl: 2, p: 1; limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8 */
		hb_vm_guest_register->ldtr_access = access & 0xF0FF;
	}

	if (hb_vm_guest_register->tr_selector == 0)
	{
		hb_vm_guest_register->tr_access = 0;
	}
	else
	{
		tss = (LDTTSS_DESC*)(gdtr.address +
			(hb_vm_guest_register->tr_selector & ~MASK_GDT_ACCESS));
		gdt = (struct desc_struct*)tss;
		access = *((u32*)gdt + 1) >> 8;

		/* type: 4, s: 1, dpl: 2, p: 1; limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8 */
		hb_vm_guest_register->tr_access = access & 0xF0FF;
	}

	hb_vm_guest_register->gdtr_base_addr = hb_vm_host_register->gdtr_base_addr;
	hb_vm_guest_register->idtr_base_addr = idtr.address;
	hb_vm_guest_register->gdtr_limit = gdtr.size;
	hb_vm_guest_register->idtr_limit = idtr.size;

	hb_vm_guest_register->ia32_debug_ctrl = 0;
	hb_vm_guest_register->ia32_sys_enter_cs = hb_vm_host_register->ia32_sys_enter_cs;
	hb_vm_guest_register->ia32_sys_enter_esp = hb_vm_host_register->ia32_sys_enter_esp;
	hb_vm_guest_register->ia32_sys_enter_eip = hb_vm_host_register->ia32_sys_enter_eip;
	hb_vm_guest_register->vmcs_link_ptr = 0xFFFFFFFFFFFFFFFF;

	hb_vm_guest_register->ia32_perf_global_ctrl =
		hb_vm_host_register->ia32_perf_global_ctrl;
	hb_vm_guest_register->ia32_pat = hb_vm_host_register->ia32_pat;
	hb_vm_guest_register->ia32_efer = hb_vm_host_register->ia32_efer;

	hb_dump_vm_guest_register(hb_vm_guest_register);
}

#if HYPERBOX_USE_MSR_PROTECTION

/*
 * Set MSR write bitmap to get a VM exit event of modification.
 */
static void hb_vm_set_msr_write_bitmap(struct hb_vm_control_register*
	hb_vm_control_register, u64 msr_number)
{
	u64 byte_offset;
	u64 bit_offset;
	u64 bitmap_add = 2048;

	byte_offset = (msr_number & 0xFFFFFFF) / 8;
	bit_offset = (msr_number & 0xFFFFFFF) % 8;

	if (msr_number >= 0xC0000000)
	{
		bitmap_add += 1024;
	}

	((u8*)hb_vm_control_register->msr_bitmap_addr)[bitmap_add + byte_offset] |=
		(0x01 << bit_offset);
}

#endif /* HYPERBOX_USE_MSR_PROTECTION */

/*
 * Set VMREAD and VMWRITE bitmap to get a VM exit event of modification.
 */
static void hb_vm_set_vmread_vmwrite_bitmap(struct hb_vm_control_register*
	hb_vm_control_register, u64 field_number)
{
	u64 byte_offset;
	u64 bit_offset;

	byte_offset = field_number / 8;
	bit_offset = field_number % 8;

	((u8*)hb_vm_control_register->vmread_bitmap_addr)[byte_offset] |=
		(0x01 << bit_offset);

	((u8*)hb_vm_control_register->vmwrite_bitmap_addr)[byte_offset] |=
		(0x01 << bit_offset);
}


/*
 * Set VM control register.
 */
static void hb_setup_vm_control_register(struct hb_vm_control_register*
	hb_vm_control_register, int cpu_id)
{
	u64 sec_flags = 0;
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Setup VM Control Register\n", cpu_id);

#if HYPERBOX_USE_EPT
	sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_UNREST_GUEST;
	sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_USE_EPT;
#endif /* HYPERBOX_USE_EPT */

	if ((hb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) &
		VM_BIT_VM_SEC_PROC_CTRL_ENABLE_INVPCID)
	{
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Support Enable INVPCID\n",
			cpu_id);
		sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_ENABLE_INVPCID;
	}

	if (g_support_xsave == 1)
	{
		if ((hb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) &
			VM_BIT_VM_SEC_PROC_CTRL_ENABLE_XSAVE)
		{
			hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Support Enable XSAVE\n",
				cpu_id);
			sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_ENABLE_XSAVE;
		}
	}

	if ((hb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) &
		VM_BIT_VM_SEC_PROC_CTRL_ENABLE_RDTSCP)
	{
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Support Enable RDTSCP\n",
			cpu_id);
		sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_ENABLE_RDTSCP;
	}

#if HYPERBOX_USE_VMCS_SHADOWING
	if ((hb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) &
		VM_BIT_VM_SEC_PROC_CTRL_VMCS_SHADOWING)
	{
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Support VMCS Shadowing\n",
			cpu_id);
		sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_VMCS_SHADOWING;
		g_support_vmcs_shadowing = 1;
	}
#endif /* HYPERBOX_USE_VMCS_SHADOWING */

#if HYPERBOX_USE_VPID
	if ((hb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) &
		VM_BIT_VM_SEC_PROC_CTRL_ENABLE_VPID)
	{
		hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Support Enable VPID\n",
			cpu_id);
		sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_ENABLE_VPID;
		g_support_vpid = 1;
	}
#endif /* HYPERBOX_USE_VPID */

#if HYPERBOX_USE_PRE_TIMER
        hb_vm_control_register->pin_based_ctrl =
                (hb_rdmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS) | VM_BIT_VM_PIN_BASED_USE_PRE_TIMER) &
                0xFFFFFFFF;
#else
        hb_vm_control_register->pin_based_ctrl = (hb_rdmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS)) &
                0xFFFFFFFF;
#endif /* HYPERBOX_USE_PRE_TIMER */

	hb_vm_control_register->pri_proc_based_ctrl =
		(hb_rdmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS) | VM_BIT_VM_PRI_PROC_CTRL_USE_IO_BITMAP |
		VM_BIT_VM_PRI_PROC_CTRL_USE_MSR_BITMAP | VM_BIT_VM_PRI_PROC_CTRL_USE_SEC_CTRL |
		VM_BIT_VM_PRI_PROC_CTRL_USE_MOVE_DR) & 0xFFFFFFFF;

	g_vm_pri_proc_based_ctrl_default = hb_vm_control_register->pri_proc_based_ctrl;
	hb_vm_control_register->sec_proc_based_ctrl =
		(hb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) | sec_flags) & 0xFFFFFFFF;

	hb_vm_control_register->vm_entry_ctrl_field =
		(hb_rdmsr(MSR_IA32_VMX_TRUE_ENTRY_CTRLS) | VM_BIT_VM_ENTRY_CTRL_IA32E_MODE_GUEST |
		VM_BIT_VM_ENTRY_LOAD_DEBUG_CTRL) & 0xFFFFFFFF;

#if HYPERBOX_USE_PRE_TIMER
	hb_vm_control_register->vm_exti_ctrl_field = (hb_rdmsr(MSR_IA32_VMX_TRUE_EXIT_CTRLS) |
		VM_BIT_VM_EXIT_CTRL_HOST_ADDR_SIZE | VM_BIT_VM_EXIT_SAVE_DEBUG_CTRL |
		VM_BIT_VM_EXIT_CTRL_SAVE_PRE_TIMER | VM_BIT_VM_EXIT_CTRL_SAVE_IA32_EFER) &
		0xFFFFFFFF;
#else
	hb_vm_control_register->vm_exti_ctrl_field = (hb_rdmsr(MSR_IA32_VMX_TRUE_EXIT_CTRLS) |
		VM_BIT_VM_EXIT_CTRL_HOST_ADDR_SIZE | VM_BIT_VM_EXIT_SAVE_DEBUG_CTRL |
		VM_BIT_VM_EXIT_CTRL_SAVE_IA32_EFER) & 0xFFFFFFFF;
#endif /* HYPERBOX_USE_PRE_TIMER */

#if HYPERBOX_USE_HW_BREAKPOINT
	hb_vm_control_register->except_bitmap = ((u64)0x01 << VM_INT_DEBUG_EXCEPTION);
#else
	hb_vm_control_register->except_bitmap = 0x00;
#endif

	hb_vm_control_register->io_bitmap_addrA = (u64)(g_io_bitmap_addrA[cpu_id]);
	hb_vm_control_register->io_bitmap_addrB = (u64)(g_io_bitmap_addrB[cpu_id]);
	hb_vm_control_register->msr_bitmap_addr = (u64)(g_msr_bitmap_addr[cpu_id]);
	hb_vm_control_register->vmread_bitmap_addr = (u64)(g_vmread_bitmap_addr[cpu_id]);
	hb_vm_control_register->vmwrite_bitmap_addr = (u64)(g_vmwrite_bitmap_addr[cpu_id]);
	hb_vm_control_register->virt_apic_page_addr = (u64)(g_virt_apic_page_addr[cpu_id]);

	memset((char*)hb_vm_control_register->io_bitmap_addrA, 0, IO_BITMAP_SIZE);
	memset((char*)hb_vm_control_register->io_bitmap_addrB, 0, IO_BITMAP_SIZE);
	memset((char*)hb_vm_control_register->msr_bitmap_addr, 0, MSR_BITMAP_SIZE);
	memset((char*)hb_vm_control_register->vmread_bitmap_addr, 0, VMREAD_BITMAP_SIZE);
	memset((char*)hb_vm_control_register->vmwrite_bitmap_addr, 0, VMWRITE_BITMAP_SIZE);
	memset((char*)hb_vm_control_register->virt_apic_page_addr, 0, VIRT_APIC_PAGE_SIZE);

	/* Registers related SYSENTER, SYSCALL MSR are write-protected. */
#if HYPERBOX_USE_MSR_PROTECTION
	hb_vm_set_msr_write_bitmap(hb_vm_control_register, MSR_IA32_SYSENTER_CS);
	hb_vm_set_msr_write_bitmap(hb_vm_control_register, MSR_IA32_SYSENTER_ESP);
	hb_vm_set_msr_write_bitmap(hb_vm_control_register, MSR_IA32_SYSENTER_EIP);
	hb_vm_set_msr_write_bitmap(hb_vm_control_register, MSR_IA32_STAR);
	hb_vm_set_msr_write_bitmap(hb_vm_control_register, MSR_IA32_LSTAR);
	hb_vm_set_msr_write_bitmap(hb_vm_control_register, MSR_IA32_FMASK);
#endif

	/* Nested VMM support. */
	hb_vm_set_vmread_vmwrite_bitmap(hb_vm_control_register, VM_HOST_RIP); 
	hb_vm_set_vmread_vmwrite_bitmap(hb_vm_control_register, VM_HOST_RSP); 
	hb_vm_set_vmread_vmwrite_bitmap(hb_vm_control_register, VM_HOST_CR3); 

	hb_vm_control_register->io_bitmap_addrA =
		(u64)virt_to_phys((void*)hb_vm_control_register->io_bitmap_addrA);
	hb_vm_control_register->io_bitmap_addrB =
		(u64)virt_to_phys((void*)hb_vm_control_register->io_bitmap_addrB);
	hb_vm_control_register->msr_bitmap_addr =
		(u64)virt_to_phys((void*)hb_vm_control_register->msr_bitmap_addr);
	hb_vm_control_register->vmread_bitmap_addr =
		(u64)virt_to_phys((void*)hb_vm_control_register->vmread_bitmap_addr);
	hb_vm_control_register->vmwrite_bitmap_addr =
		(u64)virt_to_phys((void*)hb_vm_control_register->vmwrite_bitmap_addr);
	hb_vm_control_register->virt_apic_page_addr =
		(u64)virt_to_phys((void*)hb_vm_control_register->virt_apic_page_addr);

#if HYPERBOX_USE_EPT
	hb_vm_control_register->ept_ptr =
		(u64)virt_to_phys((void*)g_ept_info.pml4_page_addr_array[0]) |
		VM_BIT_EPT_PAGE_WALK_LENGTH_BITMAP | VM_BIT_EPT_MEM_TYPE_WB;
#endif

	hb_vm_control_register->cr0_guest_host_mask = CR0_BIT_WP;
	hb_vm_control_register->cr0_read_shadow = CR0_BIT_WP;

	hb_vm_control_register->cr4_guest_host_mask = CR4_BIT_VMXE | CR4_BIT_SMEP | CR4_BIT_MCE;
	hb_vm_control_register->cr4_read_shadow = CR4_BIT_VMXE | CR4_BIT_SMEP;

	hb_dump_vm_control_register(hb_vm_control_register);
}

/*
 * Setup VMCS.
 */
static void hb_setup_vmcs(const struct hb_vm_host_register* hb_vm_host_register,
	const struct hb_vm_guest_register* hb_vm_guest_register,
	const struct hb_vm_control_register* hb_vm_control_register)
{
	int result;
	int cpu_id;
	u64 value;

	cpu_id = smp_processor_id();

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Setup VMCS\n", cpu_id);

	/* Setup host information. */
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Set Host Register\n");
	result = hb_write_vmcs(VM_HOST_CR0, hb_vm_host_register->cr0);
	hb_print_vm_result("    [*] CR0", result);
	result = hb_write_vmcs(VM_HOST_CR3, hb_vm_host_register->cr3);
	hb_print_vm_result("    [*] CR3", result);
	result = hb_write_vmcs(VM_HOST_CR4, hb_vm_host_register->cr4);
	hb_print_vm_result("    [*] CR4", result);
	result = hb_write_vmcs(VM_HOST_RSP, hb_vm_host_register->rsp);
	hb_print_vm_result("    [*] RSP", result);
	result = hb_write_vmcs(VM_HOST_RIP, hb_vm_host_register->rip);
	hb_print_vm_result("    [*] RIP", result);
	result = hb_write_vmcs(VM_HOST_CS_SELECTOR, hb_vm_host_register->cs_selector);
	hb_print_vm_result("    [*] CS Selector", result);
	result = hb_write_vmcs(VM_HOST_SS_SELECTOR, hb_vm_host_register->ss_selector);
	hb_print_vm_result("    [*] SS Selector", result);
	result = hb_write_vmcs(VM_HOST_DS_SELECTOR, hb_vm_host_register->ds_selector);
	hb_print_vm_result("    [*] DS Selector", result);
	result = hb_write_vmcs(VM_HOST_ES_SELECTOR, hb_vm_host_register->es_selector);
	hb_print_vm_result("    [*] ES Selector", result);
	result = hb_write_vmcs(VM_HOST_FS_SELECTOR, hb_vm_host_register->fs_selector);
	hb_print_vm_result("    [*] FS Selector", result);
	result = hb_write_vmcs(VM_HOST_GS_SELECTOR, hb_vm_host_register->gs_selector);
	hb_print_vm_result("    [*] GS Selector", result);
	result = hb_write_vmcs(VM_HOST_TR_SELECTOR, hb_vm_host_register->tr_selector);
	hb_print_vm_result("    [*] TR Selector", result);

	result = hb_write_vmcs(VM_HOST_FS_BASE, hb_vm_host_register->fs_base_addr);
	hb_print_vm_result("    [*] FS Base", result);
	result = hb_write_vmcs(VM_HOST_GS_BASE, hb_vm_host_register->gs_base_addr);
	hb_print_vm_result("    [*] GS Base", result);
	result = hb_write_vmcs(VM_HOST_TR_BASE, hb_vm_host_register->tr_base_addr);
	hb_print_vm_result("    [*] TR Base", result);
	result = hb_write_vmcs(VM_HOST_GDTR_BASE, hb_vm_host_register->gdtr_base_addr);
	hb_print_vm_result("    [*] GDTR Base", result);
	result = hb_write_vmcs(VM_HOST_IDTR_BASE, hb_vm_host_register->idtr_base_addr);
	hb_print_vm_result("    [*] IDTR Base", result);

	result = hb_write_vmcs(VM_HOST_IA32_SYSENTER_CS,
		hb_vm_host_register->ia32_sys_enter_cs);
	hb_print_vm_result("    [*] SYSENTER_CS Base", result);
	result = hb_write_vmcs(VM_HOST_IA32_SYSENTER_ESP,
		hb_vm_host_register->ia32_sys_enter_esp);
	hb_print_vm_result("    [*] SYSENTER_ESP", result);
	result = hb_write_vmcs(VM_HOST_IA32_SYSENTER_EIP,
		hb_vm_host_register->ia32_sys_enter_eip);
	hb_print_vm_result("    [*] SYSENTER_EIP", result);
	result = hb_write_vmcs(VM_HOST_PERF_GLOBAL_CTRL,
		hb_vm_host_register->ia32_perf_global_ctrl);
	hb_print_vm_result("    [*] Perf Global Ctrl", result);
	result = hb_write_vmcs(VM_HOST_PAT, hb_vm_host_register->ia32_pat);
	hb_print_vm_result("    [*] PAT", result);
	result = hb_write_vmcs(VM_HOST_EFER, hb_vm_host_register->ia32_efer);
	hb_print_vm_result("    [*] EFER", result);

	/* Setup guest information. */
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Set Guest Register\n");
	result = hb_write_vmcs(VM_GUEST_CR0, hb_vm_guest_register->cr0);
	hb_print_vm_result("    [*] CR0", result);
	result = hb_write_vmcs(VM_GUEST_CR3, hb_vm_guest_register->cr3);
	hb_print_vm_result("    [*] CR3", result);
	result = hb_write_vmcs(VM_GUEST_CR4, hb_vm_guest_register->cr4);
	hb_print_vm_result("    [*] CR4", result);
	result = hb_write_vmcs(VM_GUEST_DR7, hb_vm_guest_register->dr7);
	hb_print_vm_result("    [*] DR7", result);
	result = hb_write_vmcs(VM_GUEST_RSP, hb_vm_guest_register->rsp);
	hb_print_vm_result("    [*] RSP", result);
	result = hb_write_vmcs(VM_GUEST_RIP, hb_vm_guest_register->rip);
	hb_print_vm_result("    [*] RIP", result);
	result = hb_write_vmcs(VM_GUEST_RFLAGS, hb_vm_guest_register->rflags);
	hb_print_vm_result("    [*] RFLAGS", result);
	result = hb_write_vmcs(VM_GUEST_CS_SELECTOR, hb_vm_guest_register->cs_selector);
	hb_print_vm_result("    [*] CS Selector", result);
	result = hb_write_vmcs(VM_GUEST_SS_SELECTOR, hb_vm_guest_register->ss_selector);
	hb_print_vm_result("    [*] SS Selector", result);
	result = hb_write_vmcs(VM_GUEST_DS_SELECTOR, hb_vm_guest_register->ds_selector);
	hb_print_vm_result("    [*] DS Selector", result);
	result = hb_write_vmcs(VM_GUEST_ES_SELECTOR, hb_vm_guest_register->es_selector);
	hb_print_vm_result("    [*] ES Selector", result);
	result = hb_write_vmcs(VM_GUEST_FS_SELECTOR, hb_vm_guest_register->fs_selector);
	hb_print_vm_result("    [*] FS Selector", result);
	result = hb_write_vmcs(VM_GUEST_GS_SELECTOR, hb_vm_guest_register->gs_selector);
	hb_print_vm_result("    [*] GS Selector", result);
	result = hb_write_vmcs(VM_GUEST_LDTR_SELECTOR, hb_vm_guest_register->ldtr_selector);
	hb_print_vm_result("    [*] LDTR Selector", result);
	result = hb_write_vmcs(VM_GUEST_TR_SELECTOR, hb_vm_guest_register->tr_selector);
	hb_print_vm_result("    [*] TR Selector", result);

	result = hb_write_vmcs(VM_GUEST_CS_BASE, hb_vm_guest_register->cs_base_addr);
	hb_print_vm_result("    [*] CS Base", result);
	result = hb_write_vmcs(VM_GUEST_SS_BASE, hb_vm_guest_register->ss_base_addr);
	hb_print_vm_result("    [*] SS Base", result);
	result = hb_write_vmcs(VM_GUEST_DS_BASE, hb_vm_guest_register->ds_base_addr);
	hb_print_vm_result("    [*] DS Base", result);
	result = hb_write_vmcs(VM_GUEST_ES_BASE, hb_vm_guest_register->es_base_addr);
	hb_print_vm_result("    [*] ES Base", result);
	result = hb_write_vmcs(VM_GUEST_FS_BASE, hb_vm_guest_register->fs_base_addr);
	hb_print_vm_result("    [*] FS Base", result);
	result = hb_write_vmcs(VM_GUEST_GS_BASE, hb_vm_guest_register->gs_base_addr);
	hb_print_vm_result("    [*] GS Base", result);
	result = hb_write_vmcs(VM_GUEST_LDTR_BASE, hb_vm_guest_register->ldtr_base_addr);
	hb_print_vm_result("    [*] LDTR Base", result);
	result = hb_write_vmcs(VM_GUEST_TR_BASE, hb_vm_guest_register->tr_base_addr);
	hb_print_vm_result("    [*] TR Base", result);

	result = hb_write_vmcs(VM_GUEST_CS_LIMIT, hb_vm_guest_register->cs_limit);
	hb_print_vm_result("    [*] CS Limit", result);
	result = hb_write_vmcs(VM_GUEST_SS_LIMIT, hb_vm_guest_register->ss_limit);
	hb_print_vm_result("    [*] SS Limit", result);
	result = hb_write_vmcs(VM_GUEST_DS_LIMIT, hb_vm_guest_register->ds_limit);
	hb_print_vm_result("    [*] DS Limit", result);
	result = hb_write_vmcs(VM_GUEST_ES_LIMIT, hb_vm_guest_register->es_limit);
	hb_print_vm_result("    [*] ES Limit", result);
	result = hb_write_vmcs(VM_GUEST_FS_LIMIT, hb_vm_guest_register->fs_limit);
	hb_print_vm_result("    [*] FS Limit", result);
	result = hb_write_vmcs(VM_GUEST_GS_LIMIT, hb_vm_guest_register->gs_limit);
	hb_print_vm_result("    [*] GS Limit", result);
	result = hb_write_vmcs(VM_GUEST_LDTR_LIMIT, hb_vm_guest_register->ldtr_limit);
	hb_print_vm_result("    [*] LDTR Limit", result);
	result = hb_write_vmcs(VM_GUEST_TR_LIMIT, hb_vm_guest_register->tr_limit);
	hb_print_vm_result("    [*] TR Limit", result);

	result = hb_write_vmcs(VM_GUEST_CS_ACC_RIGHT, hb_vm_guest_register->cs_access);
	hb_print_vm_result("    [*] CS Access", result);
	result = hb_write_vmcs(VM_GUEST_SS_ACC_RIGHT, hb_vm_guest_register->ss_access);
	hb_print_vm_result("    [*] SS Access", result);
	result = hb_write_vmcs(VM_GUEST_DS_ACC_RIGHT, hb_vm_guest_register->ds_access);
	hb_print_vm_result("    [*] DS Access", result);
	result = hb_write_vmcs(VM_GUEST_ES_ACC_RIGHT, hb_vm_guest_register->es_access);
	hb_print_vm_result("    [*] ES Access", result);
	result = hb_write_vmcs(VM_GUEST_FS_ACC_RIGHT, hb_vm_guest_register->fs_access);
	hb_print_vm_result("    [*] FS Access", result);
	result = hb_write_vmcs(VM_GUEST_GS_ACC_RIGHT, hb_vm_guest_register->gs_access);
	hb_print_vm_result("    [*] GS Access", result);
	result = hb_write_vmcs(VM_GUEST_LDTR_ACC_RIGHT, hb_vm_guest_register->ldtr_access);
	hb_print_vm_result("    [*] LDTR Access", result);
	result = hb_write_vmcs(VM_GUEST_TR_ACC_RIGHT, hb_vm_guest_register->tr_access);
	hb_print_vm_result("    [*] TR Access", result);

	result = hb_write_vmcs(VM_GUEST_GDTR_BASE, hb_vm_guest_register->gdtr_base_addr);
	hb_print_vm_result("    [*] GDTR Base", result);
	result = hb_write_vmcs(VM_GUEST_IDTR_BASE, hb_vm_guest_register->idtr_base_addr);
	hb_print_vm_result("    [*] IDTR Base", result);
	result = hb_write_vmcs(VM_GUEST_GDTR_LIMIT, hb_vm_guest_register->gdtr_limit);
	hb_print_vm_result("    [*] GDTR Base", result);
	result = hb_write_vmcs(VM_GUEST_IDTR_LIMIT, hb_vm_guest_register->idtr_limit);
	hb_print_vm_result("    [*] IDTR Base", result);

	result = hb_write_vmcs(VM_GUEST_DEBUGCTL, hb_vm_guest_register->ia32_debug_ctrl);
	hb_print_vm_result("    [*] DEBUG CONTROL", result);
	result = hb_write_vmcs(VM_GUEST_IA32_SYSENTER_CS,
		hb_vm_guest_register->ia32_sys_enter_cs);
	hb_print_vm_result("    [*] SYSENTER_CS Base", result);
	result = hb_write_vmcs(VM_GUEST_IA32_SYSENTER_ESP,
		hb_vm_guest_register->ia32_sys_enter_esp);
	hb_print_vm_result("    [*] SYSENTER_ESP", result);
	result = hb_write_vmcs(VM_GUEST_IA32_SYSENTER_EIP,
		hb_vm_guest_register->ia32_sys_enter_eip);
	hb_print_vm_result("    [*] SYSENTER_EIP", result);
	result = hb_write_vmcs(VM_GUEST_PERF_GLOBAL_CTRL,
		hb_vm_guest_register->ia32_perf_global_ctrl);
	hb_print_vm_result("    [*] Perf Global Ctrl", result);
	result = hb_write_vmcs(VM_GUEST_PAT, hb_vm_guest_register->ia32_pat);
	hb_print_vm_result("    [*] PAT", result);
	result = hb_write_vmcs(VM_GUEST_EFER, hb_vm_guest_register->ia32_efer);
	hb_print_vm_result("    [*] EFER", result);

	result = hb_write_vmcs(VM_VMCS_LINK_PTR, hb_vm_guest_register->vmcs_link_ptr);
	hb_print_vm_result("    [*] VMCS Link ptr", result);

	result = hb_write_vmcs(VM_GUEST_INT_STATE, 0);
	hb_print_vm_result("    [*] Guest Int State", result);

	result = hb_write_vmcs(VM_GUEST_ACTIVITY_STATE, 0);
	hb_print_vm_result("    [*] Guest Activity State", result);

	result = hb_write_vmcs(VM_GUEST_SMBASE, 0);
	hb_print_vm_result("    [*] Guest SMBase", result);

	result = hb_write_vmcs(VM_GUEST_PENDING_DBG_EXCEPTS, 0);
	hb_print_vm_result("    [*] Pending DBG Excepts", result);

	value = hb_calc_vm_pre_timer_value();
	result = hb_write_vmcs(VM_GUEST_VMX_PRE_TIMER_VALUE, value);
	hb_print_vm_result("    [*] VM Preemption Timer", result);

	/* Setup VM control information. */
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Set VM Control Register\n");

#if HYPERBOX_USE_VPID
	if (g_support_vpid == 1)
	{
		/* To avoid conflicts with KVM, set the ID to the last one. */
		result = hb_write_vmcs(VM_CTRL_VIRTUAL_PROCESS_ID, 0xFFFF);
		hb_print_vm_result("    [*] VIRTUAL_PROCESS_ID", result);
	}
#endif
	result = hb_write_vmcs(VM_CTRL_PIN_BASED_VM_EXE_CTRL,
		hb_vm_control_register->pin_based_ctrl);
	hb_print_vm_result("    [*] PIN Based Ctrl", result);

	result = hb_write_vmcs(VM_CTRL_PRI_PROC_BASED_EXE_CTRL,
		hb_vm_control_register->pri_proc_based_ctrl);
	hb_print_vm_result("    [*] Primary Process Based Ctrl", result);

	result = hb_write_vmcs(VM_CTRL_SEC_PROC_BASED_EXE_CTRL,
		hb_vm_control_register->sec_proc_based_ctrl);
	hb_print_vm_result("    [*] Secondary Process Based Ctrl", result);

	result = hb_write_vmcs(VM_CTRL_EXCEPTION_BITMAP,
		hb_vm_control_register->except_bitmap);
	hb_print_vm_result("    [*] Exception Bitmap", result);

	result = hb_write_vmcs(VM_CTRL_IO_BITMAP_A_ADDR,
		hb_vm_control_register->io_bitmap_addrA);
	hb_print_vm_result("    [*] IO Bitmap A", result);

	result = hb_write_vmcs(VM_CTRL_IO_BITMAP_B_ADDR,
		hb_vm_control_register->io_bitmap_addrB);
	hb_print_vm_result("    [*] IO Bitmap B", result);

	result = hb_write_vmcs(VM_CTRL_EPT_PTR, hb_vm_control_register->ept_ptr);
	hb_print_vm_result("    [*] EPT Ptr", result);

	result = hb_write_vmcs(VM_CTRL_MSR_BITMAPS,
		hb_vm_control_register->msr_bitmap_addr);
	hb_print_vm_result("    [*] MSR Bitmap", result);

	result = hb_write_vmcs(VM_CTRL_VMREAD_BITMAP_ADDR,
		hb_vm_control_register->vmread_bitmap_addr);
	hb_print_vm_result("    [*] VMREAD Bitmap", result);

	result = hb_write_vmcs(VM_CTRL_VMWRITE_BITMAP_ADDR,
		hb_vm_control_register->vmwrite_bitmap_addr);
	hb_print_vm_result("    [*] VMWRITE Bitmap", result);

	result = hb_write_vmcs(VM_CTRL_VM_ENTRY_CTRLS,
		hb_vm_control_register->vm_entry_ctrl_field);
	hb_print_vm_result("    [*] VM Entry Control", result);

	result = hb_write_vmcs(VM_CTRL_VM_EXIT_CTRLS,
		hb_vm_control_register->vm_exti_ctrl_field);
	hb_print_vm_result("    [*] VM Exit Control", result);

	result = hb_write_vmcs(VM_CTRL_VIRTUAL_APIC_ADDR,
		hb_vm_control_register->virt_apic_page_addr);
	hb_print_vm_result("    [*] Virtual APIC Page", result);

	result = hb_write_vmcs(VM_CTRL_CR0_GUEST_HOST_MASK, 
		hb_vm_control_register->cr0_guest_host_mask);
	hb_print_vm_result("    [*] CR0 Guest Host Mask", result);

	result = hb_write_vmcs(VM_CTRL_CR4_GUEST_HOST_MASK,
		hb_vm_control_register->cr4_guest_host_mask);
	hb_print_vm_result("    [*] CR4 Guest Host Mask", result);

	result = hb_write_vmcs(VM_CTRL_CR0_READ_SHADOW, 
		hb_vm_control_register->cr0_read_shadow);
	hb_print_vm_result("    [*] CR0 Read Shadow", result);

	result = hb_write_vmcs(VM_CTRL_CR4_READ_SHADOW,
		hb_vm_control_register->cr4_read_shadow);
	hb_print_vm_result("    [*] CR4 Read Shadow", result);

	result = hb_write_vmcs(VM_CTRL_CR3_TARGET_VALUE_0, 0);
	hb_print_vm_result("    [*] CR3 Target Value 0", result);

	result = hb_write_vmcs(VM_CTRL_CR3_TARGET_VALUE_1, 0);
	hb_print_vm_result("    [*] CR3 Target Value 1", result);

	result = hb_write_vmcs(VM_CTRL_CR3_TARGET_VALUE_2, 0);
	hb_print_vm_result("    [*] CR3 Target Value 2", result);
	result = hb_write_vmcs(VM_CTRL_CR3_TARGET_VALUE_3, 0);
	hb_print_vm_result("    [*] CR3 Target Value 3", result);

	result = hb_write_vmcs(VM_CTRL_PAGE_FAULT_ERR_CODE_MASK, 0);
	hb_print_vm_result("    [*] Page Fault Error Code Mask", result)
		;
	result = hb_write_vmcs(VM_CTRL_PAGE_FAULT_ERR_CODE_MATCH, 0);
	hb_print_vm_result("    [*] Page Fault Error Code Match", result);

	result = hb_write_vmcs(VM_CTRL_CR3_TARGET_COUNT, 0);
	hb_print_vm_result("    [*] CR3 Target Count", result);

	result = hb_write_vmcs(VM_CTRL_VM_EXIT_MSR_STORE_COUNT, 0);
	hb_print_vm_result("    [*] MSR Store Count", result);

	result = hb_write_vmcs(VM_CTRL_VM_EXIT_MSR_LOAD_COUNT, 0);
	hb_print_vm_result("    [*] MSR Load Count", result);

	result = hb_write_vmcs(VM_CTRL_VM_EXIT_MSR_LOAD_ADDR, 0);
	hb_print_vm_result("    [*] MSR Load Addr", result);

	result = hb_write_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, 0);
	hb_print_vm_result("    [*] VM Entry Int Info Field", result);

	result = hb_write_vmcs(VM_CTRL_VM_ENTRY_EXCEPT_ERR_CODE, 0);
	hb_print_vm_result("    [*] VM Entry Except Err Code", result);

	result = hb_write_vmcs(VM_CTRL_VM_ENTRY_INST_LENGTH, 0);
	hb_print_vm_result("    [*] VM Entry Inst Length", result);

	result = hb_write_vmcs(VM_CTRL_VM_ENTRY_MSR_LOAD_COUNT, 0);
	hb_print_vm_result("    [*] VM Entry MSR Load Count", result);

	result = hb_write_vmcs(VM_CTRL_VM_ENTRY_MSR_LOAD_ADDR, 0);
	hb_print_vm_result("    [*] VM Entry MSR Load Addr", result);

	result = hb_write_vmcs(VM_CTRL_TPR_THRESHOLD, 0);
	hb_print_vm_result("    [*] TPR Threashold", result);

	result = hb_write_vmcs(VM_CTRL_EXECUTIVE_VMCS_PTR, 0);
	hb_print_vm_result("    [*] Executive VMCS Ptr", result);

	result = hb_write_vmcs(VM_CTRL_TSC_OFFSET, 0);
	hb_print_vm_result("    [*] TSC Offset", result);
}

/*
 * Print message with result.
 */
static void hb_print_vm_result(const char* string, int result)
{
	return ;
	if (result == 1)
	{
		hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "%s Success\n", string);
	}
	else
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "%s Fail\n", string);
	}
}

/*
 * Dump the host register information.
 */
static void hb_dump_vm_host_register(struct hb_vm_host_register* host_register)
{
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Dump Host Registers\n");
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR0 %016lX\n", host_register->cr0);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR3 %016lX\n", host_register->cr3);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR4 %016lX\n", host_register->cr4);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RSP %016lX\n", host_register->rsp);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RIP %016lX\n", host_register->rip);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Selector %08X\n",
		host_register->cs_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Selector %08X\n",
		host_register->ss_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Selector %08X\n",
		host_register->ds_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Selector %08X\n",
		host_register->es_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Selector %08X\n",
		host_register->fs_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Selector %08X\n",
		host_register->gs_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Selector %08X\n",
		host_register->tr_selector);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Base     %016lX\n",
		host_register->fs_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Base     %016lX\n",
		host_register->gs_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Base     %016lX\n",
		host_register->tr_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GDTR Base   %016lX\n",
		host_register->gdtr_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IDTR Base   %016lX\n",
		host_register->idtr_base_addr);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER CS  %016lX\n",
		host_register->ia32_sys_enter_cs);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER ESP %016lX\n",
		host_register->ia32_sys_enter_esp);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER EIP %016lX\n",
		host_register->ia32_sys_enter_eip);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 Perf Global Ctrl %016lX\n",
		host_register->ia32_perf_global_ctrl);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 PAT              %016lX\n",
		host_register->ia32_pat);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 IA32 EFER        %016lX\n",
		host_register->ia32_efer);
}

/*
 * Dump the guest register information.
 */
static void hb_dump_vm_guest_register(struct hb_vm_guest_register* guest_register)
{
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Dump Guest Registers\n");
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR0 %016lX\n", guest_register->cr0);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR3 %016lX\n", guest_register->cr3);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR4 %016lX\n", guest_register->cr4);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DR7 %016lX\n", guest_register->dr7);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RSP %016lX\n", guest_register->rsp);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RIP %016lX\n", guest_register->rip);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RFLAGS %016lX\n", guest_register->rflags);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Selector %08X\n",
		(u32)guest_register->cs_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Selector %08X\n",
		(u32)guest_register->ss_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Selector %08X\n",
		(u32)guest_register->ds_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Selector %08X\n",
		(u32)guest_register->es_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Selector %08X\n",
		(u32)guest_register->fs_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Selector %08X\n",
		(u32)guest_register->gs_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] LDTR Selector %08X\n",
		(u32)guest_register->ldtr_selector);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Selector %08X\n",
		(u32)guest_register->tr_selector);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Base     %016lX\n",
		guest_register->cs_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Base     %016lX\n",
		guest_register->ss_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Base     %016lX\n",
		guest_register->ds_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Base     %016lX\n",
		guest_register->es_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Base     %016lX\n",
		guest_register->fs_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Base     %016lX\n",
		guest_register->gs_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] LDTR Base   %016lX\n",
		guest_register->ldtr_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Base     %016lX\n",
		guest_register->tr_base_addr);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Limit    %08X\n",
		(u32)guest_register->cs_limit);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Limit    %08X\n",
		(u32)guest_register->ss_limit);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Limit    %08X\n",
		(u32)guest_register->ds_limit);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Limit    %08X\n",
		(u32)guest_register->es_limit);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Limit    %08X\n",
		(u32)guest_register->fs_limit);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Limit    %08X\n",
		(u32)guest_register->gs_limit);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] LDTR Limit  %08X\n",
		(u32)guest_register->ldtr_limit);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Limit    %08X\n",
		(u32)guest_register->tr_limit);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Access   %08X\n",
		(u32)guest_register->cs_access);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Access   %08X\n",
		(u32)guest_register->ss_access);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Access   %08X\n",
		(u32)guest_register->ds_access);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Access   %08X\n",
		(u32)guest_register->es_access);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Access   %08X\n",
		(u32)guest_register->fs_access);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Access   %08X\n",
		(u32)guest_register->gs_access);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] LDTR Access %08X\n",
		(u32)guest_register->ldtr_access);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Access   %08X\n",
		(u32)guest_register->tr_access);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GDTR Base   %016lX\n",
		guest_register->gdtr_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IDTR Base   %016lX\n",
		guest_register->idtr_base_addr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GDTR Limit  %08X\n",
		(u32)guest_register->gdtr_limit);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IDTR Limit  %08X\n",
		(u32)guest_register->idtr_limit);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 DEBUG CTRL   %016lX\n",
		guest_register->ia32_debug_ctrl);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER CS  %016lX\n",
		guest_register->ia32_sys_enter_cs);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER ESP %016lX\n",
		guest_register->ia32_sys_enter_esp);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER EIP %016lX\n",
		guest_register->ia32_sys_enter_eip);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VMCS Link Ptr     %016lX\n",
		guest_register->vmcs_link_ptr);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 Perf Global Ctrl %016lX\n",
		guest_register->ia32_perf_global_ctrl);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 PAT              %016lX\n",
		guest_register->ia32_pat);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 IA32 EFER        %016lX\n",
		guest_register->ia32_efer);
}

/*
 * Dump VM control register information.
 */
static void hb_dump_vm_control_register(struct hb_vm_control_register* control_register)
{
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Dump Control Register\n");
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Pin Based Ctrl %016lX\n", control_register->pin_based_ctrl);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Primary Process Based Ctrl %016lX\n", control_register->pri_proc_based_ctrl);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Secondary Process Based Ctrl %016lX\n", control_register->sec_proc_based_ctrl);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM Entry Ctrl %016lX\n", control_register->vm_entry_ctrl_field);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM Exit Ctrl %016lX\n", control_register->vm_exti_ctrl_field);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Exception Bitmap %016lX\n", control_register->except_bitmap);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IO Bitmap AddrA %016lX\n", control_register->io_bitmap_addrA);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IO Bitmap AddrB %016lX\n", control_register->io_bitmap_addrB);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] EPT Pointer %016lX\n", control_register->ept_ptr);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] MSRBitmap %016lX\n", control_register->msr_bitmap_addr);
}


/*
 * Get base address of the descriptor.
 */
static u64 hb_get_desc_base(u64 offset)
{
	struct desc_ptr gdtr;
	struct desc_struct* gdt;
	u64 qwTotalBase = 0;
	u64 base0 = 0;
	u64 base1 = 0;
	u64 base2 = 0;

	if (offset == 0)
	{
		return 0;
	}

	native_store_gdt(&gdtr);
	gdt = (struct desc_struct*)(gdtr.address + (offset & ~MASK_GDT_ACCESS));

	base0 = gdt->base0;
	base1 = gdt->base1;
	base2 = gdt->base2;

	qwTotalBase = base0 | (base1 << 16) | (base2 << 24);
	return qwTotalBase;
}

/*
 * Get access type of the descriptor.
 */
static u64 hb_get_desc_access(u64 offset)
{
	struct desc_ptr gdtr;
	struct desc_struct* gdt;
	u64 total_access = 0;
	u64 access = 0;

	if (offset == 0)
	{
		/* Return unused value. */
		return 0x10000;
	}

	native_store_gdt(&gdtr);
	gdt = (struct desc_struct*)(gdtr.address + (offset & ~MASK_GDT_ACCESS));
	access = *((u32*)gdt + 1) >> 8;

	/* type: 4, s: 1, dpl: 2, p: 1; limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8 */
	total_access = access & 0xF0FF;
	return total_access;
}

/*
 * Add read-only area (static kernel objects) information with the type.
 */
void hb_add_ro_area(u64 start, u64 end, u64 ro_type)
{
	int cpu_id;
	int i;

	cpu_id = smp_processor_id();

	if (g_ro_array_count >= MAX_RO_ARRAY_COUNT)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] RO array count is over\n", cpu_id);
		return ;
	}

	/* Find empty space. */
	for (i = 0 ; i < g_ro_array_count ; i++)
	{
		if ((g_ro_array[i].start == 0) && (g_ro_array[i].end == 0))
		{
			break;
		}
	}

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] RO array index [%d] "
		"ro_array_count [%d] start[%016lX] end[%016lX] is added\n",
		cpu_id, i, g_ro_array_count, start, end);

	g_ro_array[i].start = start;
	g_ro_array[i].end = end;
	g_ro_array[i].type = ro_type;

	/* No empty slot, then increase g_ro_array_count. */
	if (i == g_ro_array_count)
	{
		g_ro_array_count++;
	}
}

/*
 * Delete read-only area (static kernel objects) information with the type.
 */
int hb_delete_ro_area(u64 start, u64 end)
{
	int i;

	for (i = 0 ; i < g_ro_array_count ; i++)
	{
		if ((g_ro_array[i].start == start) && (g_ro_array[i].end == end))
		{
			g_ro_array[i].start = 0;
			g_ro_array[i].end = 0;

			return 0;
		}
	}

	return -1;
}

/*
 * Check if the address is in read-only area.
 */
int hb_is_addr_in_ro_area(void* addr)
{
	int i;

	/* Allow NULL pointer. */
	if (addr == NULL)
	{
		return 1;
	}

	for (i = 0 ; i < g_ro_array_count ; i++)
	{
		if ((g_ro_array[i].start <= (u64)addr) &&
			((u64)addr < (g_ro_array[i].end)))
		{
			hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "%p is in core area\n", addr);
			return 1;
		}
	}

	return 0;
}

/*
 * Check if the address is in kernel read-only area.
 */
int hb_is_addr_in_kernel_ro_area(void* addr)
{
	int i;

	/* Allow NULL pointer. */
	if (addr == NULL)
	{
		return 1;
	}

	for (i = 0 ; i < g_ro_array_count ; i++)
	{
		if ((g_ro_array[i].start <= (u64)addr) &&
			((u64)addr < (g_ro_array[i].end)) &&
			(g_ro_array[i].type == RO_KERNEL))
		{
			hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "%p is in core area\n", addr);
			return 1;
		}

		if (g_ro_array[i].type == RO_MODULE)
		{
			break;
		}
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static struct kprobe g_kp_for_addr, g_kp_for_trigger;

static int kprobe_handler_pre_for_addr(struct kprobe *p, struct pt_regs *regs)
{
	g_kallsyms_lookup_name_fp = (kallsyms_lookup_name_t) (regs->ip - 1);

	return 0;
}

static int kprobe_handler_pre_for_trigger(struct kprobe *p, struct pt_regs *regs)
{
	/* Do nothing. */
	return 0;
}

/*
 *	Get kallsyms_lookup_name pointer.
 */
static int hb_get_kallsyms_lookup_name_ptr(void)
{
	int ret;

	g_kp_for_addr.symbol_name = "kallsyms_lookup_name";
	g_kp_for_addr.pre_handler = kprobe_handler_pre_for_addr;

	ret = register_kprobe(&g_kp_for_addr);
	if (ret < 0)
	{
		return ret;
	}

	g_kp_for_trigger.symbol_name = "kallsyms_lookup_name";
	g_kp_for_trigger.pre_handler = kprobe_handler_pre_for_trigger;

	ret = register_kprobe(&g_kp_for_trigger);
	if (ret < 0)
	{
		unregister_kprobe(&g_kp_for_addr);
		return ret;
	}

	unregister_kprobe(&g_kp_for_addr);
	unregister_kprobe(&g_kp_for_trigger);

	return ret;
}

#endif

/*
 * Get function pointers for periodic check.
 */
static int hb_get_function_pointers(void)
{
	int ret = 0;

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Get function pointers\n");

	/* Since kernel version 5.7.0, kallsyms_lookup_name() is not exported. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	ret = hb_get_kallsyms_lookup_name_ptr();
	if (ret != 0)
	{
		return ret;
	}
#else
	g_kallsyms_lookup_name_fp = kallsyms_lookup_name;
#endif

	g_watchdog_nmi_disable_fp = (watchdog_nmi_disable_t) hb_get_symbol_address("watchdog_nmi_disable");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	g_flush_tlb_one_kernel_fp  = (flush_tlb_one_kernel_t) hb_get_symbol_address("flush_tlb_one_kernel");
#endif

	g_modules_ptr = (struct list_head*)hb_get_symbol_address("modules");

	g_root_file_ptr = filp_open("/", O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(g_root_file_ptr))
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "/ Open VFS Object Fail\n");
	}

	g_proc_file_ptr = filp_open("/proc", O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(g_proc_file_ptr))
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "/proc Open VFS Object Fail\n");
	}

	g_tcp_file_ptr = filp_open("/proc/net/tcp", O_RDONLY, 0);
	if (IS_ERR(g_tcp_file_ptr))
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "/proc/net/tcp Open VFS Object Fail\n");
	}

	g_udp_file_ptr = filp_open("/proc/net/udp", O_RDONLY, 0);
	if (IS_ERR(g_udp_file_ptr))
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "/proc/net/udp Open VFS Object Fail\n");
	}

	g_tcp6_file_ptr = filp_open("/proc/net/tcp6", O_RDONLY, 0);
	if (IS_ERR(g_tcp6_file_ptr))
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "/proc/net/tcp6 Open VFS Object Fail\n");
	}

	g_udp6_file_ptr = filp_open("/proc/net/udp6", O_RDONLY, 0);
	if (IS_ERR(g_udp6_file_ptr))
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "/proc/net/udp6 Open VFS Object Fail\n");
	}

	if (sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &g_udp_sock) < 0)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "UDP Socket Object Open Fail\n");
	}

	if (sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &g_tcp_sock) < 0)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "TCP Socket Object Open Fail\n");
	}

	return ret;
}

module_init(hyper_box_init);
module_exit(hyper_box_exit);

MODULE_AUTHOR("Seunghun Han");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hyper-box of Alcatraz: A Practical Hypervisor Sandbox to Prevent Escapes.");
