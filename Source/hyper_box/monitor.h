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
#ifndef __MONITOR_H__
#define __MONITOR_H__

#include "hyper_box.h"

/*
 * Macros.
 */
/*
 * Max count of tasks and modules.
 * If your system has more than 100000 tasks or 10000 modules, change these
 * values.
 */
#define TASK_NODE_MAX				(PID_MAX_LIMIT)
#define MODULE_NODE_MAX				(10000)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
#define GET_D_INODE_FROM_FILE_PTR(x)		((x)->f_dentry->d_inode)
#else
#define GET_D_INODE_FROM_FILE_PTR(x)		((x)->f_path.dentry->d_inode)
#endif

struct hb_common_node
{
	struct rb_node node;
	u64 key;
};

/* Task information structure. */
struct hb_task_node
{
	struct rb_node node;
	struct task_struct* task;
	struct list_head list;
	pid_t pid;
	pid_t tgid;
	char comm[TASK_COMM_LEN];
	struct cred cred;
	int syscall_number;
	int need_exit;
	int need_trace;
	int seccomp_mode;
	struct mm_struct* mm;
};

/* Module information structure. */
struct hb_module_node
{
	struct rb_node node;
	struct module* module;
	struct list_head list;
	int protect;
	u64 base;
	u64 size;
	char name[MODULE_NAME_LEN];
};

/* Task manager structure. */
struct hb_task_manager
{
	struct list_head free_node_head;
	struct rb_root existing_node_head;
	struct hb_task_node* pool;
};

/* Module manager structure. */
struct hb_module_manager
{
	struct list_head free_node_head;
	struct rb_root existing_node_head;
	struct hb_module_node* pool;
};

/*
 * Functions.
 */
int hb_prepare_monitor(void);
void hb_init_monitor(int reinitialize);
void hb_callback_vm_timer(int cpu_id);
void hb_callback_taskitch(int cpu_id);
void hb_callback_add_task(int cpu_id, struct hb_vm_exit_guest_register* context);
void hb_callback_del_task(int cpu_id, struct hb_vm_exit_guest_register* context);

void hb_callback_update_cred(int cpu_id, struct task_struct* task, struct cred* new);
int hb_callback_check_cred_update_syscall(int cpu_id, struct task_struct* task,
	int syscall_number);
void hb_check_task_info(void);
void hb_protect_monitor_data(void);

#endif /* __MONITOR_H__ */
