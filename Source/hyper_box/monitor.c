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
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <asm/spinlock.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include <asm/invpcid.h>
#include <linux/rbtree.h>
#include "hyper_box.h"
#include "monitor.h"
#include "mmu.h"
#include "asm_helper.h"
#include "workaround.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#endif

/*
 * Variables.
 */
volatile int g_module_count = 0;
volatile int g_task_count = 0;
volatile u64 g_last_task_check_jiffies = 0;
volatile u64 g_last_dkom_check_jiffies = 0;

static struct hb_task_manager g_task_manager;
static spinlock_t g_task_manager_lock;
static spinlock_t g_time_lock;
static volatile u64 g_modulelock_fail_count = 0;
static int g_vfs_object_attack_detected = 0;
static int g_net_object_attack_detected = 0;

#if HYPERBOX_USE_TERMINATE_MALICIOUS_PROCESS

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
typedef int (*hb_do_send_sig_info)(int sig, struct kernel_siginfo *info,
    struct task_struct *p, enum pid_type type);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
typedef int (*hb_do_send_sig_info)(int sig, struct siginfo *info,
	struct task_struct *p, enum pid_type type);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) */
typedef int (*hb_do_send_sig_info)(int sig, struct siginfo *info,
	struct task_struct *p, bool group);
#define PIDTYPE_TGID		true
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) */

static hb_do_send_sig_info g_do_send_sig_info_fp;
#endif /* HYPERBOX_USE_TERMINATE_MALICIOUS_PROCESS */

#define SPAWNING_DISABLED_PROCESS_MAX		1
static char* g_hb_spawning_disabled_process[SPAWNING_DISABLED_PROCESS_MAX] =
{
	"qemu-system-x86_64",
};

/* modprobe (/usr/bin/kmod) is called by some drivers. */
#define WORKAROUND_PROCESS_MAX				1
struct workaround_process_path_struct
{
	char* comm;
	char* path;
};

static struct workaround_process_path_struct g_hb_workaround_process_path[WORKAROUND_PROCESS_MAX] =
{
	{ "modprobe", "/usr/bin/kmod"},
};

/*
 * Functions.
 */
static struct hb_task_node* hb_add_task_to_task_manager(struct task_struct* task);
static int hb_del_task_from_task_manager(struct task_struct* task);
static void hb_check_task_periodic(int cpu_id);
static int hb_check_vfs_object(int cpu_id);
static int hb_check_net_object(int cpu_id);
static int hb_check_inode_op_fields(int cpu_id, const struct inode_operations* op,
	const char* obj_name);
static int hb_check_file_op_fields(int cpu_id, const struct file_operations* op,
	const char* obj_name);
static int hb_check_net_seq_afinfo_fields(int cpu_id, const struct file_operations* fops,
	const struct seq_operations* sops, const char* obj_name);
static int hb_check_proto_op_fields(int cpu_id, const struct proto_ops* op,
	const char* obj_name);
static int hb_check_task_list(int cpu_id);
static int hb_is_in_task_list(struct task_struct* task);
static int hb_get_task_count(void);
static int hb_is_valid_vm_status(int cpu_id);

static int hb_check_systemcall_for_cred(int syscall_number);
static void hb_set_exit_flag_in_list_with_lock(int tgid);

static void hb_reset_task_manager(void);
static void hb_copy_task_list_to_task_manager(void);

/* Lock task manager. */
inline __attribute__((always_inline))
static void hb_task_manager_lock(void)
{
	while (!spin_trylock(&g_task_manager_lock))
	{
		;
	}
}

/* Unlock task manager. */
inline __attribute__((always_inline))
static void hb_task_manager_unlock(void)
{
	spin_unlock(&g_task_manager_lock);
}


static void hb_add_tree(struct rb_root* root, struct hb_common_node* node)
{
  	struct rb_node** new = &(root->rb_node);
	struct rb_node* parent = NULL;
	struct hb_common_node* cur;

	/* Find position (new). */
  	while (*new)
	{
  		cur = rb_entry(*new, struct hb_common_node, node);
		parent = *new;
  		if (node->key < cur->key) {
  			new = &((*new)->rb_left);
		}
  		else if (node->key > cur->key)
		{
  			new = &((*new)->rb_right);
		}
  		else
		{
			return ;
		}
  	}

	/* Add new node and rebalance. */
  	rb_link_node(&node->node, parent, new);
  	rb_insert_color(&node->node, root);
}

static struct hb_common_node* hb_search_tree(struct rb_root* root, u64 key)
{
  	struct rb_node* node = root->rb_node;
	struct hb_common_node* cur;

  	while (node)
	{
  		cur = rb_entry(node, struct hb_common_node, node);

		if (key < cur->key)
  			node = node->rb_left;
		else if (key > cur->key)
  			node = node->rb_right;
		else
  			return cur;
	}

	hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "%s returns NULL\n", __FUNCTION__);

	return NULL;
}

static void hb_del_tree(struct rb_root* root, struct hb_common_node* node)
{
	if (node != NULL)
	{
		rb_erase(&node->node, root);
	}
}

/*
 * Prepare Monitor.
 */
int hb_prepare_monitor(void)
{
	int i;
	int size;

	memset(&g_task_manager, 0, sizeof(g_task_manager));

	INIT_LIST_HEAD(&(g_task_manager.free_node_head));
	g_task_manager.existing_node_head = RB_ROOT;

	size = sizeof(struct hb_task_node) * TASK_NODE_MAX;
	g_task_manager.pool = vmalloc(size);
	if (g_task_manager.pool == NULL)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] Task pool allcation fail\n");
		return -1;
	}
	memset(g_task_manager.pool, 0, size);

	for (i = 0 ; i < TASK_NODE_MAX ; i++)
	{
		list_add(&(g_task_manager.pool[i].list), &(g_task_manager.free_node_head));
	}

#if HYPERBOX_USE_TERMINATE_MALICIOUS_PROCESS
	g_do_send_sig_info_fp = (hb_do_send_sig_info)hb_get_symbol_address("do_send_sig_info");
#endif /* HYPERBOX_USE_TERMINATE_MALICIOUS_PROCESS */

	return 0;
}

/*
 * Hiding the monitor data from the guest.
 */
void hb_protect_monitor_data(void)
{
	u64 size;

	size = sizeof(struct hb_task_node) * TASK_NODE_MAX;
	hb_hide_range((u64)g_task_manager.pool, (u64)g_task_manager.pool + size,
		ALLOC_VMALLOC);
}

/*
 * Initialize Monitor.
 */
void hb_init_monitor(int reinitialize)
{
	spin_lock_init(&g_time_lock);
	spin_lock_init(&g_task_manager_lock);

	hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Monitor Initailize\n");

	if (reinitialize == 0)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] Check task list\n");
		hb_copy_task_list_to_task_manager();
	}
	else
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] Reset task list\n");
		hb_reset_task_manager();

		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] Check task list\n");
		hb_copy_task_list_to_task_manager();
	}

	hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Task count %d\n", g_task_count);
	hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Complete\n");
}

/*
 * Check a timer expired.
 *
 * If another core has already time lock, skip this time.
 */
static int hb_check_timer_expired_and_update(volatile u64* last_jiffies)
{
	int expired = 0;
	u64 value;

	/* For syncronization. */
	if (spin_trylock(&g_time_lock))
	{
		value = jiffies - *last_jiffies;

		if (jiffies_to_usecs(value) >= TIMER_INTERVAL)
		{
			*last_jiffies = jiffies;
			expired = 1;
		}

		spin_unlock(&g_time_lock);
	}
	else
	{
		/* Do nothing. */
	}

#if HYPERBOX_HARD_TEST
	expired = 1;
#endif /* HYPERBOX_HARD_TEST */

	return expired;
}

/*
 * Check task list periodically in VM timer.
 */
static void hb_check_task_periodic(int cpu_id)
{
	if (!hb_check_timer_expired_and_update(&g_last_task_check_jiffies))
	{
		return ;
	}

	if (write_trylock(g_tasklist_lock))
	{
		hb_check_task_list(cpu_id);
		write_unlock(g_tasklist_lock);
	}
	else
	{
		/* If lock operation is failed, try next immediately. */
		g_last_task_check_jiffies = 0;
	}

}

/*
 * Check function pointers periodically in VM timer.
 */
static void hb_check_function_pointers_periodic(int cpu_id)
{
	if (!hb_check_timer_expired_and_update(&g_last_dkom_check_jiffies))
	{
		return ;
	}

	/* If detected, no more check again. */
	if (g_vfs_object_attack_detected == 0)
	{
		if (hb_check_vfs_object(cpu_id) < 0)
		{
			g_vfs_object_attack_detected = 1;
		}
	}

	if (g_net_object_attack_detected == 0)
	{
		if (hb_check_net_object(cpu_id) < 0)
		{
			g_net_object_attack_detected = 1;
		}
	}
}

/*
 * Check if VM status is valid.
 *
 * Check VM status after Hyper-box is completely loaded.
 */
static int hb_is_valid_vm_status(int cpu_id)
{
	if (atomic_read(&g_need_init_in_secure) == 0)
	{
		return 1;
	}

	return 0;
}

/*
 * Process callback of VM timer.
 */
void hb_callback_vm_timer(int cpu_id)
{
	if (hb_is_valid_vm_status(cpu_id) == 1)
	{
		hb_check_task_periodic(cpu_id);
		hb_check_function_pointers_periodic(cpu_id);
	}
}

/*
 * Syncronize page table of the host with page table of the guest.
 */
void hb_sync_page(u64 addr, u64 size)
{
	u64 page_count;
	u64 i;

	page_count = ((addr % VAL_4KB) + size + VAL_4KB - 1) / VAL_4KB;

	for (i = 0 ; i < page_count ; i++)
	{
		hb_sync_page_table(addr + VAL_4KB * i, g_vm_init_phy_pml4, 0);
	}
}

/*
 * Process add task callback.
 */
void hb_callback_add_task(int cpu_id, struct hb_vm_exit_guest_register* context)
{
	struct task_struct* task;
	struct hb_task_node* found = NULL;
	struct hb_task_node* added_task = NULL;
	int i;
	char* comm;

	task = (struct task_struct*)context->rdi;

	/* Syncronize before introspection. */
	hb_sync_page((u64)task, sizeof(struct task_struct));

	hb_task_manager_lock();
	added_task = hb_add_task_to_task_manager(task);
	hb_task_manager_unlock();

	if (added_task == NULL)
	{
		goto EXIT;
	}

	hb_task_manager_lock();
	found = (struct hb_task_node*)hb_search_tree(&(g_task_manager.existing_node_head), (u64)current);
	hb_task_manager_unlock();

	if (found == NULL)
	{
		goto EXIT;
	}

	if ((found->syscall_number != __NR_fork) &&
		(found->syscall_number != __NR_vfork) &&
		(found->syscall_number != __NR_clone) &&
		(found->syscall_number != -1))
	{
		hb_set_exit_flag_in_list_with_lock(task->tgid);
		g_do_send_sig_info_fp(SIGKILL, SEND_SIG_PRIV, task, PIDTYPE_TGID);

		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] ======================= WARNING =======================", 
			cpu_id);
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] [%s][PID %d, TGID %d] creates task [%s][PID %d, TGID %d] in disallowed syscall[%d]. Terminate it.\n",
			cpu_id, current->comm, current->pid, current->tgid, task->comm, task->pid, task->tgid, found->syscall_number);
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] ======================= WARNING =======================",
			cpu_id);
	}
	else if (task->pid == task->tgid)
	{
		if (current->pid == current->tgid)
		{
			comm = current->comm;
		}
		else
		{	
			/* Check the leader of groups */
			if (current->group_leader!= NULL)
			{
				comm = current->group_leader->comm;
			}
			else
			{
				comm = current->comm;
			}
		}

		/* Check if spawning is not allowed. */
		for (i = 0 ; i < SPAWNING_DISABLED_PROCESS_MAX ; i++)
		{
			if (strncmp(comm, g_hb_spawning_disabled_process[i],
				TASK_COMM_LEN -1) == 0)
			{
				found->need_trace = 1;
				added_task->need_trace = 1;

				hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] [%s][PID %d, TGID %d] creates task [%s][PID %d, TGID %d]. Trace it.\n",
					cpu_id, current->comm, current->pid, current->tgid, task->comm, task->pid, task->tgid);

				break;
			}
		}
	}
EXIT:
	/* Do thing. */
	return ;
}

/*
 * Process delete task callback.
 *
 * Task is still alive when this function is called.
 */
void hb_callback_del_task(int cpu_id, struct hb_vm_exit_guest_register* context)
{
	struct task_struct* task;

	hb_task_manager_lock();
	task = (struct task_struct*)context->rdi;
	hb_del_task_from_task_manager(task);
	hb_task_manager_unlock();
}

/*
 * Check task list.
 */
static int hb_check_task_list(int cpu_id)
{
	struct rb_node *node;
	struct hb_task_node *target;
	int cur_count;

	cur_count = hb_get_task_count();

	if (g_task_count > cur_count)
	{
		for (node = rb_first(&(g_task_manager.existing_node_head)) ; node ; node = rb_next(node))
		{
			target = rb_entry(node, struct hb_task_node, node);
			if (hb_is_in_task_list(target->task))
			{
				continue;
			}

			hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Task count is different, expect=%d real=%d\n",
				cpu_id, g_task_count, cur_count);

			hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Error=%06d Hidden task, PID=%d TGID=%d fork name=\"%s\" process name=$(\"%s\")\n",
				cpu_id, ERROR_TASK_HIDDEN, target->pid, target->tgid, target->comm, target->task->comm);

#if HYPERBOX_USE_TERMINATE_MALICIOUS_PROCESS
			hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Terminate the process\n",
				cpu_id);

			/* Kill the hidden process. */
			g_do_send_sig_info_fp(SIGKILL, SEND_SIG_PRIV, target->task, PIDTYPE_TGID);
#endif /* HYPERBOX_USE_TERMINATE_MALICIOUS_PROCESS */

			hb_del_task_from_task_manager(target->task);
		}

		hb_error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}

	return 0;
}


/*
 * Process task switch callback.
 */
void hb_callback_task_switch(int cpu_id)
{
	hb_check_task_list(cpu_id);
}

/*
 * Mark all process which has same tgid with exit flag.
 */
static void hb_set_exit_flag_in_list_with_lock(int tgid)
{
	struct hb_task_node *target;
	struct rb_node *node;

	hb_task_manager_lock();
	for (node = rb_first(&(g_task_manager.existing_node_head)) ; node ; node = rb_next(node))
	{
		target = rb_entry(node, struct hb_task_node, node);
		if (target->tgid == tgid)
		{
			target->need_exit = 1;
		}
	}
	hb_task_manager_unlock();
}

/*
 * Check cred is same.
 */
inline __attribute__((always_inline))
static int hb_is_cred_same(struct cred* new, const struct cred* old)
{
	/* If all values are same, the XOR should be zero. */
	/*
	if ((old->uid.val != new->uid.val) ||
		(old->gid.val != new->gid.val) ||
		(old->suid.val != new->suid.val) ||
		(old->sgid.val != new->sgid.val) ||
		(old->euid.val != new->euid.val) ||
		(old->egid.val != new->egid.val) ||
		(old->fsuid.val != new->fsuid.val) ||
		(old->fsgid.val != new->fsgid.val))
	*/
	if(old->uid.val ^ new->uid.val ^ old->gid.val ^ new->gid.val ^
		old->suid.val ^ new->suid.val ^ old->sgid.val ^ new->sgid.val ^
		old->euid.val ^ new->euid.val ^ old->egid.val ^ new->egid.val ^
		old->fsuid.val ^ new->fsuid.val ^ old->fsgid.val ^ new->fsgid.val)

	{
		return -1;
	}

	return 0;
}

/*
 * Update cred callback.
 */
void hb_callback_update_cred(int cpu_id, struct task_struct* task, struct cred* new)
{
	struct hb_task_node *found = NULL;

	hb_task_manager_lock();
	found = (struct hb_task_node*)hb_search_tree(&(g_task_manager.existing_node_head),
		(u64)task);
	hb_task_manager_unlock();

	if (found == NULL)
	{
		goto EXIT;
	}

	/* Check valid system call. */
	if ((hb_check_systemcall_for_cred(found->syscall_number) != 0) &&
		(hb_is_cred_same(&(found->cred), new) != 0))
	{
		hb_set_exit_flag_in_list_with_lock(task->tgid);
		g_do_send_sig_info_fp(SIGKILL, SEND_SIG_PRIV, task, PIDTYPE_TGID);

		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] ======================= WARNING =======================",
			cpu_id);
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] [%s][PID %d, TGID %d]'s privilege is changed in disallowed syscall[%d]. Restore old cred and kill it.\n",
			cpu_id, current->comm, current->pid, current->tgid, found->syscall_number);
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] ======================= WARNING =======================",
			cpu_id);

		/* Recover previous uid and gid. */
		new->uid.val = found->cred.uid.val;
		new->gid.val = found->cred.gid.val;
		new->suid.val = found->cred.suid.val;
		new->sgid.val = found->cred.sgid.val;
		new->euid.val = found->cred.euid.val;
		new->egid.val = found->cred.egid.val;
		new->fsuid.val = found->cred.fsuid.val;
		new->fsgid.val = found->cred.fsgid.val;
	}
	else
	{
		/* Root process is executed after fork system call. */
		if ((found->syscall_number == __NR_execve) &&
			(new->uid.val < 1000))
		{
			memcpy(found->comm, current->comm, TASK_COMM_LEN);
		}

		memcpy(&(found->cred), new, sizeof(struct cred));
	}

EXIT:
	if (found == NULL)
	{
		hb_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] [%s] updates cred failed [PID %d] [TGID %d]\n",
			cpu_id, task->comm, task->pid, task->tgid);
	}
}

/*
 * Check system calls for updating cred.
 */
static int hb_check_systemcall_for_cred(int syscall_number)
{
	/* Check valid system call. */
	if (!((syscall_number == __NR_execve) || (syscall_number == __NR_setuid) ||
		(syscall_number == __NR_setgid) || (syscall_number == __NR_setreuid) ||
		(syscall_number == __NR_setregid) || (syscall_number == __NR_setresuid) ||
		(syscall_number == __NR_setresgid) || (syscall_number == __NR_setfsuid) ||
		(syscall_number == __NR_setfsgid) || (syscall_number == __NR_setgroups) ||
		(syscall_number == __NR_capset) || (syscall_number == __NR_prctl) ||
		(syscall_number == __NR_unshare) || (syscall_number == __NR_keyctl) ||
		(syscall_number == -1)))
	{
		return -1;
	}

	return 0;
}

/*
 * Path-related functions from Linux kernel.
 */
static int prepend(char **buffer, int *buflen, const char *str, int namelen)
{
	*buflen -= namelen;
	if (*buflen < 0)
		return -ENAMETOOLONG;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

/*
 * Path-related functions from Linux kernel.
 */
static int prepend_name(char **buffer, int *buflen, const struct qstr *name)
{
	const char *dname = smp_load_acquire(&name->name); /* ^^^ */
	u32 dlen = READ_ONCE(name->len);
	char *p;

	*buflen -= dlen + 1;
	if (*buflen < 0)
		return -ENAMETOOLONG;
	p = *buffer -= dlen + 1;
	*p++ = '/';
	while (dlen--) {
		char c = *dname++;
		if (!c)
			break;
		*p++ = c;
	}
	return 0;
}

/* 
 * Get the path of task directly.
 */
static char* hb_get_exe_path(struct task_struct* task, char* buffer, int size)
{
	struct dentry* dentry;
	char* end, *retval;
	int len = 0;
	int error = 0;

	dentry = task->mm->exe_file->f_path.dentry;
	end = buffer + size;
	len = size;
	prepend(&end, &len, "\0", 1);
	retval = end - 1;
	*retval = '/';

	while (!IS_ROOT(dentry))
	{
		struct dentry *parent = dentry->d_parent;
		
		prefetch(parent);
		error = prepend_name(&end, &len, &dentry->d_name);
		if (error)
		{
			break;
		}

		retval = end;
		dentry = parent;
	}

	return retval;
}

/*
 * Check cred callback.
 */
inline __attribute__((always_inline))
int hb_callback_check_cred_update_syscall(int cpu_id, struct task_struct* task,
	int syscall_number)
{
	struct hb_task_node *found = NULL;
	int ret = 0;
	char path_buffer[PATH_MAX] = {0, };
	char* path_name;
	int workaround = 0;
	int i;

	hb_task_manager_lock();
	found = (struct hb_task_node*)hb_search_tree(&(g_task_manager.existing_node_head),
		(u64)task);
	hb_task_manager_unlock();

	if (found == NULL)
	{
		goto EXIT;
	}

	/* Is the process execved before? */
	if ((found->syscall_number == __NR_execve) ||
		(found->syscall_number == __NR_execveat))
	{
		if (found->need_trace == 0)
		{
			found->mm = task->mm;
			strncpy(found->comm, task->comm, TASK_COMM_LEN);
		}
		else
		{
			hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] ======================= WARNING =======================",
				cpu_id);
			hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Traced process[%s][PID %d] called execve() for [%s]. Terminate it\n",
				cpu_id, found->comm, task->pid, task->comm);
			hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] ======================= WARNING =======================",
				cpu_id);
			hb_set_exit_flag_in_list_with_lock(found->tgid);
			ret = -1;
		}
	}
	/* Is the process created abnormally? */
	else if ((found->mm != task->mm) &&
		(found->syscall_number != __NR_execve) &&
		(found->syscall_number != __NR_execveat))
	{
		/* Workaround for modprobe. */
		for (i = 0 ; i < WORKAROUND_PROCESS_MAX ; i++)
		{
			if (strcmp(task->comm, g_hb_workaround_process_path[i].comm) == 0)
			{
				path_name = hb_get_exe_path(task, path_buffer, sizeof(path_buffer));
				if (strcmp(path_name, g_hb_workaround_process_path[i].path) == 0)
				{
					/* Workaround is needed. */
					workaround = 1;
					hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] [%s](%s)[PID %d] needs workaround\n",
						cpu_id, task->comm, path_name, task->pid);
					break;	
				}
			}
		}

		if (workaround == 1)
		{
			/* Update mm for workaround. */
			found->mm = task->mm;
		}
		else
		{
			hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] ======================= WARNING =======================",
				cpu_id);
			hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] [%s][PID %d] is created abnormally. Syscall[old:%d, new:%d]. Terminate it.\n",
				cpu_id, task->comm, task->pid, found->syscall_number, syscall_number);
			hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] ======================= WARNING =======================",
				cpu_id);

			hb_set_exit_flag_in_list_with_lock(found->tgid);
			ret = -1;
		}
	}

	found->syscall_number = syscall_number;

	/* Please enable if you need to check seccomp flag. */
#if 0
	/* Are seccomp flags cleared? */
	if (found->seccomp_mode == 0)
	{
		found->seccomp_mode = task->seccomp.mode;
	}
	else if (found->seccomp_mode != task->seccomp.mode)
	{
		hb_printf(LOG_LEVEL_NORMAL, LOG_ERROR "VM [%d] [%s][PID %d]'s seccomp mode is changed from [%d] to [%d]. Recover it forcely.\n",
			cpu_id, current->comm, current->pid, found->seccomp_mode, task->seccomp.mode);
		task->seccomp.mode = found->seccomp_mode;
	}
#endif
	/* Is cred changed abnormally? or should be exited? */
	if (hb_is_cred_same(&(found->cred), task->cred) != 0)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] ======================= WARNING =======================",
			cpu_id);
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] [%s][PID %d]'s privilege is changed abnormally. Terminate it. Org[UID %d, GID %d, SUID %d, SGID %d, EUID %d, EGID %d, FSUID %d, FSGID %d] New[UID %d, GID %d, SUID %d, SGID %d, EUID %d, EGID %d, FSUID %d, FSGID %d]\n",
			cpu_id, current->comm, current->pid, found->cred.uid, found->cred.gid, found->cred.suid, found->cred.sgid, found->cred.euid, found->cred.egid, found->cred.fsuid, found->cred.fsgid, task->cred->uid, task->cred->gid, task->cred->suid, task->cred->sgid, task->cred->euid, task->cred->egid, task->cred->fsuid, task->cred->fsgid);
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] ======================= WARNING =======================",
			cpu_id);

		hb_set_exit_flag_in_list_with_lock(found->tgid);

		ret = -1;
	}
	else if (found->need_exit == 1)
	{
		ret = -1;
	}

EXIT:
	if (ret == -1)
	{
		g_do_send_sig_info_fp(SIGKILL, SEND_SIG_PRIV, task, PIDTYPE_TGID);
	}
	return ret;
}

/*
 * Get task count.
 */
static int hb_get_task_count(void)
{
	struct task_struct *iter;
	int count = 0;
	struct task_struct *process;

	hb_sync_page((u64)(init_task.tasks.next), sizeof(struct task_struct));

	for_each_process_thread(process, iter)
	{
		count++;

		if (count >= TASK_NODE_MAX - 1)
		{
			hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "Task count overflows\n");
			break;
		}
		hb_sync_page((u64)(iter->tasks.next), sizeof(struct task_struct));
	}

	return count;
}

/*
 * Add new task to task manager.
 */
static struct hb_task_node* hb_add_task_to_task_manager(struct task_struct *task)
{
	struct list_head *temp;
	struct hb_task_node *node;

	g_task_count++;

	if (list_empty(&(g_task_manager.free_node_head)))
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "Task count overflows\n");
		hb_error_log(ERROR_TASK_OVERFLOW);
		return NULL;
	}

	temp = g_task_manager.free_node_head.next;
	node = container_of(temp, struct hb_task_node, list);
	list_del(&(node->list));

	node->pid = task->pid;
	node->tgid = task->tgid;
	node->task = task;
	memcpy(node->comm, task->comm, sizeof(node->comm));

	memcpy(&(node->cred), task->cred, sizeof(struct cred));
	node->syscall_number = -1;
	node->need_exit = 0;
	node->need_trace = 0;
	node->seccomp_mode = task->seccomp.mode;
	node->mm = task->mm;

	hb_add_tree(&(g_task_manager.existing_node_head), (struct hb_common_node*)node);
	return node;
}

/*
 * Reset task manager
 */
static void hb_reset_task_manager(void)
{
	int size;
	int i;

	size = sizeof(struct hb_task_node) * TASK_NODE_MAX;
	memset(g_task_manager.pool, 0, size);
	g_task_manager.existing_node_head = RB_ROOT;
	INIT_LIST_HEAD(&(g_task_manager.free_node_head));
	g_task_count = 0;

	/* Move all existing tasks to the free node. */	
	for (i = 0 ; i < TASK_NODE_MAX ; i++)
	{
		list_add(&(g_task_manager.pool[i].list), &(g_task_manager.free_node_head));
	}

}

/*
 * Copy task list to task manager.
 */
static void hb_copy_task_list_to_task_manager(void)
{
	struct task_struct *iter;
	struct task_struct *process;

	for_each_process_thread(process, iter)
	{
		if (hb_add_task_to_task_manager(iter) == 0)
		{
			return ;
		}
	}
}

/*
 * Delete the task from task manager.
 */
static int hb_del_task_from_task_manager(struct task_struct* task)
{
	struct hb_task_node *found = NULL;

	g_task_count--;

	found = (struct hb_task_node*)hb_search_tree(&(g_task_manager.existing_node_head), (u64)task);
	if (found == NULL)
	{
		return -1;
	}

	hb_del_tree(&(g_task_manager.existing_node_head), (struct hb_common_node*)found);
	list_add(&(found->list), &(g_task_manager.free_node_head));
	return 0;
}

/*
 * Check if the task is in task list.
 */
static int hb_is_in_task_list(struct task_struct* task)
{
	struct task_struct *iter;
	int is_in = 0;
	struct task_struct *process;

	hb_sync_page((u64)(init_task.tasks.next), sizeof(struct task_struct));

	for_each_process_thread(process, iter)
	{
		if ((iter == task) && (task->pid == iter->pid) &&
			(task->tgid == iter->tgid))
		{
			is_in = 1;
			break;
		}

		hb_sync_page((u64)(iter->tasks.next), sizeof(struct task_struct));
	}

	return is_in;
}

/*
 * Check integrity of inode function pointers.
 */
static int hb_check_inode_op_fields(int cpu_id, const struct inode_operations* op,
	const char* obj_name)
{
	int error = 0;

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s inode operation fields\n",
		obj_name);

	error |= !hb_is_addr_in_ro_area(op->lookup);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
	error |= !hb_is_addr_in_ro_area(op->follow_link);
#else
	error |= !hb_is_addr_in_ro_area(op->get_link);
#endif /* LINUX_VERSION_CODE */
	error |= !hb_is_addr_in_ro_area(op->permission);
	error |= !hb_is_addr_in_ro_area(op->get_acl);
	error |= !hb_is_addr_in_ro_area(op->readlink);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
	error |= !hb_is_addr_in_ro_area(op->put_link);
#endif /* LINUX_VERSION_CODE */
	error |= !hb_is_addr_in_ro_area(op->create);
	error |= !hb_is_addr_in_ro_area(op->link);
	error |= !hb_is_addr_in_ro_area(op->unlink);
	error |= !hb_is_addr_in_ro_area(op->symlink);
	error |= !hb_is_addr_in_ro_area(op->mkdir);
	error |= !hb_is_addr_in_ro_area(op->rmdir);
	error |= !hb_is_addr_in_ro_area(op->mknod);
	error |= !hb_is_addr_in_ro_area(op->rename);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	error |= !hb_is_addr_in_ro_area(op->rename2);
#endif /* LINUX_VERSION_CODE */
	error |= !hb_is_addr_in_ro_area(op->setattr);
	error |= !hb_is_addr_in_ro_area(op->getattr);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	error |= !hb_is_addr_in_ro_area(op->setxattr);
	error |= !hb_is_addr_in_ro_area(op->getxattr);
#endif /* LINUX_VERSION_CODE */
	error |= !hb_is_addr_in_ro_area(op->listxattr);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	error |= !hb_is_addr_in_ro_area(op->removexattr);
#endif /* LINUX_VERSION_CODE */
	error |= !hb_is_addr_in_ro_area(op->fiemap);
	error |= !hb_is_addr_in_ro_area(op->update_time);
	error |= !hb_is_addr_in_ro_area(op->atomic_open);
	error |= !hb_is_addr_in_ro_area(op->tmpfile);
	error |= !hb_is_addr_in_ro_area(op->set_acl);

	if (error != 0)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Error=%06d Function pointer attack is "
			"detected, function pointer=$(\"%s inode_op\")\n", cpu_id, ERROR_KERNEL_POINTER_MODIFICATION, obj_name);

		hb_error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}

/*
 * Check integrity of file function pointers.
 */
static int hb_check_file_op_fields(int cpu_id, const struct file_operations* op,
	const char* obj_name)
{
	int error = 0;

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s file operation fields\n",
		obj_name);

	error |= !hb_is_addr_in_ro_area(op->llseek);
	error |= !hb_is_addr_in_ro_area(op->read);
	error |= !hb_is_addr_in_ro_area(op->write);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	error |= !hb_is_addr_in_ro_area(op->aio_read);
	error |= !hb_is_addr_in_ro_area(op->aio_write);
#endif /* LINUX_VERSION_CODE */
	error |= !hb_is_addr_in_ro_area(op->read_iter);
	error |= !hb_is_addr_in_ro_area(op->write_iter);
	error |= !hb_is_addr_in_ro_area(op->iterate);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	error |= !hb_is_addr_in_ro_area(op->iterate_shared);
#endif /* LINUX_VERSION_CODE */
	error |= !hb_is_addr_in_ro_area(op->poll);
	error |= !hb_is_addr_in_ro_area(op->unlocked_ioctl);
#if HYPERBOX_USE_COMPAT
	error |= !hb_is_addr_in_ro_area(op->compat_ioctl);
#endif /* HYPERBOX_USE_COMPAT */
	error |= !hb_is_addr_in_ro_area(op->mmap);
	error |= !hb_is_addr_in_ro_area(op->open);
	error |= !hb_is_addr_in_ro_area(op->flush);
	error |= !hb_is_addr_in_ro_area(op->release);
	error |= !hb_is_addr_in_ro_area(op->fsync);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	error |= !hb_is_addr_in_ro_area(op->aio_fsync);
#endif /* LINUX_VERSION_CODE */
	error |= !hb_is_addr_in_ro_area(op->fasync);
	error |= !hb_is_addr_in_ro_area(op->lock);
	error |= !hb_is_addr_in_ro_area(op->sendpage);
	error |= !hb_is_addr_in_ro_area(op->get_unmapped_area);
	error |= !hb_is_addr_in_ro_area(op->check_flags);
	error |= !hb_is_addr_in_ro_area(op->flock);
	error |= !hb_is_addr_in_ro_area(op->splice_write);
	error |= !hb_is_addr_in_ro_area(op->splice_read);
	error |= !hb_is_addr_in_ro_area(op->setlease);
	error |= !hb_is_addr_in_ro_area(op->fallocate);
	error |= !hb_is_addr_in_ro_area(op->show_fdinfo);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
    error |= !hb_is_addr_in_ro_area(op->copy_file_range);
    error |= !hb_is_addr_in_ro_area(op->remap_file_range);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
	error |= !hb_is_addr_in_ro_area(op->copy_file_range);
	error |= !hb_is_addr_in_ro_area(op->clone_file_range);
	error |= !hb_is_addr_in_ro_area(op->dedupe_file_range);
#endif /* LINUX_VERSION_CODE */

	if (error != 0)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Error=%06d Function pointer attack is "
			"detected, function pointer=$(\"%s file_op\")\n", cpu_id, ERROR_KERNEL_POINTER_MODIFICATION, obj_name);
		hb_error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}

/*
 * Check integrity of VFS function pointers.
 */
static int hb_check_vfs_object(int cpu_id)
{
	struct inode_operations* inode_op;
	struct file_operations* file_op;
	int ret = 0;

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Check /proc vfs field\n", cpu_id);
	if (g_proc_file_ptr == NULL)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d]     [*] Check /proc vfs field "
			"fail\n", cpu_id);
	}
	else
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		inode_op = (struct inode_operations*)
			g_proc_file_ptr->f_dentry->d_inode->i_op;
#else
		inode_op = (struct inode_operations*)
			g_proc_file_ptr->f_path.dentry->d_inode->i_op;
#endif /* LINUX_VERSION_CODE */
		file_op = (struct file_operations*)g_proc_file_ptr->f_op;

		/* Check integrity of inode and file operation function pointers. */
		ret |= hb_check_inode_op_fields(cpu_id, inode_op, "Proc FS");
		ret |= hb_check_file_op_fields(cpu_id, file_op, "Proc FS");
	}

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Check / vfs field\n", cpu_id);
	if (g_root_file_ptr == NULL)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d]     [*] Check / vfs field fail\n",
			cpu_id);
	}
	else
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		inode_op = (struct inode_operations*)
			g_root_file_ptr->f_dentry->d_inode->i_op;
#else
		inode_op = (struct inode_operations*)
			g_root_file_ptr->f_path.dentry->d_inode->i_op;
#endif /* LINUX_VERSION_CODE */
		file_op = (struct file_operations*)
			g_root_file_ptr->f_op;

		/* Check integrity of inode and file operation function pointers. */
		ret |= hb_check_inode_op_fields(cpu_id, inode_op, "Root FS");
		ret |= hb_check_file_op_fields(cpu_id, file_op, "Root FS");
	}

	return ret;
}

/*
 * Check integrity of TCP/UDP function pointers.
 */
static int hb_check_net_seq_afinfo_fields(int cpu_id,
	const struct file_operations* fops, const struct seq_operations* sops,
	const char* obj_name)
{
	int error = 0;

	if (hb_check_file_op_fields(cpu_id, fops, obj_name) < 0)
	{
		return -1;
	}

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s seq_operations function "
		"pointer\n", obj_name);

	error |= !hb_is_addr_in_ro_area(sops->start);
	error |= !hb_is_addr_in_ro_area(sops->stop);
	error |= !hb_is_addr_in_ro_area(sops->next);
	error |= !hb_is_addr_in_ro_area(sops->show);

	if (error != 0)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Error=%06d Function pointer attack is "
			"detected, function pointer=$(\"%s seq_afinfo\")\n", cpu_id, ERROR_KERNEL_POINTER_MODIFICATION, obj_name);

		hb_error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}


/*
 * Check integrity of protocol function pointers.
 */
static int hb_check_proto_op_fields(int cpu_id, const struct proto_ops* op,
	const char* obj_name)
{
	int error = 0;

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s proto_ops operation fields\n",
		obj_name);

	error |= !hb_is_addr_in_ro_area(op->release);
	error |= !hb_is_addr_in_ro_area(op->bind);
	error |= !hb_is_addr_in_ro_area(op->connect);
	error |= !hb_is_addr_in_ro_area(op->socketpair);
	error |= !hb_is_addr_in_ro_area(op->accept);
	error |= !hb_is_addr_in_ro_area(op->getname);
	error |= !hb_is_addr_in_ro_area(op->poll);
	error |= !hb_is_addr_in_ro_area(op->ioctl);
#if HYPERBOX_USE_COMPAT
	error |= !hb_is_addr_in_ro_area(op->compat_ioctl);
#endif /* HYPERBOX_USE_COMPAT */
	error |= !hb_is_addr_in_ro_area(op->listen);
	error |= !hb_is_addr_in_ro_area(op->shutdown);
	error |= !hb_is_addr_in_ro_area(op->setsockopt);
	error |= !hb_is_addr_in_ro_area(op->getsockopt);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
#if HYPERBOX_USE_COMPAT
	error |= !hb_is_addr_in_ro_area(op->compat_setsockopt);
	error |= !hb_is_addr_in_ro_area(op->compat_getsockopt);
#endif /* HYPERBOX_USE_COMPAT */
#endif /* LINUX_VERSION_CODE */
	error |= !hb_is_addr_in_ro_area(op->sendmsg);
	error |= !hb_is_addr_in_ro_area(op->recvmsg);
	error |= !hb_is_addr_in_ro_area(op->mmap);
	error |= !hb_is_addr_in_ro_area(op->sendpage);
	error |= !hb_is_addr_in_ro_area(op->splice_read);
	error |= !hb_is_addr_in_ro_area(op->set_peek_off);
	if (error != 0)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Error=%06d Function pointer attack is "
			"detected, function pointer=$(\"%s proto_seq_afinfo\")\n", cpu_id, ERROR_KERNEL_POINTER_MODIFICATION, obj_name);

		hb_error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
/*
 * Get file_operations and seq_operations structures.
 */
static void hb_get_file_and_seq_ops(const void* i_node, int type,
	struct file_operations** fops, struct seq_operations** sops)
{
	*fops = (struct file_operations*)(PDE(i_node)->proc_fops);
	*sops = (struct seq_operations*)(PDE(i_node)->seq_ops);
}

#else /* LINUX_VERSION_CODE */

/*
 * Get file_operations and seq_operations structures.
 */
static void hb_get_file_and_seq_ops(const void* i_node, int type,
	struct file_operations** fops, struct seq_operations** sops)
{
	struct tcp_seq_afinfo* tcp_afinfo = NULL;
	struct udp_seq_afinfo* udp_afinfo = NULL;

	if (type == SOCK_TYPE_TCP)
	{
		tcp_afinfo = (struct tcp_seq_afinfo*)PDE_DATA(i_node);
		*fops = (struct file_operations*) tcp_afinfo->seq_fops;
		*sops = (struct seq_operations*) &(tcp_afinfo->seq_ops);
	}
	else
	{
		udp_afinfo = (struct udp_seq_afinfo*)PDE_DATA(i_node);
		*fops = (struct file_operations*) udp_afinfo->seq_fops;
		*sops = (struct seq_operations*) &(udp_afinfo->seq_ops);
	}
}
#endif /* LINUX_VERSION_CODE */

/*
 * Check integrity of net function pointers.
 */
static int hb_check_net_object(int cpu_id)
{
	struct file_operations* seq_fops;
	struct seq_operations* seq_sops;
	void* d_inode;
	int ret = 0;

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Check Net Object\n");

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check TCP Net Object\n");
	if (g_tcp_file_ptr != NULL)
	{
		d_inode = GET_D_INODE_FROM_FILE_PTR(g_tcp_file_ptr);
		hb_get_file_and_seq_ops(d_inode, SOCK_TYPE_TCP, &seq_fops, &seq_sops);
		ret |= hb_check_net_seq_afinfo_fields(cpu_id, seq_fops, seq_sops,
			"TCP Net");
	}

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check UDP Net Object\n");
	if (g_udp_file_ptr != NULL)
	{
		d_inode = GET_D_INODE_FROM_FILE_PTR(g_udp_file_ptr);
		hb_get_file_and_seq_ops(d_inode, SOCK_TYPE_UDP, &seq_fops, &seq_sops);
		ret |= hb_check_net_seq_afinfo_fields(cpu_id, seq_fops, seq_sops,
			"UDP Net");
	}

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check TCP6 Net Object\n");
	if (g_tcp6_file_ptr != NULL)
	{
		d_inode = GET_D_INODE_FROM_FILE_PTR(g_tcp6_file_ptr);
		hb_get_file_and_seq_ops(d_inode, SOCK_TYPE_TCP, &seq_fops, &seq_sops);
		ret |= hb_check_net_seq_afinfo_fields(cpu_id, seq_fops, seq_sops,
			"TCP6 Net");
	}

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check UDP6 Net Object\n");
	if (g_udp6_file_ptr != NULL)
	{
		d_inode = GET_D_INODE_FROM_FILE_PTR(g_udp6_file_ptr);
		hb_get_file_and_seq_ops(d_inode, SOCK_TYPE_UDP, &seq_fops, &seq_sops);
		ret |= hb_check_net_seq_afinfo_fields(cpu_id, seq_fops, seq_sops,
			"UDP6 Net");
	}

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check TCP Socket Object\n");
	if (g_tcp_sock != NULL)
	{
		ret |= hb_check_proto_op_fields(cpu_id, g_tcp_sock->ops, "TCP Socket");
	}

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check UDP Socket Object\n");
	if (g_udp_sock != NULL)
	{
		ret |= hb_check_proto_op_fields(cpu_id, g_udp_sock->ops, "UDP Socket");
	}

	return ret;
}
