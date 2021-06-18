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
#include <linux/kfifo.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include "asm_helper.h"
#include "helper.h"

/*
 * Functions.
 */
void hbh_printf(int level, char* format, ...);
void hbh_error_log(int error_code);
static int hbh_log_thread(void* argument);

/*
 * Variables.
 */
struct task_struct *g_log_thread_id = NULL;

/*
 * Print Hyper-box log.
 */
void hbh_printf(int level, char* format, ...)
{
	va_list arg_list;

	if (level <= LOG_LEVEL)
	{
		va_start(arg_list, format);
		vprintk(format, arg_list);
		va_end(arg_list);
	}
}

/*
 * Print Hyper-box error.
 */
void hbh_error_log(int error_code)
{
	hbh_printf(LOG_LEVEL_NONE, LOG_ERROR "errorcode=%d\n", error_code);
}

/* Wait until Hyper-box starts. */
static void hbh_wait_hyper_box_module(void)
{
	struct module *mod;
	struct list_head *pos, *node;
	int found = 0;

	while (found == 0)
	{
		mod = THIS_MODULE;
		pos = &THIS_MODULE->list;
		node = pos;

		list_for_each(pos, node)
		{
			mod = container_of(pos, struct module, list);
			hbh_printf(LOG_LEVEL_DEBUG, LOG_INFO "Module Name [%s]\n", mod->name);

			if (strcmp(mod->name, HYPER_BOX_MODULE_NAME) == 0)
			{
				found = 1;
				break;
			}
		}

		if (found == 0)
		{
			hbh_printf(LOG_LEVEL_NORMAL, LOG_INFO "Waiting for Hyper-box module...\n");
			msleep(1000);
		}
	}

	hbh_printf(LOG_LEVEL_NORMAL, LOG_INFO "Hyper-box module is detected.\n");
}


/*
 * Thread for log print.
 */
static int hbh_log_thread(void* argument)
{
	char buffer[MAX_LOG_LINE];
	int ret;
	int index;
	int remain;
	int end;
	int copy_bytes;
	int i;
	struct kfifo* fifo;

	/* Find the hyper-box module.*/
	hbh_wait_hyper_box_module();

	fifo = (struct kfifo*) hbh_vm_call(VM_SERVICE_GET_LOGINFO, NULL);
	if (fifo == NULL)
	{
		hbh_error_log(ERROR_LOGGING_FAIL);
		ret = -EINVAL;
	}

	index = 0;
	memset(buffer, 0, sizeof(buffer));

	while (!kthread_should_stop())
	{	
		remain = sizeof(buffer) - index;
		ret = kfifo_out(fifo, buffer + index, remain);
		end = index + ret;
		
		for (i = 0 ; i < end ; i++)
		{
			/* All flags are set by caller. */
			if (buffer[i] == '\n')
			{
				buffer[i] = '\0';
				printk("%s\n", buffer);

				/* Calculate new index. */
				copy_bytes = end - (i + 1);
				memcpy(buffer, buffer + i + 1, copy_bytes);
				index = copy_bytes;

				break;
			}
		}

		/* Buffer is full and no newline in buffer, then flush it. */
		if (i == sizeof(buffer))
		{
			buffer[sizeof(buffer) - 1] = '\0';
			printk("%s", buffer);

			index = 0;
		}

		/* if no data from fifo, sleep. */
		if ((remain > 0) && (ret == 0))
		{
			msleep(1);
		}
	}

	return 0;
}

/*
 * Start function of Hyper-box helper module
 */
static int __init hyper_box_helper_init(void)
{
	g_log_thread_id = kthread_run(hbh_log_thread, NULL, "logger");
	if (g_log_thread_id == NULL)
	{
		hbh_error_log(ERROR_LOGGING_FAIL);
		return -EINVAL;
	}

	/* Prevent module unloald. */
	try_module_get(THIS_MODULE);

	return 0;
}

/*
 * End function of Hyper-box helper module.
 */
static void __exit hyper_box_helper_exit(void)
{
	hbh_printf(LOG_LEVEL_NORMAL, LOG_INFO "Stop Hyper-Box Helper\n");
	if (g_log_thread_id != NULL)
	{
		kthread_stop(g_log_thread_id);
	}
}


module_init(hyper_box_helper_init);
module_exit(hyper_box_helper_exit);

MODULE_AUTHOR("Seunghun Han");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("Hyper-box-helper: A Practical Hypervisor Sandbox to Prevent Escapes.");
