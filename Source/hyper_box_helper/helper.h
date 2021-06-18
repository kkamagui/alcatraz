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
#ifndef __HYPER_BOX_HELPER_H__
#define __HYPER_BOX_HELPER_H__

/*
 * Macros.
 */
/* Log level. */
#define LOG_LEVEL				(LOG_LEVEL_NORMAL)
#define LOG_LEVEL_NONE				0
#define LOG_LEVEL_NORMAL			1
#define LOG_LEVEL_DEBUG				2
#define LOG_LEVEL_DETAIL			3

/* Log type. */
#define LOG_INFO				KERN_INFO "hyper-box-helper: "
#define LOG_ERROR				KERN_ERR "hyper-box-helper: "
#define LOG_WARNING				KERN_WARNING "hyper-box-helper: "

/* Log buffer size */
#define MAX_LOG_BUFFER_SIZE			(4 * 1024 * 1024)
#define MAX_LOG_LINE				(1024)

/* Shadow-box-helper error codes. */
#define ERROR_SUCCESS				0
#define ERROR_START_FAIL		 	1
#define ERROR_LOGGING_FAIL		 	2

/* VM call service number. */
#define VM_SERVICE_GET_LOGINFO			0
#define VM_SERVICE_SHUTDOWN			10000
#define VM_SERVICE_SHUTDOWN_THIS_CORE		10001

#define HYPER_BOX_MODULE_NAME			"hyper_box"

#endif
