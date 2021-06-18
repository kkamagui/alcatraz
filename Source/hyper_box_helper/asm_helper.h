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
#ifndef __ASM_H__
#define __ASM_H__

/*
 * Functions.
 */
extern void* hbh_vm_call(u64 svr_num, void* arg);

#endif
