;
;                    Hyper-Box of Alcatraz
;                    ---------------------
;      A Practical Hypervisor Sandbox to Prevent Escapes 
;
;               Copyright (C) 2021 Seunghun Han
;             at The Affiliated Institute of ETRI
;

; This software has GPL v2+ license. See the GPL_LICENSE file.

[bits 64]
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Exported functions.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global hbh_vm_call

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Imported functions.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; Call vmcall.
;	VMcall argument:
;		rax: service number
;		rbx: argument
;	Result:
;		rax: return value
hbh_vm_call:
	push rbx

	mov rax, rdi
	mov rbx, rsi

	vmcall

	pop rbx
	ret
