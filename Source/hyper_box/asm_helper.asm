;
;                   Hyper-Box of Alcatraz
;                   ---------------------
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
global hb_enable_vmx
global hb_disable_vmx
global hb_start_vmx
global hb_clear_vmcs
global hb_load_vmcs
global hb_store_vmcs
global hb_read_vmcs
global hb_write_vmcs
global hb_stop_vmx
global hb_get_cr0
global hb_set_cr0
global hb_get_cr2
global hb_get_cr3
global hb_set_cr3
global hb_get_cr4
global hb_set_cr4
global hb_get_cr8
global hb_get_cs
global hb_get_ss
global hb_get_ds
global hb_get_es
global hb_get_fs
global hb_get_gs
global hb_get_tr
global hb_get_dr7
global hb_get_rflags
global hb_get_ldtr
global hb_rdmsr
global hb_wrmsr
global hb_invept
global hb_invvpid
global hb_invpcid
global hb_xsetbv
global hb_vm_launch
global hb_vm_launch_other
global hb_resume
global hb_calc_vm_exit_callback_addr
global hb_vm_exit_callback_stub
global hb_invd
global hb_flush_gdtr
global hb_gen_int
global hb_pause_loop
global hb_vm_call
global hb_restore_context_from_stack
global hb_int_callback_stub
global hb_int_with_error_callback_stub
global hb_int_nmi_callback_stub

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Imported functions.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
extern hb_vm_exit_callback
extern hb_vm_resume_fail_callback
extern hb_int_callback
extern hb_int_with_error_callback
extern hb_int_nmi_callback

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Macros
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PUSHAQ 0
	push rbp
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
%endmacro

%macro POPAQ 0
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	pop rbp
%endmacro

; Enable VMX.
hb_enable_vmx:
	push rax

	mov rax, cr4
	bts rax, 13
	mov cr4, rax

	pop rax
	ret

; Disable VMX.
hb_disable_vmx:
	push rax

	mov rax, cr4
	btc rax, 13
	mov cr4, rax

	pop rax
	ret

; Start VMX.
hb_start_vmx:
	;call disable_A20
	vmxon [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	;call enable_A20
	ret

; Clear VMCS.
hb_clear_vmcs:
	vmclear [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Load VMCS.
hb_load_vmcs:
	vmptrld [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Store VMCS.
hb_store_vmcs:
	vmptrst [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Write data to VMCS.
hb_write_vmcs:
	vmwrite rdi, rsi
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Read data from VMCS.
hb_read_vmcs:
	vmread [rsi], rdi
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Stop VMX.
hb_stop_vmx:
	vmxoff
	ret

; Get CR0.
hb_get_cr0:
	mov rax, cr0
	ret

; Set CR0.
hb_set_cr0:
	mov cr0, rdi
	ret

; Get CR2.
hb_get_cr2:
	mov rax, cr2
	ret

; Get CR3.
hb_get_cr3:
	mov rax, cr3
	ret

; Set CR3.
hb_set_cr3:
	mov cr3, rdi
	ret

; Get CR4.
hb_get_cr4:
	mov rax, cr4
	ret

; Set CR4.
hb_set_cr4:
	mov cr4, rdi
	ret

; Get CR8.
hb_get_cr8:
	mov rax, cr8
	ret

; Get CS.
hb_get_cs:
	mov rax, cs
	ret

; Get SS.
hb_get_ss:
	mov rax, ss
	ret

; Get DS.
hb_get_ds:
	mov rax, ds
	ret

; Get ES.
hb_get_es:
	mov rax, es
	ret

; Get FS.
hb_get_fs:
	mov rax, fs
	ret

; Get GS.
hb_get_gs:
	mov rax, gs
	ret

; Get TR.
hb_get_tr:
	str rax
	ret

; Get DR7.
hb_get_dr7:
	mov rax, dr7
	ret

; Get RFLAGS.
hb_get_rflags:
	pushfq
	pop rax
	ret

; Get LDTR.
hb_get_ldtr:
	sldt rax
	ret

; Read MSR.
hb_rdmsr:
	push rdx
	push rcx

	xor rdx, rdx
	xor rax, rax

	mov ecx, edi
	rdmsr

	shl rdx, 32
	or rax, rdx

	pop rcx
	pop rdx
	ret

; write msr.
hb_wrmsr:
	push rdx
	push rcx
	push rax

	mov rdx, rsi
	shr rdx, 32
	mov eax, esi

	mov ecx, edi
	wrmsr

	pop rax
	pop rcx
	pop rdx
	ret

; Invalidate EPT.
hb_invept:
	invept rdi, [rsi]

	ret

; Invalidate VPID.
hb_invvpid:
	invvpid rdi, [rsi]

	ret

; Invalidate PCID.
hb_invpcid:
	invpcid rdi, [rsi]

	ret

; Set XCR.
hb_xsetbv:
	push rdx
	push rcx
	push rax

	mov rdx, rsi
	shr rdx, 32
	mov eax, esi

	mov ecx, edi
	xsetbv

	pop rax
	pop rcx
	pop rdx
	ret

; Launch VM.
hb_vm_launch:
	push rbx

	; For seamless interoperation, set RSP of the guest to the host.
	mov rbx, 0x681C		; RSP
	mov rax, rsp
	vmwrite rbx, rax
	
	; Get current RIP.
	call .get_rip
.get_rip:
	pop rax
	
	mov rbx, 0x681E		; RIP
	add rax, (.success - .get_rip)
	vmwrite rbx, rax

	vmlaunch

	; Process fail.
	pop rbx

	jc .errorInvalid
	jz .errorValid

	mov rax, 0
	jmp .end

.errorInvalid:
	mov rax, -1
	jmp .end

.errorValid:
	mov rax, -2

.end:
	ret

.success:
	; Start line of the guest.
	; Now the core is in the guest.
	pop rbx
	mov rax, 0
	ret

; Launch Other VM.
hb_vm_launch_other:
	vmlaunch

	jc .errorInvalid
	jz .errorValid

	mov rax, 0
	jmp .end

.errorInvalid:
	mov rax, -1
	jmp .end

.errorValid:
	mov rax, -2

.end:
	ret

.success:
	; Start line of the guest.
	; Now the core is in the guest.
	pop rbx
	mov rax, 0
	ret


; Stub of VM exit callback.
;
; When VM exit occur, RFLAGS is cleared except bit 1.
hb_vm_exit_callback_stub:
	; Start line of the host.
	; Now the core is in the host.
	PUSHAQ

	; For passing flags
	mov rax, 0x12345678
	push rax
	
	; RDI has the pointer of the guest context structure.
	mov rdi, rsp

	call hb_vm_exit_callback

	pop rbx
	cmp rbx, 0x12345678
	jne .vm_launch
	
	; Resume the guest.
	POPAQ
	vmresume
	jmp .error

.vm_launch:
	POPAQ
	vmlaunch

.error:
	; Error occur.
	mov rdi, rax
	call hb_vm_resume_fail_callback

.hang:
	jmp .hang
	ret

; Resume VM.
hb_vm_resume:
	vmresume

	jc .errorInvalid
	jz .errorValid

	mov rax, 0
	jmp .end

.errorInvalid:
	mov rax, -1
	jmp .end

.errorValid:
	mov rax, -2

.end:
	ret

.success:
	; Start line of the guest.
	; Now the core is in the guest.
	mov rax, 0
	ret

; Get current RIP.
hb_get_rip:
	pop rax
	push rax
	ret

; Process INVD.
hb_invd:
	invd
	ret

; Flush GDTR.
hb_flush_gdtr:
	push rax

	mov ax, ss
	mov ss, ax

	pop rax
	ret

; Generate interrupt 0xF8.
hb_gen_int:
	push rax

	mov rax, rdi
	sti
	int 0xf8

	pop rax
	ret

; Pause CPU.
hb_pause_loop:
	pause
	ret

; Call vmcall.
;	VMcall argument:
;		rax: service number
;		rbx: argument
;	Result:
;		rax: return value
hb_vm_call:
	push rbx

	mov rax, rdi
	mov rbx, rsi

	vmcall

	pop rbx
	ret

; Restore context from stack(vm_full_context).
hb_restore_context_from_stack:
	mov rsp, rdi
	
	pop rax			; cr4
	;mov cr4, rax

	pop rax			; cr3
	mov cr3, rax

	pop rax			; cr0
	;mov cr0, rax

	pop rax			; tr
	;ltr ax

	pop rax			; lldt
	;lldt ax

	pop rax			; gs
	;mov gs, ax

	pop rax			; fs
	mov fs, ax

	pop rax			; es
	mov es, ax

	pop rax			; ds
	mov ds, ax

	pop rax			; cs
	;ignore cs

	POPAQ			; Restore GP register.
	popfq			; Restore RFLAGS.

	ret				; Return to RIP.

; Stub for interrupt without an error code
; EFLAGS		<- RSP + 16
; CS			<- RSP + 8
; EIP 			<- RSP
 hb_int_callback_stub:
	PUSHAQ

	call hb_int_callback

	POPAQ
	iretq

; Stub for interrupt with error code
; EFLAGS		<- RSP + 24
; CS			<- RSP + 16
; EIP			<- RSP + 8
; Error Code 	<- RSP
hb_int_with_error_callback_stub:
	PUSHAQ

	call hb_int_with_error_callback

	POPAQ
	add rsp, 8		; Remove error code from stack
	iretq

; Stub for NMI interrupt
; EFLAGS		<- RSP + 16
; CS			<- RSP + 8
; EIP 			<- RSP
hb_int_nmi_callback_stub:
	PUSHAQ

	call hb_int_nmi_callback

	POPAQ
	iretq

