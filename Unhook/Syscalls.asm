IFNDEF rax
	.model flat
ENDIF

IFDEF rax

.data

extern SyscallGadget:QWORD
extern NtCreateFileSyscallNumber:DWORD
extern NtQueryInformationFileSyscallNumber:DWORD
extern NtReadFileSyscallNumber:DWORD
extern NtProtectVirtualMemorySyscallNumber:DWORD

.code

SyscallNtCreateFile proc
	mov		r10, rcx
	mov		eax, NtCreateFileSyscallNumber
	jmp		SyscallGadget
SyscallNtCreateFile endp

SyscallNtQueryInformationFile proc
	mov		r10, rcx
	mov		eax, NtQueryInformationFileSyscallNumber
	jmp		SyscallGadget
SyscallNtQueryInformationFile endp

SyscallNtReadFile proc
	mov		r10, rcx
	mov		eax, NtReadFileSyscallNumber
	jmp		SyscallGadget
SyscallNtReadFile endp

SyscallNtProtectVirtualMemory proc
	mov		r10, rcx
	mov		eax, NtProtectVirtualMemorySyscallNumber
	jmp		SyscallGadget
SyscallNtProtectVirtualMemory endp

ELSE

; For now, unhooking works on 64-bit Windows only.

.code

_SyscallNtCreateFile proc
	mov		eax, -1
	ret
_SyscallNtCreateFile endp

_SyscallNtQueryInformationFile proc
	mov		eax, -1
	ret
_SyscallNtQueryInformationFile endp

_SyscallNtReadFile proc
	mov		eax, -1
	ret
_SyscallNtReadFile endp

_SyscallNtProtectVirtualMemory proc
	mov		eax, -1
	ret
_SyscallNtProtectVirtualMemory endp

ENDIF

end