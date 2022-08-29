
; Extended Win64 programming headers (ASCII)

include 'win64a.inc'

include 'macro/if.inc'

macro allow_nesting
{ macro invoke proc,[arg]
  \{ \common fastcall [proc],arg \}
  macro fastcall proc,[arg]
  \{ \common \local list,counter,flags,outer_frame,nested_frame,..close_nest
	     match =current@frame,current@frame \\{
	       frame
	       define outer_frame \\}
	     define counter
	     define list
	     flags = 0
     \forward \local param,nested,isfloat,..next
	      match any,counter \\{ list equ list, \\}
	      counter equ counter+1
	      define param arg
	      define nested
	      isfloat = 0
	      match =invoke statement,param \\{
		nested equ param
		define param \\}
	      match =fastcall statement,param \\{
		nested equ param
		define param \\}
	      match =float =invoke statement,param \\{
		define nested invoke statement
		define param
		isfloat = 1 \\}
	      match =float =fastcall statement,param \\{
		define nested fastcall statement
		define param
		isfloat = 1 \\}
	      match statement,nested \\{
		match =nested_frame,nested_frame \\\{
		  frame
		  define nested_frame \\\}
		allow_nesting
		statement
		purge invoke_fastcall
		if counter > 4
		 if isfloat
		  movq [rsp+size@frame+(counter-1)*8],xmm0
		 else
		  mov [rsp+size@frame+(counter-1)*8],rax
		 end if
		else
		 flags = flags or 1 shl (counter-1)
		 if isfloat
		  flags = flags or 1 shl (4+counter-1)
		 end if
		 if ..close_nest > ..next
		  if float
		   movq [rsp+size@frame+(counter-1)*8],xmm0
		  else
		   mov [rsp+size@frame+(counter-1)*8],rax
		  end if
		 else
		  flags = flags or 1 shl (8+counter-1)
		 end if
		end if
		..next: \\}
	      list equ list <param>
     \common ..close_nest:
	     match ,nested_frame \\{ endf \\}
	     if flags and 1
	      if flags and 1 shl 4
	       if ~ flags and 1 shl 8
		movq xmm0,[rsp]
	       end if
	      else
	       if flags and 1 shl 8
		mov rcx,rax
	       else
		mov rcx,[rsp]
	       end if
	      end if
	     end if
	     if flags and 1 shl 1
	      if flags and 1 shl (4+1)
	       if flags and 1 shl (8+1)
		movq xmm1,xmm0
	       else
		movq xmm1,[rsp+8]
	       end if
	      else
	       if flags and 1 shl (8+1)
		mov rdx,rax
	       else
		mov rdx,[rsp+8]
	       end if
	      end if
	     end if
	     if flags and 1 shl 2
	      if flags and 1 shl (4+2)
	       if flags and 1 shl (8+2)
		movq xmm2,xmm0
	       else
		movq xmm2,[rsp+2*8]
	       end if
	      else
	       if flags and 1 shl (8+2)
		mov r8,rax
	       else
		mov r8,[rsp+2*8]
	       end if
	      end if
	     end if
	     if flags and 1 shl 3
	      if flags and 1 shl (4+3)
	       if flags and 1 shl (8+3)
		movq xmm3,xmm0
	       else
		movq xmm3,[rsp+3*8]
	       end if
	      else
	       if flags and 1 shl (8+3)
		mov r9,rax
	       else
		mov r9,[rsp+3*8]
	       end if
	      end if
	     end if
	     match args,list \\{ fastcall proc,args \\}
	     match ,list \\{ fastcall proc \\}
	     match ,outer_frame \\{ endf \\} \} }

allow_nesting

macro import lib,[functions]
{ common macro import_#lib \{ import lib,functions \} }

macro api [functions]
{ common macro all_api \{ all_api
			  api functions \} }
macro all_api {}

include 'api/kernel32.inc'
include 'api/user32.inc'
include 'api/gdi32.inc'
include 'api/advapi32.inc'
include 'api/comctl32.inc'
include 'api/comdlg32.inc'
include 'api/shell32.inc'
include 'api/wsock32.inc'

purge import,api

macro .data { section '.data' data readable writeable }

macro .code {
  section '.text' code readable executable
  entry $
  sub rsp,8
  local main,code
  entry equ main
  if main <> code
  jmp main
  end if
  code: }

macro .end value
{
   label entry at value

   section '.idata' import data readable writeable

     library kernel32,'KERNEL32.DLL',\
	     user32,'USER32.DLL',\
	     gdi32,'GDI32.DLL',\
	     advapi32,'ADVAPI32.DLL',\
	     comctl32,'COMCTL32.DLL',\
	     comdlg32,'COMDLG32.DLL',\
	     shell32,'SHELL32.DLL',\
	     wsock32,'WSOCK32.DLL'

     import_kernel32
     import_user32
     import_gdi32
     import_advapi32
     import_comctl32
     import_comdlg32
     import_shell32
     import_wsock32

     all_api
}

virtual at 0
 inc ax
 if $=1
  detected_16bit = 1
 else
  detected_16bit = 0
 end if
end virtual

if detected_16bit
 format PE64 GUI 5.0
end if
