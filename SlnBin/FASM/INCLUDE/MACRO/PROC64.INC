
; Macroinstructions for defining and calling procedures (x64 version)

macro invoke proc,[arg]
 { common fastcall [proc],arg }

macro fastcall proc,[arg]
 { common local stackspace,argscount,counter
    if argscount < 4
     stackspace = 4*8
    else if argscount and 1
     stackspace = (argscount+1)*8
    else
     stackspace = argscount*8
    end if
    counter = 0
    if stackspace
     if defined current@frame
      if current@frame<stackspace
       current@frame = stackspace
      end if
     else
      if stackspace
       sub rsp,stackspace
      end if
     end if
    end if
   forward
    counter = counter + 1
    define type@param
    define definition@param arg
    match =float value,definition@param
    \{ define definition@param value
       define type@param float \}
    match =addr value,definition@param
    \{ define definition@param value
       define type@param addr \}
    match any=,any,definition@param
    \{ \local ..string,..continue
       jmp ..continue
       align sizeof.TCHAR
       ..string TCHAR definition@param,0
       ..continue:
       define definition@param ..string
       define type@param addr \}
    match any,definition@param
    \{ match \`any,any
       \\{ \\local ..string,..continue
	   jmp ..continue
	   align sizeof.TCHAR
	   ..string TCHAR definition@param,0
	   ..continue:
	   define definition@param ..string
	   define type@param addr \\} \}
    match param,definition@param
    \{ local opcode,origin
       size@param = 0
       if param eqtype 0 | param eqtype 0f | type@param eq addr
	size@param = 8
       else if param eqtype byte 0 | param eqtype byte 0f
	match prefix value,definition@param
	 \\{ if prefix eq qword
	      size@param = 8
	     else if prefix eq dword
	      size@param = 4
	     else if prefix eq word
	      size@param = 2
	     else if prefix eq byte
	      size@param = 1
	     end if \\}
       else if ~ param in <xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8,xmm9,xmm10,xmm11,xmm12,xmm13,xmm14,xmm15>
	virtual
	 origin = $
	 inc param
	 load opcode byte from origin
	 if opcode = 67h | opcode = 41h
	  load opcode byte from origin+1
	 end if
	 if opcode and 0F8h = 48h
	  size@param = 8
	 else if opcode = 66h
	  size@param = 2
	 else if opcode = 0FFh
	  size@param = 4
	 else
	  size@param = 1
	 end if
	end virtual
       end if
       if counter = 1
	if type@param eq float
	 if ~ param eq xmm0
	  if size@param = 4
	   if param eqtype byte 0 | param eqtype byte 0f
	    mov eax,param
	    movd xmm0,eax
	   else
	    movd xmm0,param
	   end if
	  else
	   if param eqtype 0 | param eqtype 0f | param eqtype byte 0 | param eqtype byte 0f
	    mov rax,param
	    movq xmm0,rax
	   else
	    movq xmm0,param
	   end if
	  end if
	 end if
	 if vararg@fastcall & ~ param eq rcx
	   movq rcx,xmm0
	 end if
	else if type@param eq addr
	 if ~ param eq rcx
	  lea rcx,[param]
	 end if
	else if size@param = 8
	 if ~ param eq rcx
	  mov rcx,param
	 end if
	else if size@param = 4
	 if ~ param eq ecx
	  mov ecx,param
	 end if
	else if size@param = 2
	 if ~ param eq cx
	  mov cx,param
	 end if
	else if size@param = 1
	 if ~ param eq cl
	  mov cl,param
	 end if
	end if
       else if counter = 2
	if type@param eq float
	 if ~ param eq xmm1
	  if size@param = 4
	   if param eqtype byte 0 | param eqtype byte 0f
	    mov eax,param
	    movd xmm1,eax
	   else
	    movd xmm1,param
	   end if
	  else
	   if param eqtype 0 | param eqtype 0f | param eqtype byte 0 | param eqtype byte 0f
	    mov rax,param
	    movq xmm1,rax
	   else
	    movq xmm1,param
	   end if
	  end if
	 end if
	 if vararg@fastcall & ~ param eq rdx
	   movq rdx,xmm1
	 end if
	else if type@param eq addr
	 if ~ param eq rdx
	  lea rdx,[param]
	 end if
	else if size@param = 8
	 if ~ param eq rdx
	  mov rdx,param
	 end if
	else if size@param = 4
	 if ~ param eq edx
	  mov edx,param
	 end if
	else if size@param = 2
	 if ~ param eq dx
	  mov dx,param
	 end if
	else if size@param = 1
	 if ~ param eq dl
	  mov dl,param
	 end if
	end if
       else if counter = 3
	if type@param eq float
	 if ~ param eq xmm2
	  if size@param = 4
	   if param eqtype byte 0 | param eqtype byte 0f
	    mov eax,param
	    movd xmm2,eax
	   else
	    movd xmm2,param
	   end if
	  else
	   if param eqtype 0 | param eqtype 0f | param eqtype byte 0 | param eqtype byte 0f
	    mov rax,param
	    movq xmm2,rax
	   else
	    movq xmm2,param
	   end if
	  end if
	 end if
	 if vararg@fastcall & ~ param eq r8
	   movq r8,xmm2
	 end if
	else if type@param eq addr
	 if ~ param eq r8
	  lea r8,[param]
	 end if
	else if size@param = 8
	 if ~ param eq r8
	  mov r8,param
	 end if
	else if size@param = 4
	 if ~ param eq r8d
	  mov r8d,param
	 end if
	else if size@param = 2
	 if ~ param eq r8w
	  mov r8w,param
	 end if
	else if size@param = 1
	 if ~ param eq r8b
	  mov r8b,param
	 end if
	end if
       else if counter = 4
	if type@param eq float
	 if ~ param eq xmm3
	  if size@param = 4
	   if param eqtype byte 0 | param eqtype byte 0f
	    mov eax,param
	    movd xmm3,eax
	   else
	    movd xmm3,param
	   end if
	  else
	   if param eqtype 0 | param eqtype 0f | param eqtype byte 0 | param eqtype byte 0f
	    mov rax,param
	    movq xmm3,rax
	   else
	    movq xmm3,param
	   end if
	  end if
	 end if
	 if vararg@fastcall & ~ param eq r9
	   movq r9,xmm3
	 end if
	else if type@param eq addr
	 if ~ param eq r9
	  lea r9,[param]
	 end if
	else if size@param = 8
	 if ~ param eq r9
	  mov r9,param
	 end if
	else if size@param = 4
	 if ~ param eq r9d
	  mov r9d,param
	 end if
	else if size@param = 2
	 if ~ param eq r9w
	  mov r9w,param
	 end if
	else if size@param = 1
	 if ~ param eq r9b
	  mov r9b,param
	 end if
	end if
       else
	 if type@param eq addr
	  lea rax,[param]
	  mov [rsp+(counter-1)*8],rax
	 else if param eqtype [0] | param eqtype byte [0]
	  if size@param = 8
	   mov rax,param
	   mov [rsp+(counter-1)*8],rax
	  else if size@param = 4
	   mov eax,param
	   mov [rsp+(counter-1)*8],eax
	  else if size@param = 2
	   mov ax,param
	   mov [rsp+(counter-1)*8],ax
	  else
	   mov al,param
	   mov [rsp+(counter-1)*8],al
	  end if
	 else if size@param = 8
	  virtual
	   origin = $
	   mov rax,param
	   load opcode byte from origin+1
	  end virtual
	  if opcode = 0B8h
	   mov rax,param
	   mov [rsp+(counter-1)*8],rax
	  else
	   mov qword [rsp+(counter-1)*8],param
	  end if
	 else if param in <xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8,xmm9,xmm10,xmm11,xmm12,xmm13,xmm14,xmm15>
	  movq [rsp+(counter-1)*8],param
	 else
	  mov [rsp+(counter-1)*8],param
	 end if
       end if \}
   common
    argscount = counter
    call proc
    if stackspace & ~defined current@frame
     add rsp,stackspace
    end if }

macro proc [args]
 { common
    match name params, args>
    \{ define@proc name,<params \} }

prologue@proc equ prologuedef

macro prologuedef procname,flag,parmbytes,localbytes,reglist
 { local loc,fill,counter
   loc = (localbytes+15) and (not 15)
   parmbase@proc equ rbp+16
   localbase@proc equ rbp-loc
   push rbp
   mov rbp,rsp
   if loc+fill
    sub rsp,loc+fill
   end if
   counter = 0
   irps reg, reglist \{ push reg
			counter = counter+1 \}
   fill = 8*(counter and 1) }

epilogue@proc equ epiloguedef

macro epiloguedef procname,flag,parmbytes,localbytes,reglist
 { irps reg, reglist \{ reverse pop reg \}
   leave
   retn }

close@proc equ

macro define@proc name,statement
 { local params,flag,regs,parmbytes,localbytes,current
   if used name
   name:
   match =stdcall args, statement \{ params equ args
				     flag = 11b \}
   match =stdcall, statement \{ params equ
				flag = 11b \}
   match =c args, statement \{ params equ args
			       flag = 10001b \}
   match =c, statement \{ params equ
			  flag = 10001b \}
   match =params, params \{ params equ statement
			    flag = 10000b \}
   match =uses reglist=,args, params \{ regs equ reglist
					params equ args \}
   match =regs =uses reglist, regs params \{ regs equ reglist
					     params equ \}
   match =regs, regs \{ regs equ \}
   match prologue:reglist, prologue@proc:<regs> \{ prologue name,flag,parmbytes,localbytes,reglist \}
   virtual at parmbase@proc
   match =,args, params \{ defargs@proc args \}
   match =args@proc args, args@proc params \{ defargs@proc args \}
   parmbytes = $-(parmbase@proc)
   end virtual
   name # % = parmbytes/8
   all@vars equ
   current = 0
   macro locals
   \{ virtual at localbase@proc+current
      macro label def \\{ match . type,def> \\\{ deflocal@proc .,label,<type \\\} \\}
      struc db [val] \\{ \common deflocal@proc .,db,val \\}
      struc du [val] \\{ \common deflocal@proc .,du,val \\}
      struc dw [val] \\{ \common deflocal@proc .,dw,val \\}
      struc dp [val] \\{ \common deflocal@proc .,dp,val \\}
      struc dd [val] \\{ \common deflocal@proc .,dd,val \\}
      struc dt [val] \\{ \common deflocal@proc .,dt,val \\}
      struc dq [val] \\{ \common deflocal@proc .,dq,val \\}
      struc rb cnt \\{ deflocal@proc .,rb cnt, \\}
      struc rw cnt \\{ deflocal@proc .,rw cnt, \\}
      struc rp cnt \\{ deflocal@proc .,rp cnt, \\}
      struc rd cnt \\{ deflocal@proc .,rd cnt, \\}
      struc rt cnt \\{ deflocal@proc .,rt cnt, \\}
      struc rq cnt \\{ deflocal@proc .,rq cnt, \\} \}
   macro endl
   \{ purge label
      restruc db,du,dw,dp,dd,dt,dq
      restruc rb,rw,rp,rd,rt,rq
      current = $-(localbase@proc)
      end virtual \}
   macro ret operand
   \{ match any, operand \\{ retn operand \\}
      match , operand \\{ match epilogue:reglist, epilogue@proc:<regs> \\\{ epilogue name,flag,parmbytes,localbytes,reglist \\\} \\} \}
   macro finish@proc
   \{ localbytes = current
      match close:reglist, close@proc:<regs> \\{ close name,flag,parmbytes,localbytes,reglist \\}
      end if \} }

macro defargs@proc [arg]
 { common
    if ~ arg eq
   forward
     local ..arg,current@arg
     match argname:type, arg
      \{ current@arg equ argname
	 label ..arg type
	 argname equ ..arg
	 if qqword eq type
	   dq ?,?,?,?
	 else if dqword eq type
	   dq ?,?
	 else if tbyte eq type
	   dq ?,?
	 else
	   dq ?
	 end if \}
     match =current@arg,current@arg
      \{ current@arg equ arg
	 arg equ ..arg
	 ..arg dq ? \}
   common
     args@proc equ current@arg
   forward
     restore current@arg
   common
    end if }

macro deflocal@proc name,def,[val] { name def val }

macro deflocal@proc name,def,[val]
 { common
    match vars, all@vars \{ all@vars equ all@vars, \}
    all@vars equ all@vars name
   forward
    local ..var,..tmp
    ..var def val
    match =?, val \{ ..tmp equ \}
    match any =?, val \{ ..tmp equ \}
    match any (=?), val \{ ..tmp equ \}
    match =label, def \{ ..tmp equ \}
    match tmp : value, ..tmp : val
     \{ tmp: end virtual
	initlocal@proc ..var,def value
	virtual at tmp\}
   common
    match first rest, ..var, \{ name equ first \} }

struc label type { label . type }

macro initlocal@proc name,def
 { virtual at name
    def
    size@initlocal = $ - name
   end virtual
   position@initlocal = 0
   while size@initlocal > position@initlocal
    virtual at name
     def
     if size@initlocal - position@initlocal < 2
      current@initlocal = 1
      load byte@initlocal byte from name+position@initlocal
     else if size@initlocal - position@initlocal < 4
      current@initlocal = 2
      load word@initlocal word from name+position@initlocal
     else if size@initlocal - position@initlocal < 8
      current@initlocal = 4
      load dword@initlocal dword from name+position@initlocal
     else
      load qword@initlocal qword from name+position@initlocal
      if ( qword@initlocal > 0 & qword@initlocal < 80000000h ) | ( qword@initlocal < 0 & qword@initlocal >= -80000000h )
       current@initlocal = 8
      else
       current@initlocal = 4
       dword@initlocal = qword@initlocal and 0FFFFFFFFh
      end if
     end if
    end virtual
    if current@initlocal = 1
     mov byte [name+position@initlocal],byte@initlocal
    else if current@initlocal = 2
     mov word [name+position@initlocal],word@initlocal
    else if current@initlocal = 4
     mov dword [name+position@initlocal],dword@initlocal
    else
     mov qword [name+position@initlocal],qword@initlocal
    end if
    position@initlocal = position@initlocal + current@initlocal
   end while }

macro endp
 { purge ret,locals,endl
   finish@proc
   purge finish@proc
   restore regs@proc
   match all,args@proc \{ restore all \}
   restore args@proc
   match all,all@vars \{ restore all \} }

macro local [var]
 { common
    locals
   forward done@local equ
    match varname[count]:vartype, var
    \{ match =BYTE, vartype \\{ varname rb count
				restore done@local \\}
       match =WORD, vartype \\{ varname rw count
				restore done@local \\}
       match =DWORD, vartype \\{ varname rd count
				 restore done@local \\}
       match =PWORD, vartype \\{ varname rp count
				 restore done@local \\}
       match =QWORD, vartype \\{ varname rq count
				 restore done@local \\}
       match =TBYTE, vartype \\{ varname rt count
				 restore done@local \\}
       match =DQWORD, vartype \\{ label varname dqword
				  rq count*2
				  restore done@local \\}
       match =QQWORD, vartype \\{ label varname qqword
				  rq count*4
				  restore done@local \\}
       match =XWORD, vartype \\{ label varname xword
				 rq count*2
				 restore done@local \\}
       match =YWORD, vartype \\{ label varname yword
				 rq count*4
				 restore done@local \\}
       match , done@local \\{ virtual
			       varname vartype
			      end virtual
			      rb count*sizeof.\#vartype
			      restore done@local \\} \}
    match :varname:vartype, done@local:var
    \{ match =BYTE, vartype \\{ varname db ?
				restore done@local \\}
       match =WORD, vartype \\{ varname dw ?
				restore done@local \\}
       match =DWORD, vartype \\{ varname dd ?
				 restore done@local \\}
       match =PWORD, vartype \\{ varname dp ?
				 restore done@local \\}
       match =QWORD, vartype \\{ varname dq ?
				 restore done@local \\}
       match =TBYTE, vartype \\{ varname dt ?
				 restore done@local \\}
       match =DQWORD, vartype \\{ label varname dqword
				  dq ?,?
				  restore done@local \\}
       match =QQWORD, vartype \\{ label varname qqword
				  dq ?,?,?,?
				  restore done@local \\}
       match =XWORD, vartype \\{ label varname xword
				 dq ?,?
				 restore done@local \\}
       match =YWORD, vartype \\{ label varname yword
				 dq ?,?,?,?
				 restore done@local \\}
       match , done@local \\{ varname vartype
			      restore done@local \\} \}
    match ,done@local
    \{ var
       restore done@local \}
   common
    endl }

macro frame
 { local size,current
   if size
    sub rsp,size
   end if
   current = 0
   current@frame equ current
   size@frame equ size }

macro endf
 { size@frame = current@frame
   if size@frame
    add rsp,size@frame
   end if
   restore size@frame,current@frame }

macro static_rsp_prologue procname,flag,parmbytes,localbytes,reglist
 { local counter,loc,frame,current 
   counter = 0 
   irps reg, reglist \{ push reg 
			counter = counter+1 \} 
   loc = (localbytes+7) and (not 7) 
   if frame & (counter+loc shr 3+1) and 1 
    loc = loc + 8 
   end if 
   framebytes@proc equ frame+loc 
   if framebytes@proc 
    sub rsp,framebytes@proc 
   end if 
   localbase@proc equ rsp+frame 
   regsbase@proc equ rsp+frame+loc 
   parmbase@proc equ rsp+frame+loc+counter*8+8 
   current = 0 
   current@frame equ current 
   size@frame equ frame } 

macro static_rsp_epilogue procname,flag,parmbytes,localbytes,reglist 
 { if framebytes@proc 
    add rsp,framebytes@proc 
   end if 
   irps reg, reglist \{ reverse pop reg \} 
   retn } 

macro static_rsp_close procname,flag,parmbytes,localbytes,reglist 
 { size@frame = current@frame 
   restore size@frame,current@frame }

stdcall fix fastcall

macro cinvoke proc,[arg]
 { common ccall [proc],arg }

macro ccall proc,[arg]
 { common vararg@fastcall = 1
	  fastcall proc,arg
	  vararg@fastcall = 0 }

vararg@fastcall = 0