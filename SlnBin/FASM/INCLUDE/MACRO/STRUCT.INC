
; Macroinstructions for defining data structures

macro struct name
 { virtual at 0
   define @struct
   field@struct equ name
   match child parent, name \{ restore field@struct
			       field@struct equ child,fields@\#parent \}
   sub@struct equ
   struc db [val] \{ \common define field@struct .,db,<val> \}
   struc dw [val] \{ \common define field@struct .,dw,<val> \}
   struc du [val] \{ \common define field@struct .,du,<val> \}
   struc dd [val] \{ \common define field@struct .,dd,<val> \}
   struc dp [val] \{ \common define field@struct .,dp,<val> \}
   struc dq [val] \{ \common define field@struct .,dq,<val> \}
   struc dt [val] \{ \common define field@struct .,dt,<val> \}
   struc rb count \{ define field@struct .,db,count dup (?) \}
   struc rw count \{ define field@struct .,dw,count dup (?) \}
   struc rd count \{ define field@struct .,dd,count dup (?) \}
   struc rp count \{ define field@struct .,dp,count dup (?) \}
   struc rq count \{ define field@struct .,dq,count dup (?) \}
   struc rt count \{ define field@struct .,dt,count dup (?) \}
   macro db [val] \{ \common \local anonymous
		     define field@struct anonymous,db,<val> \}
   macro dw [val] \{ \common \local anonymous
		     define field@struct anonymous,dw,<val> \}
   macro du [val] \{ \common \local anonymous
		     define field@struct anonymous,du,<val> \}
   macro dd [val] \{ \common \local anonymous
		     define field@struct anonymous,dd,<val> \}
   macro dp [val] \{ \common \local anonymous
		     define field@struct anonymous,dp,<val> \}
   macro dq [val] \{ \common \local anonymous
		     define field@struct anonymous,dq,<val> \}
   macro dt [val] \{ \common \local anonymous
		     define field@struct anonymous,dt,<val> \}
   macro rb count \{ \local anonymous
		     define field@struct anonymous,db,count dup (?) \}
   macro rw count \{ \local anonymous
		     define field@struct anonymous,dw,count dup (?) \}
   macro rd count \{ \local anonymous
		     define field@struct anonymous,dd,count dup (?) \}
   macro rp count \{ \local anonymous
		     define field@struct anonymous,dp,count dup (?) \}
   macro rq count \{ \local anonymous
		     define field@struct anonymous,dq,count dup (?) \}
   macro rt count \{ \local anonymous
		     define field@struct anonymous,dt,count dup (?) \}
   macro union \{ field@struct equ ,union,<
		  sub@struct equ union \}
   macro struct \{ field@struct equ ,substruct,<
		  sub@struct equ substruct \} }

macro ends
 { match , sub@struct \{ restruc db,dw,du,dd,dp,dq,dt
			 restruc rb,rw,rd,rp,rq,rt
			 purge db,dw,du,dd,dp,dq,dt
			 purge rb,rw,rd,rp,rq,rt
			 purge union,struct
			 irpv fields,field@struct \\{ restore field@struct
						      \\common define fields@struct fields \\}
			 match name tail,fields@struct, \\{ if $
							    display 'Error: definition of ',\\`name,' contains illegal instructions.',0Dh,0Ah
							    err
							    end if \\}
			 match name=,fields,fields@struct \\{ restore @struct
							      make@struct name,fields
							      define fields@\\#name fields \\}
			 end virtual \}
   match any, sub@struct \{ tmp@struct equ field@struct
			    restore field@struct
			    field@struct equ tmp@struct> \}
   restore sub@struct }

macro make@struct name,[field,type,def]
 { common
    local define
    define equ name
   forward
    local sub
    match , field \{ make@substruct type,name,sub def
		     define equ define,.,sub, \}
    match any, field \{ define equ define,.#field,type,<def> \}
   common
    match fields, define \{ define@struct fields \} }

macro define@struct name,[field,type,def]
 { common
    virtual
    db `name
    load initial@struct byte from 0
    if initial@struct = '.'
    display 'Error: name of structure should not begin with a dot.',0Dh,0Ah
    err
    end if
    end virtual
    local list
    list equ
   forward
    if ~ field eq .
     name#field type def
     sizeof.#name#field = $ - name#field
    else
     label name#.#type
     rb sizeof.#type
    end if
    local value
    match any, list \{ list equ list, \}
    list equ list <value>
   common
    sizeof.#name = $
    restruc name
    match values, list \{
    struc name value \\{ \\local \\..base
    match , @struct \\\{ define field@struct .,name,<values> \\\}
    match no, @struct \\\{ label \\..base
   forward
     match , value \\\\{ field type def \\\\}
     match any, value \\\\{ field type value
			    if ~ field eq .
			     rb sizeof.#name#field - ($-field)
			    end if \\\\}
   common label . at \\..base \\\}
   \\}
    macro name value \\{
    match , @struct \\\{ \\\local anonymous
				  define field@struct anonymous,name,<values> \\\}
    match no, @struct \\\{
   forward
     match , value \\\\{ type def \\\\}
     match any, value \\\\{ \\\\local ..field
			   ..field = $
			   type value
			   if ~ field eq .
			    rb sizeof.#name#field - ($-..field)
			   end if \\\\}
   common \\\} \\} \} }

macro enable@substruct
 { macro make@substruct substruct,parent,name,[field,type,def]
    \{ \common
	\local define
	define equ parent,name
       \forward
	\local sub
	match , field \\{ match any, type \\\{ enable@substruct
					       make@substruct type,parent,sub def
					       purge make@substruct
					       define equ define,.,sub, \\\} \\}
	match any, field \\{ define equ define,.\#field,type,<def> \\}
       \common
	match fields, define \\{ define@\#substruct fields \\} \} }

enable@substruct

macro define@union parent,name,[field,type,def]
 { common
    virtual at parent#.#name
   forward
    if ~ field eq .
     virtual at parent#.#name
      parent#field type def
      sizeof.#parent#field = $ - parent#field
     end virtual
     if sizeof.#parent#field > $ - parent#.#name
      rb sizeof.#parent#field - ($ - parent#.#name)
     end if
    else
     virtual at parent#.#name
      label parent#.#type
      type def
     end virtual
     label name#.#type at parent#.#name
     if sizeof.#type > $ - parent#.#name
      rb sizeof.#type - ($ - parent#.#name)
     end if
    end if
   common
    sizeof.#name = $ - parent#.#name
    end virtual
    struc name [value] \{ \common
    label .\#name
    last@union equ
   forward
    match any, last@union \\{ virtual at .\#name
			       field type def
			      end virtual \\}
    match , last@union \\{ match , value \\\{ field type def \\\}
			   match any, value \\\{ field type value \\\} \\}
    last@union equ field
   common rb sizeof.#name - ($ - .\#name) \}
    macro name [value] \{ \common \local ..anonymous
			  ..anonymous name value \} }

macro define@substruct parent,name,[field,type,def]
 { common
    virtual at parent#.#name
   forward
    local value
    if ~ field eq .
     parent#field type def
     sizeof.#parent#field = $ - parent#field
    else
     label parent#.#type
     rb sizeof.#type
    end if
   common
    sizeof.#name = $ - parent#.#name
    end virtual
    struc name value \{
    label .\#name
   forward
     match , value \\{ field type def \\}
     match any, value \\{ field type value
			  if ~ field eq .
			   rb sizeof.#parent#field - ($-field)
			  end if \\}
   common \}
    macro name value \{ \local ..anonymous
			..anonymous name \} }
