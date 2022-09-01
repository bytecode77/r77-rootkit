
; Windows 874

rept 1 { local ..encoding
	 __encoding equ ..encoding }

virtual at 0
  __encoding::	    
    times 80h dw %-1
    dw 20ACh,?,?,?,?,2026h,?,?,?,?,?,?,?,?,?,?
    dw ?,2018h,2019h,201Ch,201Dh,2022h,2013h,2014h,?,?,?,?,?,?,?,?
    times 60h dw 0E00h+%-1
end virtual

macro du [arg]
 { local offset,char
   offset = $-$$
   du arg
   if arg eqtype ''
    repeat ($-offset-$$)/2
     load char byte from $$+offset+(%-1)*2
     if char > 7Fh
      load char word from __encoding:char*2
      store word char at $$+offset+(%-1)*2
     end if
    end repeat
   end if }

struc du [args]
 { common label . word
   du args }
