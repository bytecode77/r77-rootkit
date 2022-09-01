
; Windows 1252

rept 1 { local ..encoding
	 __encoding equ ..encoding }

virtual at 0
  __encoding::
    times 80h dw %-1
    dw 20ACh,?,201Ah,192h,201Eh,2026h,2020h,2021h,2C6h,2030h,160h,2039h,152h,?,17D,?
    dw ?,2018h,2019h,201Ch,201Dh,2022h,2013h,2014h,2DCh,2122h,161h,203Ah,153h,?,17Eh,178h
    times 60h dw 0A0h+%-1
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
