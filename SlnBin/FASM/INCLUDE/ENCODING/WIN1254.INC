
; Windows 1254

rept 1 { local ..encoding
	 __encoding equ ..encoding }

virtual at 0
  __encoding::
    times 80h dw %-1
    dw 20ACh,?,201Ah,192h,201Eh,2026h,2020h,2021h,2C6h,2030h,160h,2039h,152h,?,?,?
    dw ?,2018h,2019h,201Ch,201Dh,2022h,2013h,2014h,2DCh,2122h,161h,203Ah,153h,?,?,178h
    times 30h dw 0A0h+%-1
    dw 11Eh,0D1h,0D2h,0D3h,0D4h,0D5h,0D6h,0D7h,0D8h,0D9h,0DAh,0DBh,0DCh,130h,15Eh,0DFh
    times 10h dw 0E0h+%-1
    dw 11Fh,0F1h,0F2h,0F3h,0F4h,0F5h,0F6h,0F7h,0F8h,0F9h,0FAh,0FBh,0FCh,131h,15Fh,0FFh
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
