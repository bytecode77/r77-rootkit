
; Windows 1253

rept 1 { local ..encoding
	 __encoding equ ..encoding }

virtual at 0
  __encoding::
    times 80h dw %-1
    dw 20ACh,?,201Ah,192h,201Eh,2026h,2020h,2021h,?,2030h,?,2039h,?,?,?,?
    dw ?,2018h,2019h,201Ch,201Dh,2022h,2013h,2014h,?,2122h,?,203Ah,?,?,?,?
    dw 0A0h,385h,386h,0A3h,0A4h,0A5h,0A6h,0A7h,0A8h,0A9h,?,0ABh,0ACh,0ADh,0AEh,2015h
    dw 0B0h,0B1h,0B2h,0B3h,384h,0B5h,0B6h,0B7h,288h,389h,38Ah,0BBh,38Ch,0BDh,38Eh,38Fh
    times 40h dw 390h+%-1
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
