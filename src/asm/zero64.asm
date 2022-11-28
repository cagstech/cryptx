
public _zero64
public _rmemcpy

_zero64:
	pop de
	ex (sp),hl
	ld b,8
	xor a,a
.loop:
	ld (hl),a
	inc hl
	djnz .loop
	ex hl,de
	jp (hl)
