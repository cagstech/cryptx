
public _add64iu

_add64iu:
	pop bc,de
	ex (sp),hl
	push de,bc
	ex hl,de
	ld bc,(hl)
	ex hl,de
	xor a,a
	adc hl,bc
	ex hl,de
	ld (hl),de
	inc hl
	inc hl
	ld b,5
	ld c,a
.loop:
	inc hl
	adc a,(hl)
	ld (hl),a
	ld a,c
	djnz .loop
	ret
