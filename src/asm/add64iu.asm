
public _add64iu
public _u64_conv_big

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


_ll_swap_bytes:
	pop bc, de
	push de, bc
	ld hl, 7
	ld c, l
	add hl, bc
	add hl, de
	ld b, 4
.loop:
	ld a, (de)
	ldi
	dec hl
	ld (hl), a
	dec hl
	djnz .loop
	ret

_bytelen_to_bitlen:
; hl = size
; iy = dst
	pop bc, hl, iy
	push iy, hl, bc
	xor a, a
	add hl, hl
	rla
	add hl, hl
	rla
	add hl, hl
	rla
	ld (iy + 6), h
	ld (iy + 7), l
	ld h, a
	ld l, 0
	ld (iy + 3), hl
	sbc hl, hl
	ld (iy + 0), hl
	ret
