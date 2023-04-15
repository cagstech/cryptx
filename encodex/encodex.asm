;------------------------------------------
include '../../include/library.inc'

;------------------------------------------
library ENCODEX, 3

;------------------------------------------

;v1 functions
    export cryptx_asn1_decode
    export cryptx_base64_encode
    export cryptx_base64_decode
    export cryptx_bpp_encode
    export cryptx_bpp_decode
 
cryptx_asn1_decode		= asn1_decode
cryptx_base64_encode	= base64_encode
cryptx_base64_decode	= base64_decode
cryptx_bpp_encode		= encode_bpp
cryptx_bpp_decode		= decode_bpp


_rmemcpy:
; optimized by calc84maniac
    ld  iy, -3
    add iy, sp
    ld  bc, (iy + 12)
    sbc hl, hl
    add hl, bc
    ret nc
    ld  de, (iy + 9)
    add hl, de
    ld  de, (iy + 6)
.loop:
    ldi
    ret po
    dec hl
    dec hl
    jr  .loop


asn1_decode:
	ld	hl, -18
	call	ti._frameset
	ld	hl, (ix + 6)
	ld	de, (ix + 9)
	ld	bc, 0
	push	hl
	pop	iy
	add	iy, de
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_17
	ex	de, hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_17
	ld	hl, (ix + 6)
	ld	a, (hl)
	or	a, a
	jr	z, .lbl_4
	ld	de, 0
	jr	.lbl_5
.lbl_4:
	ld	de, 1
.lbl_5:
	ld	hl, (ix + 6)
	add	hl, de
	push	bc
	pop	de
	lea	bc, iy
	push	hl
	pop	iy
.lbl_6:
	lea	hl, iy
	or	a, a
	sbc	hl, bc
	jp	nc, .lbl_16
	ld	(ix - 3), iy
	push	bc
	pop	iy
	push	de
	pop	hl
	push	de
	pop	bc
	ld	de, (ix + 15)
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_17
	ld	(ix - 12), iy
	ld	(ix - 6), bc
	push	bc
	pop	hl
	ld	bc, 9
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, (ix + 12)
	ld	iy, (ix - 3)
	add	hl, de
	ld	c, (iy)
	lea	de, iy + 2
	ld	a, (iy + 1)
	push	hl
	pop	iy
	or	a, a
	sbc	hl, hl
	ld	(iy + 3), hl
	cp	a, b
	call	pe, ti._setflag
	ld	(ix - 15), iy
	jp	m, .lbl_10
	or	a, a
	sbc	hl, hl
	ld	l, a
	ld	(ix - 3), hl
	ld	(iy + 3), hl
	ld	(ix - 9), de
	jr	.lbl_12
.lbl_10:
	and	a, 127
	cp	a, 4
	jp	nc, .lbl_18
	or	a, a
	sbc	hl, hl
	ld	(ix - 3), hl
	ld	hl, (ix - 3)
	ld	l, a
	ld	(ix - 3), hl
	ld	hl, (ix - 3)
	push	hl
	ld	(ix - 9), de
	push	de
	pea	iy + 3
	ld	(ix - 18), c
	call	_rmemcpy
	ld	c, (ix - 18)
	ld	iy, (ix - 15)
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix - 3)
	ld	hl, (ix - 9)
	add	hl, de
	ld	(ix - 9), hl
	ld	hl, (iy + 3)
	ld	(ix - 3), hl
.lbl_12:
	ld	a, c
	and	a, 31
	ld	(iy), a
	ld	a, c
	ld	b, 5
	call	ti._bshru
	and	a, 1
	ld	e, a
	ld	hl, (ix - 6)
	ld	a, c
	ld	bc, 9
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, (ix + 12)
	add	iy, bc
	ld	(iy + 2), e
	ld	b, 6
	call	ti._bshru
	ld	(iy + 1), a
	ld	hl, (ix - 9)
	ld	(iy + 6), hl
	push	hl
	pop	iy
	ld	bc, (ix - 3)
	add	iy, bc
	ld	(ix - 18), iy
	bit	0, e
	push	hl
	pop	iy
	jr	nz, .lbl_14
	ld	bc, (ix - 12)
	ld	de, (ix - 6)
	jr	.lbl_15
.lbl_14:
	ld	hl, (ix + 15)
	ld	de, (ix - 6)
	or	a, a
	sbc	hl, de
	push	hl
	ld	hl, (ix - 15)
	push	hl
	push	bc
	push	iy
	call	asn1_decode
	push	hl
	pop	de
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 6)
	dec	hl
	add	hl, de
	ex	de, hl
	ld	bc, (ix - 12)
.lbl_15:
	ld	iy, (ix - 18)
	inc	de
	jp	.lbl_6
.lbl_16:
	push	de
	pop	bc
.lbl_17:
	push	bc
	pop	hl
	ld	sp, ix
	pop	ix
	ret
.lbl_18:
	ld	bc, 1
	jr	.lbl_17
	

base64_encode:
	ld	hl, -16
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	de, (ix + 12)
	ld	bc, 2
	push	de
	pop	hl
	add	hl, bc
	inc	bc
	call	ti._idivu
	ld	(ix - 15), hl
	or	a, a
	sbc	hl, hl
	push	hl
	pop	bc
	ld	(ix - 3), hl
.lbl_1:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_8
	push	bc
	pop	de
	inc	de
	ld	iy, (ix + 9)
	ld	(ix - 6), bc
	add	iy, bc
	push	de
	pop	hl
	ld	bc, (ix + 12)
	or	a, a
	sbc	hl, bc
	ld	bc, 0
	jr	nc, .lbl_4
	ld	hl, (ix - 6)
	ld	de, 2
	add	hl, de
	ld	bc, 0
	ld	c, (iy + 1)
	ex	de, hl
.lbl_4:
	ld	(ix - 12), bc
	ld	a, (iy)
	push	de
	pop	hl
	ld	bc, (ix + 12)
	or	a, a
	sbc	hl, bc
	jr	nc, .lbl_6
	ld	hl, (ix + 9)
	add	hl, de
	inc	de
	ld	bc, 0
	ld	c, (hl)
	ld	(ix - 9), bc
	ld	(ix - 6), de
	ld	de, 0
	jr	.lbl_7
.lbl_6:
	ld	(ix - 6), de
	ld	de, 0
	ld	(ix - 9), de
.lbl_7:
	ld	hl, (ix - 12)
	ld	c, 8
	call	ti._ishl
	ld	(ix - 12), hl
	ld	(ix - 16), a
	ld	b, 2
	call	ti._bshru
	push	de
	pop	bc
	ld	e, a
	ld	hl, _b64_charset
	add	hl, de
	ld	a, (hl)
	ld	de, (ix - 3)
	ld	iy, (ix + 6)
	add	iy, de
	ld	(iy), a
	push	bc
	pop	hl
	ld	l, (ix - 16)
	ld	c, 16
	call	ti._ishl
	push	hl
	pop	de
	ld	hl, (ix - 12)
	add	hl, de
	ld	c, 12
	call	ti._ishru
	ld	de, 63
	push	de
	pop	bc
	call	ti._iand
	push	hl
	pop	de
	ld	hl, _b64_charset
	add	hl, de
	ld	a, (hl)
	ld	(iy + 1), a
	ld	hl, (ix - 9)
	ld	de, (ix - 12)
	add	hl, de
	ld	c, 6
	call	ti._ishru
	ld	bc, 63
	call	ti._iand
	push	hl
	pop	de
	ld	bc, _b64_charset
	push	bc
	pop	hl
	add	hl, de
	ld	a, (hl)
	ld	(iy + 2), a
	ld	hl, (ix - 9)
	ld	bc, 63
	call	ti._iand
	push	hl
	pop	de
	ld	hl, _b64_charset
	add	hl, de
	ld	a, (hl)
	ld	de, 4
	ld	hl, (ix - 3)
	add	hl, de
	ld	(ix - 3), hl
	ld	(iy + 3), a
	ld	iy, (ix + 6)
	ld	de, (ix + 12)
	ld	bc, (ix - 6)
	jp	.lbl_1
.lbl_8:
	ld	c, 2
	ld	hl, (ix - 15)
	call	ti._ishl
	ld	(ix - 6), hl
	ex	de, hl
	ld	bc, 3
	call	ti._iremu
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _b64_mod_table
	add	hl, de
	ld	de, (hl)
	ld	bc, 1
	push	de
	pop	hl
	or	a, a
	sbc	hl, bc
	call	pe, ti._setflag
	jp	p, .lbl_10
	ld	de, 0
.lbl_10:
	ld	bc, (ix - 6)
	add	iy, bc
.lbl_11:
	dec	iy
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_13
	ld	(iy), 61
	dec	de
	jr	.lbl_11
.lbl_13:
	ld	hl, (ix - 3)
	ld	sp, ix
	pop	ix
	ret
	

base64_decode:
	ld	hl, -24
	call	ti._frameset
	ld	de, (ix + 12)
	or	a, a
	sbc	hl, hl
	ld	a, e
	and	a, 3
	or	a, a
	jp	nz, .lbl_24
	ld	iy, (ix + 9)
	ld	c, 2
	push	de
	pop	hl
	call	ti._ishru
	ld	bc, 3
	call	ti._imulu
	add	iy, de
	ld	a, (iy - 1)
	cp	a, 61
	ld	bc, -1
	push	bc
	pop	de
	jr	z, .lbl_3
	ld	de, 0
.lbl_3:
	add	hl, de
	ld	a, (iy - 2)
	cp	a, 61
	jr	z, .lbl_5
	ld	bc, 0
.lbl_5:
	add	hl, bc
	ld	(ix - 6), hl
	ld	bc, 0
	push	bc
	pop	iy
	ld	(ix - 9), bc
.lbl_6:
	ld	de, (ix + 12)
	lea	hl, iy
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_23
	lea	de, iy
	ld	hl, (ix + 9)
	add	hl, de
	ld	a, (hl)
	cp	a, 61
	push	bc
	pop	hl
	ld	(ix - 3), iy
	jr	z, .lbl_9
	or	a, a
	sbc	hl, hl
	ld	l, a
	push	hl
	ld	hl, _b64_charset
	push	hl
	call	ti._strchr
	ld	iy, (ix - 3)
	ld	bc, 0
	pop	de
	pop	de
	ld	de, _b64_charset
	or	a, a
	sbc	hl, de
.lbl_9:
	ld	(ix - 15), hl
	lea	de, iy
	ld	iy, (ix + 9)
	add	iy, de
	ld	a, (iy + 1)
	cp	a, 61
	push	bc
	pop	hl
	jr	z, .lbl_11
	or	a, a
	sbc	hl, hl
	ld	l, a
	push	hl
	ld	hl, _b64_charset
	push	hl
	call	ti._strchr
	ld	bc, 0
	pop	de
	pop	de
	ld	de, _b64_charset
	or	a, a
	sbc	hl, de
.lbl_11:
	ld	(ix - 18), hl
	ld	de, (ix - 3)
	ld	iy, (ix + 9)
	add	iy, de
	ld	a, (iy + 2)
	cp	a, 61
	push	bc
	pop	hl
	jr	z, .lbl_13
	or	a, a
	sbc	hl, hl
	ld	l, a
	push	hl
	ld	hl, _b64_charset
	push	hl
	call	ti._strchr
	ld	bc, 0
	pop	de
	pop	de
	ld	de, _b64_charset
	or	a, a
	sbc	hl, de
.lbl_13:
	ld	de, (ix - 3)
	ld	iy, (ix + 9)
	add	iy, de
	ld	a, (iy + 3)
	cp	a, 61
	ld	(ix - 12), hl
	jr	z, .lbl_15
	or	a, a
	sbc	hl, hl
	ld	l, a
	push	hl
	ld	hl, _b64_charset
	push	hl
	call	ti._strchr
	pop	de
	pop	de
	ld	de, _b64_charset
	or	a, a
	sbc	hl, de
	push	hl
	pop	bc
	ld	hl, (ix - 12)
.lbl_15:
	ld	(ix - 21), bc
	push	hl
	pop	iy
	add	iy, iy
	sbc	hl, hl
	ld	(ix - 24), hl
	ld	e, 0
	ld	bc, (ix - 15)
	ld	a, e
	ld	l, 18
	call	ti._lshl
	push	bc
	pop	iy
	ld	d, a
	ld	bc, (ix - 18)
	ld	a, e
	ld	l, 12
	call	ti._lshl
	push	bc
	pop	hl
	ld	e, a
	lea	bc, iy
	ld	a, d
	call	ti._ladd
	push	hl
	pop	iy
	ld	bc, (ix - 12)
	ld	hl, (ix - 24)
	ld	a, l
	ld	l, 6
	call	ti._lshl
	lea	hl, iy
	call	ti._ladd
	ld	bc, (ix - 21)
	xor	a, a
	call	ti._ladd
	push	hl
	pop	iy
	ld	a, e
	ld	de, (ix - 9)
	push	de
	pop	hl
	ld	bc, (ix - 6)
	or	a, a
	sbc	hl, bc
	jr	nc, .lbl_17
	lea	bc, iy
	ld	l, 16
	call	ti._lshru
	ld	a, c
	ld	hl, (ix + 6)
	add	hl, de
	inc	de
	ld	(hl), a
.lbl_17:
	push	de
	pop	bc
	push	bc
	pop	hl
	ld	de, (ix - 6)
	or	a, a
	sbc	hl, de
	jr	nc, .lbl_19
	ld	a, iyh
	ld	hl, (ix + 6)
	add	hl, bc
	inc	bc
	ld	(hl), a
.lbl_19:
	push	bc
	pop	hl
	ld	de, (ix - 6)
	or	a, a
	sbc	hl, de
	jr	nc, .lbl_21
	ld	a, iyl
	ld	hl, (ix + 6)
	add	hl, bc
	inc	bc
	ld	(ix - 9), bc
	ld	(hl), a
	jr	.lbl_22
.lbl_21:
	ld	(ix - 9), bc
.lbl_22:
	ld	de, 4
	ld	iy, (ix - 3)
	add	iy, de
	ld	bc, 0
	jp	.lbl_6
.lbl_23:
	ld	hl, (ix - 9)
.lbl_24:
	ld	sp, ix
	pop	ix
	ret


; bool decode_bpp(void *dest, void *src, size_t len, uint8_t bpp);
; note: len refers to src length, which is bpp/8 the length of dest.
; returns true and Cf unset if success, false and Cf set if invalid/unsupported bpp.
decode_bpp:
	ld	iy,0
	add	iy,sp
	ld	a,(iy+12)
	ld	hl,(iy+6)
	ld	bc,(iy+9)
	ld	iy,(iy+3)
	call	.entry
	xor	a,a
	ret
.entry:
	dec	a
	jr	z,.decode_1
	dec	a
	jr	z,.decode_2
	dec	a
	jr	z,.fail
	dec	a
	jr	z,.decode_4
.fail:
	pop	bc ; pop return from .entry
	scf
	sbc	a,a
	ret
.decode_1:
	ld	e,(hl)
	ld	d,8
.decode_1_inner:
	xor	a,a
	rlc	e
	adc	a,a
	ld	(iy),a
	inc	iy
	dec	d
	jr	nz,.decode_1_inner
	cpi
	ret	po
	jr	.decode_1
.decode_2:
	ld	e,(hl)
	ld	d,4
.decode_2_inner:
	xor	a,a
	rlc	e
	rla
	rlc	e
	rla
	ld	(iy),a
	inc	iy
	dec	d
	jr	nz,.decode_2_inner
	cpi
	ret	po
	jr	.decode_2
.decode_4:
	ld	a,(hl)
	and	a,$F0
	rra
	rra
	rra
	rra
	ld	(iy),a
	ld	a,(hl)
	and	a,$F
	ld	(iy+1),a
	lea	iy,iy+2
	cpi
	ret	po
	jr	.decode_4


; void encode_bpp(void *dest, void *src, size_t len, uint8_t bpp);
; note: len refers to dest length, which is 8/bpp times the length of src
encode_bpp:
	ld	iy,0
	add	iy,sp
	ld	a,(iy+12)
	ld	hl,(iy+3)
	ld	bc,(iy+9)
	ld	iy,(iy+6)
	call	.entry
	xor	a,a
	ret
.entry:
	dec	a
	jr	z,.encode_1
	dec	a
	jr	z,.encode_2
	dec	a
	jr	z,.fail
	dec	a
	jr	z,.encode_4
.fail:
	pop	bc ; pop return from .entry
	scf
	sbc	a,a
	ret
.encode_1:
	ld	d,8
	xor	a,a
.encode_1_inner:
	ld	e,(iy)
	rrc	e
	adc	a,a
	inc	iy
	dec	d
	jr	nz,.encode_1_inner
	ld	(hl),a
	cpi
	ret	po
	jr	.encode_1
.encode_2:
	ld	a,(iy+0)
	add	a,a
	add	a,a
	add	a,(iy+1)
	add	a,a
	add	a,a
	add	a,(iy+2)
	add	a,a
	add	a,a
	add	a,(iy+3)
	lea	iy,iy+4
	ld	(hl),a
	cpi
	ret	po
	jr	.encode_2
.encode_4:
	ld	a,(iy+1)
	and	a,$0F
	ld	e,a
	ld	a,(iy+0)
	and	a,$0F
	rla
	rla
	rla
	rla
	or	a,e
	lea	iy,iy+2
	ld	(hl),a
	cpi
	ret	po
	jr .encode_4


_b64_charset:
	db	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 0

_b64_mod_table:
	dl	0
	dl	2
	dl	1
