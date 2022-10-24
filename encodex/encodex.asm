;------------------------------------------
include '../../include/library.inc'

;------------------------------------------
library ENCODEX, 1

;------------------------------------------

;v1 functions
    export asn1_decode
    

asn1_decode:
	ld	hl, -21
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	de, (ix + 9)
	ld	bc, 0
	lea	hl, iy
	add	hl, de
	ld	a, (iy)
	or	a, a
	jr	z, .lbl_2
	ld	de, 0
	jr	.lbl_3
.lbl_2:
	ld	de, 1
.lbl_3:
	ld	(ix - 3), hl
	add	iy, de
	ld	de, (ix + 15)
.lbl_4:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_15
	lea	hl, iy
	ld	de, (ix - 3)
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_15
	push	bc
	pop	hl
	ld	(ix - 6), bc
	ld	de, 9
	push	de
	pop	bc
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, (ix + 12)
	lea	bc, iy
	push	hl
	pop	iy
	add	iy, de
	ld	(ix - 12), iy
	push	bc
	pop	iy
	ld	e, (iy)
	lea	hl, iy + 2
	ld	a, (iy + 1)
	cp	a, 0
	call	pe, ti._setflag
	ld	(ix - 15), e
	jp	m, .lbl_8
	ld	de, 0
	ld	e, a
	push	hl
	pop	iy
	ld	hl, (ix - 6)
	ld	bc, 9
	call	ti._imulu
	push	hl
	pop	bc
	ld	(ix - 9), iy
	ld	iy, (ix + 12)
	add	iy, bc
	ld	(ix - 18), de
	ld	(iy + 3), de
	jr	.lbl_10
.lbl_8:
	ld	bc, (ix - 6)
	and	a, 127
	cp	a, 4
	ld	de, 0
	jp	nc, .lbl_14
	ld	(ix - 18), de
	ex	de, hl
	ld	hl, (ix - 18)
	ld	l, a
	ld	(ix - 18), hl
	push	bc
	pop	hl
	ld	(ix - 9), de
	ld	de, 9
	push	de
	pop	bc
	call	ti._imulu
	push	hl
	pop	de
	ld	iy, (ix + 12)
	add	iy, de
	ld	(ix - 21), iy
	or	a, a
	sbc	hl, hl
	ld	(iy + 3), hl
	ld	hl, (ix - 18)
	push	hl
	ld	hl, (ix - 9)
	push	hl
	pea	iy + 3
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix - 18)
	ld	hl, (ix - 9)
	add	hl, de
	ld	(ix - 9), hl
	ld	iy, (ix - 21)
	ld	hl, (iy + 3)
	ld	(ix - 18), hl
.lbl_10:
	ld	e, (ix - 15)
	ld	a, e
	and	a, 31
	ld	hl, (ix - 12)
	ld	(hl), a
	ld	hl, (ix - 6)
	ld	bc, 9
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, (ix + 12)
	add	iy, bc
	ld	a, e
	ld	b, 5
	call	ti._bshru
	and	a, 1
	ld	(ix - 21), a
	ld	(iy + 2), a
	ld	a, e
	inc	b
	call	ti._bshru
	ld	(iy + 1), a
	ld	bc, (ix - 9)
	ld	(iy + 6), bc
	push	bc
	pop	hl
	ld	de, (ix - 18)
	push	de
	pop	iy
	add	hl, de
	ld	(ix - 15), hl
	bit	0, (ix - 21)
	jr	nz, .lbl_12
	ld	de, (ix + 15)
	ld	bc, (ix - 6)
	jr	.lbl_13
.lbl_12:
	ld	de, (ix - 6)
	dec	de
	ld	(ix - 6), de
	ld	hl, (ix + 15)
	or	a, a
	sbc	hl, de
	push	hl
	ld	hl, (ix - 12)
	push	hl
	push	iy
	push	bc
	call	asn1_decode
	pop	de
	pop	de
	pop	de
	pop	de
	ld	de, (ix + 15)
	ld	bc, (ix - 6)
	add	hl, bc
	push	hl
	pop	bc
.lbl_13:
	ld	iy, (ix - 15)
	inc	bc
	jp	.lbl_4
.lbl_14:
	push	de
	pop	bc
.lbl_15:
	push	bc
	pop	hl
	ld	sp, ix
	pop	ix
	ret
