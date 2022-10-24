;------------------------------------------
include '../../include/library.inc'

;------------------------------------------
library ENCODEX, 1

;------------------------------------------

;v1 functions
    export asn1_decode
    
    
_rmemcpy:
	call	ti._frameset0
	ld	bc, (ix + 6)
	ld	iy, (ix + 9)
	ld	de, (ix + 12)
.lbl_1:
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_3
	ld	a, (iy)
	lea	hl, iy
	push	bc
	pop	iy
	add	iy, de
	ld	(iy - 1), a
	push	hl
	pop	iy
	dec	de
	inc	iy
	jr	.lbl_1
.lbl_3:
	pop	ix
	ret


asn1_decode:
	ld	hl, -18
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
.lbl_4:
	ld	de, (ix + 15)
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_14
	lea	hl, iy
	ld	de, (ix - 3)
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_14
	ld	(ix - 6), bc
	push	bc
	pop	hl
	ld	bc, 9
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, (ix + 12)
	add	hl, de
	ld	c, (iy)
	lea	de, iy + 2
	ld	(ix - 9), de
	ld	a, (iy + 1)
	push	hl
	pop	iy
	or	a, a
	sbc	hl, hl
	ld	(iy + 3), hl
	cp	a, b
	call	pe, ti._setflag
	ld	(ix - 12), iy
	jp	m, .lbl_8
	or	a, a
	sbc	hl, hl
	ld	l, a
	ld	(ix - 15), hl
	ld	(iy + 3), hl
	jr	.lbl_10
.lbl_8:
	ld	(ix - 18), c
	and	a, 127
	cp	a, 4
	ld	bc, (ix - 6)
	jp	nc, .lbl_14
	or	a, a
	sbc	hl, hl
	ld	l, a
	ld	(ix - 15), hl
	push	hl
	ld	hl, (ix - 9)
	push	hl
	pea	iy + 3
	call	_rmemcpy
	ld	iy, (ix - 12)
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix - 15)
	ld	hl, (ix - 9)
	add	hl, de
	ld	(ix - 9), hl
	ld	hl, (iy + 3)
	ld	(ix - 15), hl
	ld	c, (ix - 18)
.lbl_10:
	ld	a, c
	and	a, 31
	ld	(iy), a
	ld	hl, (ix - 6)
	ld	e, c
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
	ld	d, a
	ld	(iy + 2), d
	ld	a, e
	inc	b
	call	ti._bshru
	ld	(iy + 1), a
	ld	bc, (ix - 9)
	ld	(iy + 6), bc
	push	bc
	pop	iy
	lea	hl, iy
	ld	bc, (ix - 15)
	add	hl, bc
	ld	(ix - 18), hl
	bit	0, d
	jr	nz, .lbl_12
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
	push	bc
	push	iy
	call	asn1_decode
	pop	de
	pop	de
	pop	de
	pop	de
	ld	de, (ix - 6)
	add	hl, de
	push	hl
	pop	bc
.lbl_13:
	inc	bc
	ld	iy, (ix - 18)
	jp	.lbl_4
.lbl_14:
	push	bc
	pop	hl
	ld	sp, ix
	pop	ix
	ret
