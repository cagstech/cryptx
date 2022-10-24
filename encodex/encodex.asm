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
	ld	bc, (ix + 15)
	or	a, a
	sbc	hl, hl
	ld	(ix - 3), hl
	lea	hl, iy
	ld	de, (ix + 9)
	add	hl, de
	ld	(ix - 6), hl
.lbl_1:
	ld	hl, (ix - 3)
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_11
	ld	hl, (ix - 3)
	ld	bc, 7
	call	ti._imulu
	push	hl
	pop	bc
	ld	hl, (ix + 12)
	add	hl, bc
	ld	a, (iy)
	ld	(hl), a
	ld	a, (iy + 1)
	cp	a, 0
	call	pe, ti._setflag
	jp	m, .lbl_4
	ld	de, 0
	ld	e, a
	lea	hl, iy + 2
	ld	(ix - 9), hl
	ld	hl, (ix - 3)
	ld	bc, 7
	call	ti._imulu
	push	hl
	pop	bc
	ld	hl, (ix + 12)
	push	hl
	pop	iy
	add	iy, bc
	ld	(ix - 12), de
	ld	(iy + 1), de
	push	hl
	pop	iy
	ld	bc, 7
	jp	.lbl_9
.lbl_4:
	lea	iy, iy + 2
	and	a, 127
	or	a, a
	sbc	hl, hl
	cp	a, 4
	jp	nc, .lbl_10
	ld	l, a
	ld	(ix - 15), hl
	ld	hl, (ix - 3)
	ld	bc, 7
	call	ti._imulu
	push	hl
	pop	de
	lea	bc, iy
	ld	hl, (ix + 12)
	add	hl, de
	ld	(ix - 12), hl
	ld	(ix - 9), bc
	ld	(ix - 18), bc
	ld	bc, (ix - 15)
.lbl_6:
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_8
	ld	iy, (ix - 12)
	ld	hl, (iy + 1)
	ld	(ix - 21), bc
	ld	c, 8
	call	ti._ishl
	ld	iy, (ix - 12)
	ld	(iy + 1), hl
	push	hl
	pop	iy
	ld	bc, 0
	ld	hl, (ix - 18)
	ld	c, (hl)
	add	iy, bc
	lea	de, iy
	ld	bc, (ix - 21)
	ld	iy, (ix - 12)
	ld	(iy + 1), de
	dec	bc
	inc	hl
	ld	(ix - 18), hl
	jr	.lbl_6
.lbl_8:
	ld	bc, (ix - 15)
	ld	hl, (ix - 9)
	add	hl, bc
	ld	(ix - 9), hl
	ld	iy, (ix - 12)
	ld	hl, (iy + 1)
	ld	(ix - 12), hl
	ld	bc, 7
	ld	iy, (ix + 12)
.lbl_9:
	ld	hl, (ix - 3)
	call	ti._imulu
	push	hl
	pop	bc
	add	iy, bc
	ld	hl, (ix - 9)
	ld	(iy + 4), hl
	ld	bc, (ix - 12)
	add	hl, bc
	push	hl
	pop	iy
	ld	bc, (ix - 6)
	or	a, a
	sbc	hl, bc
	jr	nc, .lbl_12
.lbl_10:
	ld	hl, (ix - 3)
	inc	hl
	ld	(ix - 3), hl
	ld	bc, (ix + 15)
	jp	.lbl_1
.lbl_11:
	ld	(ix - 3), bc
.lbl_12:
	ld	hl, (ix - 3)
	ld	sp, ix
	pop	ix
	ret
