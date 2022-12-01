public _rmemcpy
public _bigint_add
public _bigint_sub
public _bigint_mul
public _bigint_iszero
public _bigint_setzero
public _bigint_isequal



; rmemcpy(void *dest, void *src, size_t len)
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


; bigint_iszero(uint8_t *op);
_bigint_iszero:
	pop hl,de
	push de,hl
	ld a, 0
	ld b, 34
.loop:
	or (hl)
	djnz .loop
	or a
	ret z
	ld a, 1
	ret


;bigint_setzero(uint8_t *op);
_bigint_setzero:
	pop de,hl
	push hl,de
	ld a, 0
	ld (de), a
	push de
	pop hl
	inc de
	ld bc, 31
	ldir


; bigint_isequal(uint8_t *op1, uint8_t *op2);
_bigint_isequal:
	call ti._frameset0
	ld hl, (ix + 3)
	ld de, (ix + 6)
	ld b, 32
.loop:
	ld a, (de)
	inc de
	xor (hl)
	djnz .loop
	add a, -1
	sbc a, a
	inc a
	ret


; bigint_add(uint8_t *op1, uint8_t *op2);
; hard limit to 34 bytes
; output in op1
; because its a binary field, add is xor
_bigint_add:
	ti._frameset0
	ld hl, (ix + 3)		; op2
	ld de, (ix + 6)		; op1
	ld b, 32
.loop:
	ld a,(de)
	;adc a,(hl)
	xor (hl)
	ld (de),a
	inc hl
	inc de
	djnz .loop
	ld sp, ix
	pop ix
	ret


; bigint_sub(uint8_t *op1, uint8_t *op2);
; on a binary field addition and subtraction are the same
_bigint_sub := _bigint_add
	

; bigint_mul(uint8_t *op1, uint8_t *op2)
_bigint_mul:
	ld hl, 32
	ti._frameset
	lea de, ix - 32		; stack mem?
	ld hl, (ix + 9)		; op1 (save a copy)
	ld bc, 32
	ldir
	
	; zero out op1
	ld de, (ix + 9)
	ld (de), 0
	inc de
	ld hl, (ix + 6)
	ld bc, 32
	ldir
	
	ld hl, (ix + 3)		; op2
	ld c, 32
.loop_op2
	ld a, (hl)
	ld b, 8
.loop_bits_in_byte:
	rla
	push af
		sbc a,a
		push bc, hl
			ld c,a
			ld hl, (ix + 6)
			ld b, 32
			or a
.loop_mul2:
			rl (hl)
			inc hl
			djnz .loop_mul2
			lea de, ix - 0
			ld b, 32
.loop_add:
			dec hl
			dec de
			ld a,(de)
			and a,c
			xor a,(hl)
			ld (hl),a
			djnz .loop_add
			add hl, 29
			bit 1, (hl)
			jr z, .skip_xor_poly
			ld de, _polynomial
			ex de, hl
			add hl, 32
			ex de, hl
			ld b, 32
.xor_poly_loop
			ld a, (de)
			xor a, (hl)
			ld (hl), a
			djnz .xor_poly_loop
.skip_xor_poly
		pop hl,bc
	pop af
	djnz .loop_bits_in_byte
	inc hl
	dec c
	jr nz, .loop_op2
	ld sp, ix
	pop ix
	ret
	

; bigint_invert(BIGINT op);
_bigint_invert:
; hl = ptr to bigint
	push bc
	ld b, 32
	or a
.loop:
	rl (hl)
	inc hl
	djnz .loop
	pop bc
	ret


; after we compile, I'll remove this since its in the Curve specs
_polynomial:
db 0,0,0,1,0,0,0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0
