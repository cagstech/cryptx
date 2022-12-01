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
; hard limit to 32 bytes
; output in op1
; addition over a galois field of form GF(2^m) is mod 2 or just xor
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
; multiplication is add then double, then a polynomial reduction
_bigint_mul:
	ld hl, 32
	ti._frameset
	lea de, ix - 32		; stack mem?
	ld hl, (ix + 9)		; op1 (save a copy)
	ld bc, 32
	ldir				; ix - 32 = tmp = op1
	
	; zero out op1
	ld de, (ix + 9)
	ld (de), 0
	inc de
	ld hl, (ix + 6)
	ld bc, 32
	ldir				; op1 = res = 0
	
	ld hl, (ix + 3)		; op2 = for bit in bits
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
			
			; add op1 (res) + tmp
			ld hl, (ix +9)		; hl = op1 (dest)
			lea de, ix - 32		; de = tmp (src)
			ld b, 32
.loop_add:
			ld a, (de)
			and a, c
			xor a, (hl)
			ld (hl), a
			inc hl
			inc de
			djnz .loop_add
		
			; now double tmp
			lea hl, ix - 32		; tmp in hl
			ld b, 32
			or a				; reset carry
.loop_mul2:
			dec hl
			rl (hl)
			djnz .loop_mul2
			
			; now xor with polynomial if tmp degree too high
			; this means timing analysis will leak polynomial
			; however, this is a public spec and therefore not
			; implementation-breaking
			bit 1, (ix - 4)		; polynomial is 233 bits, check 234th bit
			jr z, .no_xor_poly

			lea hl, ix - 32		; dest = tmp (little endian)
			ld de, _polynomial+31	; (big endian)
			ld b, 32
.xor_poly_loop:
			ld a, (de)
			xor a, (hl)
			ld (hl), a
			inc hl					; while hl increments
			dec de					; de should decrement
			djnz .xor_poly_loop
.no_xor_poly
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
	
	


; after we compile, I'll remove this since its in the Curve specs
_polynomial:
db 0,0,0,1,0,0,0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0
