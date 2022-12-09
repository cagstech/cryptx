public _rmemcpy
public _bigint_add
public _bigint_sub
public _bigint_mul
public _bigint_invert
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
; point_iszero(struct Point *pt)
_point_iszero:
	ld b, 60
	jr _iszero_begin
_bigint_iszero:
	ld b, 30
_iszero_begin:
	pop de,hl
	push hl,de
	or a
.loop:
	or (hl)
	djnz .loop
	or a
	ret z
	ld a, 1
	ret


; bigint_isequal(uint8_t *op1, uint8_t *op2);
; point_isequal(struct Point *pt1, struct Point *pt2);
_point_isequal:
	ld b, 60
	jr _isequal_begin
_bigint_isequal:
	ld b, 30
_isequal_begin:
	call ti._frameset0
	ld hl, (ix + 6)
	ld de, (ix + 9)
	ld c, 0
.loop:
	ld a, (de)
	xor (hl)
	or a, c
	ld c, a
	inc de
	inc hl
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
	call ti._frameset0
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
	call ti._frameset
	lea de, ix - 32		; stack mem?
	ld hl, (ix + 9)		; op1 (save a copy)
	ld bc, 32
	ldir				; ix - 32 = tmp = op1
	
	; zero out op1
	ld de, (ix + 9)		; op 1
	ld a, 0
	ld (de), a
	inc de
	ld hl, (ix + 9)
	ld bc, 31
	ldir				; op1 = res = 0
	
	ld hl, (ix + 6)		; op2 = for bit in bits
	ld c, 32
.loop_op2:
	ld a, (hl)
	ld b, 8
.loop_bits_in_byte:
	rra
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
			inc hl
			rl (hl)
			djnz .loop_mul2
			
			; now xor with polynomial if tmp degree too high
			; this means timing analysis will leak polynomial info
			; however, this is a public spec and therefore not
			; implementation-breaking
			bit 1, (ix - 4)		; polynomial is 233 bits, check 234th bit
			jr z, .no_xor_poly

			; xor byte 1 (little-endian encoding)
			ld a, (ix - 32 + 1)
			xor 2
			ld (ix - 32 + 1), a
			
			; xor byte 21 (little endian encoding)
			ld a, (ix - 32 + 21)
			xor 4
			ld (ix - 32 + 21), a
			
			; xor byte 28 (little endian encoding)
			ld a, (ix - 32 + 28)
			xor 1
			ld (ix - 32 + 28), a
			
.no_xor_poly:
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

; local definitions for ease of use
._tmp	:=	32
._g		:=	64
._v		:=	96
._h		:= 	128
	
	ld hl, 128
	call ti._frameset

; copy op to _tmp
	ld hl, (ix + 6)
	lea de, ix - ._tmp
	ld bc, 32
	ldir
	
; set _g to 0
	xor a
	ld (de), a
	push de
	pop hl
	inc de
	ld bc, 31
	ldir
	
; rcopy _polynomial to _v
	ld hl, polynomial + 31
	ld b, 31
.loop_copy_poly:
	ldi
	dec hl
	dec hl
	djnz .loop_copy_poly

; then set op to 1 (it is result)
	lea hl, ix - ._g	; g is filled with 0
	ld de, (ix + 6)
	ld bc, 32
	ldir
	dec de
	ld a, 1
	ld (de), a
	
; while tmp != 1
.while_tmp_not_1:
	lea hl, ix - ._tmp
	ld a, (hl)
	ld b, 31
	
; or all bytes in tmp
; if tmp == 1, result should be 1
	ld a, (hl)
	cp 1
	jr nz, .tmp_not_1
	inc hl
	ld b, 31
.or_tmp_loop:
	or (hl)
	inc hl
	djnz .or_tmp_loop
	or a
	jq z, .tmp_is_1			; if is 1, op should contain inverse
	
.tmp_not_1:
	dec hl

; compute degree of v (in bits)
	lea hl, ix - ._v
	call _get_degree
	ld b, a						; in b
	
; compute degree of tmp (in bits)
	lea hl, ix - ._tmp
	call _get_degree

; subtract degree(v) from degree(tmp)
	sub a, b
	
; if no carry, skip swaps
	jr nc, .noswap
	
	push af		; we will need a after the swapping is done
	
;	swap polynomial with tmp
		lea de, ix - ._tmp
		lea hl, ix - ._v
		call _copy_w_swap
		
;	swap result with g
		ld de, (ix + 6)
		lea hl, ix - ._g
		call _copy_w_swap
		
;	negate i
	pop af
	neg
	
.noswap:
	
; shift v left by a bits, result in h

	ld c, a
	push bc
.loop_lshift_v:
		lea de, ix - ._h
		lea hl, ix - ._v
		ld b, 32
		or a
.loop_lshift_v_inner:
		ld a, (hl)
		rla
		ld (de), a
		inc hl
		inc de
		djnz .loop_lshift_v_inner
		dec c
		jr nz, .loop_lshift_v
	
; add h to tmp
		dec hl						; hl should already point to end of _h
		lea de, ix - ._tmp + 31		; point de to end of _tmp
		ld b, 32
.loop_add_h_tmp:
		ld a, (de)
		xor (hl)
		ld (de), a
		dec de
		dec hl
		djnz .loop_add_h_tmp
		
; shift g left by i bits, result in h
	pop bc		; we need c back, logic repeats for shift g
.loop_lshift_g:
	lea de, ix - ._h
	lea hl, ix - ._g
	ld b, 32
	or a
.loop_lshift_g_inner:
	ld a, (hl)
	rla
	ld (de), a
	inc hl
	inc de
	djnz .loop_lshift_g_inner
	dec c
	jr nz, .loop_lshift_g
		
; add h to result (op)
	dec hl						; hl should already point to end of _h
	ld de, (ix + 6)
	ex de, hl
	ld bc, 31
	add hl, bc
	ex de, hl					; point de to end of op
	ld b, 32
.loop_add_h_op:
	ld a, (de)
	xor (hl)
	ld (de), a
	dec de
	dec hl
	djnz .loop_add_h_op
	
	jq .while_tmp_not_1
	
.tmp_is_1:
	ld sp, ix
	pop ix
	ret
	
section	.text,"ax",@progbits
	public	_get_degree
_get_degree:
; get degree of a little-endian bitvector pointed by hl
; degree in a
	ld bc, 32
	add hl, 32
	ld bc, 081Fh
.getdegree_byteloop:
	ld a, (hl)
.getdegree_checkbit:
	rla
	jr c, .getdegree_found_bit
	djnz .getdegree_checkbit
	dec hl
	dec c
	jr nz, .getdegree_byteloop
.getdegree_tmp_found_bit:
	dec b
	ld a, c
	rla
	rla
	rla
	or b
	ret

section	.text,"ax",@progbits
	public	_copy_w_swap
; swaps data at buffers pointed to by hl and de
; hardcoded 32 byte buffer
_copy_w_swap:
	ld b, 32
.loop:
	ld a, (hl)
	ld b, (de)
	ld (de), a
	ld a, b
	ld (hl), a
	inc hl
	inc de
	djnz .loop
	ret
	
; uint8_t ec_poly_get_degree(void* polynomial);
ec_poly_get_degree:
	pop bc,hl
	push hl,bc
_get_degree:
; input: hl = ptr to binary polynomial (little endian-encoded)
; func:
;		jump to end of polynomial
;		seek backwards to first set bit
;		return its 1-indexed degree
; output: a = degree of highest set bit + 1
; destroys: bc, flags
	ld bc, 31		; input is 30 bytes, jump to MSB (hl + 29)
	add hl, bc
	ld c, 32		; check 32 bytes
	xor a
.byte_loop:
	or (hl)		; if byte is 0
	jr nz, .found_byte
	dec hl
	dec c
	jr nz, .byte_loop
; exit
	ld a, 0
	ret
.found_byte:
; process bits
	ld b, 8
	ld a, (hl)
.bit_loop:
	rla
	jr c, .found_bit
	djnz .bit_loop
.found_bit:
	ld a, c
	dec a
	add a, a
	add a, a
	add a, a
	add a, b
	ret


section	.data,"aw",@progbits
	public	polynomial
; after we compile, I'll remove this since its in the Curve specs
polynomial:
db 0,0,0,1,0,0,0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0


ti._frameset := __frameset
ti._frameset0 := __frameset0

extern __frameset
extern __frameset0

