
public _zero64
public _rmemcpy
public _aes_gf2_mul

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


_aes_gf2_mul_little:
; Galois-Field GF(2^128) multiplication routine
; little endian fields expected
	ld hl, -16
	call ti._frameset
	lea de, ix - 16		; stack mem?
	ld hl, (ix + 6)		; op1 (save a copy)
	ld bc, 16
	ldir				; ix - 32 = tmp = op1
 
	; zero out output
	ld de, (ix + 12)		; output
	xor a
	ld (de), a
	inc de
	ld hl, (ix + 12)
	ld bc, 15
	ldir
 
	ld hl, (ix + 9)		; op2 = for bit in bits
	ld b, 0
	ld c, 16
.loop_op2:
	ld a, (hl)
	push hl
		ld b, 8
.loop_bits_in_byte:
		rla
		push af
			sbc a,a
			push bc
				ld c,a
 
				; add out (res) + tmp
				ld hl, (ix + 12)		; hl = (dest)
				lea de, ix - 16		; de = tmp (src)
				ld b, 16
.loop_add:
				ld a, (de)
				and a, c
				xor a, (hl)
				ld (hl), a
				inc hl
				inc de
				djnz .loop_add
 
               ; now double tmp
				lea hl, ix - 16		; tmp in hl	little endian
                ld b, 16
                or a                ; reset carry
.loop_mul2:
                rr (hl)
                inc hl		; little endian
                djnz .loop_mul2
 
                ; now xor with polynomial x^128 + x^7 + x^2 + x + 1
                ; if bit 128 set, xor least-significant byte with 10000111b
 
                sbc a, a
			.smc_poly:=$+1
                and a, 11100001b
			.smc_read_byte:=$+2
                xor a, (ix - 16)		; little endian
			.smc_write_byte:=$+2
                ld (ix - 16), a
 
.no_xor_poly:
			pop bc
		pop af
		djnz .loop_bits_in_byte
	pop hl
	inc hl		; little endian
	dec c
	jr nz, .loop_op2
	ld sp, ix
	pop ix
	ret
	
_gf128_mul = _aes_gf2_mul_little
public _memrev

_memrev:
	ld iy, -3
	add iy, sp
	ld bc, (iy + 9)
	ld hl, (iy + 6)
	add hl, bc
	dec hl
	ld de, (iy + 6)
	inc bc
	res 0, c
.loop:
	ld a, (de)
	dec bc
	ldi
	dec hl
	ld (hl), a
	dec hl
	jp po, .loop
	ret


public _gf128_mul_set_polyval
_gf128_mul_set_polyval:
	ld a, 10000111b
	ld (_gf128_mul.smc_poly), a
	ld a, -1
	ld (_gf128_mul.smc_read_byte), a
	ld (_gf128_mul.smc_write_byte), a
	ret
	
public _gf128_mul_set_ghash
_gf128_mul_set_ghash:
	ld a, 11100001b
	ld (_gf128_mul.smc_poly), a
	ld a, -16
	ld (_gf128_mul.smc_read_byte), a
	ld (_gf128_mul.smc_write_byte), a
	ret
