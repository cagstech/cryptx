
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


_aes_gf2_mul:
	ld hl, -16
	call ti._frameset
	lea de, ix - 16		; stack mem?
	ld hl, (ix + 9)		; op1 (save a copy)
	ld bc, 16
	ldir				; ix - 32 = tmp = op1
	
	; zero out output
	ld de, (ix + 6)		; op 1
	xor a
	ld (de), a
	inc de
	ld hl, (ix + 6)
	ld bc, 15
	ldir
	
	ld hl, (ix + 12)		; op2 = for bit in bits
	ld c, 16
.loop_op2:
	ld a, (hl)
	push hl
		ld b, 8
.loop_bits_in_byte:
		rra
		push af
			sbc a,a
			push bc
				ld c,a
			
				; add op1 (res) + tmp
				ld hl, (ix + 6)		; hl = (dest)
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
		
				; check MSB of tmp
				ld a, (ix - 16)
				rla
				sbc a, a
				and a, 10000111b
				push af
					; now double tmp
					lea hl, ix - 16		; tmp in hl
					ld b, 16
					or a				; reset carry
.loop_mul2:
					rl (hl)
					inc hl
					djnz .loop_mul2
			
				; now xor with polynomial if tmp degree too high
				; method below is constant-time
				
				pop af
				xor a, (ix - 1)
				ld (ix - 1), a
				
			
.no_xor_poly:
			pop bc
		pop af
		djnz .loop_bits_in_byte
	pop hl
	inc hl
	dec c
	jr nz, .loop_op2
	ld sp, ix
	pop ix
	ret
