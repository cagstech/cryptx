export hashlib_Sha256Init
export hashlib_Sha256Update
export hashlib_Sha256Final

offset_data		 := 0
offset_datalen	  := offset_data+64
offset_bitlen	   := offset_datalen+1
offset_state		:= offset_bitlen+8
_sha256ctx_size	 := 4*8+offset_state
_sha256_m_buffer_length := 80*4

; probably better to just add the one u64 function used by hashlib rather than screw with dependencies
u64_addi:
	pop bc,hl,de
	push de,hl,bc
	xor a,a
	ld bc,(hl)
	ex hl,de
	adc hl,bc
	ex hl,de
	ld (hl),de
	inc hl
	inc hl
	inc hl
	ld b,5
	ld c,a
.loop:
	ld a,(hl)
	adc a,c
	ld (hl),a
	inc hl
	djnz .loop
	ret

; void hashlib_Sha256Init(SHA256_CTX *ctx, uint32_t *mbuffer);
hashlib_Sha256Init:
	pop bc,de
	ex (sp),hl
	push de,bc
	add hl,bc
	or a,a
	sbc hl,bc
	jr z,.dont_set_buffer
	ld (_sha256_m_buffer_ptr),hl
.dont_set_buffer:
	ld hl,$FF0000		   ; 64k of 0x00 bytes
	ld bc,_sha256ctx_size
	push de
	ldir
	pop hl
	ld c,offset_state
	add hl,bc
	ex hl,de
	ld c,8*4				; bc=0 prior to this, due to ldir
	ld hl,_sha256_state_init
	ldir
	ret

; void hashlib_Sha256Update(SHA256_CTX *ctx, const BYTE data[], size_t len);
hashlib_Sha256Update:
	call ti._frameset0
	; (ix + 0) RV
	; (ix + 3) old IX
	; (ix + 6) arg1: ctx
	; (ix + 9) arg2: data
	; (ix + 12) arg3: len

	ld iy, (ix + 6)			; iy = context, reference

		; start writing data to the right location in the data block
	ld a, (iy + offset_datalen)
	ld bc, 0
	ld c, a

	; get pointers to the things
	ld de, (ix + 9)			; de = source data
	ld hl, (ix + 6)			; hl = context, data ptr
	add hl, bc
	ex de, hl ;hl = source data, de = context / data ptr

	ld bc, (ix + 12)		   ; bc = len

	call _sha256_update_loop
_sha256_update_done:
	ld iy, (ix + 6)
	ld (iy + offset_datalen), a		   ;save current datalen
	pop ix
	ret

_sha256_update_loop:
	inc a
	cp a,64
	jr nz,.next
	push hl, de, bc
	ld bc, (ix + 6)
	push bc
	call _sha256_transform	  ; if we have one block (64-bytes), transform block
	ld hl, 512				  ; add 1 blocksize of bitlen to the bitlen field
	ex (sp),hl
	ld iy, (ix + 6)
	pea iy + offset_bitlen
	call u64_addi
	pop bc, bc, bc, de, hl
	xor a,a					 ; reset datalen to 0
.next:
	ld (iy + offset_datalen),a
	ldi ;ld (de),(hl) / inc de / inc hl / dec bc
	ret po
	jr _sha256_update_loop ;continue if bc > 0 (ldi decrements bc and updates parity flag)


; void hashlib_Sha256Final(SHA256_CTX *ctx, BYTE hash[]);
hashlib_Sha256Final:
	call ti._frameset0
	; (ix + 0) Return address
	; (ix + 3) saved IX
	; (ix + 6) arg1: ctx
	; (ix + 9) arg2: outbuf
	
	ld iy, (ix + 6)					; iy =  context block

	ld bc, 0
	ld c, (iy + offset_datalen)     ; data length
	ld hl, (ix + 6)					; ld hl, context_block_cache_addr
	add hl, bc						; hl + bc (context_block_cache_addr + bytes cached)

	ld a,56
	sub a,c ;c is set to datalen earlier
	ld (hl),$80
	jq c,_sha256_final_over_56
	ld b,a
	xor a,a
_sha_final_under_56_loop:
	inc hl
	ld (hl),a
	djnz _sha_final_under_56_loop
	jq _sha256_final_done_pad
_sha256_final_over_56:
	ld a,63 ;so we can turn the condition into a<64 into a<=63
	sub a,c ;c is set to datalen earlier
	jq c,_sha256_final_over_64 ;jump if datalen <= 63
	inc a ;adjust from earlier decrement
	ld b,a
	xor a,a
_sha256_final_64_loop:
	inc hl
	ld (hl),a
	djnz _sha256_final_64_loop
_sha256_final_over_64:
_sha256_final_done_pad:
	ld iy, (ix + 6)
	ld c, (iy + offset_datalen)
	ld b,8
	mlt bc ;multiply 8-bit datalen by 8-bit value 8
	push bc
	pea iy + offset_bitlen
	call u64_addi
	pop bc,bc

	ld iy, (ix + 6) ;ctx
	lea hl,iy + offset_bitlen
	lea de,iy + offset_datalen

	ld b,8
_sha256_final_pad_message_len_loop:
	ld a,(hl)
	ld (de),a
	inc hl
	dec de
	djnz _sha256_final_pad_message_len_loop

	ld bc, (ix + 6) ;ctx
	push bc
	call _sha256_transform
	pop bc

	ld b, 8
	ld hl, (ix + 9)
	ld iy, (ix + 6)
	lea iy, iy + offset_state
	pop ix
	; continue running into _sha256_reverse_endianness

; reverse b longs endianness from iy to hl
_sha256_reverse_endianness:
	ld a, (iy + 0)
	ld c, (iy + 1)
	ld d, (iy + 2)
	ld e, (iy + 3)
	ld (hl), e
	inc hl
	ld (hl), d
	inc hl
	ld (hl), c
	inc hl
	ld (hl), a
	inc hl
	lea iy, iy + 4
	djnz _sha256_reverse_endianness
	ret

; helper macro to xor [B,C] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _xorbc? R1,R2
	ld a,b
	xor a,R1
	ld R1,a
	ld a,c
	xor a,R2
	ld R2,a
end macro

; helper macro to add [B,C] with [R1,R2] storing into [R1,R2]
; destroys: af
; note: this will add including the carry flag, so be sure of what the carry flag is before this
; note: if you're chaining this into a number longer than 16 bits, the order must be low->high
macro _addbclow? R1,R2
	ld a,c
	add a,R2
	ld R2,a
	ld a,b
	adc a,R1
	ld R1,a
end macro
macro _addbchigh? R1,R2
	ld a,c
	adc a,R2
	ld R2,a
	ld a,b
	adc a,R1
	ld R1,a
end macro

; helper macro to move [d,e,h,l] <- [l,e,d,h] therefore shifting 8 bits right.
; destroys: af
macro _rotright8?
	ld a,l
	ld l,h
	ld h,e
	ld e,d
	ld d,a
end macro

; helper macro to move [d,e,h,l] <- [e,h,l,d] therefore shifting 8 bits left.
; destroys: af
macro _rotleft8? TR
	ld TR,d
	ld d,e
	ld e,h
	ld h,l
	ld l,TR
end macro

; helper macro to load [d,e,h,l] with (iy + offset * sizeof uint32_t)
; destroys: none
macro _longloaddehl_iy? offset
	ld de,(iy + (offset) * 4 + 2)
	ld hl,(iy + (offset) * 4 + 0)
end macro

; helper macro to load [d,e,h,l] with (ix + offset * sizeof uint32_t)
; destroys: none
macro _longloaddehl_iy? offset
	ld de,(ix + (offset) * 4 + 2)
	ld hl,(ix + (offset) * 4 + 0)
end macro

; helper macro to load [d,e,h,l] with (ix + offset)
; destroys: none
macro _loaddehl_ix? offset
	ld de,(ix + (offset) + 2)
	ld hl,(ix + (offset) + 0)
end macro



; #define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
;input: [d,e,h,l], b
;output: [d,e,h,l]
;destroys: af, b
_ROTLEFT:
	xor a,a
	rl l
	rl h
	rl e
	rl d
	adc a,l
	ld l,a
	djnz .
	ret

; #define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
;input: [d,e,h,l], b
;output: [d,e,h,l]
;destroys: af, b
_ROTRIGHT:
	xor a,a
	rr d
	rr e
	rr h
	rr l
	rra
	or a,d
	ld d,a
	djnz .
	ret

; #define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
;input [d,e,h,l]
;output [d,e,h,l]
;destroys af, bc
_SIG0:
	ld b,3
	call _ROTRIGHT  ;rotate long accumulator 3 bits right
	push hl,de	  ;save value for later
	ld b,4
	call _ROTRIGHT  ;rotate long accumulator another 4 bits right for a total of 7 bits right
	push hl,de	  ;save value for later
	_rotright8      ;rotate long accumulator 8 bits right
	ld b,3
	call _ROTRIGHT  ;rotate long accumulator another 3 bits right for a total of 18 bits right
	pop bc
	_xorbc d,e  ;xor third ROTRIGHT result with second ROTRIGHT result (upper 16 bits)
	pop bc
	_xorbc h,l  ;xor third ROTRIGHT result with second ROTRIGHT result (lower 16 bits)
	pop bc
	ld a,b
	and a,$1F   ;cut off the upper 3 bits from the result of the first ROTRIGHT call
	xor a,d	 ;xor first ROTRIGHT result with result of prior xor (upper upper 8 bits)
	ld d,a
	ld a,c
	xor a,e	 ;xor first ROTRIGHT result with result of prior xor (lower upper 8 bits)
	ld e,a
	pop bc
	_xorbc h,l  ;xor first ROTRIGHT result with result of prior xor (lower 16 bits)
	ret

; #define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
;input: [d,e,h,l]
;output: [d,e,h,l]
;destroys: af, bc
_SIG1:
	_rotright8      ;rotate long accumulator 8 bits right
	ld b,2
	call _ROTRIGHT  ;rotate long accumulator 2 bits right for a total of 10 bits right
	push hl,de	    ;save value for later
	_rotright8      ;rotate long accumulator 8 bits right for a total of 18 bits right
	ld b,1
	call _ROTLEFT  ;rotate long accumulator a bit left for a total of 17 bits right
	push hl,de	  ;save value for later
	ld b,11
	call _ROTRIGHT  ;rotate long accumulator another 2 bits right
	pop bc
	_xorbc d,e  ;xor third ROTRIGHT result with second ROTRIGHT result (upper 16 bits)
	pop bc
	_xorbc h,l  ;xor third ROTRIGHT result with second ROTRIGHT result (lower 16 bits)
	pop bc
	ld d,b     ;cut off upper 10 bits of first ROTRIGHT result meaning we're xoring by zero, so we can just load the value.
	ld a,c
	and a,$3F   ;cut off the upper 2 bits from the lower upper byte of the first ROTRIGHT result.
	xor a,e	 ;xor first ROTRIGHT result with result of prior xor (lower upper upper 8 bits)
	ld e,a
	pop bc
	_xorbc h,l  ;xor first ROTRIGHT result with result of prior xor (lower 16 bits)
	ret


; void _sha256_transform(SHA256_CTX *ctx);
_sha256_transform:
._h := -4
._g := -8
._f := -12
._e := -16
._d := -20
._c := -24
._b := -28
._a := -32
._state_vars := -32
._tmp1 := -36
._tmp2 := -40
._i := -41
._i2 := -42
._frame_offset := -42
	ld hl,._frame_offset
	call ti._frameset
	ld b,16
	ld iy,(ix + 6)
	ld hl,0
_sha256_m_buffer_ptr:=$-3
	add hl,bc
	or a,a
	sbc hl,bc
	jq z,._exit
if offset_data <> 0
	lea iy, iy + offset_data
end if
	call _sha256_reverse_endianness ;first loop is essentially just reversing the endian-ness of the data into the state (both represented as 32-bit integers)

	ld iy,(_sha256_m_buffer_ptr)
	lea iy, iy + 16*4
	ld b, 64-16
._loop2:
	push bc
; m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
	_longloaddehl_iy -2
	call _SIG1
	push de,hl
	_longloaddehl_iy -15
	call _SIG0
	push de,hl
	_longloaddehl_iy -16

; SIG0(m[i - 15]) + m[i - 16]
	pop bc
	_addbclow h,l
	pop bc
	_addbchigh d,e

; + SIG1(m[i - 2])
	pop bc
	_addbclow h,l
	pop bc
	_addbchigh d,e

; + m[i - 7]
	ld bc, (iy + -15*4)
	_addbclow h,l
	ld bc, (iy + -15*4 + 2)
	_addbchigh d,e

; --> m[i]
	ld (iy + 3), d
	ld (iy + 2), e
	ld (iy + 1), h
	ld (iy + 0), l

	lea iy, iy + 4
	pop bc
	djnz ._loop2


if offset_state <> 0
	ld iy, (ix + 6)
	lea hl, iy + offset_state - offset_datalen
else
	ld hl, (ix + 6)
end if
	lea de, ix + ._state_vars
	ld bc, 32
	ldir				; copy the state to scratch stack memory

	ld (ix + ._i2), c
	ld a, 64
	ld (ix + ._i), a
._loop3:
; tmp1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
; CH(e,f,g)
; #define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
	lea iy,ix
	ld b,4
._loop3inner1:
	ld a, (iy + ._e)
	xor a,$FF
	and a, (iy + ._g)
	ld c,a
	ld a, (iy + ._e)
	and a, (iy + ._f)
	xor a,c
	ld (iy + ._tmp1),a
	inc iy
	djnz ._loop3inner1

; EP1(e)
; #define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
	_loaddehl_ix ._e
	ld b,6    ;rotate e 6 bits right
	call _ROTRIGHT
	push de,hl
	ld b,5    ;rotate accumulator another 5 bits for a total of 11
	call _ROTRIGHT
	push de,hl
	_rotright8 ;rotate accumulator another 8 bits for a total of 19
	ld b,6
	call _ROTRIGHT ;rotate accumulator another 6 bits for a total of 25
	pop bc         ;ROTRIGHT(x,11) ^ ROTRIGHT(x,25)
	_xorbc h,l
	pop bc
	_xorbc d,e
	pop bc         ; ^ ROTRIGHT(x,6)
	_xorbc h,l
	pop bc
	_xorbc d,e

; EP1(e) + h
	ld bc, (ix + ._h)
	_addbclow h,l
	ld bc, (ix + ._h + 2)
	_addbchigh d,e

; h + EP1(e) + CH(e,f,g)
	ld bc, (ix + ._tmp1)
	_addbclow h,l
	ld bc, (ix + ._tmp1 + 2)
	_addbchigh d,e

	push de,hl
if offset_state <> 0
	ld iy, (ix + 6)
	lea hl, iy + offset_state
else
	ld hl, (ix + 6)
end if
	ld b,4
	ld c,(ix + ._i2)
	mlt bc
	add hl,bc
	ld de,(hl)
	inc hl
	inc hl
	ld hl,(hl)
	push hl,de
	ld hl,_sha256_k
	add hl,bc
	ld de,(hl)
	inc hl
	inc hl
	ld hl,(hl)
	ex hl,de

; m[i] + k[i]
	pop bc
	_addbclow h,l
	pop bc
	_addbchigh d,e

; h + EP1(e) + CH(e,f,g) + m[i] + k[i]
	pop bc
	_addbclow h,l
	pop bc
	_addbchigh d,e

	ld (ix + ._tmp1 + 3),d
	ld (ix + ._tmp1 + 2),e
	ld (ix + ._tmp1 + 1),h
	ld (ix + ._tmp1 + 0),l

; tmp2 = EP0(a) + MAJ(a,b,c);
; MAJ(a,b,c)
; #define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
	lea iy,ix
	ld b,4
._loop3inner2:
	ld a, (iy + ._a)
	and a, (iy + ._b)
	ld c,a
	ld a, (iy + ._a)
	and a, (iy + ._c)
	xor a,c
	ld c,a
	ld a, (iy + ._b)
	and a, (iy + ._c)
	xor a,c
	ld (iy + ._tmp2), a
	djnz ._loop3inner2

; EP0(a)
; #define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
	_loaddehl_ix ._a
	ld b,2
	call _ROTRIGHT     ; x >> 2
	push de,hl
	_rotright8
	ld b,3
	call _ROTRIGHT     ; x >> 13
	push de,hl
	_rotright8
	inc b
	call _ROTRIGHT     ; x >> 22
	pop bc             ; (x >> 22) ^ (x >> 13)
	_xorbc h,l
	pop bc
	_xorbc d,e
	pop bc             ; (x >> 2) ^ (x >> 22) ^ (x >> 13)
	_xorbc h,l
	pop bc
	_xorbc d,e

	ld bc, (ix + ._tmp2)  ; EP0(a) + MAJ(a,b,c)
	_addbclow h,l
	ld bc, (ix + ._tmp2 + 2)
	_addbchigh d,e
	ld (ix + ._tmp2 + 3), d
	ld (ix + ._tmp2 + 2), e
	ld (ix + ._tmp2 + 1), h
	ld (ix + ._tmp2 + 0), l

; h = g;
	ld hl, (ix + ._g + 0)
	ld a,  (ix + ._g + 3)
	ld (ix + ._h + 0), hl
	ld (ix + ._h + 3), a

; g = f;
	ld hl, (ix + ._f + 0)
	ld a,  (ix + ._f + 3)
	ld (ix + ._g + 0), hl
	ld (ix + ._g + 3), a

; f = e;
	ld hl, (ix + ._e + 0)
	ld a,  (ix + ._e + 3)
	ld (ix + ._f + 0), hl
	ld (ix + ._f + 3), a

; e = d + tmp1;
	ld hl, (ix + ._d + 0)
	ld a,  (ix + ._d + 3)
	ld de, (ix + ._tmp1 + 0)
	or a,a
	adc hl,de
	adc a, (ix + ._tmp1 + 3)
	ld (ix + ._e + 0), hl
	ld (ix + ._e + 3), a

; d = c;
	ld hl, (ix + ._c + 0)
	ld a,  (ix + ._c + 3)
	ld (ix + ._d + 0), hl
	ld (ix + ._d + 3), a

; c = b;
	ld hl, (ix + ._b + 0)
	ld a,  (ix + ._b + 3)
	ld (ix + ._c + 0), hl
	ld (ix + ._c + 3), a

; b = a;
	ld hl, (ix + ._a + 0)
	ld a,  (ix + ._a + 3)
	ld (ix + ._b + 0), hl
	ld (ix + ._b + 3), a

; a = tmp1 + tmp2;
	ld hl, (ix + ._tmp1 + 0)
	ld a,  (ix + ._tmp1 + 3)
	ld de, (ix + ._tmp2 + 0)
	or a,a
	adc hl,de
	adc a, (ix + ._tmp2 + 3)
	ld (ix + ._a + 0), hl
	ld (ix + ._a + 3), a

	inc (ix + ._i2)
	dec (ix + ._i) ;yes, this updates the Z flag
	jq nz,._loop3

	push ix
	ld iy, (ix+6)
	lea iy, iy + offset_state
	lea ix, ix + ._state_vars
	ld b,4
._loop4:
	ld hl, (iy + 0)
	ld de, (ix + 0)
	ld a, (iy + 3)
	add hl,de
	adc a,(ix + 3)
	ld (iy + 0), hl
	ld (iy + 3), a
	lea ix, ix + 4
	lea iy, iy + 4
	djnz ._loop4

	pop ix
._exit:
	ld sp,ix
	pop ix
	ret


_sha256_state_init:
	dd $6a09e667
	dd $bb67ae85
	dd $3c6ef372
	dd $a54ff53a
	dd $510e527f
	dd $9b05688c
	dd $1f83d9ab
	dd $5be0cd19

_sha256_k:
	dd	1116352408
	dd	1899447441
	dd	3049323471
	dd	3921009573
	dd	961987163
	dd	1508970993
	dd	2453635748
	dd	2870763221
	dd	3624381080
	dd	310598401
	dd	607225278
	dd	1426881987
	dd	1925078388
	dd	2162078206
	dd	2614888103
	dd	3248222580
	dd	3835390401
	dd	4022224774
	dd	264347078
	dd	604807628
	dd	770255983
	dd	1249150122
	dd	1555081692
	dd	1996064986
	dd	2554220882
	dd	2821834349
	dd	2952996808
	dd	3210313671
	dd	3336571891
	dd	3584528711
	dd	113926993
	dd	338241895
	dd	666307205
	dd	773529912
	dd	1294757372
	dd	1396182291
	dd	1695183700
	dd	1986661051
	dd	2177026350
	dd	2456956037
	dd	2730485921
	dd	2820302411
	dd	3259730800
	dd	3345764771
	dd	3516065817
	dd	3600352804
	dd	4094571909
	dd	275423344
	dd	430227734
	dd	506948616
	dd	659060556
	dd	883997877
	dd	958139571
	dd	1322822218
	dd	1537002063
	dd	1747873779
	dd	1955562222
	dd	2024104815
	dd	2227730452
	dd	2361852424
	dd	2428436474
	dd	2756734187
	dd	3204031479
	dd	3329325298

