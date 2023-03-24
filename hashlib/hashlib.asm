;------------------------------------------
include '../../include/library.inc'

;------------------------------------------
library HASHLIB, 11

;------------------------------------------

;v10 functions
    export cryptx_hash_init
	export cryptx_hash_update
	export cryptx_hash_final
	export cryptx_hash_mgf1
    
    export cryptx_hmac_init
    export cryptx_hmac_update
    export cryptx_hmac_final
    export cryptx_hmac_pbkdf2
    
    export cryptx_digest_compare
    export cryptx_digest_tostring
    
    
; redefine functions as library namespace
cryptx_hash_init	= hash_init
cryptx_hash_update	= hash_update
cryptx_hash_final	= hash_final
cryptx_hash_mgf1	= hash_mgf1
cryptx_hmac_init	= hmac_init
cryptx_hmac_update	= hmac_update
cryptx_hmac_final	= hmac_final
cryptx_hmac_pbkdf2	= hmac_pbkdf2
cryptx_digest_compare	= digest_compare
cryptx_digest_tostring	= digest_tostring
    
    
    

;------------------------------------------
; helper macro for saving the interrupt state, then disabling interrupts
macro save_interrupts?
	ld a,i
	push af
	pop bc
	ld (.__interrupt_state),bc
    di
end macro

;------------------------------------------
; helper macro for restoring the interrupt state
macro restore_interrupts? parent
	ld bc,0
parent.__interrupt_state = $-3
	push bc
	pop af
	ret po
	ei
end macro

;------------------------------------------
; helper macro for restoring the interrupt state without prematurely returning
macro restore_interrupts_noret? parent
	ld bc,0
parent.__interrupt_state = $-3
	push bc
	pop af
	jp po,.__dont_reenable_interrupts
	ei
parent.__dont_reenable_interrupts = $
end macro

;------------------------------------------
; helper macro for restoring the interrupt state, preserving a
macro restore_interrupts_preserve_a? parent
	ld bc,0
parent.__interrupt_state = $-3
	push bc
	ld c,a
	pop af
	ld a,c
	ret po
	ei
end macro

;------------------------------------------
; helper macro for restoring the interrupt state without prematurely returning, preserving a
macro restore_interrupts_preserve_a? parent
	ld bc,0
parent.__interrupt_state = $-3
	push bc
	ld c,a
	pop af
	ld a,c
	jp po,.__dont_reenable_interrupts
	ei
parent.__dont_reenable_interrupts = $
end macro

;------------------------------------------
; defines

_indcallhl:
; Calls HL
; Inputs:
;  HL : Address to call
	jp	(hl)
 
_indcall:
; Calls IY
    jp  (iy)


;number of times to test each bit
_num_tests := 1024
_max_deviation := _num_tests/4
;------------------------------------------
; structures
virtual at 0
	offset_data     rb 64
	offset_datalen  rb 1
	offset_bitlen   rb 8
	offset_state    rb 4*8
	_sha256ctx_size:
end virtual

virtual at 0
	func_init		rb 3
	func_update		rb 3
	func_final		rb 3
	sha_ctx			rb _sha256ctx_size
	_hashctx_size:
end virtual
_sha256_m_buffer_length := 64*4

;-------------------------------------------
; hash func table
hash_func_lookup:
; sha256 func ptr and digest len
    dl hash_sha256_init
    dl hash_sha256_update
    dl hash_sha256_final
    db 32
    
hmac_func_lookup:
    dl hmac_sha256_init
    dl hmac_sha256_update
    dl hmac_sha256_final
    db 32



; probably better to just add the one u64 function used by hashlib rather than screw with dependencies
; void u64_addi(uint64_t *a, uint64_t *b);
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
 
 
?stackBot		:= 0D1987Eh
; use to erase the stack to prevent buffer leak side-channel attack
stack_clear:
    
    ; save a, hl, e
    ld (.smc_a), a
    ld (.smc_hl), hl
    ld a, e
    ld (.smc_e), a
    
    ; set from stackBot + 4 to ix - 1 to 0
    lea de, ix - 2
    ld hl, -(stackBot + 3)
    add hl, de
    push hl
    pop bc
    lea hl, ix - 1
    ld (hl), 0
    lddr
    
    ; restore a, hl, e
    ld e, 0
.smc_e:=$-1
    ld a, 0
.smc_a:=$-1
    ld hl, 0
.smc_hl:=$-3
    ld sp, ix
    pop ix
    ret
 
;------------------------------------------
	
 
hash_algs_impl  =   1
 
; hash_init(context, alg);
hash_init:
  	call	ti._frameset0
    ; (ix+0) return vector
    ; (ix+3) old ix
    ; (ix+6) context
    ; (ix+9) alg
    
    ; check if value of alg < hash_algs_impl, return 0 if not
    ld a, (ix + 9)
    ld l, a
    cp a, hash_algs_impl
    sbc a,a
    jr z, .exit
    
    ; multiply alg by 10 to get correct set of pointers
    ; copy 10 bytes from hmac_func_lookup+offset to context
    ld h, 10
    mlt hl
    ld bc, hash_func_lookup
    add hl, bc
    ld de, (ix + 6)
    ld bc, 10
    ldir
    
    ; push arguments onto stack for internal hash caller
    ld hl, (ix + 12)
    push hl
    ld hl, (ix + 9)
    push hl
    ld iy, (ix+6)
    pea iy + 10
    ld hl, (ix + 6)
    ld hl, (hl)
    call _indcallhl
    
    ; pop arguments from stack
    pop hl,hl,hl
    ld a, 1     ; return true
.exit:
    ld sp, ix
    pop ix
    ret
    
    
    
; hash_update(context, data, len);
hash_update:
    call	ti._frameset0
    ; (ix+0) return vector
    ; (ix+3) old ix
    ; (ix+6) context
    ; (ix+9) data
    ; (ix+12) len
    
    ld hl, (ix + 12)
    push hl
    ld hl, (ix + 9)
    push hl
    ld iy, (ix + 6)
    pea iy + 10
    ld hl, (iy + 3)
    call _indcallhl
    ld sp, ix
    pop ix
    ret
    
; hash_final(context, outbuf);
hash_final:
     call	ti._frameset0
    ; (ix+0) return vector
    ; (ix+3) old ix
    ; (ix+6) context
    ; (ix+9) outbuf
    
    ld hl, (ix + 9)
    push hl
    ld iy, (ix + 6)
    pea iy + 10
    ld hl, (iy + 6)
    call _indcallhl
    ld sp, ix
    pop ix
    ret
    
    
; hmac_init(context, key, keylen, alg);
hmac_init:
 	call	ti._frameset0
    ; (ix+0) return vector
    ; (ix+3) old ix
    ; (ix+6) context
    ; (ix+9) key
    ; (ix+12) keylen
    ; (ix+15) alg
    
    ; check if value of alg < hash_algs_impl, return 0 if not
    ld a, (ix + 15)
    ld l, a
    cp a, hash_algs_impl
    sbc a,a
    jr z, .exit
    
    ; multiply alg by 10 to get correct set of pointers
    ; copy 10 bytes from hmac_func_lookup+offset to context
    ld h, 10
    mlt hl
    ld bc, hmac_func_lookup
    add hl, bc
    ld de, (ix + 6)
    ld bc, 10
    ldir
    
    ; push arguments onto stack for internal hash caller
    ld hl, (ix + 12)
    push hl
    ld hl, (ix + 9)
    push hl
    ld iy, (ix+6)
    pea iy + 10
    ld hl, (iy)
    call _indcallhl
    
    ; pop arguments from stack
    pop hl,hl,hl
    ld a, 1     ; return true
.exit:
    ld sp, ix
    pop ix
    ret
    
    
; hmac_update(context, data, len);
hmac_update:
    call	ti._frameset0
    ; (ix+0) return vector
    ; (ix+3) old ix
    ; (ix+6) context
    ; (ix+9) data
    ; (ix+12) len
    
    ld hl, (ix + 12)
    push hl
    ld hl, (ix + 9)
    push hl
    ld iy, (ix + 6)
    pea iy + 10
    ld hl, (iy + 3)
    call _indcallhl
    ld sp, ix
    pop ix
    ret
    
; hash_final(context, outbuf);
hmac_final:
     call	ti._frameset0
    ; (ix+0) return vector
    ; (ix+3) old ix
    ; (ix+6) context
    ; (ix+9) outbuf
    
    ld hl, (ix + 9)
    push hl
    ld iy, (ix + 6)
    pea iy + 10
    ld hl, (iy + 6)
    call _indcallhl
    ld sp, ix
    pop ix
    ret
    
    
 
; void hash_sha256_init(SHA256_CTX *ctx);
hash_sha256_init:
    pop iy,de
    push de
    ld hl,$FF0000
    ld bc,offset_state
    ldir
    ld c,8*4
    ld hl,_sha256_state_init
    ldir
    ld a, 1
    jp (iy)
    

; void hashlib_Sha256Update(SHA256_CTX *ctx, const BYTE data[], size_t len);
hash_sha256_update:
	save_interrupts

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

	; scf
	; sbc hl,hl
	; ld (hl),2

	; get pointers to the things
	ld de, (ix + 9)			; de = source data
	ld hl, (ix + 6)			; hl = context, data ptr
	add hl, bc
	ex de, hl ;hl = source data, de = context / data ptr

	ld bc, (ix + 12)		   ; bc = len

	call _sha256_update_loop
	cp a,64
	call z,_sha256_update_apply_transform

	ld iy, (ix + 6)
	ld (iy + offset_datalen), a		   ;save current datalen
	pop ix

	restore_interrupts hash_sha256_update
	ret

_sha256_update_loop:
	inc a
	ldi ;ld (de),(hl) / inc de / inc hl / dec bc
	ret po ;return if bc==0 (ldi decrements bc and updates parity flag)
	cp a,64
	call z,_sha256_update_apply_transform
	jq _sha256_update_loop
_sha256_update_apply_transform:
	push hl, de, bc
	ld bc, (ix + 6)
	push bc
	call _sha256_transform	  ; if we have one block (64-bytes), transform block
	pop iy
	ld bc, 512				  ; add 1 blocksize of bitlen to the bitlen field
	push bc
	pea iy + offset_bitlen
	call u64_addi
	pop bc, bc, bc, de, hl
	xor a,a
	ld de, (ix + 6)
	ret

; void hashlib_Sha256Final(SHA256_CTX *ctx, BYTE hash[]);
hash_sha256_final:
	save_interrupts

	ld hl,-_sha256ctx_size
	call ti._frameset
	; ix-_sha256ctx_size to ix-1
	; (ix + 0) Return address
	; (ix + 3) saved IX
	; (ix + 6) arg1: ctx
	; (ix + 9) arg2: outbuf
	
	; scf
	; sbc hl,hl
	; ld (hl),2

	ld iy, (ix + 6)					; iy =  context block
	lea hl, iy
	lea de, ix-_sha256ctx_size
	ld bc, _sha256ctx_size
	ldir

	ld bc, 0
	ld c, (iy + offset_datalen)     ; data length
	lea hl, ix-_sha256ctx_size					; ld hl, context_block_cache_addr
	add hl, bc						; hl + bc (context_block_cache_addr + bytes cached)

	ld a,55
	sub a,c ;c is set to datalen earlier
	ld (hl),$80
	jq c, _sha256_final_over_56
	inc a
_sha256_final_under_56:
	ld b,a
	xor a,a
_sha256_final_pad_loop2:
	inc hl
	ld (hl), a
	djnz _sha256_final_pad_loop2
	jq _sha256_final_done_pad
_sha256_final_over_56:
	ld a, 64
	sub a,c
	ld b,a
	xor a,a
_sha256_final_pad_loop1:
	inc hl
	ld (hl), a
	djnz _sha256_final_pad_loop1
	push iy
	call _sha256_transform
	pop de
	ld hl,$FF0000
	ld bc,56
	ldir
_sha256_final_done_pad:
	lea iy, ix-_sha256ctx_size
	ld c, (iy + offset_datalen)
	ld b,8
	mlt bc ;multiply 8-bit datalen by 8-bit value 8
	push bc
	pea iy + offset_bitlen
	call u64_addi
	pop bc,bc

	lea iy, ix-_sha256ctx_size ;ctx
	lea hl,iy + offset_bitlen
	lea de,iy + offset_data + 63

	ld b,8
_sha256_final_pad_message_len_loop:
	ld a,(hl)
	ld (de),a
	inc hl
	dec de
	djnz _sha256_final_pad_message_len_loop

	push iy ;ctx
	call _sha256_transform
	pop iy

	ld hl, (ix + 9)
	lea iy, iy + offset_state
	ld b, 8
	call _sha256_reverse_endianness

	ld sp,ix
	pop ix

	restore_interrupts hash_sha256_final
	ret

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
macro _rotleft8?
	ld a,d
	ld d,e
	ld e,h
	ld h,l
	ld l,a
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
	ld b,2
	call _ROTRIGHT  ;rotate long accumulator another 2 bits right
	pop bc
	_xorbc d,e  ;xor third ROTRIGHT result with second ROTRIGHT result (upper 16 bits)
	pop bc
	_xorbc h,l  ;xor third ROTRIGHT result with second ROTRIGHT result (lower 16 bits)

	;we're cutting off upper 10 bits of first ROTRIGHT result meaning we're xoring by zero, so we can just keep the value of d.
	pop bc
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
._frame_offset := -41
	ld hl,._frame_offset
	call ti._frameset
	ld hl,_sha256_m_buffer
	add hl,bc
	or a,a
	sbc hl,bc
	jq z,._exit
	ld iy,(ix + 6)
	ld b,16
	call _sha256_reverse_endianness ;first loop is essentially just reversing the endian-ness of the data into m (both represented as 32-bit integers)

	ld iy,_sha256_m_buffer
	lea iy, iy + 16*4
	ld b, 64-16
._loop2:
	push bc
; m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
	ld hl,(iy + -2*4 + 0)
	ld de,(iy + -2*4 + 2)
	call _SIG1
	push de,hl
	ld hl,(iy + -15*4 + 0)
	ld de,(iy + -15*4 + 2)
	call _SIG0

; SIG0(m[i - 15]) + m[i - 16]
	ld bc, (iy + -16*4 + 0)
	_addbclow h,l
	ld bc, (iy + -16*4 + 2)
	_addbchigh d,e

; + SIG1(m[i - 2])
	pop bc
	_addbclow h,l
	pop bc
	_addbchigh d,e

; + m[i - 7]
	ld bc, (iy + -7*4)
	_addbclow h,l
	ld bc, (iy + -7*4 + 2)
	_addbchigh d,e

; --> m[i]
	ld (iy + 3), d
	ld (iy + 2), e
	ld (iy + 1), h
	ld (iy + 0), l

	lea iy, iy + 4
	pop bc
	djnz ._loop2


	ld iy, (ix + 6)
	lea hl, iy + offset_state
	lea de, ix + ._state_vars
	ld bc, 8*4
	ldir				; copy the ctx state to scratch stack memory (uint32_t a,b,c,d,e,f,g,h)

	ld (ix + ._i), c
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

	; scf
	; sbc hl,hl
	; ld (hl),2

; EP1(e)
; #define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
	ld hl,(ix + ._e + 0)
	ld de,(ix + ._e + 2)
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

; B0ED BDD0
	push de,hl
	ld hl,_sha256_m_buffer
	ld b,4
	ld c,(ix + ._i)
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

; m[i] + k[i]
	pop bc
	_addbclow d,e
	pop bc
	_addbchigh h,l

; m[i] + k[i] + h + EP1(e) + CH(e,f,g)
	pop bc
	_addbclow d,e
	pop bc
	_addbchigh h,l

; --> tmp1
	ld (ix + ._tmp1 + 3),h
	ld (ix + ._tmp1 + 2),l
	ld (ix + ._tmp1 + 1),d
	ld (ix + ._tmp1 + 0),e

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
	inc iy
	djnz ._loop3inner2

; EP0(a)
; #define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
	ld hl,(ix + ._a + 0)
	ld de,(ix + ._a + 2)
	ld b,2
	call _ROTRIGHT     ; x >> 2
	push de,hl
	_rotright8         ; x >> 10
	ld b,3
	call _ROTRIGHT     ; x >> 13
	push de,hl
	_rotright8         ; x >> 21
	inc b ;_ROTRIGHT sets b to zero
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
	ld a,(ix + ._i)
	inc a
	ld (ix + ._i),a
	cp a,64
	jq c,._loop3

	push ix
	ld iy, (ix + 6)
	lea iy, iy + offset_state
	lea ix, ix + ._state_vars
	ld b,8
._loop4:
	ld hl, (iy + 0)
	ld de, (ix + 0)
	ld a, (iy + 3)
	or a,a
	adc hl,de
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
    

 digest_compare:
    pop	iy, de, hl, bc
	push	bc, hl, de, iy
	xor	a, a
.loop:
	ld	iyl, a
	ld	a, (de)
	inc	de
	xor	a, (hl)
	or	a, iyl
	cpi
	jq	pe, .loop
	add	a, -1
	sbc	a, a
	inc	a
	ret
    
	
hash_mgf1:
	save_interrupts

 	ld	hl, -332
	call	ti._frameset
	ld	bc, -304
	lea	iy, ix
	add	iy, bc
	or	a, a
	sbc	hl, hl
	push	ix
	ld	bc, -307
	add	ix, bc
	ld	(ix), hl
	pop	ix
	ld	bc, -310
	lea	hl, ix
	add	hl, bc
	ld	(hl), iy
	lea	de, iy + 115
	ld	l, (ix + 18)
	push	hl
	ld	bc, -313
	lea	hl, ix
	add	hl, bc
	ld	(hl), de
	push	de
	call	cryptx_hash_init
	pop	hl
	pop	hl
	bit	0, a
	jp	z, .lbl_6
	ld	hl, (ix + 6)
	ld	de, (ix + 9)
	lea	bc, ix - 70
	ld	(ix - 3), de
	ld	de, -320
	lea	iy, ix
	add	iy, de
	ld	(iy), bc
	push	ix
	ld	de, -310
	add	ix, de
	ld	iy, (ix)
	pop	ix
	lea	bc, iy
	push	ix
	ld	de, -323
	add	ix, de
	ld	(ix), bc
	pop	ix
	ld	bc, 0
	ld	c, (iy + 124)
	ld	de, -316
	lea	iy, ix
	add	iy, de
	ld	(iy), bc
	ld	de, (ix - 3)
	push	de
	push	hl
	ld	bc, -313
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -317
	lea	hl, ix
	add	hl, bc
	ld	(hl), a
	call	cryptx_hash_update
	ld	de, (ix + 15)
	pop	hl
	pop	hl
	pop	hl
	push	de
	pop	bc
	xor	a, a
	ld	(ix - 3), bc
	ld	bc, -310
	lea	hl, ix
	add	hl, bc
	ld	(hl), a
	ld	bc, -317
	lea	iy, ix
	add	iy, bc
	ld	a, (iy)
	ld	iy, 0
	ld	bc, (ix - 3)
.lbl_2:
	lea	hl, iy
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_6
	ld	de, -326
	lea	hl, ix
	add	hl, de
	ld	(hl), iy
	push	bc
	pop	hl
	ld	(ix - 3), bc
	ld	bc, -316
	lea	iy, ix
	add	iy, bc
	ld	de, (iy)
	or	a, a
	sbc	hl, de
	ld	bc, (ix - 3)
	ld	(ix - 3), de
	ld	de, -329
	lea	hl, ix
	push	af
	add	hl, de
	pop	af
	ld	(hl), bc
	ld	de, (ix - 3)
	jr	c, .lbl_5
	push	de
	pop	bc
.lbl_5:
	ld	de, -332
	lea	hl, ix
	add	hl, de
	ld	(hl), bc
	ld	bc, -307
	lea	iy, ix
	add	iy, bc
	ld	de, (iy)
	push	de
	pop	bc
	ld	(ix - 3), de
	push	ix
	ld	de, -310
	add	ix, de
	ld	a, (ix)
	pop	ix
	ld	l, 24
	call	ti._lshru
	ld	a, c
	ld	(ix - 74), a
	ld	de, (ix - 3)
	push	de
	pop	bc
	ld	(ix - 3), de
	push	ix
	ld	de, -310
	add	ix, de
	ld	a, (ix)
	pop	ix
	ld	l, 16
	call	ti._lshru
	ld	a, c
	ld	(ix - 73), a
	ld	de, (ix - 3)
	push	ix
	ld	bc, -307
	add	ix, bc
	ld	(ix), de
	pop	ix
	ld	a, d
	ld	(ix - 72), a
	ld	a, e
	ld	(ix - 71), a
	push	ix
	ld	bc, -323
	add	ix, bc
	ld	de, (ix)
	pop	ix
	push	de
	pop	iy
	push	ix
	ld	bc, -313
	add	ix, bc
	ld	hl, (ix)
	pop	ix
	ld	bc, 115
	ldir
	ld	hl, 4
	push	hl
	pea	ix - 74
	push	iy
	call	cryptx_hash_update
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -320
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -323
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_hash_final
	pop	hl
	pop	hl
	ld	bc, -326
	lea	hl, ix
	add	hl, bc
	ld	de, (hl)
	ld	hl, (ix + 12)
	add	hl, de
	ld	bc, -332
	lea	iy, ix
	add	iy, bc
	ld	de, (iy)
	push	de
	push	ix
	ld	bc, -320
	add	ix, bc
	ld	de, (ix)
	pop	ix
	push	de
	push	hl
	call	ti._memcpy
	ld	bc, -326
	lea	hl, ix
	add	hl, bc
	ld	iy, (hl)
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -316
	lea	hl, ix
	add	hl, bc
	ld	de, (hl)
	add	iy, de
	push	ix
	ld	bc, -307
	add	ix, bc
	ld	hl, (ix)
	pop	ix
	push	ix
	ld	bc, -310
	add	ix, bc
	ld	e, (ix)
	pop	ix
	ld	bc, 1
	xor	a, a
	call	ti._ladd
	ld	(ix - 3), bc
	push	ix
	ld	bc, -307
	add	ix, bc
	ld	(ix), hl
	pop	ix
	push	ix
	ld	bc, -310
	add	ix, bc
	ld	(ix), e
	pop	ix
	push	ix
	ld	bc, -329
	add	ix, bc
	ld	hl, (ix)
	pop	ix
	push	ix
	ld	bc, -316
	add	ix, bc
	ld	de, (ix)
	pop	ix
	or	a, a
	sbc	hl, de
	ld	bc, (ix - 3)
	push	hl
	pop	bc
	push	ix
	ld	de, -317
	add	ix, de
	ld	a, (ix)
	pop	ix
	ld	de, (ix + 15)
	jp	.lbl_2
.lbl_6:
	ld	sp, ix
	pop	ix
	ret
    restore_interrupts_noret hash_mgf1
	jp stack_clear
 
 
hmac_sha256_init:
	save_interrupts

	ld	hl, -70
	call	ti._frameset
	ld	hl, 64
	ld	de, 0
	lea	bc, ix + -64
	ld	(ix + -67), bc
	push	hl
	push	de
	push	bc
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	ld	de, 65
	ld	hl, (ix + 12)
	or	a, a
	sbc	hl, de
	ld	de, 128
	jq	c, .lbl_2
	ld	hl, (ix + 6)
	add	hl, de
	ld	(ix + -70), hl
	push	hl
	call	hash_sha256_init
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, (ix + 12)
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + -70)
	push	hl
	call	hash_sha256_update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + -67)
	push	hl
	ld	hl, (ix + -70)
	push	hl
	call	hash_sha256_final
	jq	.lbl_3
.lbl_2:
	ld	hl, (ix + 12)
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + -67)
	push	hl
	call	ti._memcpy
	pop	hl
.lbl_3:
	pop	hl
	pop	hl
	ld	hl, 64
	push	hl
	ld	hl, 54
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 64
	push	hl
	ld	hl, 92
	push	hl
	ld	iy, (ix + 6)
	pea	iy + 64
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	ld	de, 64
	ld	bc, 0
.lbl_5:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	ld	hl, (ix + -67)
	jq	z, .lbl_7
	add	hl, bc
	ld	l, (hl)
	ld	iy, (ix + 6)
	add	iy, bc
	ld	a, (iy)
	xor	a, l
	ld	(iy), a
	ld	a, (iy + 64)
	xor	a, l
	ld	(iy + 64), a
	inc	bc
	jq	.lbl_5
.lbl_7:
	ld	hl, (ix + 6)
	ld	de, 128
	add	hl, de
	ld	(ix + -67), hl
	push	hl
	call	hash_sha256_init
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, 64
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix + -67)
	push	hl
	call	hash_sha256_update

	restore_interrupts_noret hmac_sha256_init
	jp stack_clear
    
 
hmac_sha256_update:
	call	ti._frameset0
	ld	hl, (ix + 6)
	ld	iy, (ix + 9)
	ld	bc, (ix + 12)
	ld	de, 128
	add	hl, de
	ld	de, 0
	push	de
	push	bc
	push	iy
	push	hl
	call	hash_sha256_update
	ld	sp, ix
	pop	ix
	ret
	
    
hmac_sha256_final:
	save_interrupts

    ld	hl, -280
	call	ti._frameset
	ld	bc, (ix + 6)
	ld	hl, 236
	lea	de, ix + -38
	ld	(ix + -3), bc
	ld	bc, -280
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), de
	push	ix
	ld	bc, -274
	add	ix, bc
	lea	de, ix + 0
	pop	ix
	push	ix
	ld	bc, -277
	add	ix, bc
	ld	(ix + 0), de
	pop	ix
	push	hl
	ld	bc, (ix + -3)
	push	bc
	push	de
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	de, 128
	ld	bc, -277
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	add	hl, de
	push	ix
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	ld	bc, -280
	add	ix, bc
	ld	de, (ix + 0)
	pop	ix
	push	de
	push	hl
	call	hash_sha256_final
	pop	hl
	pop	hl
	ld	bc, -277
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hash_sha256_init
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, 64
	push	hl
	ld	iy, (ix + 6)
	pea	iy + 64
	ld	bc, -277
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hash_sha256_update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, 32
	push	hl
	ld	bc, -280
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -277
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hash_sha256_update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 9)
	push	hl
	ld	bc, -277
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hash_sha256_final

	restore_interrupts_noret hmac_sha256_final
	jp stack_clear
	
    
hmac_sha256_reset:
	save_interrupts

    ld	hl, -3
	call	ti._frameset
	ld	hl, (ix + 6)
	ld	de, 128
	add	hl, de
	ld	(ix + -3), hl
	push	hl
	call	hash_sha256_init
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, 64
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix + -3)
	push	hl
	call	hash_sha256_update
	ld	sp, ix
	pop	ix

	restore_interrupts hmac_sha256_reset
	ret

hmac_pbkdf2:
	save_interrupts

	ld	hl, -655
	call	ti._frameset
	ld	bc, -381
	lea	iy, ix
	add	iy, bc
	xor	a, a
	lea	hl, iy
	push	ix
	ld	bc, -627
	add	ix, bc
	ld	(ix), iy
	pop	ix
	ld	(iy), a
	push	hl
	pop	iy
	lea	de, iy
	inc	de
	ld	bc, 242
	ldir
	ld	hl, (ix + 21)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_17
	ld	bc, -630
	lea	hl, ix
	add	hl, bc
	ld	(hl), iy
	ld	de, (ix + 9)
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_17
	ld	bc, (ix + 6)
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_17
	ld	hl, (ix + 18)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_17
	ld	hl, (ix + 24)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_17
	ld	l, (ix + 27)
	push	hl
	push	de
	push	bc
	ld	bc, -630
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_hmac_init
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	bit	0, a
	ld	a, 0
	jp	z, .lbl_17
	ld	de, -138
	lea	hl, ix
	add	hl, de
	ld	de, -636
	lea	iy, ix
	add	iy, de
	ld	(iy), hl
	ld	bc, 243
	ld	a, 1
	lea	hl, ix - 70
	push	ix
	ld	de, -633
	add	ix, de
	ld	(ix), hl
	pop	ix
	ld	de, -134
	lea	hl, ix
	add	hl, de
	push	ix
	ld	de, -639
	add	ix, de
	ld	(ix), hl
	pop	ix
	ld	(ix - 3), bc
	ld	bc, -624
	lea	hl, ix
	add	hl, bc
	push	hl
	pop	de
	or	a, a
	sbc	hl, hl
	push	ix
	ld	bc, -627
	add	ix, bc
	ld	iy, (ix)
	pop	ix
	ld	l, (iy + 9)
	lea	iy, ix
	add	iy, bc
	ld	(iy), hl
	ld	bc, -646
	lea	hl, ix
	add	hl, bc
	ld	(hl), de
	push	ix
	ld	bc, -630
	add	ix, bc
	ld	hl, (ix)
	pop	ix
	ld	bc, (ix - 3)
	ldir
	ld	bc, 1
	ld	l, b
	push	ix
	ld	de, -640
	add	ix, de
	ld	(ix), l
	pop	ix
	ld	de, (ix + 21)
	ld	iy, 0
.lbl_7:
	lea	hl, iy
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_17
	ex	de, hl
	lea	de, iy
	ld	(ix - 3), bc
	ld	bc, -643
	lea	iy, ix
	add	iy, bc
	ld	(iy), de
	or	a, a
	sbc	hl, de
	push	ix
	ld	de, -652
	add	ix, de
	ld	(ix), hl
	pop	ix
	ld	bc, (ix - 3)
	push	bc
	pop	de
	ld	(ix - 3), de
	push	ix
	ld	de, -640
	add	ix, de
	ld	h, (ix)
	pop	ix
	ld	a, h
	ld	l, 24
	call	ti._lshru
	ld	a, c
	push	ix
	ld	bc, -636
	add	ix, bc
	ld	iy, (ix)
	pop	ix
	ld	(iy), a
	ld	de, (ix - 3)
	push	de
	pop	bc
	ld	a, h
	ld	l, 16
	call	ti._lshru
	ld	a, c
	ld	bc, -636
	lea	iy, ix
	add	iy, bc
	ld	iy, (iy)
	ld	(iy + 1), a
	ld	a, d
	ld	(iy + 2), a
	push	ix
	ld	bc, -649
	add	ix, bc
	ld	(ix), de
	pop	ix
	ld	a, e
	ld	(iy + 3), a
	ld	hl, (ix + 15)
	push	hl
	ld	hl, (ix + 12)
	push	hl
	ld	bc, -630
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_hmac_update
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 4
	push	hl
	ld	bc, -636
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -630
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_hmac_update
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -633
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -630
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_hmac_final
	pop	hl
	pop	hl
	ld	bc, -627
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -633
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -639
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	iy, 1
.lbl_9:
	ld	bc, (ix + 18)
	lea	hl, iy
	ld	de, (ix + 24)
	or	a, a
	sbc	hl, de
	jp	z, .lbl_14
	ld	bc, -655
	lea	hl, ix
	add	hl, bc
	ld	(hl), iy
	ld	bc, -630
	lea	iy, ix
	add	iy, bc
	ld	iy, (iy)
	lea	de, iy
	push	ix
	ld	bc, -646
	add	ix, bc
	ld	hl, (ix)
	pop	ix
	ld	bc, 243
	ldir
	ld	bc, -627
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -633
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	push	iy
	call	cryptx_hmac_update
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -633
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -630
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_hmac_final
	pop	hl
	pop	hl
	ld	bc, -633
	lea	hl, ix
	add	hl, bc
	ld	iy, (hl)
	push	ix
	ld	bc, -639
	add	ix, bc
	ld	de, (ix)
	pop	ix
	ld	(ix - 3), de
	push	ix
	ld	de, -627
	add	ix, de
	ld	bc, (ix)
	pop	ix
	ld	de, (ix - 3)
.lbl_11:
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_13
	ex	de, hl
	ld	a, (hl)
	xor	a, (iy)
	ld	(hl), a
	dec	bc
	inc	hl
	ex	de, hl
	inc	iy
	jr	.lbl_11
.lbl_13:
	ld	de, -655
	lea	hl, ix
	add	hl, de
	ld	iy, (hl)
	inc	iy
	jp	.lbl_9
.lbl_14:
	ld	de, -652
	lea	hl, ix
	add	hl, de
	ld	iy, (hl)
	lea	hl, iy
	ld	(ix - 3), bc
	push	ix
	ld	bc, -627
	add	ix, bc
	ld	de, (ix)
	pop	ix
	or	a, a
	sbc	hl, de
	ld	bc, (ix - 3)
	jr	c, .lbl_16
	push	de
	pop	iy
.lbl_16:
	ld	(ix - 3), bc
	ld	bc, -643
	lea	hl, ix
	add	hl, bc
	ld	de, (hl)
	ld	bc, (ix - 3)
	push	bc
	pop	hl
	add	hl, de
	push	iy
	ld	bc, -639
	lea	iy, ix
	add	iy, bc
	ld	de, (iy)
	push	de
	push	hl
	call	ti._memcpy
	ld	bc, -643
	lea	hl, ix
	add	hl, bc
	ld	iy, (hl)
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -630
	lea	hl, ix
	add	hl, bc
	ld	de, (hl)
	push	ix
	ld	bc, -646
	add	ix, bc
	ld	hl, (ix)
	pop	ix
	ld	bc, 243
	ldir
	ld	bc, -627
	lea	hl, ix
	add	hl, bc
	ld	de, (hl)
	add	iy, de
	push	ix
	ld	bc, -649
	add	ix, bc
	ld	hl, (ix)
	pop	ix
	push	ix
	ld	bc, -640
	add	ix, bc
	ld	e, (ix)
	pop	ix
	ld	bc, 1
	xor	a, a
	call	ti._ladd
	push	hl
	pop	bc
	ld	(ix - 3), bc
	push	ix
	ld	bc, -640
	add	ix, bc
	ld	(ix), e
	pop	ix
	inc	a
	ld	de, (ix + 21)
	ld	bc, (ix - 3)
	jp	.lbl_7
.lbl_17:
	ld	sp, ix
	pop	ix
    restore_interrupts hmac_pbkdf2
	ret
 

digest_tostring:
	save_interrupts

	ld	hl, -9
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	hl, (ix + 12)
	ld	(ix + -3), hl
	lea	hl, iy + 0
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	c, 1
	ld	b, 0
	ld	a, c
	jq	z, .lbl_2
	ld	a, b
.lbl_2:
	ld	de, (ix + 9)
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	l, c
	jq	z, .lbl_4
	ld	l, b
.lbl_4:
	or	a, l
	ld	b, a
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_6
	ld	c, 0
.lbl_6:
	ld	l, 1
	ld	a, c
	or	a, b
	ld	c, a
	bit	0, c
	jq	nz, .lbl_11
	ld	b, 4
.lbl_8:
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_9
	ld	a, (iy)
	call	ti._bshru
	ld	(ix + -9), de
	ld	de, 0
	ld	e, a
	ld	hl, _hexc
	add	hl, de
	ld	a, (hl)
	ld	(ix + -6), iy
	ld	iy, (ix + -3)
	ld	(iy), a
	ld	hl, (ix + -6)
	ld	a, (hl)
	and	a, 15
	ld	de, 0
	ld	e, a
	ld	hl, _hexc
	add	hl, de
	ld	de, (ix + -9)
	ld	a, (hl)
	ld	(iy + 1), a
	lea	iy, iy + 2
	ld	(ix + -3), iy
	ld	iy, (ix + -6)
	dec	de
	inc	iy
	jq	.lbl_8
.lbl_9:
	ld	hl, (ix + -3)
	ld	(hl), 0
	ld	l, 1
.lbl_11:
	ld	a, c
	xor	a, l
	ld	sp, ix
	pop	ix

	restore_interrupts digest_tostring
	ret
 
 _hexc:     db	"0123456789ABCDEF"
 _hash_out_lens:    db 32

_sprng_entropy_pool.size = 119
virtual at $E30800
    _sprng_entropy_pool     rb _sprng_entropy_pool.size
    _sprng_sha_digest       rb 32
    _sprng_sha_mbuffer      rb (64*4)
    _sprng_sha_ctx          rb _sha256ctx_size
    _sprng_rand             rb 4
end virtual
_sha256_m_buffer    :=  _sprng_sha_mbuffer
 
 _sha256_state_init:
	dl 648807
	db 106
	dl 6794885
	db -69
	dl 7271282
	db 60
	dl 5240122
	db -91
	dl 938623
	db 81
	dl 354444
	db -101
	dl -8136277
	db 31
	dl -2044647
	db 91
 
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


