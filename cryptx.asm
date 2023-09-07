;------------------------------------------
include '../include/library.inc'

;------------------------------------------
library CRYPTX, 13

;------------------------------------------

; hashing functions
	export cryptx_hash_init
	export cryptx_hash_update
	export cryptx_hash_digest
	export cryptx_hash_mgf1
	export cryptx_hmac_init
	export cryptx_hmac_update
	export cryptx_hmac_digest
	export cryptx_hmac_pbkdf2
	export cryptx_digest_compare
	export cryptx_digest_tostring
	
; encryption functions
	export cryptx_csrand_init
	export cryptx_csrand_get
	export cryptx_csrand_fill
	export cryptx_aes_init
	export cryptx_aes_encrypt
	export cryptx_aes_decrypt
	export cryptx_aes_update_aad
	export cryptx_aes_digest
	export cryptx_aes_verify
	export cryptx_rsa_encrypt
	export cryptx_ecdh_publickey
	export cryptx_ecdh_secret
	
; encoding functions
	export cryptx_asn1_decode
	export cryptx_base64_encode
	export cryptx_base64_decode
	

; hazardous materials
	export cryptx_hazmat_aes_ecb_encrypt
	export cryptx_hazmat_aes_ecb_decrypt
	export cryptx_hazmat_rsa_oaep_encode
	export cryptx_hazmat_rsa_oaep_decode
	export cryptx_hazmat_powmod
	export cryptx_hazmat_ecc_point_add
	export cryptx_hazmat_ecc_point_double
	export cryptx_hazmat_ecc_point_mul_scalar
   
	
	
; redefine functions as library namespace
cryptx_hash_init	= hash_init
cryptx_hash_update	= hash_update
cryptx_hash_digest	= hash_final
cryptx_hash_mgf1	= hash_mgf1
cryptx_hmac_init	= hmac_init
cryptx_hmac_update	= hmac_update
cryptx_hmac_digest	= hmac_final
cryptx_hmac_pbkdf2	= hmac_pbkdf2
cryptx_digest_compare	= digest_compare
cryptx_digest_tostring	= digest_tostring
cryptx_csrand_init		= csrand_init
cryptx_csrand_get		= csrand_get
cryptx_csrand_fill		= csrand_fill
cryptx_aes_init			= aes_init
cryptx_aes_encrypt		= aes_encrypt
cryptx_aes_decrypt		= aes_decrypt
cryptx_rsa_encrypt		= rsa_encrypt
cryptx_ecdh_publickey	= ecdh_publickey
cryptx_ecdh_secret		= ecdh_secret
cryptx_hazmat_aes_ecb_encrypt		= aes_ecb_unsafe_encrypt
cryptx_hazmat_aes_ecb_decrypt		= aes_ecb_unsafe_decrypt
cryptx_hazmat_rsa_oaep_encode		= oaep_encode
cryptx_hazmat_rsa_oaep_decode		= oaep_decode
cryptx_hazmat_powmod				= _powmod
cryptx_hazmat_ecc_point_add		= _point_add
cryptx_hazmat_ecc_point_double	= _point_double
cryptx_hazmat_ecc_point_mul_scalar	= _point_mul_scalar

cryptx_internal_gf2_frombytes		= bigint_frombytes
cryptx_internal_gf2_tobytes			= bigint_tobytes
cryptx_internal_gf2_add				= _bigint_add
cryptx_internal_gf2_mul				= _bigint_mul
cryptx_internal_gf2_square			= _bigint_square
cryptx_internal_gf2_invert			= _bigint_invert
cryptx_asn1_decode		= _asn1_decode
cryptx_base64_encode	= base64_encode
cryptx_base64_decode	= base64_decode
	
	
	

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
	dl hash_sha1_init
	dl hash_sha1_update
	dl hash_sha1_final
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
	
 
hash_algs_impl  =   2
 
; hash_init(context, alg);
hash_init:
	call	ti._frameset0
	; (ix+0) return vector
	; (ix+3) old ix
	; (ix+6) context
	; (ix+9) alg
	; (ix + 12) flags
	
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

; helper macro to xor [(R3), (R3+1)] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _xoriix? R1,R2, R3
	ld a,R1
	xor a,(R3)
	ld R1,a
	ld a,R2
	xor a,(R3+1)
	ld R2,a
end macro

; helper macro to and [(R3), (R3+1)] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _andiix? R1,R2, R3
	ld a,R1
	and a,(R3)
	ld R1,a
	ld a,R2
	and a,(R3+1)
	ld R2,a
end macro

; helper macro to or [(R3), (R3+1)] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _oriix? R1,R2, R3
	ld a,R1
	or a,(R3)
	ld R1,a
	ld a,R2
	or a,(R3+1)
	ld R2,a
end macro

; helper macro to add [(R3), (R3+1)] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _addiix? R1,R2, R3
	ld a,R1
	add a,(R3)
	ld R1,a
	ld a,R2
	adc a,(R3+1)
	ld R2,a
end macro

; helper macro to adc [(R3), (R3+1)] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _adciix? R1,R2, R3
	ld a,R1
	adc a,(R3)
	ld R1,a
	ld a,R2
	adc a,(R3+1)
	ld R2,a
end macro

; helper macro to add [(R3), (R3+1)] with [R1,R2] storing into [(R3), (R3+1)]
; destroys: af
macro _addiix_store? R1,R2, R3
	ld a,R1
	add a,(R3)
	ld R1,a
	ld a,R2
	adc a,(R3+1)
	ld R2,a
end macro

; helper macro to adc [(R3), (R3+1)] with [R1,R2] storing into [(R3), (R3+1)]
; destroys: af
macro _adciix_store? R1,R2, R3
	ld a,R1
	adc a,(R3)
	ld (R3),a
	ld a,R2
	adc a,(R3+1)
	ld (R3+1),a
end macro

; helper macro to xor [R1,R2] with [R3,R4] storing into [R1,R2]
; destroys: af
macro _xor? R1,R2,R3,R4
	ld a,R1
	xor a,R3
	ld R1,a
	ld a,R2
	xor a,R4
	ld R2,a
end macro

; helper macro to or [R1,R2] with [R3,R4] storing into [R1,R2]
; destroys: af
macro _or? R1,R2,R3,R4
	ld a,R1
	or a,R3
	ld R1,a
	ld a,R2
	or a,R4
	ld R2,a
end macro

; helper macro to and [R1,R2] with [R3,R4] storing into [R1,R2]
; destroys: af
macro _and? R1,R2,R3,R4
	ld a,R1
	and a,R3
	ld R1,a
	ld a,R2
	and a,R4
	ld R2,a
end macro

; helper macro to add [R1,R2] with [R3,R4] storing into [R1,R2]
; destroys: af
macro _add? R1,R2,R3,R4
	ld a,R1
	add a,R3
	ld R1,a
	ld a,R2
	adc a,R4
	ld R2,a
end macro

; helper macro to adc [R1,R2] with [R3,R4] storing into [R1,R2]
; destroys: af
macro _adc? R1,R2,R3,R4
	ld a,R1
	adc a,R3
	ld R1,a
	ld a,R2
	adc a,R4
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

; void hash_sha1_init(SHA256_CTX *ctx);
hash_sha1_init:
	pop iy,de
	push de
	ld hl,$FF0000
	ld bc,offset_state
	ldir
	ld c,8*4
	ld hl,_sha1_state_init
	ldir
	ld a, 1
_indcall:
; Calls IY
	jp (iy)

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
	
; void hash_sha1_update(SHA256_CTX *ctx);
hash_sha1_update:
	save_interrupts

	call ti._frameset0
	; (ix + 0) RV
	; (ix + 3) old IX
	; (ix + 6) arg1: ctx
	; (ix + 9) arg2: data
	; (ix + 12) arg3: len

	ld iy, (ix + 6) ; iy = context
	
	ld a, (iy + offset_datalen)
	ld bc, 0
	ld c, a
	
	ld de, (ix+9)
	ld hl, (ix+6)
	add hl, bc
	ex de, hl

	ld bc, (ix + 12)
	call _sha1_update_loop
	cp a,64
	call z, _sha1_update_apply_transform
	
	ld iy, (ix+6)
	ld (iy + offset_datalen), a
	pop ix

	restore_interrupts hash_sha1_update
	ret

_sha1_update_loop:
	inc a
	ldi ;ld (de),(hl) / inc de / inc hl / dec bc
	ret po ;return if bc==0 (ldi decrements bc and updates parity flag)
	cp a,64
	call z, _sha1_update_apply_transform
	jr _sha1_update_loop
_sha1_update_apply_transform:
	push hl, de, bc
	ld bc, (ix + 6)
	push bc
	call _sha1_transform	  ; if we have one block (64-bytes), transform block
	pop iy
	ld bc, 512				  ; add 1 blocksize of bitlen to the bitlen field
	push bc
	pea iy + offset_bitlen
	call u64_addi
	pop bc, bc, bc, de, hl
	xor a,a
	ld de, (ix + 6)
	ret


; void hashlib_Sha1Final(SHA256_CTX *ctx, BYTE hash[]);
hash_sha1_final:
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
	jq c, _sha1_final_over_56
	inc a
_sha1_final_under_56:
	ld b,a
	xor a,a
_sha1_final_pad_loop2:
	inc hl
	ld (hl), a
	djnz _sha1_final_pad_loop2
	jr _sha1_final_done_pad
_sha1_final_over_56:
	ld a, 64
	sub a,c
	ld b,a
	xor a,a
_sha1_final_pad_loop1:
	inc hl
	ld (hl), a
	djnz _sha1_final_pad_loop1
	push iy
	call _sha1_transform
	pop de
	ld hl,$FF0000
	ld bc,56
	ldir
_sha1_final_done_pad:
	lea iy, ix-_sha1ctx_size
	ld c, (iy + offset_datalen)
	ld b,8
	mlt bc ;multiply 8-bit datalen by 8-bit value 8
	push bc
	pea iy + offset_bitlen
	call u64_addi
	pop bc,bc

	lea iy, ix-_sha1ctx_size ;ctx
	lea hl,iy + offset_bitlen
	lea de,iy + offset_data + 63

	ld b,8
_sha1_final_pad_message_len_loop:
	ld a,(hl)
	ld (de),a
	inc hl
	dec de
	djnz _sha1_final_pad_message_len_loop

	push iy ;ctx
	call _sha1_transform
	pop iy

	ld hl, (ix + 9)
	lea iy, iy + offset_state
	ld b, 8
	call _sha256_reverse_endianness

	ld sp,ix
	pop ix

	restore_interrupts hash_sha1_final
	ret

; void _sha1_transform(SHA256_CTX *ctx);
_sha1_transform:
._e := -4
._d := -8
._c := -12
._b := -16
._a := -20
._state_vars := -20
._tmp1 := -24
._tmp2 := -28
._i := -29
._frame_offset := -29
_sha1_w_buffer := _sha256_m_buffer ; reuse m buffer from sha256 as w
	ld hl,._frame_offset
	call ti._frameset
	ld hl,_sha1_k
	ld (.sha1_k_smc),hl
	ld hl,_sha1_w_buffer
	ld (.step_3_smc),hl
	add hl,bc
	or a,a
	sbc hl,bc
	jq z,._exit
	ld iy,_sha1_w_buffer
	ld b,16
	call _sha256_reverse_endianness ; first loop is essentially just reversing the endian-ness of the data into w
	ld iy, (ix + 6)
	lea hl, iy + offset_state
	lea de, ix + ._state_vars
	ld bc, 4*5
	ldir
	ld (ix + ._i), 0
.outerloop:
	ld a, (ix + ._i)
	cp a, 16
	jq c,.skip_inner_1
	and a, $F
	ld c,a
	sbc hl,hl
	ld l,a
	ld de, _sha1_w_buffer
	add hl,de ; &w[s]
	push hl
	ld a,c
	add a, 2
	ld c,a
	and a, $F
	sbc hl,hl
	ld l,a
	add hl,de ; &w[(s + 2) & 0xf]
	push hl
	ld a,c
	add a,8-2
	ld c,a
	and a,$F
	sbc hl,hl
	ld l,a
	add hl,de ; &w[(s + 8) & 0xf]
	push hl
	ld a,c
	add a,13-8
	and a,$F
	sbc hl,hl
	ld l,a
	add hl,de ; &w[(s + 13) & 0xf]

; w[(s+13)&0xf]
	ld de,(hl)
	inc hl
	inc hl
	ld bc,(hl)

; ^ w[(s+8)&0xf]
	pop hl
	_xorihl d,e
	_xorihl b,c

; ^ w[(s+2)&0xf]
	pop hl
	_xorihl d,e
	_xorihl b,c

; ^ w[s]
	pop hl
	_xorihl d,e
	_xorihl b,c

	ld h,b
	ld l,c
	ld b,1
	call _ROTLEFT
.skip_inner_1:
	
	ld a, (ix + ._i)
	cp a, 20
	jq nc,.i_gteq_20
; low word of ((~b) & d) | (b & c)
	ld de, (ix + ._d + 0)
	ld a, (ix + ._b + 0)
	cpl
	and a,e
	ld e,a
	ld a, (ix + ._b + 1)
	cpl
	and a,d
	ld d,a
	ld bc, (ix + ._b + 0)
	_andiix b,c, ix+._b+0
	ld a,c
	or a,e
	ld l,a
	ld a,b
	or a,d
	ld h,a
; high word of ((~b) & d) | (b & c)
	ld de, (ix + ._d + 2)
	ld a, (ix + ._b + 2)
	cpl
	and a,e
	ld e,a
	ld a, (ix + ._b + 3)
	cpl
	and a,d
	ld d,a
	ld bc, (ix + ._b + 2)
	_andiix b,c, ix+._b+2
	ld a,c
	or a,e
	ld e,a
	ld a,b
	or a,d
	ld d,a
	jq .step_3
.i_gteq_20:
	cp a,40
	jr nc,.i_gteq_40
.i_gteq_60:
	ld hl, (ix + ._b + 0)
	ld de, (ix + ._b + 2)
	_xoriix h,l, ix+._c+0
	_xoriix d,e, ix+._c+2
	_xoriix h,l, ix+._d+0
	_xoriix d,e, ix+._d+2
	jr .step_3
.i_gteq_40:
	cp a,60
	jr nc,.i_gteq_60
; low word of (b&c) | (b&d) | (c&d)
	ld hl, (ix + ._b + 0)
	_andiix h,l, ix+._c+0
	ld de, (ix + ._b + 0)
	_andiix d,e, ix+._d+0
	_or h,l,d,e
	ld de, (ix + ._b + 0)
	_andiix d,e, ix+._d+0
	_or h,l,d,e
; high word of (b&c) | (b&d) | (c&d)
	ld de, (ix + ._b + 0)
	_andiix d,e, ix+._c+0
	ld bc, (ix + ._b + 0)
	_andiix b,c, ix+._d+0
	_or d,e,b,c
	ld bc, (ix + ._b + 0)
	_andiix b,c, ix+._d+0
	_or d,e,b,c

.step_3:
	ld iy,_sha1_w_buffer
.step_3_smc := $-3
	_addiix h,l, ix+._e+0
	_adciix d,e, ix+._e+2
	_addiix h,l, iy+0
	_adciix d,e, iy+2
	ld iy,_sha1_k
.sha1_k_smc := $-3
	_addiix h,l, iy+0
	_adciix d,e, iy+2
	push de,hl
	ld hl,(ix + ._a + 0)
	ld de,(ix + ._a + 2)
	ld b,5
	call _ROTLEFT ; rotl32(a, 5)
	pop bc
	_add h,l,b,c
	pop bc
	_adc d,e,b,c
	; d,e,h,l = rotl32(a, 5) + f(t, b,c,d) + e + w[s] + k[t/20];
	push de,hl
	lea hl, ix + ._d + 3
	lea de, ix + ._e + 3
	ld bc,4*4
	lddr
	ld hl,(ix + ._c + 0)
	ld de,(ix + ._c + 2)
	ld b,32-30
	call _ROTRIGHT ; rotl32(b, 30)
	ld (ix + ._c + 0),l
	ld (ix + ._c + 1),h
	ld (ix + ._c + 2),e
	ld (ix + ._c + 3),d
	pop hl,de
	ld (ix + ._a + 0),l
	ld (ix + ._a + 1),h
	ld (ix + ._a + 2),e
	ld (ix + ._a + 3),d
	ld a, (ix + ._i)
	inc a
	cp a,80
	jr z,.done
	cp a,20
	jr z,.next_k
	cp a,40
	jr z,.next_k
	cp a,60
	jr nz,.not_next_k
.next_k:
	ld hl,(.sha1_k_smc)
	inc hl
	ld (.sha1_k_smc),hl
.not_next_k:	
	ld hl,(.step_3_smc)
	inc hl
	and a,$F
	jr nz,.set_step_3_smc
	ld hl,_sha1_w_buffer
.set_step_3_smc:
	ld (.step_3_smc),hl
	jq .loop
.done:
	ld iy, (ix + 6)
	
repeat 5
	ld hl,(ix + ._a + (% * 4 + 0))
	ld de,(ix + ._a + (% * 4 + 2))
	_addiix_store h,l, (iy + offset_state + (% * 4 + 0))
	_adciix_store d,e, (iy + offset_state + (% * 4 + 2))
end repeat

	ld sp,ix
	pop ix
	ret




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
	call	cryptx_hash_digest
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
	call	cryptx_hmac_digest
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
	call	cryptx_hmac_digest
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
 
 
_ll_swap_bytes:
; de = u8[8]
; reverses the bytes of a u8[8]
	pop bc, de
	push de, bc
	ld hl, 8
	add hl, de
; de = arg0, hl = arg0 + 8
	ld b, 4
.loop:
	dec hl
	ld a, (de)
	ldi
	dec hl
	ld (hl), a
	djnz .loop
	ret
	
_bytelen_to_bitlen:
; hl = size
; iy = dst
; converts a size_t to a u8[8]
; outputs in big endian
	pop bc, hl, iy
	push iy, hl, bc
	xor a, a
	add hl, hl
	adc a, a
	add hl, hl
	adc a, a
	add hl, hl
	adc a, a
	ld (iy + 5), a
	ld (iy + 6), h
	ld (iy + 7), l
	sbc hl, hl
	ld (iy + 0), hl
	ld (iy + 2), hl
	ret
 
; aes_gf2_mul(uint8_t *op1, uint8_t *op2, uint8_t *out);
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
			 and a, 11100001b
			 xor a, (ix - 16)		; little endian
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
 
 
;------------------------------------------
; csrand_init(void);
;------------------------------------------
csrand_init:
; ix = selected byte
; de = current deviation
; hl = starting address
; inputs: stack = samples / 4, Max is 256 (256*4 = 1024 samples)
; outputs: hl = address
	ld de, 256		; thorough sampling
.start:
	ld a, e
	ld (_smc_samples), a
 
	push ix
	   ld ix, 0
	   ld hl, $D65800
	   ld bc,513
.test_range_loop:
	   push bc
		  call _test_byte
	   pop bc
	   cpi
	   jp pe,.test_range_loop
 
	   lea hl, ix+0
	   ld (_sprng_read_addr), hl
 
	   xor a, a
	   sbc hl, bc  ; subtract 0 to set the z flag if HL is 0
	pop ix
	ret z
	ld bc,0x0218
	ld (_csrand_init_skip_smc),bc
	inc a
	ret
 
_test_byte:
; inputs: hl = byte
; inputs: de = minimum deviance
; inputs: ix = pointer to the byte with minimum deviance
; outputs: de is the new minimum deviance (if updated)
; outputs: ix updated to hl if this byte contains the bit with lowest deviance
; outputs: b = 0
; outputs: a = 0x86
; destroys: f
; modifies: a, b, de, ix
	ld a,0x46 ; second half of the `bit 0,(hl)` command
.test_byte_bitloop:
	push hl
	   push de
		  call _test_bit  ; HL = deviance (|desired - actual|)
	   pop de
 
	   add a,8       ; never overflows, so resets carry
	   sbc hl, de    ; check if HL is smaller than DE
 
	   jq nc, .skip_next_bit          ; HL >= DE
	   add hl,de
	   ex de,hl
	   pop ix
	   push ix
.skip_next_bit:
	pop hl
	cp 0x86
	jq nz, .test_byte_bitloop
	ret
  
_test_bit:
; inputs: a = second byte of CB**
; inputs: hl = byte
; outputs: hl = hit count
; destroys: af, bc, de, hl
 
_smc_samples:=$+1
	ld b,0
	ld (.smc1),a
	ld (.smc2),a
	ld (.smc3),a
	ld (.smc4),a
	ld de,0
.loop:
	bit 0,(hl)
.smc1:=$-1
	jq z,.next1
	inc de
.next1:
	bit 0,(hl)
.smc2:=$-1
	jq nz,.next2    ; notice the inverted logic !
	dec de          ; and the dec instead of inc !
.next2:
	bit 0,(hl)
.smc3:=$-1
	jq z, .next3
	inc de
.next3:
	bit 0,(hl)
.smc4:=$-1
	jq nz,.next4    ; notice the inverted logic !
	dec de          ; and the dec instead of inc !
.next4:
	djnz .loop
 
	; return |DE|
	or a,a
	sbc hl,hl
	sbc hl,de
	ret nc
	ex de,hl
	ret
	
	
hashlib_SPRNGAddEntropy:
	ld hl, (_sprng_read_addr)
	add	hl,de
	or	a,a
	sbc	hl,de
	ret z
	ld de, _sprng_entropy_pool
	ld b, 119
.byte_read_loop:
	ld a, (hl)
	xor a, (hl)
	xor a, (hl)
	xor a, (hl)
	xor a, (hl)
	xor a, (hl)
	xor a, (hl)
	ld (de), a
	inc de
	djnz .byte_read_loop
	ret
	
 
csrand_get:

	save_interrupts

_csrand_init_skip_smc	:=	$
	call csrand_init

; set rand to 0
	ld hl, 0
	ld a, l
	ld (_sprng_rand), hl
	ld (_sprng_rand+3), a
	call hashlib_SPRNGAddEntropy
; hash entropy pool
	ld hl, 0
	push hl
	ld hl, _sprng_hash_ctx
	push hl
	call cryptx_hash_init
	pop bc, hl
	ld hl, 119
	push hl
	ld hl, _sprng_entropy_pool
	push hl
	push bc
	call cryptx_hash_update
	pop bc, hl, hl
	ld hl, _sprng_sha_digest
	push hl
	push bc
	call cryptx_hash_digest
	pop bc, hl
	
; xor hash cyclically into _rand
	ld hl,_sprng_sha_digest
	ld de,_sprng_rand
	ld c,4
.outer:
	xor a,a
	ld b,8
.inner:
	xor a,(hl)
	inc hl
	djnz .inner
	ld (de),a
	inc de
	dec c
	jq nz,.outer
	
; destroy sprng state
	ld hl, _sprng_entropy_pool
	ld (hl), 0
	ld de, _sprng_entropy_pool + 1
	ld bc, _sprng_rand - _sprng_entropy_pool - 1
	ldir
	
	ld hl, (_sprng_rand)
	ld a, (_sprng_rand+3)
	ld e, a

.return:
	restore_interrupts csrand_get
	ret
	
 
 L_.str2:
	db	"%lu",012o,000o
 
csrand_fill:
	save_interrupts

	ld	hl, -10
	call	ti._frameset
	ld	de, (ix + 9)
	ld	iy, 0
	ld	(ix + -7), de
.lbl1:
	lea	hl, iy + 0
	or	a, a
	sbc	hl, de
	jq	nc, .lbl2
	ld	(ix + -10), iy
	call	csrand_get
	ld	(ix + -4), hl
	ld	(ix + -1), e
	ld	de, (ix + -10)
	ld	iy, (ix + 6)
	add	iy, de
	ld	bc, (ix + -7)
	push	bc
	pop	hl
	ld	de, 4
	or	a, a
	sbc	hl, de
	jq	c, .lbl5
	ld	bc, 4
.lbl5:
	push	bc
	pea	ix + -4
	push	iy
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	iy, (ix + -10)
	ld	de, 4
	add	iy, de
	ld	de, -4
	ld	hl, (ix + -7)
	add	hl, de
	ld	(ix + -7), hl
	ld	de, (ix + 9)
	jq	.lbl1
.lbl2:
	ld	sp, ix
	pop	ix

	restore_interrupts csrand_fill
	ret
	
	
_xor_buf:
	ld	hl, -3
	call	ti._frameset
	ld	de, (ix + 6)
	ld	iy, (ix + 9)
	ld	bc, (ix + 12)
.lbl_1:
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_3
	ld	a, (iy)
	ld	(ix - 3), iy
	ex	de, hl
	xor	a, (hl)
	ld	iy, (ix - 3)
	ld	(iy), a
	inc	hl
	ex	de, hl
	ld	iy, (ix - 3)
	inc	iy
	dec	bc
	jr	.lbl_1
.lbl_3:
	pop	hl
	pop	ix
	ret
	
_aes_SubWord:
	ld	hl, -9
	call	ti._frameset
	ld	bc, (ix + 6)
	ld	a, (ix + 9)
	ld	iy, 15
	ld	l, 4
	call	ti._lshru
	push	bc
	pop	hl
	lea	bc, iy + 0
	call	ti._iand
	push	hl
	pop	de
	ld	hl, (ix + 6)
	call	ti._iand
	push	hl
	pop	iy
	ex	de, hl
	ld	c, 4
	call	ti._ishl
	push	hl
	pop	de
	ld	hl, _aes_sbox
	add	hl, de
	lea	de, iy + 0
	add	hl, de
	ld	a, (hl)
	or	a, a
	sbc	hl, hl
	ld	l, a
	ld	(ix + -3), hl
	ld	l, 12
	ld	bc, (ix + 6)
	ld	e, (ix + 9)
	ld	a, e
	call	ti._lshru
	push	bc
	pop	hl
	ld	iy, 15
	lea	bc, iy + 0
	call	ti._iand
	ld	(ix + -6), hl
	ld	l, 8
	ld	bc, (ix + 6)
	ld	a, e
	call	ti._lshru
	push	bc
	pop	hl
	lea	bc, iy + 0
	call	ti._iand
	push	hl
	pop	de
	ld	hl, (ix + -6)
	ld	c, 4
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	bc, 0
	ld	c, a
	ld	d, 0
	ld	a, d
	ld	l, 8
	call	ti._lshl
	push	bc
	pop	hl
	ld	e, a
	ld	bc, (ix + -3)
	ld	a, d
	call	ti._ladd
	ld	(ix + -3), hl
	ld	(ix + -6), e
	ld	l, 20
	ld	iy, (ix + 6)
	lea	bc, iy + 0
	ld	a, (ix + 9)
	call	ti._lshru
	push	bc
	pop	hl
	ld	de, 15
	push	de
	pop	bc
	call	ti._iand
	ld	(ix + -9), hl
	ld	l, 16
	lea	bc, iy + 0
	ld	a, (ix + 9)
	ld	iyl, a
	ex	de, hl
	ld	iyh, e
	ex	de, hl
	call	ti._lshru
	push	bc
	pop	hl
	push	de
	pop	bc
	call	ti._iand
	push	hl
	pop	de
	ld	hl, (ix + -9)
	ld	c, 4
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	bc, 0
	ld	c, a
	xor	a, a
	ex	de, hl
	ld	e, iyh
	ex	de, hl
	call	ti._lshl
	ld	hl, (ix + -3)
	ld	e, (ix + -6)
	call	ti._ladd
	ld	(ix + -3), hl
	ld	(ix + -6), e
	ld	l, 28
	ld	de, (ix + 6)
	push	de
	pop	bc
	ex	de, hl
	ld	d, iyl
	ex	de, hl
	ld	a, h
	call	ti._lshru
	push	bc
	pop	iy
	ld	l, 24
	push	de
	pop	bc
	ld	a, h
	call	ti._lshru
	push	bc
	pop	hl
	ld	bc, 15
	call	ti._iand
	push	hl
	pop	de
	lea	hl, iy + 0
	ld	c, 4
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	bc, 0
	ld	c, a
	xor	a, a
	ld	l, 24
	call	ti._lshl
	ld	hl, (ix + -3)
	ld	e, (ix + -6)
	call	ti._ladd
	ld	sp, ix
	pop	ix
	ret
	
	
_aes_AddRoundKey:
	ld	hl, -3
	call	ti._frameset
	ld	iy, (ix + 9)
	ld	de, (iy)
	ld	h, (iy + 3)
	ld	l, 24
	push	de
	pop	bc
	ld	a, h
	call	ti._lshru
	ld	(ix + -3), bc
	ld	l, 16
	push	de
	pop	bc
	ld	a, h
	call	ti._lshru
	ld	iy, (ix + 6)
	ld	a, (iy)
	ld	hl, (ix + -3)
	xor	a, l
	ld	(iy), a
	ld	a, (iy + 4)
	xor	a, c
	ld	(iy + 4), a
	ld	a, (iy + 8)
	xor	a, d
	ld	(iy + 8), a
	ld	a, (iy + 12)
	xor	a, e
	ld	(iy + 12), a
	ld	hl, (ix + 9)
	push	hl
	pop	iy
	ld	de, (iy + 4)
	ld	h, (iy + 7)
	push	de
	pop	bc
	ld	a, h
	ld	l, 24
	call	ti._lshru
	ld	(ix + -3), bc
	push	de
	pop	bc
	ld	a, h
	ld	l, 16
	call	ti._lshru
	ld	iy, (ix + 6)
	ld	a, (iy + 1)
	ld	hl, (ix + -3)
	xor	a, l
	ld	(iy + 1), a
	ld	a, (iy + 5)
	xor	a, c
	ld	(iy + 5), a
	ld	a, (iy + 9)
	xor	a, d
	ld	(iy + 9), a
	ld	a, (iy + 13)
	xor	a, e
	ld	(iy + 13), a
	ld	hl, (ix + 9)
	push	hl
	pop	iy
	ld	de, (iy + 8)
	ld	h, (iy + 11)
	push	de
	pop	bc
	ld	a, h
	ld	l, 24
	call	ti._lshru
	ld	(ix + -3), bc
	push	de
	pop	bc
	ld	a, h
	ld	l, 16
	call	ti._lshru
	ld	iy, (ix + 6)
	ld	a, (iy + 2)
	ld	hl, (ix + -3)
	xor	a, l
	ld	(iy + 2), a
	ld	a, (iy + 6)
	xor	a, c
	ld	(iy + 6), a
	ld	a, (iy + 10)
	xor	a, d
	ld	(iy + 10), a
	ld	a, (iy + 14)
	xor	a, e
	ld	(iy + 14), a
	ld	hl, (ix + 9)
	push	hl
	pop	iy
	ld	de, (iy + 12)
	ld	h, (iy + 15)
	push	de
	pop	bc
	ld	a, h
	ld	l, 24
	call	ti._lshru
	ld	(ix + -3), bc
	push	de
	pop	bc
	ld	a, h
	ld	l, 16
	call	ti._lshru
	ld	iy, (ix + 6)
	ld	a, (iy + 3)
	ld	hl, (ix + -3)
	xor	a, l
	ld	(iy + 3), a
	ld	a, (iy + 7)
	xor	a, c
	ld	(iy + 7), a
	ld	a, (iy + 11)
	xor	a, d
	ld	(iy + 11), a
	ld	a, (iy + 15)
	xor	a, e
	ld	(iy + 15), a
	pop	hl
	pop	ix
	ret
	
_aes_SubBytes:
	call	ti._frameset0
	ld	hl, (ix + 6)
	ld	iy, _aes_sbox
	ld	a, (hl)
	ld	de, 0
	ld	e, a
	ld	b, 4
	push	de
	pop	hl
	ld	c, b
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	lea	hl, iy + 0
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy), a
	ld	a, (iy + 1)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 1), a
	ld	a, (iy + 2)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 2), a
	ld	a, (iy + 3)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 3), a
	ld	a, (iy + 4)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	iy, _aes_sbox
	lea	hl, iy + 0
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 4), a
	ld	a, (iy + 5)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 5), a
	ld	a, (iy + 6)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 6), a
	ld	a, (iy + 7)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	iy, _aes_sbox
	lea	hl, iy + 0
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 7), a
	ld	a, (iy + 8)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 8), a
	ld	a, (iy + 9)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 9), a
	ld	a, (iy + 10)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 10), a
	ld	a, (iy + 11)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 11), a
	ld	a, (iy + 12)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 12), a
	ld	a, (iy + 13)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 13), a
	ld	a, (iy + 14)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	ld	b, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	ld	c, b
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 14), a
	ld	a, (iy + 15)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 15), a
	pop	ix
	ret
	
_aes_InvSubBytes:
	call	ti._frameset0
	ld	hl, (ix + 6)
	ld	iy, _aes_invsbox
	ld	a, (hl)
	ld	de, 0
	ld	e, a
	ld	b, 4
	push	de
	pop	hl
	ld	c, b
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	lea	hl, iy + 0
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy), a
	ld	a, (iy + 1)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 1), a
	ld	a, (iy + 2)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 2), a
	ld	a, (iy + 3)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 3), a
	ld	a, (iy + 4)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	iy, _aes_invsbox
	lea	hl, iy + 0
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 4), a
	ld	a, (iy + 5)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 5), a
	ld	a, (iy + 6)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 6), a
	ld	a, (iy + 7)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	iy, _aes_invsbox
	lea	hl, iy + 0
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 7), a
	ld	a, (iy + 8)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 8), a
	ld	a, (iy + 9)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 9), a
	ld	a, (iy + 10)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 10), a
	ld	a, (iy + 11)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 11), a
	ld	a, (iy + 12)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 12), a
	ld	a, (iy + 13)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 13), a
	ld	a, (iy + 14)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	ld	b, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	ld	c, b
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 14), a
	ld	a, (iy + 15)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 15), a
	pop	ix
	ret
	
_aes_ShiftRows:
	call	ti._frameset0
	ld	iy, (ix + 6)
	ld	a, (iy + 4)
	ld	l, (iy + 5)
	ld	(iy + 4), l
	ld	l, (iy + 6)
	ld	(iy + 5), l
	ld	l, (iy + 7)
	ld	(iy + 6), l
	ld	(iy + 7), a
	ld	a, (iy + 8)
	ld	l, (iy + 10)
	ld	(iy + 8), l
	ld	(iy + 10), a
	ld	a, (iy + 9)
	ld	l, (iy + 11)
	ld	(iy + 9), l
	ld	(iy + 11), a
	ld	a, (iy + 12)
	ld	l, (iy + 15)
	ld	(iy + 12), l
	ld	l, (iy + 14)
	ld	(iy + 15), l
	ld	l, (iy + 13)
	ld	(iy + 14), l
	ld	(iy + 13), a
	pop	ix
	ret
	
_aes_InvShiftRows:
	call	ti._frameset0
	ld	iy, (ix + 6)
	ld	a, (iy + 7)
	ld	l, (iy + 6)
	ld	(iy + 7), l
	ld	l, (iy + 5)
	ld	(iy + 6), l
	ld	l, (iy + 4)
	ld	(iy + 5), l
	ld	(iy + 4), a
	ld	a, (iy + 11)
	ld	l, (iy + 9)
	ld	(iy + 11), l
	ld	(iy + 9), a
	ld	a, (iy + 10)
	ld	l, (iy + 8)
	ld	(iy + 10), l
	ld	(iy + 8), a
	ld	a, (iy + 15)
	ld	l, (iy + 12)
	ld	(iy + 15), l
	ld	l, (iy + 13)
	ld	(iy + 12), l
	ld	l, (iy + 14)
	ld	(iy + 13), l
	ld	(iy + 14), a
	pop	ix
	ret

_aes_MixColumns:
	ld	hl, -13
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	e, (iy)
	ld	(ix + -2), e
	ld	a, (iy + 4)
	ld	(ix + -1), a
	ld	l, (iy + 8)
	ld	(ix + -3), l
	ld	l, (iy + 12)
	ld	(ix + -6), l
	or	a, a
	sbc	hl, hl
	ld	l, e
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	de
	ld	iy, _gf_mul
	lea	hl, iy + 0
	add	hl, de
	ld	(ix + -9), hl
	ld	l, (hl)
	ld	(ix + -13), l
	or	a, a
	sbc	hl, hl
	ld	l, a
	call	ti._imulu
	push	hl
	pop	de
	add	iy, de
	ld	bc, 0
	push	bc
	pop	hl
	ld	e, (ix + -3)
	ld	l, e
	ld	a, (ix + -6)
	ld	c, a
	ld	(ix + -12), bc
	xor	a, e
	xor	a, (ix + -13)
	xor	a, (iy + 1)
	lea	de, iy + 0
	ld	iy, (ix + 6)
	ld	(iy), a
	push	de
	pop	iy
	ld	a, (iy)
	xor	a, (ix + -2)
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	xor	a, (ix + -6)
	xor	a, (iy + 1)
	lea	hl, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 4), a
	ld	a, (ix + -1)
	xor	a, (ix + -2)
	ld	e, a
	ld	a, (hl)
	xor	a, e
	ld	(ix + -2), a
	ld	hl, (ix + -12)
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	ld	a, (iy + 1)
	lea	hl, iy + 0
	xor	a, (ix + -2)
	ld	iy, (ix + 6)
	ld	(iy + 8), a
	ld	a, (ix + -3)
	xor	a, (ix + -1)
	ld	iy, (ix + -9)
	xor	a, (iy + 1)
	xor	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 12), a
	ld	e, (iy + 1)
	ld	(ix + -2), e
	ld	a, (iy + 5)
	ld	(ix + -1), a
	ld	l, (iy + 9)
	ld	(ix + -3), l
	ld	l, (iy + 13)
	ld	(ix + -6), l
	ld	iy, 0
	lea	hl, iy + 0
	ld	l, e
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	add	hl, de
	ld	(ix + -9), hl
	ld	l, (hl)
	ld	(ix + -13), l
	lea	hl, iy + 0
	ld	l, a
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	add	hl, de
	push	hl
	pop	iy
	ld	bc, 0
	push	bc
	pop	hl
	ld	e, (ix + -3)
	ld	l, e
	ld	a, (ix + -6)
	ld	c, a
	ld	(ix + -12), bc
	xor	a, e
	xor	a, (ix + -13)
	xor	a, (iy + 1)
	lea	de, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 1), a
	push	de
	pop	iy
	ld	a, (iy)
	xor	a, (ix + -2)
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	xor	a, (ix + -6)
	xor	a, (iy + 1)
	lea	hl, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 5), a
	ld	a, (ix + -1)
	xor	a, (ix + -2)
	ld	e, a
	ld	a, (hl)
	xor	a, e
	ld	(ix + -2), a
	ld	hl, (ix + -12)
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	ld	a, (iy + 1)
	lea	hl, iy + 0
	xor	a, (ix + -2)
	ld	iy, (ix + 6)
	ld	(iy + 9), a
	ld	a, (ix + -3)
	xor	a, (ix + -1)
	ld	iy, (ix + -9)
	xor	a, (iy + 1)
	xor	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 13), a
	ld	e, (iy + 2)
	ld	(ix + -2), e
	ld	a, (iy + 6)
	ld	(ix + -1), a
	ld	l, (iy + 10)
	ld	(ix + -3), l
	ld	l, (iy + 14)
	ld	(ix + -6), l
	ld	iy, 0
	lea	hl, iy + 0
	ld	l, e
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	add	hl, de
	ld	(ix + -9), hl
	ld	l, (hl)
	ld	(ix + -13), l
	lea	hl, iy + 0
	ld	l, a
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	add	hl, de
	push	hl
	pop	iy
	ld	bc, 0
	push	bc
	pop	hl
	ld	e, (ix + -3)
	ld	l, e
	ld	a, (ix + -6)
	ld	c, a
	ld	(ix + -12), bc
	xor	a, e
	xor	a, (ix + -13)
	xor	a, (iy + 1)
	lea	de, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 2), a
	push	de
	pop	iy
	ld	a, (iy)
	xor	a, (ix + -2)
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	xor	a, (ix + -6)
	xor	a, (iy + 1)
	lea	hl, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 6), a
	ld	a, (ix + -1)
	xor	a, (ix + -2)
	ld	e, a
	ld	a, (hl)
	xor	a, e
	ld	(ix + -2), a
	ld	hl, (ix + -12)
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	ld	a, (iy + 1)
	lea	hl, iy + 0
	xor	a, (ix + -2)
	ld	iy, (ix + 6)
	ld	(iy + 10), a
	ld	a, (ix + -3)
	xor	a, (ix + -1)
	ld	iy, (ix + -9)
	xor	a, (iy + 1)
	xor	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 14), a
	ld	e, (iy + 3)
	ld	(ix + -1), e
	ld	a, (iy + 7)
	ld	(ix + -9), a
	ld	l, (iy + 11)
	ld	(ix + -2), l
	ld	l, (iy + 15)
	ld	(ix + -3), l
	ld	iy, 0
	lea	hl, iy + 0
	ld	l, e
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	add	hl, de
	ld	(ix + -6), hl
	ld	l, (hl)
	ld	(ix + -13), l
	lea	hl, iy + 0
	ld	l, a
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	add	hl, de
	push	hl
	pop	iy
	ld	de, 0
	push	de
	pop	bc
	ld	l, (ix + -2)
	ld	c, l
	ld	a, (ix + -3)
	ld	e, a
	ld	(ix + -12), de
	xor	a, l
	xor	a, (ix + -13)
	xor	a, (iy + 1)
	lea	hl, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 3), a
	ld	a, (hl)
	xor	a, (ix + -1)
	push	bc
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	xor	a, (ix + -3)
	xor	a, (iy + 1)
	lea	bc, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 7), a
	ld	d, (ix + -9)
	ld	a, d
	xor	a, (ix + -1)
	ld	e, a
	push	bc
	pop	hl
	ld	a, (hl)
	xor	a, e
	ld	e, a
	ld	hl, (ix + -12)
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	a, (iy + 1)
	lea	hl, iy + 0
	xor	a, e
	ld	iy, (ix + 6)
	ld	(iy + 11), a
	lea	bc, iy + 0
	ld	a, (ix + -2)
	xor	a, d
	ld	iy, (ix + -6)
	xor	a, (iy + 1)
	xor	a, (hl)
	push	bc
	pop	iy
	ld	(iy + 15), a
	ld	sp, ix
	pop	ix
	ret
	
_aes_InvMixColumns:
	ld	hl, -11
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	l, (iy)
	ld	a, (iy + 4)
	ld	e, (iy + 8)
	ld	(ix + -9), e
	ld	e, (iy + 12)
	ld	(ix + -10), e
	ld	de, 0
	ld	e, l
	ld	bc, 6
	push	de
	pop	hl
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -3), iy
	ld	l, (iy + 5)
	ld	(ix + -11), l
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -6), iy
	ld	a, (iy + 3)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -9)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -9), iy
	ld	a, (iy + 4)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -10)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, bc
	ld	a, (iy + 2)
	lea	bc, iy + 0
	xor	a, (ix + -11)
	ld	hl, (ix + 6)
	ld	(hl), a
	ld	iy, (ix + -6)
	ld	a, (iy + 5)
	ld	iy, (ix + -3)
	xor	a, (iy + 2)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 3)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 4)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 4), a
	ld	iy, (ix + -6)
	ld	a, (iy + 2)
	ld	iy, (ix + -3)
	xor	a, (iy + 4)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 5)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 3)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 8), a
	ld	iy, (ix + -6)
	ld	a, (iy + 4)
	ld	iy, (ix + -3)
	xor	a, (iy + 3)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 2)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 5)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 12), a
	ld	l, (iy + 1)
	ld	a, (iy + 5)
	ld	c, (iy + 9)
	ld	(ix + -9), c
	ld	c, (iy + 13)
	ld	(ix + -10), c
	ld	e, l
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -3), iy
	ld	l, (iy + 5)
	ld	(ix + -11), l
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -6), iy
	ld	a, (iy + 3)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -9)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -9), iy
	ld	a, (iy + 4)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -10)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, bc
	ld	a, (iy + 2)
	lea	bc, iy + 0
	xor	a, (ix + -11)
	ld	iy, (ix + 6)
	ld	(iy + 1), a
	ld	iy, (ix + -6)
	ld	a, (iy + 5)
	ld	iy, (ix + -3)
	xor	a, (iy + 2)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 3)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 4)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 5), a
	ld	iy, (ix + -6)
	ld	a, (iy + 2)
	ld	iy, (ix + -3)
	xor	a, (iy + 4)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 5)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 3)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 9), a
	ld	iy, (ix + -6)
	ld	a, (iy + 4)
	ld	iy, (ix + -3)
	xor	a, (iy + 3)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 2)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 5)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 13), a
	ld	l, (iy + 2)
	ld	a, (iy + 6)
	ld	c, (iy + 10)
	ld	(ix + -9), c
	ld	c, (iy + 14)
	ld	(ix + -10), c
	ld	e, l
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -3), iy
	ld	l, (iy + 5)
	ld	(ix + -11), l
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -6), iy
	ld	a, (iy + 3)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -9)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -9), iy
	ld	a, (iy + 4)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -10)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, bc
	ld	a, (iy + 2)
	lea	bc, iy + 0
	xor	a, (ix + -11)
	ld	iy, (ix + 6)
	ld	(iy + 2), a
	ld	iy, (ix + -6)
	ld	a, (iy + 5)
	ld	iy, (ix + -3)
	xor	a, (iy + 2)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 3)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 4)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 6), a
	ld	iy, (ix + -6)
	ld	a, (iy + 2)
	ld	iy, (ix + -3)
	xor	a, (iy + 4)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 5)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 3)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 10), a
	ld	iy, (ix + -6)
	ld	a, (iy + 4)
	ld	iy, (ix + -3)
	xor	a, (iy + 3)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 2)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 5)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 14), a
	ld	l, (iy + 3)
	ld	a, (iy + 7)
	ld	c, (iy + 11)
	ld	(ix + -6), c
	ld	c, (iy + 15)
	ld	(ix + -10), c
	ld	e, l
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -9), iy
	ld	l, (iy + 5)
	ld	(ix + -11), l
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -3), iy
	ld	a, (iy + 3)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -6)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -6), iy
	ld	a, (iy + 4)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -10)
	ld	e, a
	ex	de, hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	de
	ld	iy, _gf_mul
	add	iy, de
	ld	a, (iy + 2)
	lea	de, iy + 0
	xor	a, (ix + -11)
	ld	iy, (ix + 6)
	ld	(iy + 3), a
	ld	iy, (ix + -3)
	ld	a, (iy + 5)
	ld	iy, (ix + -9)
	xor	a, (iy + 2)
	lea	bc, iy + 0
	ld	l, a
	ld	iy, (ix + -6)
	ld	a, (iy + 3)
	xor	a, l
	ld	l, a
	push	de
	pop	iy
	ld	a, (iy + 4)
	xor	a, l
	ld	hl, (ix + 6)
	push	hl
	pop	iy
	ld	(iy + 7), a
	ld	iy, (ix + -3)
	ld	a, (iy + 2)
	push	bc
	pop	iy
	xor	a, (iy + 4)
	ld	l, a
	ld	iy, (ix + -6)
	ld	a, (iy + 5)
	xor	a, l
	ld	l, a
	push	de
	pop	iy
	ld	a, (iy + 3)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 11), a
	ld	iy, (ix + -3)
	ld	a, (iy + 4)
	push	bc
	pop	iy
	xor	a, (iy + 3)
	ld	l, a
	ld	iy, (ix + -6)
	ld	a, (iy + 2)
	xor	a, l
	ld	l, a
	push	de
	pop	iy
	ld	a, (iy + 5)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 15), a
	ld	sp, ix
	pop	ix
	ret
	
_increment_iv:
	ld	hl, -9
	call	ti._frameset
	ld	de, (ix + 9)
	ld	hl, 16
	ld	iy, 1
	ld	bc, 0
	or	a, a
	sbc	hl, de
	ld	(ix + -3), hl
	lea	hl, iy + 0
	or	a, a
	sbc	hl, de
	ld	(ix + -6), hl
	ld	iy, (ix + 6)
	lea	hl, iy + 15
	ld	(ix + -9), hl
.loop:
	push	bc
	pop	hl
	ld	de, 15
	add	hl, de
	ld	de, (ix + -3)
	or	a, a
	sbc	hl, de
	jq	c, .exit_loop
	ld	iy, (ix + -9)
	add	iy, bc
	inc	(iy)
	ld	hl, (ix + -6)
	or	a, a
	sbc	hl, bc
	jq	z, .exit_loop
	ld	a, (iy)
	dec	bc
	or	a, a
	jq	z, .loop
.exit_loop:
	ld	sp, ix
	pop	ix
	ret
	
	
aes_ecb_unsafe_encrypt:
	save_interrupts

	ld	hl, -22
	call	ti._frameset
	ld	iy, (ix + 6)
	lea	de, ix + -16
	ld	(ix + -19), de
	ld	hl, (ix + 12)
	ld	hl, (hl)
	ld	(ix + -22), hl
	ld	a, (iy)
	ld	(ix + -16), a
	ld	a, (iy + 1)
	ld	(ix + -12), a
	ld	a, (iy + 2)
	ld	(ix + -8), a
	ld	a, (iy + 3)
	ld	(ix + -4), a
	ld	a, (iy + 4)
	ld	(ix + -15), a
	ld	a, (iy + 5)
	ld	(ix + -11), a
	ld	a, (iy + 6)
	ld	(ix + -7), a
	ld	a, (iy + 7)
	ld	(ix + -3), a
	ld	a, (iy + 8)
	ld	(ix + -14), a
	ld	a, (iy + 9)
	ld	(ix + -10), a
	ld	a, (iy + 10)
	ld	(ix + -6), a
	ld	a, (iy + 11)
	ld	(ix + -2), a
	ld	a, (iy + 12)
	ld	(ix + -13), a
	ld	a, (iy + 13)
	ld	(ix + -9), a
	ld	a, (iy + 14)
	ld	(ix + -5), a
	ld	a, (iy + 15)
	ld	(ix + -1), a
	ld	iy, (ix + 12)
	pea	iy + 3
	push	de
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 19
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 35
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 51
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 67
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 83
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 99
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 115
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 131
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 147
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	de, 128
	ld	hl, (ix + -22)
	or	a, a
	sbc	hl, de
	jq	nz, .lbl2
	ld	de, 163
	jq	.lbl4
.lbl2:
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 163
	ld	hl, (ix + 12)
	push	hl
	pop	iy
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 179
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	de, 192
	ld	hl, (ix + -22)
	or	a, a
	sbc	hl, de
	jq	nz, .lbl5
	ld	de, 195
.lbl4:
	ld	iy, (ix + 12)
	jq	.lbl6
.lbl5:
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 195
	ld	hl, (ix + 12)
	push	hl
	pop	iy
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 211
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	ld	iy, (ix + 12)
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	de, 227
.lbl6:
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	a, (ix + -16)
	ld	iy, (ix + 9)
	ld	(iy), a
	ld	a, (ix + -12)
	ld	(iy + 1), a
	ld	a, (ix + -8)
	ld	(iy + 2), a
	ld	a, (ix + -4)
	ld	(iy + 3), a
	ld	a, (ix + -15)
	ld	(iy + 4), a
	ld	a, (ix + -11)
	ld	(iy + 5), a
	ld	a, (ix + -7)
	ld	(iy + 6), a
	ld	a, (ix + -3)
	ld	(iy + 7), a
	ld	a, (ix + -14)
	ld	(iy + 8), a
	ld	a, (ix + -10)
	ld	(iy + 9), a
	ld	a, (ix + -6)
	ld	(iy + 10), a
	ld	a, (ix + -2)
	ld	(iy + 11), a
	ld	a, (ix + -13)
	ld	(iy + 12), a
	ld	a, (ix + -9)
	ld	(iy + 13), a
	ld	a, (ix + -5)
	ld	(iy + 14), a
	ld	a, (ix + -1)
	ld	(iy + 15), a
	ld	sp, ix
	pop	ix

	restore_interrupts aes_ecb_unsafe_encrypt
	ret


aes_ecb_unsafe_decrypt:
	save_interrupts
	ld	hl, -19
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	hl, (ix + 12)
	lea	de, ix + -16
	ld	(ix + -19), de
	ld	de, (hl)
	ld	a, (iy)
	ld	(ix + -16), a
	ld	a, (iy + 1)
	ld	(ix + -12), a
	ld	a, (iy + 2)
	ld	(ix + -8), a
	ld	a, (iy + 3)
	ld	(ix + -4), a
	ld	a, (iy + 4)
	ld	(ix + -15), a
	ld	a, (iy + 5)
	ld	(ix + -11), a
	ld	a, (iy + 6)
	ld	(ix + -7), a
	ld	a, (iy + 7)
	ld	(ix + -3), a
	ld	a, (iy + 8)
	ld	(ix + -14), a
	ld	a, (iy + 9)
	ld	(ix + -10), a
	ld	a, (iy + 10)
	ld	(ix + -6), a
	ld	a, (iy + 11)
	ld	(ix + -2), a
	ld	a, (iy + 12)
	ld	(ix + -13), a
	ld	a, (iy + 13)
	ld	(ix + -9), a
	ld	a, (iy + 14)
	ld	(ix + -5), a
	ld	a, (iy + 15)
	ld	(ix + -1), a
	ld	bc, 129
	push	de
	pop	hl
	or	a, a
	sbc	hl, bc
	call	ti._setflag
	jq	m, .lbl3
	ld	bc, (ix + -19)
	ld	iy, 193
	ex	de, hl
	lea	de, iy + 0
	or	a, a
	sbc	hl, de
	call	ti._setflag
	ld	hl, (ix + 12)
	jq	m, .lbl4
	ld	de, 227
	push	hl
	pop	iy
	add	iy, de
	push	iy
	push	bc
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	de, 211
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	de, 195
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	jq	.lbl5
.lbl3:
	ld	de, 163
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	jq	.lbl7
.lbl4:
	ld	de, 195
	push	hl
	pop	iy
	add	iy, de
	push	iy
	push	bc
	call	_aes_AddRoundKey
	pop	hl
.lbl5:
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	de, 179
	ld	hl, (ix + 12)
	push	hl
	pop	iy
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	de, 163
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
.lbl7:
	pop	hl
	ld	de, (ix + -19)
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	push	de
	call	_aes_InvSubBytes
	pop	hl
	ld	de, 147
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	de, 131
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 115
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 99
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 83
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 67
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 51
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 35
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 19
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 3
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	a, (ix + -16)
	ld	iy, (ix + 9)
	ld	(iy), a
	ld	a, (ix + -12)
	ld	(iy + 1), a
	ld	a, (ix + -8)
	ld	(iy + 2), a
	ld	a, (ix + -4)
	ld	(iy + 3), a
	ld	a, (ix + -15)
	ld	(iy + 4), a
	ld	a, (ix + -11)
	ld	(iy + 5), a
	ld	a, (ix + -7)
	ld	(iy + 6), a
	ld	a, (ix + -3)
	ld	(iy + 7), a
	ld	a, (ix + -14)
	ld	(iy + 8), a
	ld	a, (ix + -10)
	ld	(iy + 9), a
	ld	a, (ix + -6)
	ld	(iy + 10), a
	ld	a, (ix + -2)
	ld	(iy + 11), a
	ld	a, (ix + -13)
	ld	(iy + 12), a
	ld	a, (ix + -9)
	ld	(iy + 13), a
	ld	a, (ix + -5)
	ld	(iy + 14), a
	ld	a, (ix + -1)
	ld	(iy + 15), a
	ld	sp, ix
	pop	ix
	restore_interrupts aes_ecb_unsafe_decrypt
	ret


_ghash:
	ld	hl, -34
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	de, 16
	or	a, a
	sbc	hl, hl
	ld	(ix - 22), hl
	lea	hl, ix - 16
	ld	(ix - 19), hl
	ld	bc, 342
	lea	hl, iy
	add	hl, bc
	ld	(ix - 25), hl
	ld	c, (hl)
	ld	a, c
	or	a, a
	jp	z, .lbl_7
	ex	de, hl
	ld	de, 0
	ld	e, c
	ld	(ix - 28), de
	or	a, a
	sbc	hl, de
	ld	(ix - 22), hl
	ld	de, (ix + 15)
	or	a, a
	sbc	hl, de
	jr	c, .lbl_3
	ld	(ix - 22), de
.lbl_3:
	ld	hl, (ix - 22)
	ld	de, (ix - 28)
	add	hl, de
	ld	bc, 16
	or	a, a
	sbc	hl, bc
	jr	nc, .lbl_6
	add	iy, de
	ld	de, 294
	add	iy, de
	ld	hl, (ix - 22)
	push	hl
	ld	hl, (ix + 12)
	push	hl
	push	iy
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 25)
	ld	a, (hl)
	ld	de, (ix - 22)
	add	a, e
	ld	(hl), a
.lbl_5:
	ld	sp, ix
	pop	ix
	ret
.lbl_6:
	lea	hl, iy
	push	de
	pop	bc
	ld	de, 294
	add	hl, de
	push	bc
	push	hl
	ld	hl, (ix - 19)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 19)
	ld	de, (ix - 28)
	add	hl, de
	ld	de, (ix - 22)
	push	de
	ld	de, (ix + 12)
	push	de
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix - 19)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	ld	de, 278
	add	hl, de
	ld	de, (ix + 9)
	push	de
	push	hl
	push	de
	call	_gf128_mul
	ld	iy, (ix + 6)
	pop	hl
	pop	hl
	pop	hl
	lea	hl, iy
	ld	de, 342
	add	hl, de
	ld	(hl), 0
.lbl_7:
	lea	hl, iy
	ld	de, 278
	add	hl, de
	ld	(ix - 31), hl
	ld	bc, (ix - 22)
	ld	de, 294
	add	iy, de
	ld	(ix - 34), iy
	ld	de, (ix + 15)
	push	de
	pop	hl
	or	a, a
	sbc	hl, bc
	push	hl
	pop	iy
	ld	a, e
	sub	a, c
	push	bc
	pop	hl
	push	de
	pop	bc
.lbl_8:
	push	hl
	pop	de
	or	a, a
	sbc	hl, bc
	jp	nc, .lbl_5
	ld	(ix - 28), a
	ld	(ix - 25), de
	lea	hl, iy
	ld	iy, (ix + 12)
	add	iy, de
	ld	(ix - 22), hl
	ld	de, 16
	or	a, a
	sbc	hl, de
	jr	nc, .lbl_11
	ld	hl, (ix - 22)
	push	hl
	push	iy
	ld	hl, (ix - 34)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	ld	de, 342
	add	hl, de
	ld	a, (ix - 28)
	ld	(hl), a
	ld	hl, 16
	ex	de, hl
	jr	.lbl_12
.lbl_11:
	ld	de, (ix - 19)
	lea	hl, iy
	ld	iy, 16
	lea	bc, iy
	ldir
	push	iy
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix - 19)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix + 9)
	push	de
	ld	hl, (ix - 31)
	push	hl
	push	de
	call	_gf128_mul
	ld	de, 16
	pop	hl
	pop	hl
	pop	hl
	ld	a, (ix - 28)
.lbl_12:
	ld	hl, (ix - 25)
	add	hl, de
	ld	de, -16
	ld	iy, (ix - 22)
	add	iy, de
	add	a, e
	ld	bc, (ix + 15)
	jp	.lbl_8
	
	
_aes_gcm_prepare_iv:
	ld	hl, -22
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	bc, (ix + 12)
	ld	de, 12
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jr	nz, .lbl_2
	ld	de, 258
	add	iy, de
	ld	(iy), d
	jp	.lbl_5
.lbl_2:
	ld	hl, 16
	lea	de, ix - 16
	or	a, a
	sbc	hl, bc
	push	hl
	pop	iy
	push	bc
	pop	hl
	ld	bc, 16
	or	a, a
	sbc	hl, bc
	ld	bc, 0
	push	bc
	pop	hl
	jr	nc, .lbl_4
	lea	hl, iy
.lbl_4:
	ld	(ix - 19), de
	ld	iy, (ix - 19)
	ld	de, (ix + 12)
	add	iy, de
	push	hl
	push	bc
	push	iy
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 12)
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix - 19)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	de, 243
	ld	iy, (ix + 6)
	add	iy, de
	ld	(ix - 22), iy
	ld	(iy), d
	lea	hl, iy
	inc	hl
	ld	bc, 15
	ex	de, hl
	lea	hl, iy
	ldir
	ld	hl, 16
	push	hl
	ld	hl, (ix - 19)
	push	hl
	push	iy
	ld	hl, (ix + 6)
	push	hl
	call	_ghash
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	or	a, a
	sbc	hl, hl
	ld	(ix - 16), hl
	ld	(ix - 13), hl
	ld	(ix - 10), l
	ld	(ix - 9), h
	ld	iy, (ix - 19)
	pea	iy + 8
	ld	hl, (ix + 12)
	push	hl
	call	_bytelen_to_bitlen
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix - 19)
	push	hl
	ld	hl, (ix - 22)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	_ghash
	pop	hl
	pop	hl
	pop	hl
	pop	hl
.lbl_5:
	ld	sp, ix
	pop	ix
	ret
	

aes_init:
	save_interrupts

	ld	hl, -46
	call	ti._frameset
	ld	hl, (ix + 21)
	ld	e, 0
	ld	a, l
	and	a, 3
	cp	a, 3
	jr	nz, .lbl_2
	ld	de, 3
	jp	.lbl_43
.lbl_2:
	ld	(ix - 30), e
	ld	(ix - 23), a
	ld	hl, (ix + 18)
	ld	de, 1
	ld	bc, 17
	or	a, a
	sbc	hl, bc
	jp	nc, .lbl_43
	ld	iy, (ix + 6)
	ld	(iy), 0
	lea	hl, iy
	inc	hl
	ld	bc, 349
	ex	de, hl
	lea	hl, iy
	ldir
	ld	de, 259
	add	iy, de
	ld	a, (ix - 23)
	ld	(iy), a
	ld	c, e
	ld	hl, (ix + 12)
	call	ti._ishl
	push	hl
	pop	bc
	ld	de, 128
	or	a, a
	sbc	hl, de
	jr	nz, .lbl_5
	ld	(ix - 19), bc
	ld	hl, 44
	ld	(ix - 29), hl
	ld	hl, 4
	jr	.lbl_7
.lbl_5:
	ld	de, 192
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jp	nz, .lbl_30
	ld	(ix - 19), bc
	ld	hl, 52
	ld	(ix - 29), hl
	ld	hl, 6
.lbl_7:
	ld	(ix - 22), hl
.lbl_8:
	ld	bc, (ix + 15)
	lea	hl, ix - 16
	ld	(ix - 42), hl
	ld	de, 243
	ld	hl, (ix + 6)
	push	hl
	pop	iy
	add	iy, de
	ld	(ix - 36), iy
	ld	hl, (ix + 18)
	push	hl
	push	bc
	push	iy
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	iy, (ix - 36)
	ld	de, (ix + 18)
	add	iy, de
	ld	hl, 16
	or	a, a
	sbc	hl, de
	push	hl
	or	a, a
	sbc	hl, hl
	push	hl
	push	iy
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 19)
	ld	iy, (ix + 6)
	ld	(iy), hl
	ld	c, 2
	ld	hl, (ix - 22)
	call	ti._ishl
	ld	(ix - 19), hl
	ld	bc, 0
	push	bc
	pop	iy
.lbl_9:
	ld	hl, (ix - 19)
	lea	de, iy
	or	a, a
	sbc	hl, de
	jr	z, .lbl_11
	ld	(ix - 26), iy
	lea	de, iy
	ld	(ix - 33), de
	ld	iy, (ix + 9)
	add	iy, de
	ld	bc, 0
	ld	c, (iy)
	ld	e, b
	ld	a, e
	ld	l, 24
	call	ti._lshl
	ld	(ix - 39), bc
	ld	d, a
	ld	bc, 0
	ld	c, (iy + 1)
	ld	a, e
	ld	l, 16
	call	ti._lshl
	push	bc
	pop	hl
	ld	e, a
	ld	bc, (ix - 39)
	ld	a, d
	call	ti._ladd
	ld	(ix - 39), hl
	ld	bc, 0
	ld	c, (iy + 2)
	xor	a, a
	ld	l, 8
	call	ti._lshl
	ld	hl, (ix - 39)
	call	ti._ladd
	ld	bc, 0
	ld	c, (iy + 3)
	xor	a, a
	call	ti._ladd
	ld	iy, (ix + 6)
	ld	bc, (ix - 33)
	add	iy, bc
	ld	(iy + 3), hl
	ld	(iy + 6), e
	ld	bc, 0
	ld	de, 4
	ld	iy, (ix - 26)
	add	iy, de
	jp	.lbl_9
.lbl_11:
	ld	a, 2
	ld	de, (ix - 22)
	push	de
	pop	hl
	push	bc
	pop	iy
	ld	c, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, (ix + 6)
	add	hl, bc
	dec	hl
	ld	(ix - 26), hl
	ld	(ix - 19), iy
	push	de
	pop	bc
.lbl_12:
	ld	hl, (ix - 29)
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_20
	ld	de, (ix - 19)
	ld	iy, (ix - 26)
	add	iy, de
	ld	de, (iy)
	ld	a, (iy + 3)
	push	bc
	pop	hl
	ld	iy, (ix - 22)
	ld	(ix - 33), bc
	lea	bc, iy
	call	ti._iremu
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	nz, .lbl_15
	ld	hl, (ix - 33)
	dec	hl
	ld	(ix - 39), hl
	push	de
	pop	bc
	ld	h, a
	ld	l, 8
	call	ti._lshl
	ld	(ix - 45), bc
	ld	(ix - 46), a
	push	de
	pop	bc
	ld	a, h
	ld	l, 24
	call	ti._lshru
	ld	hl, (ix - 45)
	ld	e, (ix - 46)
	call	ti._lor
	push	de
	push	hl
	ld	(ix - 22), iy
	call	_aes_SubWord
	ld	(ix - 45), hl
	ld	a, e
	pop	hl
	pop	hl
	ld	hl, (ix - 39)
	ld	bc, (ix - 22)
	call	ti._idivu
	ld	c, 2
	call	ti._ishl
	push	hl
	pop	de
	ld	iy, L___const.hashlib_AESLoadKey.Rcon
	add	iy, de
	ld	hl, (iy)
	ld	e, (iy + 3)
	ld	bc, (ix - 45)
	call	ti._lxor
	push	hl
	pop	bc
	ld	a, e
	jr	.lbl_19
.lbl_15:
	bit	0, (ix - 30)
	jr	z, .lbl_18
	ld	bc, 4
	or	a, a
	sbc	hl, bc
	jr	nz, .lbl_18
	ld	l, a
	push	hl
	push	de
	call	_aes_SubWord
	push	hl
	pop	bc
	ld	a, e
	pop	hl
	pop	hl
	jr	.lbl_19
.lbl_18:
	push	de
	pop	bc
.lbl_19:
	ld	de, (ix - 19)
	ld	(ix - 39), de
	ld	iy, (ix + 6)
	add	iy, de
	ld	hl, (iy + 3)
	ld	e, (iy + 6)
	call	ti._lxor
	ld	iy, (ix - 26)
	ld	bc, (ix - 39)
	add	iy, bc
	ld	(iy + 4), hl
	ld	(iy + 7), e
	ld	bc, (ix - 33)
	inc	bc
	ld	de, 4
	ld	hl, (ix - 19)
	add	hl, de
	ld	(ix - 19), hl
	ld	iy, 0
	jp	.lbl_12
.lbl_20:
	ld	l, (ix - 23)
	ld	a, l
	or	a, a
	jr	nz, .lbl_23
	ld	hl, (ix + 21)
	ld	a, l
	ld	b, 2
	call	ti._bshru
	and	a, 3
	ld	de, 261
	ld	hl, (ix + 6)
	add	hl, de
	ld	(hl), a
.lbl_22:
	lea	de, iy
	jp	.lbl_43
.lbl_23:
	ld	a, l
	cp	a, 1
	jp	nz, .lbl_32
	ld	hl, (ix + 21)
	ld	a, l
	ld	b, 4
	call	ti._bshru
	ld	d, a
	ld	a, h
	and	a, 15
	ld	e, a
	ld	a, l
	cp	a, 16
	ld	bc, 17
	ld	l, 8
	jr	nc, .lbl_26
	ld	a, e
	or	a, a
	ld	a, l
	jp	z, .lbl_40
.lbl_26:
	ld	hl, (ix + 21)
	ld	a, l
	cp	a, 16
	jr	nc, .lbl_28
	ld	a, e
	or	a, a
	jp	nz, .lbl_39
.lbl_28:
	ld	hl, (ix + 21)
	ld	a, l
	cp	a, 16
	sbc	a, a
	ld	c, a
	ld	a, e
	or	a, a
	jp	nz, .lbl_35
	ld	h, 0
	jp	.lbl_36
.lbl_30:
	ld	de, 256
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jp	nz, .lbl_34
	ld	(ix - 19), bc
	ld	hl, 8
	ld	(ix - 22), hl
	ld	hl, 60
	ld	(ix - 29), hl
	ld	a, 1
	ld	(ix - 30), a
	jp	.lbl_8
.lbl_32:
	ld	a, l
	cp	a, 2
	jp	nz, .lbl_22
	ld	(ix - 16), 0
	ld	iy, (ix - 42)
	lea	de, iy
	inc	de
	ld	bc, 15
	lea	hl, iy
	ldir
	ld	de, 278
	ld	hl, (ix + 6)
	push	hl
	pop	bc
	add	hl, de
	push	bc
	push	hl
	push	iy
	call	aes_ecb_unsafe_encrypt
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 18)
	push	hl
	ld	hl, (ix + 15)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	_aes_gcm_prepare_iv
	pop	hl
	pop	hl
	pop	hl
	ld	de, 310
	ld	hl, (ix + 6)
	add	hl, de
	ld	(hl), 0
	push	hl
	pop	iy
	inc	iy
	lea	de, iy
	ld	bc, 15
	ldir
	ld	de, 326
	ld	hl, (ix + 6)
	add	hl, de
	ex	de, hl
	ld	iy, (ix - 36)
	lea	hl, iy
	ld	bc, 16
	ldir
	ld	hl, 4
	push	hl
	ld	hl, 12
	push	hl
	push	iy
	call	_increment_iv
	pop	hl
	pop	hl
	pop	hl
	jr	.lbl_42
.lbl_34:
	ld	de, 1
	jr	.lbl_43
.lbl_35:
	ld	h, -1
.lbl_36:
	ld	l, 16
	ld	a, c
	or	a, h
	ld	c, a
	ld	a, l
	sub	a, d
	bit	0, c
	jr	nz, .lbl_38
	ld	e, a
.lbl_38:
	ld	l, d
	ld	a, e
	ld	bc, 17
	jr	.lbl_40
.lbl_39:
	ld	a, 16
	sub	a, e
	ld	l, a
	ld	a, e
.lbl_40:
	ld	de, 0
	push	bc
	pop	iy
	ld	c, l
	push	de
	pop	hl
	ld	l, a
	ld	b, c
	ld	e, c
	add	hl, de
	lea	de, iy
	or	a, a
	sbc	hl, de
	ld	de, 1
	jr	nc, .lbl_43
	ld	de, 261
	ld	hl, (ix + 6)
	push	hl
	pop	iy
	add	hl, de
	ld	(hl), b
	inc	de
	lea	hl, iy
	add	hl, de
	ld	(hl), a
.lbl_42:
	ld	de, 0
.lbl_43:
	ex	de, hl
	restore_interrupts_noret aes_init
	jq stack_clear


; aes_error_t cryptx_aes_update_assoc(aes_ctx* ctx, uint8_t* data, size_t len);
cryptx_aes_update_aad:
	call	ti._frameset0
	ld	iy, (ix + 6)
	ld	hl, 6
	ld	de, 259
	lea	bc, iy
	add	iy, de
	ld	a, (iy)
	cp	a, 2
	jr	nz, .lbl_3
	ld	de, 349
	push	bc
	pop	iy
	add	iy, de
	ld	a, (iy)
	or	a, a
	jr	nz, .lbl_3
	ld	iy, (ix + 12)
	ld	de, 310
	push	bc
	pop	hl
	add	hl, de
	push	iy
	ld	de, (ix + 9)
	push	de
	push	hl
	push	bc
	call	_ghash
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	de, 343
	ld	iy, (ix + 6)
	add	iy, de
	ld	hl, (iy)
	ld	de, (ix + 12)
	add	hl, de
	ld	(iy), hl
	or	a, a
	sbc	hl, hl
.lbl_3:
	pop	ix
	ret

cryptx_aes_digest:
	ld	hl, -22
	call	ti._frameset
	ld	bc, (ix + 6)
	ld	de, 1
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_5
	ld	hl, (ix + 9)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_5
	ld	de, 259
	push	bc
	pop	iy
	add	iy, de
	ld	a, (iy)
	cp	a, 2
	jp	nz, .lbl_4
	lea	bc, ix - 16
	ld	hl, (ix + 6)
	push	hl
	pop	iy
	ld	de, 349
	add	iy, de
	ld	(iy), 2
	ld	de, 310
	add	hl, de
	ld	(ix - 22), hl
	ld	(ix - 16), 0
	push	bc
	pop	iy
	inc	iy
	lea	de, iy
	push	bc
	pop	iy
	ld	(ix - 19), iy
	lea	hl, iy
	ld	bc, 15
	ldir
	ld	de, 342
	ld	bc, (ix + 6)
	push	bc
	pop	hl
	add	hl, de
	ld	de, 0
	ld	e, (hl)
	ld	hl, 16
	or	a, a
	sbc	hl, de
	push	hl
	push	iy
	ld	hl, (ix - 22)
	push	hl
	push	bc
	call	_ghash
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	de, 343
	ld	hl, (ix + 6)
	add	hl, de
	ld	hl, (hl)
	ld	de, (ix - 19)
	push	de
	push	hl
	call	_bytelen_to_bitlen
	pop	hl
	pop	hl
	ld	de, 346
	ld	hl, (ix + 6)
	add	hl, de
	ld	hl, (hl)
	ld	iy, (ix - 19)
	pea	iy + 8
	push	hl
	call	_bytelen_to_bitlen
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix - 19)
	push	hl
	ld	hl, (ix - 22)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	_ghash
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	de, 326
	ld	hl, (ix + 6)
	push	hl
	add	hl, de
	ld	de, (ix - 19)
	push	de
	push	hl
	call	aes_ecb_unsafe_encrypt
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix - 19)
	push	hl
	ld	hl, (ix - 22)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix + 9)
	ld	hl, (ix - 19)
	ld	bc, 16
	ldir
	ld	de, 0
	jr	.lbl_5
.lbl_4:
	ld	de, 3
.lbl_5:
	ex	de, hl
	ld	sp, ix
	pop	ix
	ret

cryptx_aes_verify:
	ld	hl, -378
	call	ti._frameset
	ld	de, -372
	lea	iy, ix
	add	iy, de
	ld	bc, 350
	lea	hl, iy + 16
	lea	de, iy
	ld	(ix - 3), bc
	ld	bc, -378
	lea	iy, ix
	add	iy, bc
	ld	(iy), de
	push	ix
	ld	bc, -375
	add	ix, bc
	ld	(ix), hl
	pop	ix
	ex	de, hl
	ld	hl, (ix + 6)
	ld	bc, (ix - 3)
	ldir
	ld	hl, (ix + 9)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_2
	ld	de, (ix + 12)
	push	de
	push	hl
	ld	bc, -375
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_aes_update_aad
	pop	hl
	pop	hl
	pop	hl
.lbl_2:
	ld	hl, 0
	push	hl
	ld	hl, (ix + 18)
	push	hl
	ld	hl, (ix + 15)
	push	hl
	ld	bc, -375
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	aes_decrypt
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -378
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -375
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_aes_digest
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	bc, -378
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	hl, (ix + 21)
	push	hl
	call	cryptx_digest_compare
	ld	sp, ix
	pop	ix
	ret
	

aes_encrypt:
	save_interrupts

	ld	hl, -43
	call	ti._frameset
	ld	hl, (ix + 6)
	ld	bc, 6
	ld	de, 243
	push	hl
	pop	iy
	add	iy, de
	ld	de, 260
	add	hl, de
	ld	a, (hl)
	cp	a, 2
	jr	nz, .lbl_2
	push	bc
	pop	de
	jr	.lbl_6
.lbl_2:
	ld	(ix - 19), iy
	ld	iy, (ix + 9)
	ld	de, 1
	ld	(hl), e
	lea	hl, iy
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_6
	ld	hl, (ix + 15)
	ld	(ix - 22), hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_6
	ld	de, (ix + 12)
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	nz, .lbl_7
	ld	de, 2
.lbl_6:
	ex	de, hl
	restore_interrupts_noret aes_encrypt
	jq stack_clear
.lbl_7:
	lea	hl, ix - 16
	ld	(ix - 25), hl
	ld	c, 4
	ex	de, hl
	call	ti._ishru
	push	hl
	pop	bc
	ld	de, 259
	ld	hl, (ix + 6)
	add	hl, de
	ld	l, (hl)
	ld	a, l
	or	a, a
	jp	nz, .lbl_19
	ld	(ix - 28), iy
	inc	bc
	ld	hl, (ix + 12)
	ld	(ix - 34), hl
.lbl_9:
	ld	de, 0
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_6
	ld	(ix - 31), bc
	ld	bc, (ix - 34)
	push	bc
	pop	hl
	ld	de, 16
	or	a, a
	sbc	hl, de
	jr	c, .lbl_12
	ld	bc, 16
.lbl_12:
	ld	hl, 16
	or	a, a
	sbc	hl, bc
	ld	(ix - 40), hl
	ld	(ix - 37), bc
	push	bc
	ld	hl, (ix - 28)
	push	hl
	ld	hl, (ix - 25)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 31)
	ld	de, 1
	or	a, a
	sbc	hl, de
	ld	de, (ix - 19)
	jr	nz, .lbl_18
	ld	hl, (ix + 6)
	ld	bc, 261
	add	hl, bc
	ld	l, (hl)
	ld	a, l
	or	a, a
	jr	nz, .lbl_15
	ld	hl, (ix - 25)
	ld	de, (ix - 37)
	add	hl, de
	ld	de, (ix - 40)
	push	de
	push	de
	push	hl
	call	ti._memset
	jr	.lbl_17
.lbl_15:
	ld	a, l
	cp	a, 1
	jr	nz, .lbl_18
	ld	hl, (ix - 25)
	ld	de, (ix - 37)
	add	hl, de
	ld	de, (ix - 40)
	push	de
	ld	de, _iso_pad
	push	de
	push	hl
	call	ti._memcpy
.lbl_17:
	ld	de, (ix - 19)
	pop	hl
	pop	hl
	pop	hl
.lbl_18:
	ld	hl, 16
	push	hl
	ld	hl, (ix - 25)
	push	hl
	push	de
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 22)
	push	hl
	ld	hl, (ix - 25)
	push	hl
	call	aes_ecb_unsafe_encrypt
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix - 19)
	ld	hl, (ix - 22)
	ld	bc, 16
	ldir
	ld	bc, (ix - 31)
	dec	bc
	ld	de, -16
	ld	hl, (ix - 34)
	add	hl, de
	ld	(ix - 34), hl
	ld	iy, (ix - 28)
	lea	iy, iy + 16
	ld	(ix - 28), iy
	ld	iy, (ix - 22)
	lea	iy, iy + 16
	ld	(ix - 22), iy
	jp	.lbl_9
.lbl_19:
	ld	a, l
	cp	a, 1
	jp	nz, .lbl_29
	ld	de, 263
	ld	iy, (ix + 6)
	lea	hl, iy
	add	hl, de
	ld	l, (hl)
	ld	a, l
	and	a, 15
	or	a, a
	ld	de, 0
	ld	(ix - 28), de
	jr	z, .lbl_22
	ld	de, 0
	ld	e, l
	ld	(ix - 22), de
	ld	hl, 16
	or	a, a
	sbc	hl, de
	ld	(ix - 28), hl
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 15)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	ld	de, (ix - 22)
	add	hl, de
	ld	de, 264
	add	hl, de
	ld	de, (ix - 28)
	push	de
	ld	de, (ix + 15)
	push	de
	push	hl
	call	_xor_buf
	ld	iy, (ix + 6)
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 12)
	ld	de, (ix - 28)
	or	a, a
	sbc	hl, de
	ld	c, 4
	call	ti._ishru
	push	hl
	pop	bc
.lbl_22:
	ld	de, 264
	add	iy, de
	ld	(ix - 40), iy
	inc	bc
	ld	hl, (ix + 15)
	ld	de, (ix - 28)
	add	hl, de
	ld	(ix - 22), hl
	ld	iy, (ix + 9)
	add	iy, de
	ld	hl, (ix + 12)
	or	a, a
	sbc	hl, de
	ld	de, 0
	ld	(ix - 34), hl
.lbl_23:
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_6
	ld	(ix - 31), bc
	ld	de, (ix - 34)
	push	de
	pop	hl
	ld	bc, 16
	or	a, a
	sbc	hl, bc
	jr	c, .lbl_26
	ld	de, 16
.lbl_26:
	ld	(ix - 37), de
	push	de
	push	iy
	ld	hl, (ix - 22)
	push	hl
	ld	(ix - 28), iy
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 25)
	push	hl
	ld	hl, (ix - 19)
	push	hl
	call	aes_ecb_unsafe_encrypt
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 37)
	push	hl
	ld	hl, (ix - 22)
	push	hl
	ld	hl, (ix - 25)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	bc, (ix + 6)
	push	bc
	pop	hl
	ld	de, 261
	add	hl, de
	ld	de, 0
	ld	e, (hl)
	push	bc
	pop	hl
	ld	bc, 262
	add	hl, bc
	ld	bc, 0
	ld	c, (hl)
	push	bc
	push	de
	ld	hl, (ix - 19)
	push	hl
	call	_increment_iv
	ld	iy, (ix + 6)
	pop	hl
	pop	hl
	pop	hl
	ld	bc, (ix - 31)
	push	bc
	pop	hl
	ld	de, 1
	or	a, a
	sbc	hl, de
	jr	nz, .lbl_28
	ld	de, (ix - 40)
	ld	hl, (ix - 25)
	ld	bc, 16
	ldir
	ld	bc, (ix - 31)
	ld	hl, (ix - 37)
	ld	a, l
	lea	hl, iy
	ld	de, 263
	add	hl, de
	ld	(hl), a
.lbl_28:
	dec	bc
	ld	iy, (ix - 22)
	lea	iy, iy + 16
	ld	(ix - 22), iy
	ld	iy, (ix - 28)
	lea	iy, iy + 16
	ld	de, -16
	ld	hl, (ix - 34)
	add	hl, de
	ld	(ix - 34), hl
	ld	de, 0
	jp	.lbl_23
.lbl_29:
	ld	a, l
	cp	a, 2
	jp	nz, .lbl_43
	ld	(ix - 31), bc
	ld	de, 261
	ld	iy, (ix + 6)
	lea	hl, iy
	add	hl, de
	ld	(ix - 22), hl
	ld	de, 310
	lea	hl, iy
	add	hl, de
	ld	de, 349
	add	iy, de
	ld	a, (iy)
	cp	a, 2
	ld	de, 6
	ld	bc, 0
	jp	nc, .lbl_6
	ld	(ix - 28), iy
	ld	(ix - 37), hl
	ld	hl, (ix - 22)
	ld	e, (hl)
	or	a, a
	ld	iy, (ix + 6)
	jr	nz, .lbl_34
	ld	(ix - 22), e
	ld	de, 342
	lea	hl, iy
	add	hl, de
	ld	e, (ix - 22)
	ld	l, (hl)
	ld	a, l
	or	a, a
	jr	z, .lbl_34
	ld	(ix - 16), 0
	ld	bc, (ix - 25)
	ld	a, l
	push	bc
	pop	hl
	inc	hl
	ex	de, hl
	push	bc
	pop	hl
	ld	bc, 15
	ldir
	ld	de, 0
	ld	e, a
	ld	hl, 16
	or	a, a
	sbc	hl, de
	push	hl
	ld	hl, (ix - 25)
	push	hl
	ld	hl, (ix - 37)
	push	hl
	push	iy
	call	_ghash
	ld	e, (ix - 22)
	ld	iy, (ix + 6)
	ld	bc, 0
	pop	hl
	pop	hl
	pop	hl
	pop	hl
.lbl_34:
	ld	hl, (ix - 28)
	ld	(hl), 1
	ld	a, e
	and	a, 15
	or	a, a
	ld	(ix - 28), bc
	jr	z, .lbl_36
	or	a, a
	sbc	hl, hl
	push	hl
	pop	bc
	ld	c, e
	ld	(ix - 22), bc
	ld	hl, 16
	sbc	hl, bc
	ld	(ix - 28), hl
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 15)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	ld	de, (ix - 22)
	add	hl, de
	ld	de, 262
	add	hl, de
	ld	de, (ix - 28)
	push	de
	ld	de, (ix + 15)
	push	de
	push	hl
	call	_xor_buf
	ld	iy, (ix + 6)
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 12)
	ld	de, (ix - 28)
	or	a, a
	sbc	hl, de
	ld	c, 4
	call	ti._ishru
	ld	(ix - 31), hl
.lbl_36:
	lea	hl, iy
	ld	de, 262
	add	hl, de
	ld	(ix - 43), hl
	ld	de, (ix - 31)
	inc	de
	ld	hl, (ix + 12)
	ld	bc, (ix - 28)
	or	a, a
	sbc	hl, bc
	ld	(ix - 22), hl
	ld	(ix - 28), bc
.lbl_37:
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_44
	ld	(ix - 31), de
	ld	de, (ix - 22)
	push	de
	pop	hl
	ld	bc, 16
	or	a, a
	sbc	hl, bc
	push	de
	pop	bc
	jr	c, .lbl_40
	ld	hl, 16
	push	hl
	pop	bc
.lbl_40:
	ld	(ix - 34), bc
	ld	de, (ix - 28)
	ld	hl, (ix + 15)
	push	hl
	pop	iy
	add	iy, de
	ld	(ix - 40), iy
	ld	hl, (ix + 9)
	add	hl, de
	push	bc
	push	hl
	push	iy
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 25)
	push	hl
	ld	hl, (ix - 19)
	push	hl
	call	aes_ecb_unsafe_encrypt
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 34)
	push	hl
	ld	hl, (ix - 40)
	push	hl
	ld	hl, (ix - 25)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 4
	push	hl
	ld	hl, 12
	push	hl
	ld	hl, (ix - 19)
	push	hl
	call	_increment_iv
	ld	iy, (ix + 6)
	pop	hl
	pop	hl
	pop	hl
	ld	bc, (ix - 31)
	push	bc
	pop	hl
	ld	de, 1
	or	a, a
	sbc	hl, de
	jr	nz, .lbl_42
	ld	de, (ix - 43)
	ld	hl, (ix - 25)
	ld	bc, 16
	ldir
	ld	bc, (ix - 31)
	ld	hl, (ix - 34)
	ld	a, l
	lea	hl, iy
	ld	de, 261
	add	hl, de
	ld	(hl), a
.lbl_42:
	dec	bc
	ld	de, 16
	ld	hl, (ix - 28)
	add	hl, de
	ld	(ix - 28), hl
	ld	de, -16
	ld	hl, (ix - 22)
	add	hl, de
	ld	(ix - 22), hl
	push	bc
	pop	de
	jp	.lbl_37
.lbl_43:
	ld	de, 3
	jp	.lbl_6
.lbl_44:
	ld	hl, (ix + 12)
	push	hl
	ld	hl, (ix + 15)
	push	hl
	ld	hl, (ix - 37)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	_ghash
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	de, 346
	ld	iy, (ix + 6)
	add	iy, de
	ld	hl, (iy)
	ld	de, (ix + 12)
	add	hl, de
	ld	(iy), hl
	ld	de, 0
	jp	.lbl_6
	
	
aes_decrypt:
	save_interrupts

	ld	hl, -56
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	de, (ix + 12)
	ld	hl, 1
	ld	(ix - 35), hl
	ld	bc, 243
	lea	hl, iy
	add	hl, bc
	ld	(ix - 44), hl
	ld	c, 4
	ex	de, hl
	call	ti._ishru
	lea	bc, iy
	ld	(ix - 38), hl
	ld	hl, (ix + 15)
	ld	(ix - 41), hl
	ld	hl, (ix + 15)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	de, 259
	jr	nz, .lbl_2
	push	bc
	pop	hl
	add	hl, de
	ld	a, (hl)
	cp	a, 2
	jp	nz, .lbl_31
.lbl_2:
	push	de
	pop	iy
	push	bc
	pop	hl
	ld	de, 6
	ld	bc, 260
	add	hl, bc
	ld	a, (hl)
	cp	a, b
	jr	nz, .lbl_4
.lbl_3:
	ld	(ix - 35), de
	jp	.lbl_31
.lbl_4:
	ld	bc, (ix + 9)
	ld	(hl), 2
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_31
	ld	de, 5
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	(ix - 35), de
	jp	z, .lbl_31
	lea	hl, ix - 16
	ld	(ix - 47), hl
	ld	hl, (ix + 6)
	lea	de, iy
	add	hl, de
	ld	l, (hl)
	ld	a, l
	or	a, a
	jp	nz, .lbl_11
	ld	hl, (ix + 12)
	ld	a, l
	and	a, 15
	or	a, a
	jp	nz, .lbl_31
	lea	hl, ix - 32
	ld	(ix - 50), hl
	push	bc
	pop	iy
	ld	bc, (ix - 38)
	ld	de, (ix - 47)
.lbl_9:
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_13
	ld	de, (ix - 47)
	lea	hl, iy
	ld	(ix - 38), bc
	ld	bc, 16
	ldir
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 50)
	push	hl
	ld	hl, (ix - 47)
	push	hl
	ld	(ix - 35), iy
	call	aes_ecb_unsafe_decrypt
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix - 50)
	push	hl
	ld	hl, (ix - 44)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix - 41)
	ld	hl, (ix - 50)
	ld	iy, 16
	lea	bc, iy
	ldir
	ld	de, (ix - 44)
	ld	hl, (ix - 47)
	lea	bc, iy
	ldir
	ld	de, (ix - 47)
	ld	bc, (ix - 38)
	dec	bc
	ld	iy, (ix - 35)
	lea	iy, iy + 16
	ld	(ix - 35), iy
	ld	iy, (ix - 41)
	lea	iy, iy + 16
	ld	(ix - 41), iy
	ld	iy, (ix - 35)
	jr	.lbl_9
.lbl_11:
	ld	a, l
	cp	a, 1
	jr	nz, .lbl_14
	ld	hl, (ix + 6)
	push	hl
	pop	iy
	ld	de, 260
	add	hl, de
	ld	(ix - 35), hl
	ld	(hl), d
	ld	de, (ix + 15)
	push	de
	ld	de, (ix + 12)
	push	de
	push	bc
	push	iy
	call	aes_encrypt
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 35)
	ld	(hl), 2
	ld	de, 0
	jp	.lbl_3
.lbl_13:
	or	a, a
	sbc	hl, hl
	jp	.lbl_30
.lbl_14:
	ld	a, l
	cp	a, 2
	jp	nz, .lbl_29
	ld	de, 261
	ld	bc, (ix + 6)
	push	bc
	pop	hl
	add	hl, de
	ld	(ix - 41), hl
	ld	de, 310
	push	bc
	pop	iy
	add	iy, de
	ld	de, 349
	push	bc
	pop	hl
	add	hl, de
	ld	a, (hl)
	cp	a, 2
	ld	de, 6
	ld	(ix - 35), de
	jp	nc, .lbl_31
	ld	(ix - 35), iy
	ld	(ix - 53), hl
	ld	hl, (ix - 41)
	ld	l, (hl)
	ld	(ix - 50), l
	or	a, a
	ld	iy, (ix + 6)
	jr	nz, .lbl_19
	ld	de, 342
	lea	hl, iy
	add	hl, de
	ld	l, (hl)
	ld	a, l
	or	a, a
	jr	z, .lbl_19
	ld	(ix - 16), 0
	ld	bc, (ix - 47)
	push	bc
	pop	de
	inc	de
	ld	a, l
	push	bc
	pop	hl
	ld	bc, 15
	ldir
	ld	de, 0
	ld	e, a
	ld	hl, 16
	or	a, a
	sbc	hl, de
	push	hl
	ld	hl, (ix - 47)
	push	hl
	ld	hl, (ix - 35)
	push	hl
	push	iy
	call	_ghash
	ld	iy, (ix + 6)
	pop	hl
	pop	hl
	pop	hl
	pop	hl
.lbl_19:
	ld	hl, (ix + 12)
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix - 35)
	push	hl
	push	iy
	call	_ghash
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	de, 346
	ld	iy, (ix + 6)
	add	iy, de
	ld	hl, (iy)
	ld	de, (ix + 12)
	add	hl, de
	ld	(iy), hl
	ld	iy, (ix + 15)
	lea	hl, iy
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	de, 0
	jp	z, .lbl_3
	ld	hl, (ix - 53)
	ld	(hl), 1
	ld	l, (ix - 50)
	ld	a, l
	and	a, 15
	or	a, a
	ld	(ix - 41), de
	ld	bc, (ix - 38)
	jr	z, .lbl_22
	ld	a, l
	or	a, a
	sbc	hl, hl
	ex	de, hl
	ld	e, a
	ld	(ix - 35), de
	ld	hl, 16
	sbc	hl, de
	ld	(ix - 41), hl
	push	hl
	ld	hl, (ix + 9)
	push	hl
	push	iy
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	ld	de, (ix - 35)
	add	hl, de
	ld	de, 262
	add	hl, de
	ld	de, (ix - 41)
	push	de
	ld	de, (ix + 15)
	push	de
	push	hl
	call	_xor_buf
	ld	iy, (ix + 15)
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 12)
	ld	de, (ix - 41)
	or	a, a
	sbc	hl, de
	ld	c, 4
	call	ti._ishru
	push	hl
	pop	bc
.lbl_22:
	ld	hl, (ix + 6)
	ld	de, 262
	add	hl, de
	ld	(ix - 56), hl
	inc	bc
	ld	de, (ix - 41)
	add	iy, de
	ld	hl, (ix + 9)
	add	hl, de
	ld	(ix - 35), hl
	ld	hl, (ix + 12)
	or	a, a
	sbc	hl, de
	ld	de, 0
	ld	(ix - 50), hl
.lbl_23:
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_3
	ld	(ix - 38), bc
	ld	de, (ix - 50)
	push	de
	pop	hl
	ld	bc, 16
	or	a, a
	sbc	hl, bc
	jr	c, .lbl_26
	ld	de, 16
.lbl_26:
	ld	(ix - 53), de
	push	de
	ld	hl, (ix - 35)
	push	hl
	push	iy
	ld	(ix - 41), iy
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 47)
	push	hl
	ld	hl, (ix - 44)
	push	hl
	call	aes_ecb_unsafe_encrypt
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 53)
	push	hl
	ld	hl, (ix - 41)
	push	hl
	ld	hl, (ix - 47)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 4
	push	hl
	ld	hl, 12
	push	hl
	ld	hl, (ix - 44)
	push	hl
	call	_increment_iv
	ld	iy, (ix + 6)
	pop	hl
	pop	hl
	pop	hl
	ld	bc, (ix - 38)
	push	bc
	pop	hl
	ld	de, 1
	or	a, a
	sbc	hl, de
	jr	nz, .lbl_28
	ld	de, (ix - 56)
	ld	hl, (ix - 47)
	ld	bc, 16
	ldir
	ld	bc, (ix - 38)
	ld	hl, (ix - 53)
	ld	a, l
	lea	hl, iy
	ld	de, 261
	add	hl, de
	ld	(hl), a
.lbl_28:
	dec	bc
	ld	iy, (ix - 41)
	lea	iy, iy + 16
	lea	hl, iy
	ld	iy, (ix - 35)
	lea	iy, iy + 16
	ld	(ix - 35), iy
	push	hl
	pop	iy
	ld	de, -16
	ld	hl, (ix - 50)
	add	hl, de
	ld	(ix - 50), hl
	ld	de, 0
	jp	.lbl_23
.lbl_29:
	ld	hl, 3
.lbl_30:
	ld	(ix - 35), hl
.lbl_31:
	ld	hl, (ix - 35)
	restore_interrupts_noret aes_decrypt
	jq stack_clear
	
	
 
oaep_encode:
	save_interrupts

	ld	hl, -401
	call	ti._frameset
	lea	de, ix - 121
	ld	l, (ix + 21)
	push	hl
	ld	bc, -380
	lea	hl, ix
	add	hl, bc
	ld	(hl), de
	push	de
	call	cryptx_hash_init
	pop	hl
	pop	hl
	bit	0, a
	jp	z, .lbl_6
	ld	de, 0
	ld	e, (ix - 112)
	ld	c, 1
	push	de
	pop	hl
	call	ti._ishl
	push	hl
	pop	iy
	ld	hl, (ix + 9)
	ld	bc, 2
	add	hl, bc
	lea	bc, iy
	add	hl, bc
	push	hl
	pop	bc
	ld	iy, (ix + 15)
	lea	hl, iy
	ld	(ix - 3), de
	push	ix
	ld	de, -383
	add	ix, de
	ld	(ix), bc
	pop	ix
	or	a, a
	sbc	hl, bc
	push	ix
	ld	bc, -389
	add	ix, bc
	ld	(ix), hl
	pop	ix
	ld	de, (ix - 3)
	push	de
	pop	hl
	call	ti._inot
	lea	bc, iy
	add	hl, bc
	ld	(ix - 3), de
	ld	de, -386
	lea	iy, ix
	add	iy, de
	ld	(iy), hl
	push	bc
	pop	hl
	ld	de, (ix - 3)
	push	de
	pop	iy
	inc	iy
	add	iy, de
	ld	bc, 257
	or	a, a
	sbc	hl, bc
	jr	nc, .lbl_6
	ld	(ix - 3), de
	ld	de, -383
	lea	hl, ix
	add	hl, de
	ld	bc, (hl)
	ld	de, (ix - 3)
	ld	(ix - 3), bc
	push	ix
	ld	bc, -392
	add	ix, bc
	ld	(ix), de
	pop	ix
	ld	hl, (ix + 9)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	bc, (ix - 3)
	jr	z, .lbl_6
	ld	hl, (ix + 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_6
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_6
	ex	de, hl
	ld	hl, (ix + 15)
	or	a, a
	sbc	hl, bc
	jr	nc, .lbl_8
.lbl_6:
	or	a, a
	sbc	hl, hl
.lbl_7:
	restore_interrupts_noret oaep_encode
	jp stack_clear
.lbl_8:
	ld	bc, -377
	lea	hl, ix
	add	hl, bc
	push	ix
	ld	bc, -383
	add	ix, bc
	ld	(ix), hl
	pop	ix
	ld	bc, -401
	lea	hl, ix
	add	hl, bc
	ld	(hl), iy
	push	de
	pop	hl
	ld	(hl), 0
	inc	de
	ld	bc, -392
	lea	iy, ix
	add	iy, bc
	ld	hl, (iy)
	push	hl
	ld	bc, -395
	lea	hl, ix
	add	hl, bc
	ld	(hl), de
	push	de
	call	cryptx_csrand_fill
	pop	hl
	pop	hl
	ld	hl, (ix + 18)
	push	hl
	pop	de
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	(ix - 3), de
	ld	de, -380
	lea	iy, ix
	push	af
	add	iy, de
	pop	af
	ld	bc, (iy)
	ld	de, (ix - 3)
	jr	z, .lbl_10
	push	de
	call	ti._strlen
	pop	de
	push	hl
	ld	hl, (ix + 18)
	push	hl
	ld	bc, -380
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_hash_update
	ld	de, -380
	lea	hl, ix
	add	hl, de
	ld	bc, (hl)
	pop	hl
	pop	hl
	pop	hl
.lbl_10:
	ld	hl, (ix + 12)
	ld	(ix - 3), bc
	ld	bc, -392
	lea	iy, ix
	add	iy, bc
	ld	de, (iy)
	add	hl, de
	inc	hl
	push	ix
	ld	de, -398
	add	ix, de
	ld	(ix), hl
	pop	ix
	push	hl
	ld	bc, (ix - 3)
	push	bc
	call	cryptx_hash_digest
	pop	hl
	pop	hl
	ld	hl, (ix + 12)
	ld	bc, -401
	lea	iy, ix
	add	iy, bc
	ld	de, (iy)
	add	hl, de
	push	ix
	ld	bc, -389
	add	ix, bc
	ld	de, (ix)
	pop	ix
	push	de
	ld	de, 0
	push	de
	push	hl
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -389
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	ld	bc, -401
	lea	iy, ix
	add	iy, bc
	ld	de, (iy)
	add	hl, de
	ex	de, hl
	ld	hl, (ix + 12)
	add	hl, de
	ld	(hl), 1
	inc	hl
	ex	de, hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	push	de
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	l, (ix + 21)
	push	hl
	ld	bc, -386
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -383
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -392
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -395
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_hash_mgf1
	ld	de, -386
	lea	hl, ix
	add	hl, de
	ld	bc, (hl)
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	de, 0
.lbl_11:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jr	z, .lbl_13
	ld	bc, -383
	lea	hl, ix
	add	hl, bc
	ld	iy, (hl)
	add	iy, de
	push	ix
	ld	bc, -398
	add	ix, bc
	ld	hl, (ix)
	pop	ix
	add	hl, de
	ld	a, (hl)
	xor	a, (iy)
	ld	(ix - 3), de
	ld	de, -386
	lea	iy, ix
	add	iy, de
	ld	bc, (iy)
	ld	(hl), a
	ld	de, (ix - 3)
	inc	de
	jr	.lbl_11
.lbl_13:
	ld	l, (ix + 21)
	push	hl
	ld	de, -392
	lea	hl, ix
	add	hl, de
	ld	hl, (hl)
	push	hl
	ld	de, -383
	lea	hl, ix
	add	hl, de
	ld	hl, (hl)
	push	hl
	push	bc
	ld	bc, -398
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_hash_mgf1
	ld	de, -392
	lea	hl, ix
	add	hl, de
	ld	bc, (hl)
	pop	de
	pop	de
	pop	de
	pop	de
	pop	de
	ld	de, (ix + 15)
.lbl_14:
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_16
	ld	(ix - 3), de
	ld	de, -395
	lea	hl, ix
	add	hl, de
	ld	hl, (hl)
	ld	a, (hl)
	ld	de, -383
	lea	iy, ix
	add	iy, de
	ld	iy, (iy)
	xor	a, (iy)
	ld	(hl), a
	dec	bc
	inc	iy
	push	ix
	add	ix, de
	ld	(ix), iy
	pop	ix
	inc	hl
	ld	de, -395
	lea	iy, ix
	add	iy, de
	ld	(iy), hl
	ld	de, (ix - 3)
	jr	.lbl_14
.lbl_16:
	ex	de, hl
	jp	.lbl_7
	
 
 
oaep_decode:
	save_interrupts

	ld	hl, -718
	call	ti._frameset
	ld	hl, (ix + 9)
	ld	de, -257
	ld	bc, 0
	add	hl, de
	inc	de
	or	a, a
	sbc	hl, de
	jp	c, .lbl_20
	ld	hl, (ix + 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_20
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_20
	lea	de, ix - 121
	ld	l, (ix + 18)
	push	hl
	ld	bc, -712
	lea	hl, ix
	add	hl, bc
	ld	(hl), de
	push	de
	call	cryptx_hash_init
	pop	hl
	pop	hl
	bit	0, a
	jp	z, .lbl_19
	ld	bc, -185
	lea	hl, ix
	add	hl, bc
	ld	bc, -715
	lea	iy, ix
	add	iy, bc
	ld	(iy), hl
	ld	bc, -441
	lea	hl, ix
	add	hl, bc
	push	ix
	ld	bc, -706
	add	ix, bc
	ld	(ix), hl
	pop	ix
	ld	bc, -697
	lea	hl, ix
	add	hl, bc
	push	ix
	ld	bc, -700
	add	ix, bc
	ld	(ix), hl
	pop	ix
	or	a, a
	sbc	hl, hl
	ld	l, (ix - 112)
	push	ix
	ld	bc, -703
	add	ix, bc
	ld	(ix), hl
	pop	ix
	call	ti._inot
	push	hl
	pop	iy
	ld	hl, (ix + 9)
	ex	de, hl
	add	iy, de
	ld	bc, -718
	lea	hl, ix
	add	hl, bc
	ld	(hl), iy
	ld	bc, -703
	lea	iy, ix
	add	iy, bc
	ld	hl, (iy)
	inc	hl
	push	ix
	ld	bc, -709
	add	ix, bc
	ld	(ix), hl
	pop	ix
	push	de
	ld	hl, (ix + 6)
	push	hl
	ld	bc, -700
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	de, -700
	lea	hl, ix
	add	hl, de
	ld	hl, (hl)
	ld	de, -703
	lea	iy, ix
	add	iy, de
	ld	bc, (iy)
	add	hl, bc
	inc	hl
	ld	e, (ix + 18)
	push	de
	push	bc
	push	ix
	ld	bc, -706
	add	ix, bc
	ld	de, (ix)
	pop	ix
	push	de
	push	ix
	ld	bc, -718
	add	ix, bc
	ld	de, (ix)
	pop	ix
	push	de
	push	hl
	call	cryptx_hash_mgf1
	ld	de, -703
	lea	hl, ix
	add	hl, de
	ld	bc, (hl)
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	de, 0
.lbl_5:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jr	z, .lbl_7
	ld	(ix - 3), bc
	ld	bc, -706
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	add	hl, de
	ld	bc, -700
	lea	iy, ix
	add	iy, bc
	ld	iy, (iy)
	add	iy, de
	inc	de
	ld	a, (iy + 1)
	xor	a, (hl)
	ld	(iy + 1), a
	ld	bc, (ix - 3)
	jr	.lbl_5
.lbl_7:
	ld	de, -700
	lea	hl, ix
	add	hl, de
	ld	hl, (hl)
	inc	hl
	ld	e, (ix + 18)
	push	de
	ld	(ix - 3), bc
	ld	bc, -718
	lea	iy, ix
	add	iy, bc
	ld	de, (iy)
	push	de
	push	ix
	ld	bc, -706
	add	ix, bc
	ld	de, (ix)
	pop	ix
	push	de
	ld	bc, (ix - 3)
	push	bc
	push	hl
	call	cryptx_hash_mgf1
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -709
	lea	hl, ix
	add	hl, bc
	ld	de, (hl)
	ld	bc, (ix + 9)
.lbl_8:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jr	z, .lbl_10
	ld	(ix - 3), bc
	ld	bc, -700
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	add	hl, de
	ld	a, (hl)
	ld	bc, -706
	lea	iy, ix
	add	iy, bc
	ld	iy, (iy)
	xor	a, (iy)
	ld	(hl), a
	inc	de
	inc	iy
	lea	hl, ix
	add	hl, bc
	ld	(hl), iy
	ld	bc, (ix - 3)
	jr	.lbl_8
.lbl_10:
	ld	bc, -709
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	ld	bc, -703
	lea	iy, ix
	add	iy, bc
	ld	de, (iy)
	add	hl, de
	push	ix
	ld	bc, -709
	add	ix, bc
	ld	(ix), hl
	pop	ix
	ld	hl, (ix + 15)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	push	ix
	ld	bc, -712
	push	af
	add	ix, bc
	pop	af
	ld	de, (ix)
	pop	ix
	jr	z, .lbl_12
	push	hl
	call	ti._strlen
	pop	de
	push	hl
	ld	hl, (ix + 15)
	push	hl
	ld	bc, -712
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_hash_update
	ld	bc, -712
	lea	hl, ix
	add	hl, bc
	ld	de, (hl)
	pop	hl
	pop	hl
	pop	hl
.lbl_12:
	ld	bc, -715
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	push	de
	call	cryptx_hash_digest
	pop	hl
	pop	hl
	ld	bc, -703
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	hl, (ix + 12)
	push	hl
	ld	bc, -715
	lea	hl, ix
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	cryptx_digest_compare
	pop	hl
	pop	hl
	pop	hl
	bit	0, a
	jr	z, .lbl_19
	ld	de, -709
	lea	hl, ix
	add	hl, de
	ld	bc, (hl)
	push	bc
	pop	hl
	ld	de, (ix + 9)
	or	a, a
	sbc	hl, de
	jr	c, .lbl_15
	push	bc
	pop	de
.lbl_15:
	push	de
	pop	iy
.lbl_16:
	push	bc
	pop	hl
	ld	de, (ix + 9)
	or	a, a
	sbc	hl, de
	jr	nc, .lbl_21
	ld	de, -700
	lea	hl, ix
	add	hl, de
	ld	hl, (hl)
	add	hl, bc
	ld	a, (hl)
	cp	a, 1
	jr	z, .lbl_22
	inc	bc
	jr	.lbl_16
.lbl_19:
	ld	bc, 0
.lbl_20:
	push	bc
	pop	hl
	restore_interrupts_noret oaep_decode
	jp stack_clear
.lbl_21:
	lea	hl, iy
	jr	.lbl_23
.lbl_22:
	push	bc
	pop	hl
.lbl_23:
	ld	bc, -703
	lea	iy, ix
	add	iy, bc
	ld	(iy), hl
	ld	de, (ix + 9)
	or	a, a
	sbc	hl, de
	ld	bc, 0
	jr	z, .lbl_20
	ld	bc, -700
	lea	hl, ix
	add	hl, bc
	ld	iy, (hl)
	ex	de, hl
	push	ix
	ld	bc, -703
	add	ix, bc
	ld	de, (ix)
	pop	ix
	add	iy, de
	inc	de
	inc	iy
	or	a, a
	sbc	hl, de
	push	ix
	ld	bc, -700
	add	ix, bc
	ld	(ix), hl
	pop	ix
	push	hl
	push	iy
	ld	hl, (ix + 12)
	push	hl
	call	ti._memcpy
	ld	de, -700
	lea	hl, ix
	add	hl, de
	ld	bc, (hl)
	pop	hl
	pop	hl
	pop	hl
	jr	.lbl_20
 
	
rsa_encrypt:
	save_interrupts

	ld	hl, -9
	call	ti._frameset
	ld	hl, (ix + 6)
	xor	a, a
	ld	bc, 1
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_12
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_12
	ld	hl, (ix + 18)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_12
	ld	hl, (ix + 15)
	ld	de, -257
	ld	bc, 3
	add	hl, de
	ld	de, -129
	or	a, a
	sbc	hl, de
	jp	c, .lbl_12
	ld	iy, (ix + 12)
	ld	de, (ix + 15)
	add	iy, de
	ld	l, a
	ld	a, (iy - 1)
	and	a, 1
	bit	0, a
	ld	a, l
	jp	z, .lbl_12
	ld	bc, 2
	ld	iy, (ix + 12)
	lea	hl, iy
.lbl_6:
	ld	de, 0
	ld	e, a
	add	hl, de
	ld	iyl, a
	ld	a, (hl)
	or	a, a
	jr	nz, .lbl_8
	inc	iyl
	ld	hl, (ix + 18)
	add	hl, de
	ld	(hl), 0
	ld	a, iyl
	ld	hl, (ix + 12)
	jr	.lbl_6
.lbl_8:
	push	de
	pop	iy
	ld	de, (ix + 9)
	ex	de, hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_12
	ld	de, 66
	add	hl, de
	ld	(ix - 3), hl
	ld	hl, (ix + 15)
	lea	de, iy
	ld	(ix - 6), de
	or	a, a
	sbc	hl, de
	ld	(ix - 9), hl
	ld	de, (ix - 3)
	or	a, a
	sbc	hl, de
	ld	iy, (ix + 6)
	jr	c, .lbl_12
	ld	hl, (ix + 18)
	ld	bc, (ix - 6)
	add	hl, bc
	ld	c, (ix + 21)
	push	bc
	ld	bc, 0
	push	bc
	ld	de, (ix - 9)
	push	de
	push	hl
	ld	hl, (ix + 9)
	push	hl
	push	iy
	call	oaep_encode
	pop	de
	pop	de
	pop	de
	pop	de
	pop	de
	pop	de
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	bc, 4
	jr	z, .lbl_12
	ld	hl, (ix + 12)
	push	hl
	ld	hl, 65537
	push	hl
	ld	hl, (ix + 18)
	push	hl
	ld	hl, (ix + 15)
	push	hl
	call	_powmod
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, 0
.lbl_12:
	push	bc
	pop	hl
	restore_interrupts_noret rsa_encrypt
	jp stack_clear
 

	
 
;void powmod(uint8_t size, uint8_t *restrict base, uint24_t exp, const uint8_t *restrict mod);
_powmod:
   push   ix
   ld   ix, 0
   lea   bc, ix
   add   ix, sp
.ret  := ix    + long
.size := .ret  + long
.base := .size + long
.exp  := .base + long
.mod  := .exp  + long
.acc  := ix    - long
.tmp  := .acc  - long
.end  := .tmp  - byte
   ld   c, (.size)
   dec   c
   ld   hl, .end - ix
   add   hl, sp
   push   hl
;   scf
   sbc   hl, bc
   push   hl
;   or   a, a
   sbc   hl, bc
   ld   sp, hl
   ld   hl, (.mod)
   add   hl, bc
   ld   (.mod), hl
   ld   b, bsr 8
   ld   e, b
;   ld   e, 1
.nmi.loop:
   ld   a, e
   ld   d, (hl)
   mlt   de
   inc   de
   inc   de
   ld   d, a
   mlt   de
   djnz   .nmi.loop ; leaks size
   ld   a, e
   ld   (.nmi), a
   ld   hl, (.base)
   add   hl, bc
   ld   (.base), hl
   ld   c, 8
.mod.outer:
   ld   b, (.size)
.mod.inner:
   push   bc, hl
   ld   b, (.size)
;   or   a, a
.shift:
   rl   (hl)
   dec   hl
   djnz   .shift ; leaks size
   pop   hl
   push   hl
   call   .reduce
   pop   hl, bc
   djnz   .mod.inner ; leaks size
   dec   c
   jq   nz, .mod.outer ; leaks constant
   ld   c, (.size)
   dec   c
   inc   bc
   ld   de, (.acc)
   lddr ; leaks size
   ld   hl, (.exp)
   scf
.normalize:
   adc   hl, hl
   jq   nc, .normalize ; leaks exp
   xor   a, a
.loop:
   push   hl, af
   ld   hl, (.acc)
   call   nz, .mul ; leaks exp
   pop   af
   ld   hl, (.base)
   call   c, .mul ; leaks exp
   pop   hl
;   or   a, a
   adc   hl, hl
   jq   nz, .loop ; leaks exp
   ld   de, (.tmp)
   add   hl, de
   dec   de
;   ld   bc, 0
   ld   c, (.size)
   dec   c
   ld   (hl), b
   push   hl
   lddr ; leaks size
   pop   hl
   inc   (hl)
   ld   iy, (.base)
   call   .mul.alt
   ld   sp, ix
   pop   ix
   ret
   ; vi(acc) = vi(acc) * vi(hl) % vi(mod)
   ; assumes bc = 0
   ; destroys vi(tmp)
   ; returns bc = 0, cf = 0
.mul:
   ld   iy, (.tmp)
.mul.alt:
   push   hl
   lea   hl, iy - 0
   lea   de, iy - 1
   ld   c, (.size)
   dec   c
   ld   (hl), b
   lddr ; leaks size
   ld   de, (.acc)
   ld   (.acc), iy
   ld   (.tmp), de
   pop   hl
   ld   c, (.size)
   or   a, a
.mul.outer:
   ld   a, (de)
   ld   (.cur), a
   dec   de
   push   de, hl, ix, iy, af
   ld   e, (hl)
   ld   d, a
   mlt   de
   push   hl
   ld   l, (iy)
   ld   h, 0
   add   hl, de
   ld   e, l
   ld   d, 0
.nmi := $ - byte
   mlt   de
   ld   a, e
   ld   (.adj), a
   ld   b, (.size)
   dec   b
   ld   ix, (.mod)
   ld   d, (ix)
   mlt   de
   add.s   hl, de
   ld   e, h
   ld   d, l
;   ld   d, 0
   rl   d
   pop   hl
.mul.inner:
   dec   hl
   push   hl
   ld   l, (hl)
   ld   h, 0
.cur := $ - byte
   mlt   hl
   adc   hl, de
   dec   ix
   ld   e, (ix)
   ld   d, 0
.adj := $ - byte
   mlt   de
   add.s   hl, de
   ld   e, h
   ld   d, 0
   rl   d
   ld   a, l
   dec   iy
   add   a, (iy)
   ld   (iy + 1), a
   pop   hl
   djnz   .mul.inner ; leaks size
   ld   l, b
   rl   l
   ld   h, b
   pop   af
   adc   hl, de
   ld   (iy + 0), l
   sra   h
   pop   iy, ix, hl, de
   dec   c
   jq   nz, .mul.outer ; leaks size
   lea   hl, iy
   ; if (cf:vi(hl) >= vi(mod)) cf:vi(hl) -= vi(mod)
   ; assumes bcu = 0
   ; destroys vi(tmp)
   ; returns bc = 0, cf = 0
.reduce:
   ccf
   sbc   a, a
   ld   c, a
   ld   b, (.size)
   ld   de, (.tmp)
   ld   iy, (.mod)
   or   a, a
   push   hl, de
.reduce.sub:
   ld   a, (hl)
   dec   hl
   sbc   a, (iy)
   dec   iy
   ld   (de), a
   dec   de
   djnz   .reduce.sub ; leaks size
   sbc   a, a
   and   a, c
   and   a, long
   sbc   hl, hl
   ld   l, a
   add   hl, sp
   ld   hl, (hl)
   pop   de, de
   ld   c, (.size)
   dec   c
   inc   bc
   lddr ; leaks size, assuming that base and stack are in normal ram
   ret
 
; point_iszero(struct Point *pt)
_point_iszero:
	pop bc,hl
	push hl,bc
	ld b, 60
	xor a
.loop:
	or (hl)
	inc hl
	djnz .loop
	add a, -1
	sbc a, a
	inc a
	ret

; bigint_iszero(uint8_t *op);
_bigint_iszero:
	pop bc,hl
	push hl,bc
	ld b, 30
	xor a
.loop:
	or (hl)
	inc hl
	djnz .loop
	add a, -1
	sbc a, a
	inc a
	ret

; point_isequal(struct Point *pt1, struct Point *pt2);
_point_isequal:
	call ti._frameset0
	ld hl, (ix + 6)
	ld de, (ix + 9)
	ld b, 60
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
	pop ix
	ret
	
; bigint_isequal(uint8_t *op1, uint8_t *op2);
_bigint_isequal:
	call ti._frameset0
	ld hl, (ix + 6)
	ld de, (ix + 9)
	ld b, 30
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
	pop ix
	ret


; gf2_bigint_add(uint8_t *out, uint8_t *op1, uint8_t *op2);
; hard limit to 32 bytes
; output in op1
; addition over a galois field of form GF(2^m) is mod 2 or just xor
_bigint_add:
	call ti._frameset0
	ld hl, (ix + 9)		; op1
	ld de, (ix + 12)		; op2
	ld ix, (ix + 6)		; out
_ibigint_add:
	ld b, 30
.loop:
	ld a, (de)
	xor a, (hl)
	ld (ix), a
	inc hl
	inc de
	inc ix
	djnz .loop
	pop ix
	ret
	

; gf2_bigint_sub(uint8_t *op1, uint8_t *op2);
; on a binary field addition and subtraction are the same
_bigint_sub = _bigint_add
	

; gf2_bigint_mul(uint8_t *out, uint8_t *op1, uint8_t *op2)
; multiplication is add then double, then a polynomial reduction
_bigint_mul:
	ld hl, -30
	call ti._frameset
	lea de, ix - 30		; stack mem?
	ld hl, (ix + 9)		; op1 (save a copy)
	ld bc, 30
	ldir				; ix - 32 = tmp = op1
	
	; zero out output
	ld de, (ix + 6)		; op 1
	xor a
	ld (de), a
	inc de
	ld hl, (ix + 6)
	ld bc, 29
	ldir
	
	ld hl, (ix + 12)		; op2 = for bit in bits
	ld c, 30
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
				lea de, ix - 30		; de = tmp (src)
				ld b, 30
.loop_add:
				ld a, (de)
				and a, c
				xor a, (hl)
				ld (hl), a
				inc hl
				inc de
				djnz .loop_add
		
				; now double tmp
				lea hl, ix - 30		; tmp in hl
				ld b, 30
				or a				; reset carry
.loop_mul2:
				rl (hl)
				inc hl
				djnz .loop_mul2
			
				; now xor with polynomial if tmp degree too high
				; method below is constant-time
				
				ld b, (ix - 1)
				ld c, b
				res 0, b
				res 1, c
				
				ld (ix - 1), c
				
				ld a, b
				rlca
				xor a, (ix - 21)
				ld (ix - 21), a
				
				ld a, b
				rrca
				xor a, (ix - 30)
				ld (ix - 30), a
			
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
	
	
_bigint_square:
; Destination needs space for 61 bytes during computation (But at the end, only the first 30 bytes contain valid data)
; Input: DE: Start of source, IY: Start of destination
; Output: A destroyed, B=C=0, DE: Start of destination + 10, HL: Start of destination + 9, IY: Start of destination + 31
	ld hl, -61
	call ti._frameset
	lea iy, ix - 61			; using a temp buffer for dest
	ld de, (ix + 9)			; iy = src
	ld c, 30
.byteLoop:
	ld a, (de)
	inc de
	ld b, 8
	.bitLoop:
		add hl, hl
		rla
		adc hl, hl
		djnz .bitLoop
	ld (iy), hl
	lea iy, iy + 2
	dec c
	jr nz, .byteLoop
	
	ld b, 29
	.reduceLoop:
		dec iy
		ld hl, (iy - 2)
		ld a, h
		rra
		ld a, l
		rra
		xor a, (iy - 31)
		ld (iy - 31), a
		add hl, hl
		lea de, iy - 21
		ld a, (de)
		xor a, h
		ld (de), a
		djnz .reduceLoop
	
	ld a, l
	rrca
	and a, 1
	ld (iy - 2), a
	rlca
	xor a, l
	lea hl, iy - 22
	xor a, (hl)
	ld (hl), a
	
	; copy tmp buffer to dest
	ld de, (ix + 6)
	lea hl, ix - 61
	ld bc, 30
	ldir
	
	ld sp, ix
	pop ix
	ret


; gf2_bigint_invert(BIGINT out, BIGINT op);
_bigint_invert:

; local definitions for ease of use
; _tmp	= ix - 30
; _g	= ix - 60
; _v	= ix - 90
; ptr_op	= ix - 93
; ptr_tmp	= ix - 96
; ptr_g		= ix - 99
; ptr_v		= ix - 102

	ld hl, -102
	call ti._frameset

; rcopy _polynomial to _v
	ld hl, _sect233k1 + 29		; skip to the end of the 30-byte binary polynomial repr.
	lea de, ix - 90				; _v
	ld bc, 30
.loop_copy_poly:
	ldi
	dec hl
	dec hl
	jp pe, .loop_copy_poly
	
; zero out g
	lea de, ix - 60			; g
	xor a
	ld (de), a
	inc de
	lea hl, ix - 60
	ld bc, 29
	ldir

; copy op to _tmp
	ld hl, (ix + 9)
	lea de, ix - 30
	ld bc, 30
	ldir

; then set res to 1 (it is result)
	ld de, (ix + 6)		; res
	push de
	ld hl, (ix + 6)
	xor a
	ld (de), a
	inc de
	ld bc, 29
	ldir
	pop de
	ld a, 1
	ld (de), a
	
	; save pointer to op
	ld hl, (ix + 6)
	ld (ix - 93), hl
	
	lea hl, ix - 30
	ld (ix - 96), hl
	
	lea hl, ix - 60
	ld (ix - 99), hl
	
	lea hl, ix - 90
	ld (ix - 102), hl
	
; (ix - 93) = op
; (ix - 96) = tmp
; (ix - 99) = g
; (ix - 102) = v
	
; while tmp != 1
.while_tmp_not_1:

; compute degree of tmp (in bits)
	ld hl, (ix - 96)
	call _get_degree		; degree of 1 means value of _tmp = 1
	
	cp 1			; if degree is 1, then value is 1 and we can exit
	jr z, .tmp_is_1
	
	push af

; compute degree of v (in bits)
		ld hl, (ix - 102)
		call _get_degree
		ld b, a						; in b
	pop af

; subtract degree(tmp) - degree(v)
	sub a, b
	
; if no carry, skip swaps
	jr nc, .noswap
	
	push af		; we will need a after the swapping is done
	
;	swap polynomial with tmp (pointer swap, not data swap)
		ld hl, (ix - 96)
		ld de, (ix - 102)
		ld (ix - 96), de
		ld (ix - 102), hl
		
;	swap result with g
		ld hl, (ix - 93)
		ld de, (ix - 99)
		ld (ix - 93), de
		ld (ix - 99), hl
		
;	negate i
	pop af
	neg
	
.noswap:
	
; shift v left by a bits, xor with tmp

	ld iy, (ix - 102)
	ld de, (ix - 96)
	push af
		call _lshift_add
		
; shift g left by i bits, xor with op
	
		ld iy, (ix - 99)
		ld de, (ix - 93)
	pop af		; we need a back, logic repeats for shift g
	call _lshift_add
	
	jr .while_tmp_not_1
; if tmp is 1, exit
.tmp_is_1:
	ld hl, (ix - 93)
	ld de, (ix + 6)
	sbc hl, de		; if hl and de are equal, don't need to copy
	jr z, .exit
	add hl, de
	ld bc, 30
	ldir
.exit:
	ld sp, ix
	pop ix
	ret


_lshift_add:
; inputs: iy = ptr to src, de = ptr to dest, a = shift count
; outputs: (de) += (iy) << a
; destroys: af, bc, de, hl, iy
	; divide a by 8 and put bits multiplier in c
	or a, a
	sbc hl, hl
	ex de, hl
	rra
	ld e, a
	sbc a, a
	xor a, $55
	ld c, a
	srl e
	sbc a, a
	xor a, $33
	and a, c
	ld c, a
	srl e
	sbc a, a
	xor a, $0F
	and a, c
	ld c, a
	; adjust dest pointer in hl
	add hl, de
	; put loop counter in b
	ld a, 30+1
	sub a, e
	rra
	ld b, a
	jr nc, .loop_lshift_add_entry
	inc iy
.loop_lshift_add:
	ld a, d
	ld e, (iy - 1)
	ld d, c
	mlt de
	or a, e
	xor a, (hl)
	ld (hl), a
	inc hl
.loop_lshift_add_entry:
	ld a, d
	ld e, (iy)
	ld d, c
	mlt de
	or a, e
	xor a, (hl)
	ld (hl), a
	inc hl
	lea iy, iy + 2
	djnz .loop_lshift_add
	ret
	
	
_get_degree:
; input: hl = ptr to binary polynomial (little endian-encoded)
; func:
;		jump to end of polynomial
;		seek backwards to first set bit
;		return its 1-indexed degree
; output: a = degree of highest set bit + 1
; destroys: bc, flags
	ld bc, 29       ; input is 32 bytes, jump to MSB (hl + 31)
	add hl, bc
	inc bc        ; check 30 bytes
	xor a
.byte_loop:
	cpd     		; cp hl with a, dec hl, bc
	jr nz, .found_byte
	cpd
	jr nz, .found_byte
	cpd
	jr nz, .found_byte
	cpd
	jr nz, .found_byte
	cpd
	jr nz, .found_byte
	jp pe, .byte_loop
; exit
	xor a
	ret
.found_byte:
; process bits
	ld b, c
	inc b
	inc hl
	ld a, (hl)
	ld c, 1
.bit_loop:
	dec c
	rla
	jr nc, .bit_loop
	ld a, b
	add a, a
	add a, a
	add a, a
	add a, c
	ret


 
 _point_double:
	ld	hl, -36
	call	ti._frameset
	ld	iy, (ix + 6)
	lea	hl, iy + 30
	ld	(ix - 36), hl
	push	hl
	call	_bigint_iszero
	pop	hl
	bit	0, a
	jr	z, .lbl_2
	ld	hl, (ix + 6)
	ld	(hl), 0
	push	hl
	pop	iy
	inc	iy
	ld	bc, 59
	lea	de, iy
	ldir
	jp	.lbl_3
.lbl_2:
	lea	de, ix - 30
	ld	(ix - 33), de
	ld	hl, (ix + 6)
	push	hl
	push	de
	call	_bigint_invert
	pop	hl
	pop	hl
	ld	hl, (ix - 36)
	push	hl
	ld	hl, (ix - 33)
	push	hl
	push	hl
	call	_bigint_mul
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 33)
	push	hl
	push	hl
	call	_bigint_add
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 36)
	push	hl
	call	_bigint_square
	pop	hl
	pop	hl
	ld	hl, (ix - 33)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	_bigint_square
	pop	hl
	pop	hl
	ld	hl, (ix - 33)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	push	hl
	call	_bigint_add
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 33)
	push	hl
	push	hl
	call	_bigint_mul
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 33)
	push	hl
	ld	hl, (ix - 36)
	push	hl
	push	hl
	call	_bigint_add
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 36)
	push	hl
	push	hl
	call	_bigint_add
	pop	hl
	pop	hl
	pop	hl
.lbl_3:
	ld	sp, ix
	pop	ix
	ret
	

_point_add:
	ld	hl, -102
	call	ti._frameset
	ld	hl, (ix + 9)
	push	hl
	call	_point_iszero
	pop	hl
	bit	0, a
	jp	nz, .lbl_10
	ld	hl, (ix + 6)
	push	hl
	call	_point_iszero
	pop	hl
	bit	0, a
	jr	z, .lbl_3
	ld	bc, 60
	ld	de, (ix + 6)
	ld	hl, (ix + 9)
	jr	.lbl_7
.lbl_3:
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	_point_isequal
	pop	hl
	pop	hl
	bit	0, a
	jr	z, .lbl_5
	ld	hl, (ix + 6)
	push	hl
	call	_point_double
	jp	.lbl_9
.lbl_5:
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	_bigint_isequal
	pop	hl
	pop	hl
	bit	0, a
	jr	z, .lbl_8
	ld	hl, (ix + 6)
	ld	(hl), 0
	push	hl
	pop	iy
	inc	iy
	ld	bc, 59
	lea	de, iy
.lbl_7:
	ldir
	jp	.lbl_10
.lbl_8:
	lea	bc, ix - 30
	ld	(ix - 99), bc
	lea	hl, ix - 60
	ld	(ix - 93), hl
	lea	hl, ix - 90
	ld	(ix - 96), hl
	ld	hl, (ix + 6)
	push	hl
	pop	iy
	lea	hl, iy + 30
	ld	(ix - 102), hl
	ld	de, (ix + 9)
	push	de
	pop	iy
	pea	iy + 30
	push	hl
	push	bc
	call	_bigint_add
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 93)
	push	hl
	call	_bigint_add
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 93)
	push	hl
	ld	hl, (ix - 96)
	push	hl
	call	_bigint_invert
	pop	hl
	pop	hl
	ld	hl, (ix - 96)
	push	hl
	ld	hl, (ix - 99)
	push	hl
	push	hl
	call	_bigint_mul
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 99)
	push	hl
	ld	hl, (ix - 96)
	push	hl
	call	_bigint_square
	pop	hl
	pop	hl
	ld	hl, (ix - 93)
	push	hl
	ld	hl, (ix - 96)
	push	hl
	push	hl
	call	_bigint_add
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 99)
	push	hl
	ld	hl, (ix - 96)
	push	hl
	push	hl
	call	_bigint_add
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 96)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 93)
	push	hl
	call	_bigint_add
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix + 6)
	ld	hl, (ix - 96)
	ld	bc, 30
	ldir
	ld	hl, (ix - 99)
	push	hl
	ld	hl, (ix - 93)
	push	hl
	push	hl
	call	_bigint_mul
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 102)
	push	hl
	ld	hl, (ix - 93)
	push	hl
	push	hl
	call	_bigint_add
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 93)
	push	hl
	ld	hl, (ix - 102)
	push	hl
	call	_bigint_add
	pop	hl
	pop	hl
.lbl_9:
	pop	hl
.lbl_10:
	ld	sp, ix
	pop	ix
	ret
	
	
; void ecc_point_mul_scalar(struct Point *p, uint8_t *scalar, uint8_t scalar_len);
_point_mul_scalar:
	ld	hl, -69
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	bc, 60
	lea	de, ix - 60
	ld	(ix - 69), de
	lea	hl, iy
	ldir
	ld	(iy), 0
	lea	hl, iy
	inc	hl
	ld	bc, 59
	ex	de, hl
	lea	hl, iy
	ldir
	ld	de, (ix + 12)
.lbl_1:
	ld	bc, 1
	push	de
	pop	hl
	or	a, a
	sbc	hl, bc
	call	pe, ti._setflag
	jp	m, .lbl_5
	ld	(ix - 63), de
	dec	de
	ld	(ix - 66), de
	ld	hl, (ix + 6)
	push	hl
	call	_point_double
	pop	hl
	ld	hl, (ix - 66)
	ld	c, 3
	call	ti._ishru
	push	hl
	pop	de
	ld	hl, (ix + 9)
	add	hl, de
	ld	e, (hl)
	ld	hl, (ix - 66)
	ld	bc, 7
	call	ti._iand
	ld	a, 1
	ld	b, l
	call	ti._bshl
	and	a, e
	or	a, a
	ld	hl, _ta_resist
	jr	z, .lbl_4
	ld	hl, (ix - 69)
.lbl_4:
	ld	de, (ix - 63)
	dec	de
	ld	(ix - 63), de
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	_point_add
	ld	de, (ix - 63)
	pop	hl
	pop	hl
	jr	.lbl_1
.lbl_5:
	ld	sp, ix
	pop	ix
	ret
	
	
_point_isvalid:
	ld	hl, -69
	call	ti._frameset
	ld	hl, (ix + 6)
	push	hl
	call	_point_iszero
	pop	hl
	bit	0, a
	jr	z, .lbl_2
	ld	a, 1
	jr	.lbl_3
.lbl_2:
	lea	de, ix - 30
	ld	(ix - 66), de
	lea	hl, ix - 60
	ld	(ix - 63), hl
	ld	hl, (ix + 6)
	push	hl
	push	hl
	push	de
	call	_bigint_mul
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 66)
	push	hl
	push	hl
	call	_bigint_mul
	pop	hl
	pop	hl
	pop	hl
	ld	a, (ix - 30)
	xor	a, 1
	ld	(ix - 30), a
	ld	iy, (ix + 6)
	lea	hl, iy + 30
	ld	(ix - 69), hl
	push	hl
	push	hl
	ld	hl, (ix - 63)
	push	hl
	call	_bigint_mul
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 63)
	push	hl
	ld	hl, (ix - 66)
	push	hl
	push	hl
	call	_bigint_add
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 69)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 63)
	push	hl
	call	_bigint_mul
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 63)
	push	hl
	ld	hl, (ix - 66)
	push	hl
	call	_bigint_isequal
	pop	hl
	pop	hl
.lbl_3:
	ld	sp, ix
	pop	ix
	ret
	
ecdh_publickey:
	save_interrupts
	call	ti._frameset0
	ld	hl, (ix + 6)
	ld	de, 1
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_3
	ld	hl, (ix + 9)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_3
	ld	de, 30
	ld	hl, _sect233k1+30
	push	de
	push	hl
	ld	hl, (ix + 9)
	push	hl
	call	_rmemcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 30
	push	hl
	ld	hl, _sect233k1+60
	push	hl
	ld	iy, (ix + 9)
	pea	iy + 30
	call	_rmemcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 240
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix + 9)
	push	hl
	call	_point_mul_scalar
	pop	hl
	pop	hl
	pop	hl
	ld	de, 0
.lbl_3:
	ex de, hl
	restore_interrupts_noret ecdh_publickey
	jp stack_clear
	
 
 ecdh_secret:
	save_interrupts
	ld	hl, -1
	call	ti._frameset
	ld	hl, (ix + 6)
	ld	bc, 1
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_10
	ld	iy, (ix + 9)
	lea	hl, iy
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_10
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_10
	ld	bc, 60
	ex	de, hl
	lea	hl, iy
	ldir
	ld	a, (_sect233k1+90)
	ld	(ix - 1), a
	ld	hl, (ix + 12)
	push	hl
	call	_point_iszero
	pop	hl
	bit	0, a
	jr	z, .lbl_5
	ld	bc, 3
	jr	.lbl_10
.lbl_5:
	ld	hl, (ix + 12)
	push	hl
	call	_point_isvalid
	pop	hl
	bit	0, a
	ld	de, (ix + 12)
	ld	bc, 3
	jr	z, .lbl_10
	ld	hl, 240
	push	hl
	ld	hl, (ix + 6)
	push	hl
	push	de
	call	_point_mul_scalar
	pop	hl
	pop	hl
	pop	hl
	ld	a, (ix - 1)
.lbl_7:
	cp	a, 2
	jr	c, .lbl_9
	ld	(ix - 1), a
	ld	hl, (ix + 12)
	push	hl
	call	_point_double
	pop	hl
	ld	a, (ix - 1)
	srl	a
	jr	.lbl_7
.lbl_9:
	ld	bc, 0
.lbl_10:
	push	bc
	pop	hl
	restore_interrupts_noret ecdh_secret
	jp stack_clear

	
;bool bigint_frombytes(BIGINT dest, const void *restrict src, size_t len, bool big_endian);
bigint_frombytes:
	call ti._frameset0
; (ix + 6) = dest
; (ix + 9) = src
; (ix + 12) = len
; (ix + 15) = big_endian

; ensure that src and dest don't overlap
	ld hl, (ix + 9)
	ld de, (ix + 6)
	xor a
	sbc hl, de
	jr z, .exit
	add hl, de
	push hl,de
	
; zero out dest
		xor a
		ld (de), a
		inc de
		ld hl, (ix + 6)
		ld bc, 31
		ldir

; restore src and dest, load num bytes to copy
	pop de,hl
	ld bc, (ix + 12)
	ld a, (ix + 15)
	or a
	jr nz, .copy_bigendian
	add hl, bc
	dec hl
.loop_littleendian:
	ldi
	dec hl
	dec hl
	jp pe, .loop_littleendian
	jr .return_1
.copy_bigendian:
	ex de, hl
	push bc
		ld bc, 32
		add hl, bc
	pop bc
	or a
	sbc hl, bc
	ex de, hl
	ldir
.return_1:
	ld a, 1
.exit:
	ld	sp, ix
	pop	ix
	ret
	
;bool bigint_tobytes(void *dest, const BIGINT restrict src, bool big_endian);
bigint_tobytes:
	call ti._frameset0
; (ix + 6) = dest
; (ix + 9) = src
; (ix + 12) = big_endian

; ensure that src and dest don't overlap
	ld hl, (ix + 9)
	ld de, (ix + 6)
	xor a
	sbc hl, de
	jr z, .exit
	add hl, de
	push hl, de
	
; no need to zero out dest, always copy 32 bytes

; restore src and dest, load num bytes to copy
	pop de,hl
	ld bc, 32
	ld a, (ix + 12)
	or a
	jr nz, .copy_bigendian
	add hl, bc
	dec hl
.loop_littleendian:
	ldi
	dec hl
	dec hl
	jp pe, .loop_littleendian
	jr .return_1
.copy_bigendian:
	ldir
.return_1:
	ld a, 1
.exit:
	ld	sp, ix
	pop	ix
	ret
	

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
	
	
; av(void *data, size_t len)
_memrev:
	pop hl, de, bc
	push bc, de, de
	ex (sp), hl
	add hl, bc
	set 0, c
	cpd
.loop:
	ret po
	ld a, (de)
	dec bc
	ldi
	dec hl
	ld (hl), a
	dec hl
	jr .loop
	
_asn1_decode:
	ld	hl, -16
	call	ti._frameset
	ld	iy, (ix + 6)
	xor	a, a
	ld	bc, 2
	lea	hl, iy
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	nz, .lbl_2
	push	bc
	pop	hl
	jp	.lbl_22
.lbl_2:
	ld	de, (ix + 9)
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	push	bc
	pop	hl
	jp	z, .lbl_22
	ld	c, a
	ld	a, (ix + 12)
	ld	hl, 0
	ld	(ix - 9), hl
	lea	hl, iy
	add	hl, de
	ex	de, hl
	or	a, a
	sbc	hl, hl
	ld	(ix - 3), hl
	ld	l, a
	ld	a, c
	inc	hl
	ld	(ix - 6), hl
.lbl_4:
	ld	hl, (ix - 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_13
	ld	(ix - 12), de
	ld	de, (ix - 3)
	add	iy, de
	ld	a, (iy)
	or	a, a
	ld	de, 1
	jr	z, .lbl_7
	ld	de, 0
.lbl_7:
	add	iy, de
	lea	hl, iy
	ld	de, (ix - 12)
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_20
	ld	a, (iy)
	ld	(ix - 13), a
	lea	hl, iy + 2
	ld	(ix - 9), hl
	ld	a, (iy + 1)
	or	a, a
	sbc	hl, hl
	ld	(ix - 3), hl
	cp	a, h
	call	pe, ti._setflag
	jp	m, .lbl_10
	or	a, a
	sbc	hl, hl
	ld	l, a
	ld	(ix - 3), hl
	jr	.lbl_12
.lbl_10:
	and	a, 127
	cp	a, 4
	jr	nc, .lbl_21
	or	a, a
	sbc	hl, hl
	ld	l, a
	ld	(ix - 16), hl
	push	hl
	ld	hl, (ix - 9)
	push	hl
	pea	ix - 3
	call	_rmemcpy
	ld	de, (ix - 12)
	pop	hl
	pop	hl
	pop	hl
	ld	bc, (ix - 16)
	ld	hl, (ix - 9)
	add	hl, bc
	ld	(ix - 9), hl
.lbl_12:
	ld	hl, (ix - 6)
	dec	hl
	ld	(ix - 6), hl
	ld	iy, (ix - 9)
	ld	a, (ix - 13)
	jp	.lbl_4
.lbl_13:
	ld	hl, (ix + 15)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_15
	ld	(hl), a
.lbl_15:
	ld	iy, (ix + 18)
	lea	hl, iy
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	hl, (ix + 21)
	jr	z, .lbl_17
	ld	de, (ix - 3)
	ld	(iy), de
.lbl_17:
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_19
	ld	de, (ix - 9)
	ld	(hl), de
.lbl_19:
	or	a, a
	sbc	hl, hl
	jr	.lbl_22
.lbl_20:
	ld	hl, 1
	jr	.lbl_22
.lbl_21:
	ld	hl, 3
.lbl_22:
	ld	sp, ix
	pop	ix
	ret
	


base64_encode:
	ld	hl, -16
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	de, (ix + 12)
	ld	bc, 2
	push	de
	pop	hl
	add	hl, bc
	inc	bc
	call	ti._idivu
	ld	(ix - 15), hl
	or	a, a
	sbc	hl, hl
	push	hl
	pop	bc
	ld	(ix - 3), hl
.lbl_1:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_8
	push	bc
	pop	de
	inc	de
	ld	iy, (ix + 9)
	ld	(ix - 6), bc
	add	iy, bc
	push	de
	pop	hl
	ld	bc, (ix + 12)
	or	a, a
	sbc	hl, bc
	ld	bc, 0
	jr	nc, .lbl_4
	ld	hl, (ix - 6)
	ld	de, 2
	add	hl, de
	ld	bc, 0
	ld	c, (iy + 1)
	ex	de, hl
.lbl_4:
	ld	(ix - 12), bc
	ld	a, (iy)
	push	de
	pop	hl
	ld	bc, (ix + 12)
	or	a, a
	sbc	hl, bc
	jr	nc, .lbl_6
	ld	hl, (ix + 9)
	add	hl, de
	inc	de
	ld	bc, 0
	ld	c, (hl)
	ld	(ix - 9), bc
	ld	(ix - 6), de
	ld	de, 0
	jr	.lbl_7
.lbl_6:
	ld	(ix - 6), de
	ld	de, 0
	ld	(ix - 9), de
.lbl_7:
	ld	hl, (ix - 12)
	ld	c, 8
	call	ti._ishl
	ld	(ix - 12), hl
	ld	(ix - 16), a
	ld	b, 2
	call	ti._bshru
	push	de
	pop	bc
	ld	e, a
	ld	hl, _b64_charset
	add	hl, de
	ld	a, (hl)
	ld	de, (ix - 3)
	ld	iy, (ix + 6)
	add	iy, de
	ld	(iy), a
	push	bc
	pop	hl
	ld	l, (ix - 16)
	ld	c, 16
	call	ti._ishl
	push	hl
	pop	de
	ld	hl, (ix - 12)
	add	hl, de
	ld	c, 12
	call	ti._ishru
	ld	de, 63
	push	de
	pop	bc
	call	ti._iand
	push	hl
	pop	de
	ld	hl, _b64_charset
	add	hl, de
	ld	a, (hl)
	ld	(iy + 1), a
	ld	hl, (ix - 9)
	ld	de, (ix - 12)
	add	hl, de
	ld	c, 6
	call	ti._ishru
	ld	bc, 63
	call	ti._iand
	push	hl
	pop	de
	ld	bc, _b64_charset
	push	bc
	pop	hl
	add	hl, de
	ld	a, (hl)
	ld	(iy + 2), a
	ld	hl, (ix - 9)
	ld	bc, 63
	call	ti._iand
	push	hl
	pop	de
	ld	hl, _b64_charset
	add	hl, de
	ld	a, (hl)
	ld	de, 4
	ld	hl, (ix - 3)
	add	hl, de
	ld	(ix - 3), hl
	ld	(iy + 3), a
	ld	iy, (ix + 6)
	ld	de, (ix + 12)
	ld	bc, (ix - 6)
	jp	.lbl_1
.lbl_8:
	ld	c, 2
	ld	hl, (ix - 15)
	call	ti._ishl
	ld	(ix - 6), hl
	ex	de, hl
	ld	bc, 3
	call	ti._iremu
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _b64_mod_table
	add	hl, de
	ld	de, (hl)
	ld	bc, 1
	push	de
	pop	hl
	or	a, a
	sbc	hl, bc
	call	pe, ti._setflag
	jp	p, .lbl_10
	ld	de, 0
.lbl_10:
	ld	bc, (ix - 6)
	add	iy, bc
.lbl_11:
	dec	iy
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_13
	ld	(iy), 61
	dec	de
	jr	.lbl_11
.lbl_13:
	ld	hl, (ix - 3)
	ld	sp, ix
	pop	ix
	ret
	

base64_decode:
	ld	hl, -24
	call	ti._frameset
	ld	de, (ix + 12)
	or	a, a
	sbc	hl, hl
	ld	a, e
	and	a, 3
	or	a, a
	jp	nz, .lbl_24
	ld	iy, (ix + 9)
	ld	c, 2
	push	de
	pop	hl
	call	ti._ishru
	ld	bc, 3
	call	ti._imulu
	add	iy, de
	ld	a, (iy - 1)
	cp	a, 61
	ld	bc, -1
	push	bc
	pop	de
	jr	z, .lbl_3
	ld	de, 0
.lbl_3:
	add	hl, de
	ld	a, (iy - 2)
	cp	a, 61
	jr	z, .lbl_5
	ld	bc, 0
.lbl_5:
	add	hl, bc
	ld	(ix - 6), hl
	ld	bc, 0
	push	bc
	pop	iy
	ld	(ix - 9), bc
.lbl_6:
	ld	de, (ix + 12)
	lea	hl, iy
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_23
	lea	de, iy
	ld	hl, (ix + 9)
	add	hl, de
	ld	a, (hl)
	cp	a, 61
	push	bc
	pop	hl
	ld	(ix - 3), iy
	jr	z, .lbl_9
	or	a, a
	sbc	hl, hl
	ld	l, a
	push	hl
	ld	hl, _b64_charset
	push	hl
	call	ti._strchr
	ld	iy, (ix - 3)
	ld	bc, 0
	pop	de
	pop	de
	ld	de, _b64_charset
	or	a, a
	sbc	hl, de
.lbl_9:
	ld	(ix - 15), hl
	lea	de, iy
	ld	iy, (ix + 9)
	add	iy, de
	ld	a, (iy + 1)
	cp	a, 61
	push	bc
	pop	hl
	jr	z, .lbl_11
	or	a, a
	sbc	hl, hl
	ld	l, a
	push	hl
	ld	hl, _b64_charset
	push	hl
	call	ti._strchr
	ld	bc, 0
	pop	de
	pop	de
	ld	de, _b64_charset
	or	a, a
	sbc	hl, de
.lbl_11:
	ld	(ix - 18), hl
	ld	de, (ix - 3)
	ld	iy, (ix + 9)
	add	iy, de
	ld	a, (iy + 2)
	cp	a, 61
	push	bc
	pop	hl
	jr	z, .lbl_13
	or	a, a
	sbc	hl, hl
	ld	l, a
	push	hl
	ld	hl, _b64_charset
	push	hl
	call	ti._strchr
	ld	bc, 0
	pop	de
	pop	de
	ld	de, _b64_charset
	or	a, a
	sbc	hl, de
.lbl_13:
	ld	de, (ix - 3)
	ld	iy, (ix + 9)
	add	iy, de
	ld	a, (iy + 3)
	cp	a, 61
	ld	(ix - 12), hl
	jr	z, .lbl_15
	or	a, a
	sbc	hl, hl
	ld	l, a
	push	hl
	ld	hl, _b64_charset
	push	hl
	call	ti._strchr
	pop	de
	pop	de
	ld	de, _b64_charset
	or	a, a
	sbc	hl, de
	push	hl
	pop	bc
	ld	hl, (ix - 12)
.lbl_15:
	ld	(ix - 21), bc
	push	hl
	pop	iy
	add	iy, iy
	sbc	hl, hl
	ld	(ix - 24), hl
	ld	e, 0
	ld	bc, (ix - 15)
	ld	a, e
	ld	l, 18
	call	ti._lshl
	push	bc
	pop	iy
	ld	d, a
	ld	bc, (ix - 18)
	ld	a, e
	ld	l, 12
	call	ti._lshl
	push	bc
	pop	hl
	ld	e, a
	lea	bc, iy
	ld	a, d
	call	ti._ladd
	push	hl
	pop	iy
	ld	bc, (ix - 12)
	ld	hl, (ix - 24)
	ld	a, l
	ld	l, 6
	call	ti._lshl
	lea	hl, iy
	call	ti._ladd
	ld	bc, (ix - 21)
	xor	a, a
	call	ti._ladd
	push	hl
	pop	iy
	ld	a, e
	ld	de, (ix - 9)
	push	de
	pop	hl
	ld	bc, (ix - 6)
	or	a, a
	sbc	hl, bc
	jr	nc, .lbl_17
	lea	bc, iy
	ld	l, 16
	call	ti._lshru
	ld	a, c
	ld	hl, (ix + 6)
	add	hl, de
	inc	de
	ld	(hl), a
.lbl_17:
	push	de
	pop	bc
	push	bc
	pop	hl
	ld	de, (ix - 6)
	or	a, a
	sbc	hl, de
	jr	nc, .lbl_19
	ld	a, iyh
	ld	hl, (ix + 6)
	add	hl, bc
	inc	bc
	ld	(hl), a
.lbl_19:
	push	bc
	pop	hl
	ld	de, (ix - 6)
	or	a, a
	sbc	hl, de
	jr	nc, .lbl_21
	ld	a, iyl
	ld	hl, (ix + 6)
	add	hl, bc
	inc	bc
	ld	(ix - 9), bc
	ld	(hl), a
	jr	.lbl_22
.lbl_21:
	ld	(ix - 9), bc
.lbl_22:
	ld	de, 4
	ld	iy, (ix - 3)
	add	iy, de
	ld	bc, 0
	jp	.lbl_6
.lbl_23:
	ld	hl, (ix - 9)
.lbl_24:
	ld	sp, ix
	pop	ix
	ret

 
 _hexc:     db	"0123456789ABCDEF"
 _hash_out_lens:    db 32
 
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
 
_sha1_k:
	dd	$5A827999
	dd	$6ED9EBA1
	dd	$8F1BBCDC
	dd	$CA62C1D6

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


_sect233k1:
	db	2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 1
	db	$01,$72,$32,$BA,$85,$3A,$7E,$73,$1A,$F1,$29,$F2,$2F,$F4,$14,$95,$63,$A4,$19,$C2,$6B,$F5,$0A,$4C,$9D,$6E,$EF,$AD,$61,$26
	db	$01,$DB,$53,$7D,$EC,$E8,$19,$B7,$F7,$0F,$55,$5A,$67,$C4,$27,$A8,$CD,$9B,$F1,$8A,$EB,$9B,$56,$E0,$C1,$10,$56,$FA,$E6,$A3
	db	4
	
_ta_resist:
	db	60 dup 0
 

_sprng_read_addr:        rb 3
_sprng_entropy_pool.size = 119
virtual at $E30800
	_sprng_entropy_pool     rb _sprng_entropy_pool.size
	_sprng_sha_digest       rb 32
	_sprng_sha_mbuffer      rb (64*4)
	_sprng_hash_ctx         rb _hashctx_size
	_sprng_rand             rb 4
end virtual
_sha256_m_buffer    :=  _sprng_sha_mbuffer



 _aes_sbox:
	db	"c|w{",362o,"ko",305o,"0",001o,"g+",376o,327o,253o,"v"
	db	"",312o,202o,311o,"}",372o,"YG",360o,255o,324o,242o,257o,234o,244o,"r",300o
	db	"",267o,375o,223o,"&6?",367o,314o,"4",245o,345o,361o,"q",330o,"1",025o
	db	"",004o,307o,"#",303o,030o,226o,005o,232o,007o,022o,200o,342o,353o,"'",262o,"u"
	db	"",011o,203o,",",032o,033o,"nZ",240o,"R;",326o,263o,")",343o,"/",204o
	db	"S",321o,000o,355o," ",374o,261o,"[j",313o,276o,"9JLX",317o
	db	"",320o,357o,252o,373o,"CM3",205o,"E",371o,002o,177o,"P<",237o,250o
	db	"Q",243o,"@",217o,222o,235o,"8",365o,274o,266o,332o,"!",020o,377o,363o,322o
	db	"",315o,014o,023o,354o,"_",227o,"D",027o,304o,247o,"~=d]",031o,"s"
	db	"`",201o,"O",334o,"""*",220o,210o,"F",356o,270o,024o,336o,"^",013o,333o
	db	"",340o,"2:",012o,"I",006o,"$\",302o,323o,254o,"b",221o,225o,344o,"y"
	db	"",347o,310o,"7m",215o,325o,"N",251o,"lV",364o,352o,"ez",256o,010o
	db	"",272o,"x%.",034o,246o,264o,306o,350o,335o,"t",037o,"K",275o,213o,212o
	db	"p>",265o,"fH",003o,366o,016o,"a5W",271o,206o,301o,035o,236o
	db	"",341o,370o,230o,021o,"i",331o,216o,224o,233o,036o,207o,351o,316o,"U(",337o
	db	"",214o,241o,211o,015o,277o,346o,"BhA",231o,"-",017o,260o,"T",273o,026o
 
 L___const.hashlib_AESLoadKey.Rcon:
	dd	16777216
	dd	33554432
	dd	67108864
	dd	134217728
	dd	268435456
	dd	536870912
	dd	1073741824
	dd	2147483648
	dd	452984832
	dd	905969664
	dd	1811939328
	dd	3623878656
	dd	2868903936
	dd	1291845632
	dd	2583691264
 
 _aes_invsbox:
	db	"R",011o,"j",325o,"06",245o,"8",277o,"@",243o,236o,201o,363o,327o,373o
	db	"|",343o,"9",202o,233o,"/",377o,207o,"4",216o,"CD",304o,336o,351o,313o
	db	"T{",224o,"2",246o,302o,"#=",356o,"L",225o,013o,"B",372o,303o,"N"
	db	"",010o,".",241o,"f(",331o,"$",262o,"v[",242o,"Im",213o,321o,"%"
	db	"r",370o,366o,"d",206o,"h",230o,026o,324o,244o,"\",314o,"]e",266o,222o
	db	"lpHP",375o,355o,271o,332o,"^",025o,"FW",247o,215o,235o,204o
	db	"",220o,330o,253o,000o,214o,274o,323o,012o,367o,344o,"X",005o,270o,263o,"E",006o
	db	"",320o,",",036o,217o,312o,"?",017o,002o,301o,257o,275o,003o,001o,023o,212o,"k"
	db	":",221o,021o,"AOg",334o,352o,227o,362o,317o,316o,360o,264o,346o,"s"
	db	"",226o,254o,"t""",347o,255o,"5",205o,342o,371o,"7",350o,034o,"u",337o,"n"
	db	"G",361o,032o,"q",035o,")",305o,211o,"o",267o,"b",016o,252o,030o,276o,033o
	db	"",374o,"V>K",306o,322o,"y ",232o,333o,300o,376o,"x",315o,"Z",364o
	db	"",037o,335o,250o,"3",210o,007o,307o,"1",261o,022o,020o,"Y'",200o,354o,"_"
	db	"`Q",177o,251o,031o,265o,"J",015o,"-",345o,"z",237o,223o,311o,234o,357o
	db	"",240o,340o,";M",256o,"*",365o,260o,310o,353o,273o,"<",203o,"S",231o,"a"
	db	"",027o,"+",004o,"~",272o,"w",326o,"&",341o,"i",024o,"cU!",014o,"}"
 
 _gf_mul:
	db	6 dup 0
	db	"",002o,003o,011o,013o,015o,016o
	db	"",004o,006o,022o,026o,032o,034o
	db	"",006o,005o,033o,035o,027o,022o
	db	"",010o,014o,"$,48"
	db	"",012o,017o,"-'96"
	db	"",014o,012o,"6:.$"
	db	"",016o,011o,"?1#*"
	db	"",020o,030o,"HXhp"
	db	"",022o,033o,"ASe~"
	db	"",024o,036o,"ZNrl"
	db	"",026o,035o,"SE",177o,"b"
	db	"",030o,024o,"lt\H"
	db	"",032o,027o,"e",177o,"QF"
	db	"",034o,022o,"~bFT"
	db	"",036o,021o,"wiKZ"
	db	" 0",220o,260o,320o,340o
	db	"""3",231o,273o,335o,356o
	db	"$6",202o,246o,312o,374o
	db	"&5",213o,255o,307o,362o
	db	"(<",264o,234o,344o,330o
	db	"*?",275o,227o,351o,326o
	db	",:",246o,212o,376o,304o
	db	".9",257o,201o,363o,312o
	db	"0(",330o,350o,270o,220o
	db	"2+",321o,343o,265o,236o
	db	"4.",312o,376o,242o,214o
	db	"6-",303o,365o,257o,202o
	db	"8$",374o,304o,214o,250o
	db	":'",365o,317o,201o,246o
	db	"<""",356o,322o,226o,264o
	db	">!",347o,331o,233o,272o
	db	"@`;{",273o,333o
	db	"Bc2p",266o,325o
	db	"Df)m",241o,307o
	db	"Fe f",254o,311o
	db	"Hl",037o,"W",217o,343o
	db	"Jo",026o,"\",202o,355o
	db	"Lj",015o,"A",225o,377o
	db	"Ni",004o,"J",230o,361o
	db	"Pxs#",323o,253o
	db	"R{z(",336o,245o
	db	"T~a5",311o,267o
	db	"V}h>",304o,271o
	db	"XtW",017o,347o,223o
	db	"Zw^",004o,352o,235o
	db	"\rE",031o,375o,217o
	db	"^qL",022o,360o,201o
	db	"`P",253o,313o,"k;"
	db	"bS",242o,300o,"f5"
	db	"dV",271o,335o,"q'"
	db	"fU",260o,326o,"|)"
	db	"h\",217o,347o,"_",003o
	db	"j_",206o,354o,"R",015o
	db	"lZ",235o,361o,"E",037o
	db	"nY",224o,372o,"H",021o
	db	"pH",343o,223o,003o,"K"
	db	"rK",352o,230o,016o,"E"
	db	"tN",361o,205o,031o,"W"
	db	"vM",370o,216o,024o,"Y"
	db	"xD",307o,277o,"7s"
	db	"zG",316o,264o,":}"
	db	"|B",325o,251o,"-o"
	db	"~A",334o,242o," a"
	db	"",200o,300o,"v",366o,"m",255o
	db	"",202o,303o,177o,375o,"`",243o
	db	"",204o,306o,"d",340o,"w",261o
	db	"",206o,305o,"m",353o,"z",277o
	db	"",210o,314o,"R",332o,"Y",225o
	db	"",212o,317o,"[",321o,"T",233o
	db	"",214o,312o,"@",314o,"C",211o
	db	"",216o,311o,"I",307o,"N",207o
	db	"",220o,330o,">",256o,005o,335o
	db	"",222o,333o,"7",245o,010o,323o
	db	"",224o,336o,",",270o,037o,301o
	db	"",226o,335o,"%",263o,022o,317o
	db	"",230o,324o,032o,202o,"1",345o
	db	"",232o,327o,023o,211o,"<",353o
	db	"",234o,322o,010o,224o,"+",371o
	db	"",236o,321o,001o,237o,"&",367o
	db	"",240o,360o,346o,"F",275o,"M"
	db	"",242o,363o,357o,"M",260o,"C"
	db	"",244o,366o,364o,"P",247o,"Q"
	db	"",246o,365o,375o,"[",252o,"_"
	db	"",250o,374o,302o,"j",211o,"u"
	db	"",252o,377o,313o,"a",204o,"{"
	db	"",254o,372o,320o,"|",223o,"i"
	db	"",256o,371o,331o,"w",236o,"g"
	db	"",260o,350o,256o,036o,325o,"="
	db	"",262o,353o,247o,025o,330o,"3"
	db	"",264o,356o,274o,010o,317o,"!"
	db	"",266o,355o,265o,003o,302o,"/"
	db	"",270o,344o,212o,"2",341o,005o
	db	"",272o,347o,203o,"9",354o,013o
	db	"",274o,342o,230o,"$",373o,031o
	db	"",276o,341o,221o,"/",366o,027o
	db	"",300o,240o,"M",215o,326o,"v"
	db	"",302o,243o,"D",206o,333o,"x"
	db	"",304o,246o,"_",233o,314o,"j"
	db	"",306o,245o,"V",220o,301o,"d"
	db	"",310o,254o,"i",241o,342o,"N"
	db	"",312o,257o,"`",252o,357o,"@"
	db	"",314o,252o,"{",267o,370o,"R"
	db	"",316o,251o,"r",274o,365o,"\"
	db	"",320o,270o,005o,325o,276o,006o
	db	"",322o,273o,014o,336o,263o,010o
	db	"",324o,276o,027o,303o,244o,032o
	db	"",326o,275o,036o,310o,251o,024o
	db	"",330o,264o,"!",371o,212o,">"
	db	"",332o,267o,"(",362o,207o,"0"
	db	"",334o,262o,"3",357o,220o,""""
	db	"",336o,261o,":",344o,235o,","
	db	"",340o,220o,335o,"=",006o,226o
	db	"",342o,223o,324o,"6",013o,230o
	db	"",344o,226o,317o,"+",034o,212o
	db	"",346o,225o,306o," ",021o,204o
	db	"",350o,234o,371o,021o,"2",256o
	db	"",352o,237o,360o,032o,"?",240o
	db	"",354o,232o,353o,007o,"(",262o
	db	"",356o,231o,342o,014o,"%",274o
	db	"",360o,210o,225o,"en",346o
	db	"",362o,213o,234o,"nc",350o
	db	"",364o,216o,207o,"st",372o
	db	"",366o,215o,216o,"xy",364o
	db	"",370o,204o,261o,"IZ",336o
	db	"",372o,207o,270o,"BW",320o
	db	"",374o,202o,243o,"_@",302o
	db	"",376o,201o,252o,"TM",314o
	db	"",033o,233o,354o,367o,332o,"A"
	db	"",031o,230o,345o,374o,327o,"O"
	db	"",037o,235o,376o,341o,300o,"]"
	db	"",035o,236o,367o,352o,315o,"S"
	db	"",023o,227o,310o,333o,356o,"y"
	db	"",021o,224o,301o,320o,343o,"w"
	db	"",027o,221o,332o,315o,364o,"e"
	db	"",025o,222o,323o,306o,371o,"k"
	db	"",013o,203o,244o,257o,262o,"1"
	db	"",011o,200o,255o,244o,277o,"?"
	db	"",017o,205o,266o,271o,250o,"-"
	db	"",015o,206o,277o,262o,245o,"#"
	db	"",003o,217o,200o,203o,206o,011o
	db	"",001o,214o,211o,210o,213o,007o
	db	"",007o,211o,222o,225o,234o,025o
	db	"",005o,212o,233o,236o,221o,033o
	db	";",253o,"|G",012o,241o
	db	"9",250o,"uL",007o,257o
	db	"?",255o,"nQ",020o,275o
	db	"=",256o,"gZ",035o,263o
	db	"3",247o,"Xk>",231o
	db	"1",244o,"Q`3",227o
	db	"7",241o,"J}$",205o
	db	"5",242o,"Cv)",213o
	db	"+",263o,"4",037o,"b",321o
	db	")",260o,"=",024o,"o",337o
	db	"/",265o,"&",011o,"x",315o
	db	"-",266o,"/",002o,"u",303o
	db	"#",277o,020o,"3V",351o
	db	"!",274o,031o,"8[",347o
	db	"'",271o,002o,"%L",365o
	db	"%",272o,013o,".A",373o
	db	"[",373o,327o,214o,"a",232o
	db	"Y",370o,336o,207o,"l",224o
	db	"_",375o,305o,232o,"{",206o
	db	"]",376o,314o,221o,"v",210o
	db	"S",367o,363o,240o,"U",242o
	db	"Q",364o,372o,253o,"X",254o
	db	"W",361o,341o,266o,"O",276o
	db	"U",362o,350o,275o,"B",260o
	db	"K",343o,237o,324o,011o,352o
	db	"I",340o,226o,337o,004o,344o
	db	"O",345o,215o,302o,023o,366o
	db	"M",346o,204o,311o,036o,370o
	db	"C",357o,273o,370o,"=",322o
	db	"A",354o,262o,363o,"0",334o
	db	"G",351o,251o,356o,"'",316o
	db	"E",352o,240o,345o,"*",300o
	db	"{",313o,"G<",261o,"z"
	db	"y",310o,"N7",274o,"t"
	db	"",177o,315o,"U*",253o,"f"
	db	"}",316o,"\!",246o,"h"
	db	"s",307o,"c",020o,205o,"B"
	db	"q",304o,"j",033o,210o,"L"
	db	"w",301o,"q",006o,237o,"^"
	db	"u",302o,"x",015o,222o,"P"
	db	"k",323o,017o,"d",331o,012o
	db	"i",320o,006o,"o",324o,004o
	db	"o",325o,035o,"r",303o,026o
	db	"m",326o,024o,"y",316o,030o
	db	"c",337o,"+H",355o,"2"
	db	"a",334o,"""C",340o,"<"
	db	"g",331o,"9^",367o,"."
	db	"e",332o,"0U",372o," "
	db	"",233o,"[",232o,001o,267o,354o
	db	"",231o,"X",223o,012o,272o,342o
	db	"",237o,"]",210o,027o,255o,360o
	db	"",235o,"^",201o,034o,240o,376o
	db	"",223o,"W",276o,"-",203o,324o
	db	"",221o,"T",267o,"&",216o,332o
	db	"",227o,"Q",254o,";",231o,310o
	db	"",225o,"R",245o,"0",224o,306o
	db	"",213o,"C",322o,"Y",337o,234o
	db	"",211o,"@",333o,"R",322o,222o
	db	"",217o,"E",300o,"O",305o,200o
	db	"",215o,"F",311o,"D",310o,216o
	db	"",203o,"O",366o,"u",353o,244o
	db	"",201o,"L",377o,"~",346o,252o
	db	"",207o,"I",344o,"c",361o,270o
	db	"",205o,"J",355o,"h",374o,266o
	db	"",273o,"k",012o,261o,"g",014o
	db	"",271o,"h",003o,272o,"j",002o
	db	"",277o,"m",030o,247o,"}",020o
	db	"",275o,"n",021o,254o,"p",036o
	db	"",263o,"g.",235o,"S4"
	db	"",261o,"d'",226o,"^:"
	db	"",267o,"a<",213o,"I("
	db	"",265o,"b5",200o,"D&"
	db	"",253o,"sB",351o,017o,"|"
	db	"",251o,"pK",342o,002o,"r"
	db	"",257o,"uP",377o,025o,"`"
	db	"",255o,"vY",364o,030o,"n"
	db	"",243o,177o,"f",305o,";D"
	db	"",241o,"|o",316o,"6J"
	db	"",247o,"yt",323o,"!X"
	db	"",245o,"z}",330o,",V"
	db	"",333o,";",241o,"z",014o,"7"
	db	"",331o,"8",250o,"q",001o,"9"
	db	"",337o,"=",263o,"l",026o,"+"
	db	"",335o,">",272o,"g",033o,"%"
	db	"",323o,"7",205o,"V8",017o
	db	"",321o,"4",214o,"]5",001o
	db	"",327o,"1",227o,"@""",023o
	db	"",325o,"2",236o,"K/",035o
	db	"",313o,"#",351o,"""dG"
	db	"",311o," ",340o,")iI"
	db	"",317o,"%",373o,"4~["
	db	"",315o,"&",362o,"?sU"
	db	"",303o,"/",315o,016o,"P",177o
	db	"",301o,",",304o,005o,"]q"
	db	"",307o,")",337o,030o,"Jc"
	db	"",305o,"*",326o,023o,"Gm"
	db	"",373o,013o,"1",312o,334o,327o
	db	"",371o,010o,"8",301o,321o,331o
	db	"",377o,015o,"#",334o,306o,313o
	db	"",375o,016o,"*",327o,313o,305o
	db	"",363o,007o,025o,346o,350o,357o
	db	"",361o,004o,034o,355o,345o,341o
	db	"",367o,001o,007o,360o,362o,363o
	db	"",365o,002o,016o,373o,377o,375o
	db	"",353o,023o,"y",222o,264o,247o
	db	"",351o,020o,"p",231o,271o,251o
	db	"",357o,025o,"k",204o,256o,273o
	db	"",355o,026o,"b",217o,243o,265o
	db	"",343o,037o,"]",276o,200o,237o
	db	"",341o,034o,"T",265o,215o,221o
	db	"",347o,031o,"O",250o,232o,203o
	db	"",345o,032o,"F",243o,227o,215o
 
_aes_padding:
	db	128
	db	14 dup 0
 
 _iso_pad:
	db	128
	db	15 dup 0

_b64_charset:
	db	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 0

_b64_mod_table:
	dl	0
	dl	2
	dl	1
