;------------------------------------------
include '../../include/library.inc'
include '../../include/include_library.inc'

;------------------------------------------
library ENCRYPT, 2
include_library '../hashlib/hashlib.asm'

;------------------------------------------

;v1 functions
    export cryptx_csrand_init
    export cryptx_csrand_get
    export cryptx_csrand_fill
    
    export cryptx_aes_init
    export cryptx_aes_encrypt
    export cryptx_aes_decrypt
    export cryptx_aes_update_assoc
    export cryptx_aes_render_digest
    export cryptx_rsa_encrypt
    export cryptx_ecdh_init
    export cryptx_ecdh_secret
    
    export cryptx_internal_aes_ecb_encrypt
    export cryptx_internal_aes_ecb_decrypt
    export cryptx_internal_rsa_oaep_encode
    export cryptx_internal_rsa_oaep_decode
    export cryptx_internal_powmod
    export cryptx_internal_gf2_frombytes
    export cryptx_internal_gf2_tobytes
    export cryptx_internal_gf2_add
    export cryptx_internal_gf2_mul
    export cryptx_internal_gf2_square
    export cryptx_internal_gf2_invert
    export cryptx_internal_ecc_point_add
    export cryptx_internal_ecc_point_double
    export cryptx_internal_ecc_point_mul_scalar
   
   
cryptx_csrand_init		= csrand_init
cryptx_csrand_get		= csrand_get
cryptx_csrand_fill		= csrand_fill
cryptx_aes_init			= aes_init
cryptx_aes_encrypt		= aes_encrypt
cryptx_aes_decrypt		= aes_decrypt
cryptx_rsa_encrypt		= rsa_encrypt
cryptx_ecdh_init		= ecdh_init
cryptx_ecdh_secret		= ecdh_secret

cryptx_internal_aes_ecb_encrypt		= aes_ecb_unsafe_encrypt
cryptx_internal_aes_ecb_decrypt		= aes_ecb_unsafe_decrypt
cryptx_internal_rsa_oaep_encode		= oaep_encode
cryptx_internal_rsa_oaep_decode		= oaep_decode
cryptx_internal_powmod				= _powmod
cryptx_internal_gf2_frombytes		= bigint_frombytes
cryptx_internal_gf2_tobytes			= bigint_tobytes
cryptx_internal_gf2_add				= _bigint_add
cryptx_internal_gf2_mul				= _bigint_mul
cryptx_internal_gf2_square			= _bigint_square
cryptx_internal_gf2_invert			= _bigint_invert
cryptx_internal_ecc_point_add		= _point_add
cryptx_internal_ecc_point_double	= _point_double
cryptx_internal_ecc_point_mul_scalar	= _point_mul_scalar

    
    

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

;------------------------------------------
; structures
virtual at 0
	offset_data     rb 64
	offset_datalen  rb 1
	offset_bitlen   rb 8
	offset_state    rb 4*8
	_sha256_size:
end virtual

virtual at 0
	func_init		rb 3
	func_update		rb 3
	func_final		rb 3
	sha_ctx			rb _sha256_size
	_hashctx_size:
end virtual
_sha256_m_buffer_length := 64*4

;-------------------------------------------
    


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
 
 _AES_PUT_BE64:
	call	ti._frameset0
	ld	hl, (ix + 9)
	ld	de, (ix + 12)
	ld	iy, (ix + 15)
	ld	bc, 56
	push	bc
	ld	c, iyl
	ld	b, iyh
	call	__llshru
	pop	de
	ld	a, l
	ld	hl, (ix + 6)
	ld	(hl), a
	ld	hl, 48
	push	hl
	ld	hl, (ix + 9)
	ld	de, (ix + 12)
	ld	c, iyl
	ld	b, iyh
	call	__llshru
	pop	de
	ld	a, l
	ld	iy, (ix + 6)
	ld	(iy + 1), a
	ld	hl, 40
	push	hl
	ld	hl, (ix + 9)
	ld	de, (ix + 12)
	ld	bc, (ix + 15)
	call	__llshru
	pop	de
	ld	a, l
	ld	(iy + 2), a
	ld	hl, 32
	push	hl
	ld	hl, (ix + 9)
	ld	de, (ix + 12)
	ld	bc, (ix + 15)
	call	__llshru
	pop	de
	ld	a, l
	ld	(iy + 3), a
	ld	hl, 24
	push	hl
	ld	hl, (ix + 9)
	ld	de, (ix + 12)
	ld	bc, (ix + 15)
	call	__llshru
	pop	de
	ld	a, l
	ld	(iy + 4), a
	ld	hl, 16
	push	hl
	ld	hl, (ix + 9)
	ld	de, (ix + 12)
	ld	bc, (ix + 15)
	call	__llshru
	pop	de
	ld	a, l
	ld	(iy + 5), a
	ld	hl, (ix + 9)
	ld	a, h
	ld	(iy + 6), a
	ld	a, l
	ld	(iy + 7), a
	pop	ix
	ret
 

__llshrs:
; Suboptimal for large shift amounts
	push	af
	push	iy
	ld	iy, 0
	add	iy, sp
	ld	a, (iy + 9)
	or	a, a
	jr	z, .finish
	push	de
	push	hl
.loop:
	sra	b
.hijack_llshru:
	rr	c
	rr	(iy - 1)
	rr	(iy - 2)
	rr	(iy - 3)
	rr	(iy - 4)
	rr	(iy - 5)
	rr	(iy - 6)
	dec	a
	jr	nz, .loop
	pop	hl
	pop	de
.finish:
	pop	iy
	pop	af
	ret
	
__llshru:
; Suboptimal for large shift amounts
	push	af
	push	iy
	ld	iy, 0
	add	iy, sp
	ld	a, (iy + 9)
	or	a, a
	jp	z, __llshrs.finish
	push	de
	push	hl
	srl	b
	jp	__llshrs.hijack_llshru


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
		
               ; now double tmp
                lea hl, ix - 16 - 1     ; tmp-1 in hl
                ld b, 16
                or a                ; reset carry
.loop_mul2:
                inc hl
                rl (hl)
                djnz .loop_mul2
            
                ; now xor with polynomial if tmp degree too high
                ; method below is constant-time
                
                ld a, (hl)
                rla
                sbc a, a
                and a, 10000111b
                xor a, (hl)
                ld (hl), a
				
			
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

 
;------------------------------------------
; csrand_init(uint24_t sample_ct);
;------------------------------------------
csrand_init:
; ix = selected byte
; de = current deviation
; hl = starting address
; inputs: stack = samples / 4, Max is 256 (256*4 = 1024 samples)
; outputs: hl = address
    pop hl
    pop de
    push de
    push hl
    inc e
    dec e
    ld de, 256		; thorough sampling
    jq z, .start
    dec d
    ld e, 128		; fast sampling
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

; set rand to 0
	ld hl, 0
	ld a, l
	ld (_sprng_rand), hl
	ld (_sprng_rand), a
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
	call cryptx_hash_final
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
	ld	hl, 3
	jp	.lbl_23
.lbl_2:
	ld	(ix - 42), e
	ld	hl, (ix + 6)
	ld	(hl), 0
	push	hl
	pop	iy
	inc	iy
	ld	bc, 295
	lea	de, iy
	push	hl
	pop	iy
	ldir
	ld	de, 259
	add	iy, de
	ld	(ix - 38), a
	ld	(iy), a
	ld	c, e
	ld	hl, (ix + 12)
	call	ti._ishl
	push	hl
	pop	bc
	ld	de, 128
	or	a, a
	sbc	hl, de
	jr	nz, .lbl_4
	ld	(ix - 25), bc
	ld	hl, 44
	ld	(ix - 31), hl
	ld	hl, 4
	jr	.lbl_6
.lbl_4:
	ld	de, 192
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jp	nz, .lbl_31
	ld	(ix - 25), bc
	ld	hl, 52
	ld	(ix - 31), hl
	ld	hl, 6
.lbl_6:
	ld	(ix - 19), hl
.lbl_7:
	ld	hl, (ix + 6)
	ld	iy, (ix + 15)
	ld	bc, (ix + 18)
	lea	de, ix - 16
	ld	(ix - 22), de
	ld	de, 243
	add	hl, de
	ld	(ix - 37), hl
	push	bc
	push	iy
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	iy, (ix - 37)
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
	ld	hl, (ix - 25)
	ld	iy, (ix + 6)
	ld	(iy), hl
	lea	hl, iy + 3
	ld	(ix - 25), hl
	ld	iy, (ix + 9)
	lea	iy, iy + 3
	ld	de, (ix - 19)
.lbl_8:
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	z, .lbl_10
	ld	bc, 0
	ld	c, (iy - 3)
	ld	h, b
	ld	a, h
	ld	l, 24
	call	ti._lshl
	ld	(ix - 34), bc
	ld	(ix - 28), de
	ld	d, a
	ld	bc, 0
	ld	c, (iy - 2)
	ld	a, h
	ld	l, 16
	call	ti._lshl
	push	bc
	pop	hl
	ld	e, a
	ld	bc, (ix - 34)
	ld	a, d
	call	ti._ladd
	ld	(ix - 34), hl
	ld	bc, 0
	ld	c, (iy - 1)
	xor	a, a
	ld	l, 8
	call	ti._lshl
	ld	hl, (ix - 34)
	call	ti._ladd
	ld	bc, 0
	ld	c, (iy)
	xor	a, a
	call	ti._ladd
	lea	bc, iy
	ld	iy, (ix - 25)
	ld	(iy), hl
	ld	(iy + 3), e
	ld	de, (ix - 28)
	dec	de
	lea	iy, iy + 4
	ld	(ix - 25), iy
	push	bc
	pop	iy
	lea	iy, iy + 4
	jr	.lbl_8
.lbl_10:
	ld	c, 2
	ld	de, (ix - 19)
	push	de
	pop	hl
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, (ix + 6)
	add	hl, bc
	dec	hl
	ld	(ix - 25), hl
	or	a, a
	sbc	hl, hl
	push	hl
	pop	iy
	push	de
	pop	bc
.lbl_11:
	ld	de, (ix - 22)
	ld	hl, (ix - 31)
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_20
	ld	(ix - 28), iy
	lea	de, iy
	ld	iy, (ix - 25)
	add	iy, de
	ld	de, (iy)
	ld	a, (iy + 3)
	ld	iy, (ix - 19)
	push	bc
	pop	hl
	ld	(ix - 34), bc
	lea	bc, iy
	call	ti._iremu
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	nz, .lbl_15
	ld	hl, (ix - 34)
	dec	hl
	ld	(ix - 41), hl
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
	ld	(ix - 19), iy
	call	_aes_SubWord
	ld	(ix - 45), hl
	ld	a, e
	pop	hl
	pop	hl
	ld	hl, (ix - 41)
	ld	bc, (ix - 19)
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
.lbl_14:
	ld	iy, (ix + 6)
	jr	.lbl_19
.lbl_15:
	bit	0, (ix - 42)
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
	jr	.lbl_14
.lbl_18:
	ld	iy, (ix + 6)
	push	de
	pop	bc
.lbl_19:
	ld	de, (ix - 28)
	ld	(ix - 41), de
	add	iy, de
	ld	hl, (iy + 3)
	ld	e, (iy + 6)
	call	ti._lxor
	ld	iy, (ix - 25)
	ld	bc, (ix - 41)
	add	iy, bc
	ld	(iy + 4), hl
	ld	(iy + 7), e
	ld	iy, (ix - 28)
	ld	bc, (ix - 34)
	inc	bc
	ld	de, 4
	add	iy, de
	jp	.lbl_11
.lbl_20:
	ld	l, (ix - 38)
	ld	a, l
	or	a, a
	ld	iy, (ix + 6)
	jr	nz, .lbl_24
	ld	hl, (ix + 21)
	ld	a, l
	ld	b, 2
	call	ti._bshru
	and	a, 3
	ld	de, 261
	add	iy, de
	ld	(iy), a
.lbl_22:
	or	a, a
	sbc	hl, hl
.lbl_23:
	restore_interrupts_noret aes_init
	jq stack_clear
.lbl_24:
	ld	a, l
	cp	a, 1
	jp	nz, .lbl_33
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
	ld	c, 8
	jr	nc, .lbl_27
	ld	a, e
	or	a, a
	ld	a, c
	jp	z, .lbl_44
.lbl_27:
	ld	hl, (ix + 21)
	ld	a, l
	cp	a, 16
	jr	nc, .lbl_29
	ld	a, e
	or	a, a
	jp	nz, .lbl_42
.lbl_29:
	ld	hl, (ix + 21)
	ld	a, l
	cp	a, 16
	sbc	a, a
	ld	c, a
	ld	a, e
	or	a, a
	jr	nz, .lbl_37
	ld	h, 0
	jr	.lbl_38
.lbl_31:
	ld	de, 256
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jr	nz, .lbl_36
	ld	(ix - 25), bc
	ld	hl, 8
	ld	(ix - 19), hl
	ld	hl, 60
	ld	(ix - 31), hl
	ld	a, 1
	ld	(ix - 42), a
	jp	.lbl_7
.lbl_33:
	ld	a, l
	cp	a, 2
	jp	nz, .lbl_22
	ld	(ix - 16), 0
	push	de
	pop	hl
	inc	de
	ld	bc, 15
	ld	(ix - 25), de
	ldir
	ld	de, 261
	lea	hl, iy
	add	hl, de
	push	iy
	ld	(ix - 19), hl
	push	hl
	ld	hl, (ix - 22)
	push	hl
	call	aes_ecb_unsafe_encrypt
	pop	hl
	pop	hl
	pop	hl
	ld	de, 12
	ld	hl, (ix + 18)
	or	a, a
	sbc	hl, de
	jr	nz, .lbl_41
	ld	de, 258
	ld	hl, (ix + 6)
	add	hl, de
	ld	(hl), d
	jp	.lbl_22
.lbl_36:
	ld	hl, 1
	jp	.lbl_23
.lbl_37:
	ld	h, -1
.lbl_38:
	ld	l, 16
	ld	a, c
	or	a, h
	ld	c, a
	ld	a, l
	sub	a, d
	bit	0, c
	jr	nz, .lbl_40
	ld	e, a
.lbl_40:
	ld	c, d
	jp	.lbl_43
.lbl_41:
	ld	hl, (ix - 37)
	ld	(hl), 0
	push	hl
	pop	iy
	inc	iy
	ld	bc, 15
	lea	de, iy
	push	hl
	pop	iy
	ldir
	ld	hl, 16
	push	hl
	push	iy
	ld	hl, (ix + 15)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 19)
	push	hl
	ld	hl, (ix - 37)
	push	hl
	push	hl
	call	_aes_gf2_mul
	pop	hl
	pop	hl
	pop	hl
	ld	c, 3
	ld	hl, (ix + 18)
	call	ti._ishl
	push	hl
	pop	iy
	ld	de, 0
	ld.sis	bc, 0
	ld	hl, 16
	push	hl
	lea	hl, iy
	call	__llshru
	pop	de
	ld	a, l
	ld	(ix - 16), 0
	ld	bc, 12
	ld	de, (ix - 25)
	ld	hl, (ix - 22)
	ldir
	ld	(ix - 3), a
	ld	a, iyh
	ld	(ix - 2), a
	ld	a, iyl
	ld	(ix - 1), a
	ld	hl, 16
	push	hl
	ld	hl, (ix - 37)
	push	hl
	ld	hl, (ix - 22)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 19)
	push	hl
	ld	hl, (ix - 37)
	push	hl
	push	hl
	call	_aes_gf2_mul
	pop	hl
	pop	hl
	pop	hl
	jp	.lbl_22
.lbl_42:
	ld	a, 16
	sub	a, e
	ld	c, a
.lbl_43:
	ld	a, e
.lbl_44:
	ld	de, 0
	push	de
	pop	hl
	ld	l, a
	ld	e, c
	add	hl, de
	ld	de, 17
	or	a, a
	sbc	hl, de
	ld	hl, 1
	jp	nc, .lbl_23
	ld	de, 261
	lea	hl, iy
	add	iy, de
	ld	(iy), c
	inc	de
	add	hl, de
	ld	(hl), a
	jp	.lbl_22
 
	
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


; aes_error_t cryptx_aes_update_assoc(aes_ctx* ctx, uint8_t* data, size_t len);
cryptx_aes_update_assoc:
	save_interrupts
	ld	hl, -34
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	bc, 0
	ld	de, 259
	lea	hl, iy
	add	hl, de
	ld	a, (hl)
	cp	a, 2
	jp	nz, .lbl_6
	lea	de, ix - 16
	ld	(ix - 19), de
	ld	de, 261
	lea	hl, iy
	add	hl, de
	ld	(ix - 31), hl
	ld	de, 277
	lea	hl, iy
	add	hl, de
	ld	(ix - 28), hl
	ld	de, (ix + 12)
	ld	(ix - 22), de
.lbl_2:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jp	nc, .lbl_7
	ld	iy, (ix - 22)
	lea	hl, iy
	ld	de, 16
	or	a, a
	sbc	hl, de
	ld	hl, 16
	jr	c, .lbl_5
	push	hl
	pop	iy
.lbl_5:
	ld	(ix - 34), iy
	push	bc
	pop	de
	ld	hl, (ix + 9)
	add	hl, de
	push	iy
	push	hl
	ld	hl, (ix - 19)
	push	hl
	ld	(ix - 25), bc
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	iy, (ix - 19)
	ld	de, (ix - 34)
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
	ld	hl, 16
	push	hl
	ld	hl, (ix - 28)
	push	hl
	ld	hl, (ix - 19)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 31)
	push	hl
	ld	hl, (ix - 28)
	push	hl
	push	hl
	call	_aes_gf2_mul
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 25)
	ld	de, 16
	add	hl, de
	ld	(ix - 25), hl
	ld	de, -16
	ld	hl, (ix - 22)
	add	hl, de
	ld	(ix - 22), hl
	ld	iy, (ix + 6)
	ld	bc, (ix - 25)
	ld	de, (ix + 12)
	jp	.lbl_2
.lbl_6:
	ld	hl, 3
	jr	.lbl_8
.lbl_7:
	push	de
	pop	bc
	ld	de, 293
	add	iy, de
	ld	hl, (iy)
	add	hl, bc
	ld	(iy), hl
	or	a, a
	sbc	hl, hl
.lbl_8:
	restore_interrupts_noret cryptx_aes_update_assoc
	jq stack_clear

; aes_error_t cryptx_aes_render_digest(aes_ctx* ctx, uint8_t *digest);
cryptx_aes_render_digest:
	call	ti._frameset0
	ld	iy, (ix + 6)
	ld	de, 259
	lea	hl, iy
	add	hl, de
	ld	a, (hl)
	cp	a, 2
	jr	nz, .lbl_2
	ld	de, (ix + 9)
	ld	bc, 277
	add	iy, bc
	lea	hl, iy
	ld	bc, 16
	ldir
	or	a, a
	sbc	hl, hl
	jr	.lbl_3
.lbl_2:
	ld	hl, 3
.lbl_3:
	pop	ix
	ret


aes_encrypt:
	save_interrupts

	ld	hl, -84
	call	ti._frameset
	ld	hl, (ix + 6)
	ld	de, 243
	push	hl
	pop	iy
	add	iy, de
	ld	de, 260
	add	hl, de
	ld	a, (hl)
	cp	a, 2
	jr	nz, .lbl_2
	ld	de, 6
	jp	.lbl_38
.lbl_2:
	ld	(ix - 51), iy
	ld	iy, (ix + 9)
	ld	de, 1
	ld	(hl), e
	lea	hl, iy
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_38
	ld	hl, (ix + 15)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_38
	ld	(ix - 54), hl
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	nz, .lbl_6
	ld	de, 2
	jp	.lbl_38
.lbl_6:
	lea	de, ix - 16
	ld	(ix - 57), de
	ld	c, 4
	ld	(ix - 60), hl
	call	ti._ishru
	push	hl
	pop	bc
	ld	de, 259
	ld	hl, (ix + 6)
	add	hl, de
	ld	l, (hl)
	ld	a, l
	or	a, a
	jp	nz, .lbl_18
	ld	(ix - 63), iy
	inc	bc
.lbl_8:
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_37
	ld	(ix - 66), bc
	ld	de, (ix - 60)
	push	de
	pop	hl
	ld	bc, 16
	or	a, a
	sbc	hl, bc
	jr	c, .lbl_11
	ld	de, 16
.lbl_11:
	ld	hl, 16
	or	a, a
	sbc	hl, de
	ld	(ix - 72), hl
	ld	(ix - 69), de
	push	de
	ld	hl, (ix - 63)
	push	hl
	ld	hl, (ix - 57)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 66)
	ld	de, 1
	or	a, a
	sbc	hl, de
	ld	de, (ix - 51)
	jr	nz, .lbl_17
	ld	hl, (ix + 6)
	ld	bc, 261
	add	hl, bc
	ld	l, (hl)
	ld	a, l
	or	a, a
	jr	nz, .lbl_14
	ld	hl, (ix - 57)
	ld	de, (ix - 69)
	add	hl, de
	ld	de, (ix - 72)
	push	de
	push	de
	push	hl
	call	ti._memset
	jr	.lbl_16
.lbl_14:
	ld	a, l
	cp	a, 1
	jr	nz, .lbl_17
	ld	hl, (ix - 57)
	ld	de, (ix - 69)
	add	hl, de
	ld	de, (ix - 72)
	push	de
	ld	de, _iso_pad
	push	de
	push	hl
	call	ti._memcpy
.lbl_16:
	ld	de, (ix - 51)
	pop	hl
	pop	hl
	pop	hl
.lbl_17:
	ld	hl, 16
	push	hl
	ld	hl, (ix - 57)
	push	hl
	push	de
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 54)
	push	hl
	ld	hl, (ix - 57)
	push	hl
	call	aes_ecb_unsafe_encrypt
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix - 51)
	ld	hl, (ix - 54)
	ld	bc, 16
	ldir
	ld	bc, (ix - 66)
	dec	bc
	ld	hl, (ix - 60)
	ld	de, -16
	add	hl, de
	ld	(ix - 60), hl
	ld	iy, (ix - 63)
	lea	iy, iy + 16
	ld	(ix - 63), iy
	ld	iy, (ix - 54)
	lea	iy, iy + 16
	ld	(ix - 54), iy
	jp	.lbl_8
.lbl_18:
	ld	a, l
	cp	a, 1
	jp	nz, .lbl_28
	ld	de, 263
	ld	hl, (ix + 6)
	add	hl, de
	ld	l, (hl)
	ld	a, l
	and	a, 15
	or	a, a
	ld	de, 0
	ld	(ix - 63), de
	jr	z, .lbl_21
	ld	de, 0
	ld	e, l
	ld	(ix - 66), de
	ld	hl, 16
	or	a, a
	sbc	hl, de
	ld	(ix - 63), hl
	push	hl
	push	iy
	ld	hl, (ix + 15)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	ld	de, (ix - 66)
	add	hl, de
	ld	de, 264
	add	hl, de
	ld	de, (ix - 63)
	push	de
	ld	de, (ix + 15)
	push	de
	push	hl
	call	_xor_buf
	ld	iy, (ix + 9)
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 12)
	ld	de, (ix - 63)
	or	a, a
	sbc	hl, de
	ld	c, 4
	call	ti._ishru
	push	hl
	pop	bc
.lbl_21:
	ld	hl, (ix + 6)
	ld	de, 264
	add	hl, de
	ld	(ix - 72), hl
	inc	bc
	ld	de, (ix - 63)
	add	iy, de
	ld	hl, (ix + 15)
	add	hl, de
	ld	(ix - 54), hl
.lbl_22:
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_37
	ld	(ix - 66), bc
	ld	de, (ix - 60)
	push	de
	pop	hl
	ld	bc, 16
	or	a, a
	sbc	hl, bc
	jr	c, .lbl_25
	ld	de, 16
.lbl_25:
	ld	(ix - 69), de
	push	de
	ld	(ix - 63), iy
	push	iy
	ld	hl, (ix - 54)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 57)
	push	hl
	ld	hl, (ix - 51)
	push	hl
	call	aes_ecb_unsafe_encrypt
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 69)
	push	hl
	ld	hl, (ix - 54)
	push	hl
	ld	hl, (ix - 57)
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
	ld	hl, (ix - 51)
	push	hl
	call	_increment_iv
	pop	hl
	pop	hl
	pop	hl
	ld	bc, (ix - 66)
	push	bc
	pop	hl
	ld	de, 1
	or	a, a
	sbc	hl, de
	jr	nz, .lbl_27
	ld	de, (ix - 72)
	ld	hl, (ix - 57)
	ld	bc, 16
	ldir
	ld	bc, (ix - 66)
	ld	hl, (ix - 69)
	ld	a, l
	ld	hl, (ix + 6)
	ld	de, 263
	add	hl, de
	ld	(hl), a
.lbl_27:
	dec	bc
	ld	hl, (ix - 60)
	ld	de, -16
	add	hl, de
	ld	(ix - 60), hl
	ld	iy, (ix - 63)
	lea	iy, iy + 16
	lea	hl, iy
	ld	iy, (ix - 54)
	lea	iy, iy + 16
	ld	(ix - 54), iy
	push	hl
	pop	iy
	jp	.lbl_22
.lbl_28:
	ld	a, l
	cp	a, 2
	jp	nz, .lbl_39
	ld	(ix - 63), iy
	lea	hl, ix - 32
	ld	(ix - 78), hl
	lea	de, ix - 48
	ld	hl, (ix + 6)
	push	hl
	pop	iy
	ld	(ix - 66), bc
	ld	bc, 261
	add	iy, bc
	ld	(ix - 75), iy
	ld	bc, 277
	add	hl, bc
	ld	(ix - 60), hl
	ld	(ix - 72), de
	ld	iy, (ix - 51)
	lea	hl, iy
	ld	bc, 16
	ldir
	ld	hl, 4
	push	hl
	ld	hl, 12
	push	hl
	push	iy
	call	_increment_iv
	ld	bc, (ix - 66)
	pop	hl
	pop	hl
	pop	hl
	inc	bc
	ld	de, 16
	ld	iy, (ix + 12)
	lea	hl, iy
.lbl_30:
	push	hl
	pop	iy
	or	a, a
	sbc	hl, de
	ld	(ix - 69), iy
	jr	c, .lbl_32
	ld	iy, 16
.lbl_32:
	ld	(ix - 81), iy
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	de, (ix + 6)
	ex	de, hl
	jp	z, .lbl_36
	ld	(ix - 66), bc
	ld	bc, (ix - 69)
	push	bc
	pop	hl
	ld	de, 16
	or	a, a
	sbc	hl, de
	jr	c, .lbl_35
	ld	bc, 16
.lbl_35:
	ld	(ix - 84), bc
	push	bc
	ld	hl, (ix - 63)
	push	hl
	ld	hl, (ix - 54)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	iy, (ix - 54)
	ld	de, (ix - 81)
	add	iy, de
	ld	hl, 16
	ld	de, (ix - 84)
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
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 57)
	push	hl
	ld	hl, (ix - 51)
	push	hl
	call	aes_ecb_unsafe_encrypt
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix - 54)
	push	hl
	ld	hl, (ix - 57)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 4
	push	hl
	ld	hl, 12
	push	hl
	ld	hl, (ix - 51)
	push	hl
	call	_increment_iv
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix - 60)
	push	hl
	ld	hl, (ix - 54)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 75)
	push	hl
	ld	hl, (ix - 60)
	push	hl
	push	hl
	call	_aes_gf2_mul
	pop	hl
	pop	hl
	pop	hl
	ld	bc, (ix - 66)
	dec	bc
	ld	de, -16
	ld	hl, (ix - 69)
	add	hl, de
	ld	iy, (ix - 54)
	lea	iy, iy + 16
	ld	(ix - 54), iy
	ld	iy, (ix - 63)
	lea	iy, iy + 16
	ld	(ix - 63), iy
	ld	de, 16
	jp	.lbl_30
.lbl_36:
	ld	bc, 293
	add	hl, bc
	ld	hl, (hl)
	ld	a, 3
	ld	c, a
	call	ti._ishl
	push	hl
	pop	iy
	ld	(ix - 51), iy
	ld	de, 0
	ld.sis	bc, 0
	ld	hl, 16
	push	hl
	lea	hl, iy
	call	__llshru
	pop	de
	ld	e, l
	ld	(ix - 32), 0
	ld	iy, (ix - 78)
	lea	hl, iy
	inc	hl
	ld	c, (iy)
	ld	(hl), c
	ld	l, (ix - 31)
	ld	(ix - 30), l
	ld	l, (ix - 30)
	ld	(ix - 29), l
	ld	l, (ix - 29)
	ld	(ix - 28), l
	ld	(ix - 27), e
	ld	de, (ix - 51)
	ld	l, d
	ld	(ix - 26), l
	ld	l, e
	ld	(ix - 25), l
	lea	iy, iy + 8
	ld	hl, (ix + 12)
	ld	c, a
	call	ti._ishl
	push	hl
	pop	de
	ld	(ix - 51), de
	ld	hl, 16
	push	hl
	ex	de, hl
	ld	de, 0
	ld.sis	bc, 0
	call	__llshru
	pop	de
	ld	a, l
	ld	(ix - 24), 0
	lea	hl, iy
	inc	hl
	ld	e, (iy)
	ld	(hl), e
	ld	l, (ix - 23)
	ld	(ix - 22), l
	ld	l, (ix - 22)
	ld	(ix - 21), l
	ld	l, (ix - 21)
	ld	(ix - 20), l
	ld	(ix - 19), a
	ld	hl, (ix - 51)
	ld	a, h
	ld	(ix - 18), a
	ld	a, l
	ld	(ix - 17), a
	ld	hl, 16
	push	hl
	ld	hl, (ix - 60)
	push	hl
	ld	hl, (ix - 78)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 75)
	push	hl
	ld	hl, (ix - 60)
	push	hl
	push	hl
	call	_aes_gf2_mul
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 72)
	push	hl
	push	hl
	call	aes_ecb_unsafe_encrypt
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix - 60)
	push	hl
	ld	hl, (ix - 72)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
.lbl_37:
	ld	de, 0
.lbl_38:
	ex	de, hl
	restore_interrupts_noret aes_encrypt
	jq stack_clear
.lbl_39:
	ld	de, 3
	jr	.lbl_38
	
    
aes_decrypt:
	save_interrupts

	ld	hl, -50
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	de, 243
	lea	hl, iy
	add	hl, de
	ld	(ix - 35), hl
	ld	de, 278
	add	iy, de
	ld	a, (iy)
	cp	a, d
	jr	nz, .lbl_2
	ld	de, 6
	jp	.lbl_14
.lbl_2:
	ld	hl, (ix + 9)
	ld	de, 1
	ld	(iy), 2
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_14
	ld	(ix - 38), hl
	ld	hl, (ix + 15)
	ld	(ix - 41), hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_14
	ld	iy, (ix + 12)
	ld	de, 5
	lea	hl, iy
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jp	z, .lbl_14
	ld	hl, (ix + 6)
	ld	bc, 259
	add	hl, bc
	ld	l, (hl)
	ld	a, l
	or	a, a
	jp	nz, .lbl_10
	ld	a, iyl
	and	a, 15
	or	a, a
	jp	nz, .lbl_14
	lea	hl, ix - 16
	ld	(ix - 44), hl
	lea	hl, ix - 32
	ld	(ix - 47), hl
	ld	c, 4
	lea	hl, iy
	call	ti._ishru
.lbl_8:
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	iy, (ix + 6)
	jp	z, .lbl_12
	ld	(ix - 50), hl
	ld	de, (ix - 44)
	ld	hl, (ix - 38)
	ld	bc, 16
	ldir
	push	iy
	ld	hl, (ix - 47)
	push	hl
	ld	hl, (ix - 44)
	push	hl
	call	aes_ecb_unsafe_decrypt
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix - 47)
	push	hl
	ld	hl, (ix - 35)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix - 41)
	ld	hl, (ix - 47)
	ld	iy, 16
	lea	bc, iy
	ldir
	ld	de, (ix - 35)
	ld	hl, (ix - 44)
	lea	bc, iy
	ldir
	ld	hl, (ix - 50)
	ld	iy, (ix - 38)
	lea	iy, iy + 16
	ld	(ix - 38), iy
	ld	iy, (ix - 41)
	lea	iy, iy + 16
	ld	(ix - 41), iy
	dec	hl
	jr	.lbl_8
.lbl_10:
	ld	a, l
	cp	a, 1
	jr	nz, .lbl_13
	ld	hl, (ix + 6)
	ld	de, 278
	add	hl, de
	ld	(ix - 35), hl
	ld	(hl), d
	ld	de, (ix + 15)
	push	de
	push	iy
	ld	de, (ix + 9)
	push	de
	ld	hl, (ix + 6)
	push	hl
	call	aes_encrypt
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix - 35)
	ld	(hl), 2
.lbl_12:
	ld	de, 0
	jr	.lbl_14
.lbl_13:
	ld	de, 3
.lbl_14:
	ex	de, hl
	;ld	sp, ix
	;pop	ix
	;ret
    restore_interrupts_noret aes_decrypt
    jp stack_clear
	
    
 
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
	call	cryptx_hash_final
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
	call	cryptx_hash_final
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
	
ecdh_init:
	save_interrupts
	ld	hl, -3
	call	ti._frameset
	ld	hl, (ix + 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jr	nz, .lbl_2
	ld	hl, 1
	jr	.lbl_3
.lbl_2:
	ld	de, 29
	push	de
	push	hl
	call	cryptx_csrand_fill
	pop	hl
	pop	hl
	ld	iy, (ix + 6)
	lea	de, iy + 30
	ld	(ix - 3), de
	ld	hl, 30
	push	hl
	ld	hl, _sect233k1+30
	push	hl
	push	de
	call	_rmemcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 30
	push	hl
	ld	hl, _sect233k1+60
	push	hl
	ld	iy, (ix + 6)
	pea	iy + 60
	call	_rmemcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 240
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix - 3)
	push	hl
	call	_point_mul_scalar
	or	a, a
	sbc	hl, hl
	pop	de
	pop	de
	pop	de
.lbl_3:
	restore_interrupts_noret ecdh_init
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
	
_sect233k1:
	db	2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 1
	db	$01,$72,$32,$BA,$85,$3A,$7E,$73,$1A,$F1,$29,$F2,$2F,$F4,$14,$95,$63,$A4,$19,$C2,$6B,$F5,$0A,$4C,$9D,$6E,$EF,$AD,$61,$26
	db	$01,$DB,$53,$7D,$EC,$E8,$19,$B7,$F7,$0F,$55,$5A,$67,$C4,$27,$A8,$CD,$9B,$F1,$8A,$EB,$9B,$56,$E0,$C1,$10,$56,$FA,$E6,$A3
	db	4
	
_ta_resist:
	db	60 dup 0
 
 
 _hexc:     db	"0123456789ABCDEF"
 _hash_out_lens:    db 32

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
