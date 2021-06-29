;------------------------------------------
include '../include/library.inc'

;------------------------------------------
library "HASHLIB", 4

;------------------------------------------

; v2 functions
    export hashlib_CSPRNGInit
    export hashlib_CSPRNGAddEntropy
    export hashlib_CSPRNGRandom
    export hashlib_RandomBytes
    
; v1 functions
    export hashlib_Sha256Init
	export hashlib_Sha256Update
	export hashlib_Sha256Final
 
 ; v3 functions
    export hashlib_AESLoadKey
    export hashlib_AESEncrypt
    export hashlib_AESDecrypt
    export hashlib_AESOutputMAC
    export hashlib_AESVerifyMAC
    
    export hashlib_b64encode
    export hashlib_b64decode
    
    export hashlib_EraseContext
    export hashlib_PadMessage
    export hashlib_StripPadding
    export hashlib_CompareDigest

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
	sha1_ctx:
	.data:    rb 64
	.datalen: rb 4
	.bitlen:  rb 8
	.state:   rb 4*5
	.k:       rb 4*4
	.size:
end virtual

virtual at 0
	sha256_ctx:
	.data:    rb 64
	.datalen: rb 4
	.bitlen:  rb 8
	.state:   rb 4*8
	.size:
end virtual
;------------------------------------------
    

hashlib_CSPRNGInit:
; ix = selected byte
; de = current deviation
; hl = starting address
; bc = bytes to check
; outputs: hl = address
    push ix
    ld ix, 0
    ld de, _max_deviation
    ld hl, $D65800
    ld bc, 513
.test_range_loop:
    push bc
    push hl
    call _test_byte
    pop hl
    pop bc
    inc hl
    dec bc
    ld a,c
    or a,b
    jq nz,.test_range_loop
    push ix
    pop hl
    ld (_csprng_state), hl
    push hl
    call hashlib_CSPRNGAddEntropy
    pop hl
    pop ix
    ret

_test_byte:
; inputs: hl = byte
; outputs: none, but de should be edited if address contains less deviant bit
; outputs: none, but ix should be edited to this address if contains less deviant bit
; destroys: bc, af, hl
; modifies: de, ix
    push iy
    push hl
    ld b, 8
    ld c, 0
.test_byte_bitloop:
    push bc
    push de
    ld a,c
    call _test_bit  ; HL = bits set
    pop de
    pop bc
    or a,a
    sbc hl, de
    jq nc, .skip_next_bit    ; IF HL < DE
    add hl,de
    ex hl, de
    pop ix
    push ix
.skip_next_bit:
    inc c
    djnz .test_byte_bitloop
    pop iy
    pop iy
    ret

_test_bit:
; inputs: a = bit
; inputs: hl = byte
; outputs: hl = hit count
; destroys: af, bc, de, hl
    add a,a
    add a,a
    add a,a
    add a,$46 ;bit 0,(hl)
    ld (.smc1),a
    ld (.smc2),a
    ld (.smc3),a
    ld (.smc4),a
    ld bc,$ff
    ld de,0
.loop:
    bit 0,(hl)
.smc1:=$-1
    jq z,.next1
    inc de
.next1:
    bit 0,(hl)
.smc2:=$-1
    jq z,.next2
    inc de
.next2:
    bit 0,(hl)
.smc3:=$-1
    jq z, .next3
    inc de
.next3:
    bit 0,(hl)
.smc4:=$-1
    jq z, .next4
    inc de
.next4:
    djnz .loop
    ld hl,_num_tests/2
    or a,a
    sbc hl,de
    ret nc
    ex hl,de
    or a,a
    sbc hl,hl
    sbc hl,de
    ret
    
	
hashlib_CSPRNGAddEntropy:
    ld hl, (_csprng_state)
    add	hl,de
	or	a,a
	sbc	hl,de
    ret z
    ld de, _csprng_state + 3
    ld b, 192
.byte_read_loop:
    ld a, (de)
    xor a, (hl)
    ld (de), a
    inc de
    djnz .byte_read_loop
    ret
    
 
hashlib_CSPRNGRandom:
	ld	hl, -162
	call	ti._frameset
	ld	e, 0
	ld	bc, 0
	ld	d, -5
	lea	hl, ix + -10
	ld	(ix + -3), bc
	ld	bc, -161
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), hl
	lea	hl, ix + -42
	push	ix
	ld	bc, -156
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	bc, -150
	lea	hl, ix + 0
	add	hl, bc
	push	ix
	ld	bc, -153
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	bc, (ix + -3)
BB2_1:
	ld	iy, (_csprng_state)
	ld	a, d
	or	a, a
	jq	z, BB2_4
	lea	hl, iy + 0
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, BB2_4
	ld	bc, -157
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), d
	call	hashlib_CSPRNGInit
	ld	bc, -157
	lea	iy, ix + 0
	add	iy, bc
	ld	d, (iy + 0)
	ld	e, 0
	ld	bc, 0
	inc	d
	jq	BB2_1
BB2_4:
	lea	hl, iy + 0
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, BB2_5
	jq	BB2_12
BB2_5:
	ld	(ix + -10), bc
	ld	(ix + -7), e
	ld	de, 4
BB2_6:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jq	z, BB2_7
	ld	a, (iy)
	ld	de, -157
	lea	hl, ix + 0
	add	hl, de
	ld	(hl), a
	push	ix
	ld	de, -161
	add	ix, de
	ld	hl, (ix + 0)
	pop	ix
	add	hl, bc
	push	hl
	pop	de
	ld	a, (hl)
	ld	(ix + -3), bc
	push	ix
	ld	bc, -157
	add	ix, bc
	xor	a, (ix + 0)
	pop	ix
	ld	de, 4
	ld	(hl), a
	ld	bc, (ix + -3)
	inc	bc
	jq	BB2_6
BB2_7:
	ld	bc, -153
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Init
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, 192
	push	hl
	ld	hl, _csprng_state+3
	push	hl
	ld	bc, -153
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -156
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -153
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	pop	hl
	pop	hl
	ld	a, (ix + -10)
	ld	bc, -158
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), a
	ld	a, (ix + -9)
	inc	bc
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), a
	ld	a, (ix + -8)
	push	ix
	ld	bc, -153
	add	ix, bc
	ld	(ix + 0), a
	pop	ix
	ld	e, (ix + -7)
	or	a, a
	sbc	hl, hl
BB2_9:
	ld	bc, 255
	call	ti._iand
	ld	a, l
	cp	a, 32
	jq	nc, BB2_11
	push	hl
	pop	bc
	ld	(ix + -3), bc
	ld	bc, -162
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), e
	push	ix
	ld	bc, -156
	add	ix, bc
	ld	de, (ix + 0)
	pop	ix
	push	de
	pop	iy
	ld	bc, (ix + -3)
	add	iy, bc
	ld	(ix + -3), de
	push	ix
	ld	de, -158
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	xor	a, (iy)
	lea	iy, ix + 0
	add	iy, de
	ld	(iy + 0), a
	inc	bc
	ld	de, (ix + -3)
	push	de
	pop	iy
	add	iy, bc
	push	ix
	ld	bc, -157
	add	ix, bc
	ld	a, (ix + 0)
	pop	ix
	xor	a, (iy)
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), a
	push	hl
	pop	iy
	ld	bc, 2
	add	iy, bc
	lea	bc, iy + 0
	push	de
	pop	iy
	add	iy, bc
	push	ix
	ld	bc, -153
	add	ix, bc
	ld	a, (ix + 0)
	pop	ix
	xor	a, (iy)
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), a
	push	hl
	pop	iy
	ld	bc, 3
	add	iy, bc
	lea	bc, iy + 0
	push	de
	pop	iy
	add	iy, bc
	push	ix
	ld	bc, -162
	add	ix, bc
	ld	a, (ix + 0)
	pop	ix
	xor	a, (iy)
	ld	e, a
	ld	bc, 4
	add	hl, bc
	jq	BB2_9
BB2_11:
	ld	bc, -158
	lea	hl, ix + 0
	add	hl, bc
	ld	a, (hl)
	ld	(ix + -10), a
	inc	bc
	lea	iy, ix + 0
	add	iy, bc
	ld	a, (iy + 0)
	ld	(ix + -9), a
	push	ix
	ld	bc, -153
	add	ix, bc
	ld	a, (ix + 0)
	pop	ix
	ld	(ix + -8), a
	push	ix
	ld	bc, -161
	add	ix, bc
	ld	iy, (ix + 0)
	pop	ix
	lea	hl, iy + 3
	ld	bc, -153
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), hl
	ld	(ix + -7), e
	call	hashlib_CSPRNGAddEntropy
	ld	bc, (ix + -10)
	ld	de, -153
	lea	hl, ix + 0
	add	hl, de
	ld	hl, (hl)
	ld	e, (hl)
BB2_12:
	push	bc
	pop	hl
	ld	sp, ix
	pop	ix
	ret
 
 L_.str2:
	db	"%lu",012o,000o
 
hashlib_RandomBytes:
	ld	hl, -10
	call	ti._frameset
	ld	de, (ix + 9)
	ld	iy, 0
	ld	(ix + -7), de
BB3_1:
	lea	hl, iy + 0
	or	a, a
	sbc	hl, de
	jq	nc, BB3_2
	ld	(ix + -10), iy
	call	hashlib_CSPRNGRandom
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
	jq	c, BB3_5
	ld	bc, 4
BB3_5:
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
	jq	BB3_1
BB3_2:
	ld	sp, ix
	pop	ix
	ret
	
	
_sha256_transform:
	ld	hl, -356
	call	ti._frameset
	ld	iy, 16
	xor	a, a
	ld	bc, 0
	ld	de, -262
	lea	hl, ix + 0
	add	hl, de
	push	ix
	ld	de, -268
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	ld	de, -265
	lea	hl, ix + 0
	add	hl, de
	ld	(hl), bc
	push	ix
	ld	de, -269
	add	ix, de
	ld	(ix + 0), a
	pop	ix
	push	ix
	ld	de, -272
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	ld	d, a
	push	ix
	ld	bc, -275
	add	ix, bc
	ld	(ix + 0), a
	pop	ix
BB9_1:
	ld	bc, -265
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	ix
	ld	bc, -269
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	lea	bc, iy + 0
	ld	a, d
	call	ti._lcmpu
	jq	nc, BB9_2
	ld	iy, (ix + 9)
	lea	hl, iy + 0
	push	ix
	ld	de, -272
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	add	hl, bc
	ld	a, (hl)
	or	a, a
	sbc	hl, hl
	ex	de, hl
	ld	e, a
	ld	(ix + -3), bc
	ld	bc, -284
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), de
	ld	bc, (ix + -3)
	push	bc
	pop	hl
	push	bc
	pop	de
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	(ix + 0), de
	pop	ix
	ld	bc, 1
	call	ti._ior
	push	hl
	pop	bc
	add	iy, bc
	ld	a, (iy)
	ld	iy, 0
	lea	hl, iy + 0
	ld	l, a
	push	ix
	ld	bc, -287
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	de
	pop	hl
	ld	bc, 2
	call	ti._ior
	push	hl
	pop	bc
	ld	hl, (ix + 9)
	add	hl, bc
	ld	a, (hl)
	ld	iyl, a
	ld	bc, -281
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), iy
	ex	de, hl
	ld	bc, 3
	call	ti._ior
	push	hl
	pop	bc
	ld	hl, (ix + 9)
	add	hl, bc
	ld	a, (hl)
	or	a, a
	sbc	hl, hl
	ld	l, a
	ld	de, -278
	lea	iy, ix + 0
	add	iy, de
	ld	(iy + 0), hl
	ld	de, -284
	lea	hl, ix + 0
	add	hl, de
	ld	bc, (hl)
	ld	e, 0
	ld	a, e
	ld	l, 24
	call	ti._lshl
	push	bc
	pop	iy
	ld	d, a
	ld	(ix + -3), de
	push	ix
	ld	de, -287
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	ld	a, e
	ld	l, 16
	call	ti._lshl
	push	bc
	pop	hl
	ld	e, a
	lea	bc, iy + 0
	ld	a, d
	call	ti._ladd
	push	hl
	pop	iy
	ld	(ix + -3), de
	push	ix
	ld	de, -281
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	xor	a, a
	ld	l, 8
	call	ti._lshl
	lea	hl, iy + 0
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(ix + -3), de
	ld	de, -278
	lea	iy, ix + 0
	add	iy, de
	ld	bc, (iy + 0)
	xor	a, a
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(ix + -3), bc
	push	ix
	ld	bc, -278
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	a, e
	push	ix
	ld	bc, -265
	add	ix, bc
	ld	de, (ix + 0)
	pop	ix
	push	de
	pop	hl
	ld	bc, (ix + -3)
	ld	c, 2
	call	ti._ishl
	push	hl
	pop	bc
	ld	(ix + -3), de
	push	ix
	ld	de, -268
	add	ix, de
	ld	iy, (ix + 0)
	pop	ix
	add	iy, bc
	push	ix
	ld	bc, -278
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	ld	(iy), hl
	ld	(iy + 3), a
	ld	iy, 16
	ld	de, (ix + -3)
	ex	de, hl
	push	ix
	ld	bc, -269
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, 1
	xor	a, a
	call	ti._ladd
	ld	(ix + -3), bc
	push	ix
	ld	bc, -265
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	ld	bc, -269
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	ld	bc, -275
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	ld	bc, 4
	ld	d, a
	call	ti._ladd
	ld	(ix + -3), bc
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	ld	bc, -275
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	ld	bc, (ix + -3)
	jq	BB9_1
BB9_2:
	ld	e, d
BB9_4:
	lea	hl, iy + 0
	push	ix
	ld	bc, -269
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	ld	bc, 64
	ld	a, d
	call	ti._lcmpu
	jq	nc, BB9_6
	lea	hl, iy + 0
	ld	de, -2
	add	hl, de
	ld	a, 2
	ld	c, a
	call	ti._ishl
	push	hl
	pop	de
	ld	(ix + -3), bc
	push	ix
	ld	bc, -265
	add	ix, bc
	ld	(ix + 0), iy
	pop	ix
	ld	bc, -268
	lea	iy, ix + 0
	add	iy, bc
	ld	iy, (iy + 0)
	add	iy, de
	ld	hl, (iy)
	ld	d, (iy + 3)
	push	hl
	pop	iy
	ld	bc, (ix + -3)
	lea	bc, iy + 0
	ld	a, d
	ld	l, 15
	call	ti._lshl
	ld	(ix + -3), de
	push	ix
	ld	de, -272
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	ld	de, (ix + -3)
	ld	e, a
	lea	bc, iy + 0
	ld	a, d
	ld	l, 17
	call	ti._lshru
	ld	(ix + -3), bc
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lor
	ld	(ix + -3), bc
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	ld	bc, -275
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	ld	bc, (ix + -3)
	lea	bc, iy + 0
	ld	a, d
	ld	l, 13
	call	ti._lshl
	ld	(ix + -3), de
	push	ix
	ld	de, -278
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	ld	de, (ix + -3)
	ld	e, a
	lea	bc, iy + 0
	ld	a, d
	ld	l, 19
	call	ti._lshru
	ld	(ix + -3), bc
	push	ix
	ld	bc, -278
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lor
	push	hl
	pop	bc
	ld	a, e
	ld	(ix + -3), bc
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	ld	bc, -275
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lxor
	ld	(ix + -3), de
	push	ix
	ld	de, -272
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	lea	bc, iy + 0
	ld	de, (ix + -3)
	ld	a, d
	ld	l, 10
	call	ti._lshru
	ld	(ix + -3), bc
	ld	bc, -272
	lea	iy, ix + 0
	add	iy, bc
	ld	hl, (iy + 0)
	ld	bc, (ix + -3)
	call	ti._lxor
	ld	(ix + -3), de
	push	ix
	ld	de, -272
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	push	ix
	ld	de, -265
	add	ix, de
	ld	hl, (ix + 0)
	pop	ix
	ld	bc, -7
	add	hl, bc
	ld	c, 2
	call	ti._ishl
	push	hl
	pop	bc
	push	ix
	ld	de, -268
	add	ix, de
	ld	iy, (ix + 0)
	pop	ix
	add	iy, bc
	ld	bc, (iy)
	ld	a, (iy + 3)
	ld	de, -272
	lea	iy, ix + 0
	add	iy, de
	ld	hl, (iy + 0)
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(ix + -3), bc
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	ld	bc, -275
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	push	ix
	ld	bc, -265
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	ld	de, -15
	add	hl, de
	ld	bc, (ix + -3)
	ld	c, 2
	call	ti._ishl
	push	hl
	pop	de
	ld	(ix + -3), bc
	push	ix
	ld	bc, -268
	add	ix, bc
	ld	iy, (ix + 0)
	pop	ix
	add	iy, de
	ld	hl, (iy)
	ld	d, (iy + 3)
	push	hl
	pop	iy
	ld	bc, (ix + -3)
	lea	bc, iy + 0
	ld	a, d
	ld	l, 25
	call	ti._lshl
	ld	(ix + -3), de
	push	ix
	ld	de, -278
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	ld	de, (ix + -3)
	ld	e, a
	lea	bc, iy + 0
	ld	a, d
	ld	l, 7
	call	ti._lshru
	ld	(ix + -3), bc
	push	ix
	ld	bc, -278
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lor
	ld	(ix + -3), bc
	push	ix
	ld	bc, -278
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	ld	bc, -281
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	ld	bc, (ix + -3)
	lea	bc, iy + 0
	ld	a, d
	ld	l, 14
	call	ti._lshl
	ld	(ix + -3), de
	push	ix
	ld	de, -284
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	ld	de, (ix + -3)
	ld	e, a
	lea	bc, iy + 0
	ld	a, d
	ld	l, 18
	call	ti._lshru
	ld	(ix + -3), bc
	push	ix
	ld	bc, -284
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lor
	push	hl
	pop	bc
	ld	a, e
	ld	(ix + -3), bc
	push	ix
	ld	bc, -278
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	ld	bc, -281
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lxor
	ld	(ix + -3), de
	push	ix
	ld	de, -278
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	lea	bc, iy + 0
	ld	de, (ix + -3)
	ld	a, d
	ld	l, 3
	call	ti._lshru
	ld	(ix + -3), bc
	ld	bc, -278
	lea	iy, ix + 0
	add	iy, bc
	ld	hl, (iy + 0)
	ld	bc, (ix + -3)
	call	ti._lxor
	ld	(ix + -3), bc
	push	ix
	ld	bc, -278
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	d, e
	push	ix
	ld	bc, -265
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	ld	bc, -16
	add	hl, bc
	ld	c, 2
	call	ti._ishl
	push	hl
	pop	bc
	ld	(ix + -3), de
	push	ix
	ld	de, -268
	add	ix, de
	ld	iy, (ix + 0)
	pop	ix
	add	iy, bc
	ld	bc, (iy)
	ld	a, (iy + 3)
	ld	de, -272
	lea	iy, ix + 0
	add	iy, de
	ld	hl, (iy + 0)
	ld	de, (ix + -3)
	ld	(ix + -3), bc
	push	ix
	ld	bc, -275
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._ladd
	ld	(ix + -3), de
	push	ix
	ld	de, -278
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	ld	a, d
	call	ti._ladd
	ld	(ix + -3), bc
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	a, e
	push	ix
	ld	bc, -265
	add	ix, bc
	ld	de, (ix + 0)
	pop	ix
	push	de
	pop	hl
	ld	bc, (ix + -3)
	ld	c, 2
	call	ti._ishl
	push	hl
	pop	bc
	ld	(ix + -3), de
	push	ix
	ld	de, -268
	add	ix, de
	ld	iy, (ix + 0)
	pop	ix
	add	iy, bc
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	ld	(iy), hl
	ld	(iy + 3), a
	ld	de, (ix + -3)
	ex	de, hl
	ld	bc, -269
	lea	iy, ix + 0
	add	iy, bc
	ld	e, (iy + 0)
	ld	bc, 1
	xor	a, a
	ld	d, a
	call	ti._ladd
	push	hl
	pop	iy
	jq	BB9_4
BB9_6:
	ld	iy, (ix + 6)
	ld	hl, (iy + 76)
	push	ix
	ld	bc, -329
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	a, (iy + 79)
	ld	bc, -326
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), a
	ld	hl, (iy + 80)
	push	ix
	inc	bc
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	a, (iy + 83)
	ld	bc, -322
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), a
	ld	hl, (iy + 84)
	push	ix
	inc	bc
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	a, (iy + 87)
	ld	bc, -318
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), a
	ld	hl, (iy + 88)
	push	ix
	inc	bc
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	a, (iy + 91)
	ld	bc, -314
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), a
	ld	hl, (iy + 92)
	push	ix
	inc	bc
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	a, (iy + 95)
	ld	bc, -310
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), a
	ld	hl, (iy + 96)
	push	ix
	inc	bc
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	h, (iy + 99)
	ld	bc, (iy + 100)
	ld	(ix + -3), de
	push	ix
	ld	de, -306
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	ld	a, (iy + 103)
	ld	bc, (iy + 104)
	ld	l, (iy + 107)
	lea	iy, ix + 0
	add	iy, de
	ld	iy, (iy + 0)
	push	ix
	ld	de, -338
	add	ix, de
	ld	(ix + 0), a
	pop	ix
	push	ix
	inc	de
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	push	ix
	ld	de, -302
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	push	ix
	ld	bc, -334
	add	ix, bc
	ld	(ix + 0), l
	pop	ix
	push	ix
	ld	bc, -303
	add	ix, bc
	ld	(ix + 0), l
	pop	ix
	ld	de, (ix + -3)
	ld	e, d
	ld	(ix + -3), de
	push	ix
	ld	de, -309
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -290
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	push	ix
	ld	bc, -339
	add	ix, bc
	ld	(ix + 0), h
	pop	ix
	push	ix
	ld	bc, -291
	add	ix, bc
	ld	(ix + 0), h
	pop	ix
	ld	bc, -313
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	ix
	ld	bc, -275
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	bc, -310
	lea	hl, ix + 0
	add	hl, bc
	ld	l, (hl)
	push	ix
	ld	bc, -269
	add	ix, bc
	ld	(ix + 0), l
	pop	ix
	push	ix
	ld	bc, -317
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	ld	bc, -298
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	bc, -314
	lea	hl, ix + 0
	add	hl, bc
	ld	l, (hl)
	push	ix
	ld	bc, -299
	add	ix, bc
	ld	(ix + 0), l
	pop	ix
	push	ix
	ld	bc, -321
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	ld	bc, -278
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	bc, -318
	lea	hl, ix + 0
	add	hl, bc
	ld	l, (hl)
	push	ix
	ld	bc, -281
	add	ix, bc
	ld	(ix + 0), l
	pop	ix
	push	ix
	ld	bc, -325
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	ld	bc, -284
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	bc, -322
	lea	hl, ix + 0
	add	hl, bc
	ld	l, (hl)
	push	ix
	ld	bc, -287
	add	ix, bc
	ld	(ix + 0), l
	pop	ix
	push	ix
	ld	bc, -329
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	bc, -326
	lea	hl, ix + 0
	add	hl, bc
	ld	l, (hl)
	push	ix
	ld	bc, -265
	add	ix, bc
	ld	(ix + 0), l
	pop	ix
	or	a, a
	sbc	hl, hl
	ld	de, (ix + -3)
BB9_7:
	push	ix
	ld	bc, -292
	add	ix, bc
	ld	(ix + 0), a
	pop	ix
	push	ix
	ld	bc, -295
	add	ix, bc
	ld	(ix + 0), iy
	pop	ix
	ld	bc, -330
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), e
	push	hl
	pop	iy
	ld	bc, 64
	ld	a, d
	call	ti._lcmpu
	jq	nc, BB9_9
	ld	de, -275
	lea	hl, ix + 0
	add	hl, de
	ld	bc, (hl)
	push	ix
	ld	de, -333
	add	ix, de
	ld	(ix + 0), iy
	pop	ix
	push	bc
	pop	iy
	push	ix
	ld	de, -269
	add	ix, de
	ld	h, (ix + 0)
	pop	ix
	ld	a, h
	ld	l, 26
	call	ti._lshl
	push	bc
	pop	de
	ld	(ix + -3), de
	push	ix
	ld	de, -342
	add	ix, de
	ld	(ix + 0), a
	pop	ix
	lea	bc, iy + 0
	ld	a, h
	ld	l, 6
	call	ti._lshru
	ld	de, (ix + -3)
	ex	de, hl
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lor
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	ld	bc, (ix + -3)
	lea	bc, iy + 0
	ld	(ix + -3), de
	push	ix
	ld	de, -269
	add	ix, de
	ld	h, (ix + 0)
	pop	ix
	ld	a, h
	ld	l, 21
	call	ti._lshl
	ld	de, (ix + -3)
	push	bc
	pop	de
	ld	(ix + -3), de
	push	ix
	ld	de, -346
	add	ix, de
	ld	(ix + 0), a
	pop	ix
	lea	bc, iy + 0
	ld	a, h
	ld	l, 11
	call	ti._lshru
	ld	de, (ix + -3)
	ex	de, hl
	ld	(ix + -3), bc
	push	ix
	ld	bc, -346
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lor
	push	hl
	pop	bc
	ld	a, e
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lxor
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	ld	bc, (ix + -3)
	lea	bc, iy + 0
	ld	(ix + -3), bc
	push	ix
	ld	bc, -269
	add	ix, bc
	ld	d, (ix + 0)
	pop	ix
	ld	a, d
	ld	l, 7
	ld	bc, (ix + -3)
	call	ti._lshl
	ld	(ix + -3), de
	push	ix
	ld	de, -346
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	ld	de, (ix + -3)
	ld	e, a
	lea	bc, iy + 0
	ld	a, d
	ld	l, 25
	call	ti._lshru
	ld	(ix + -3), bc
	push	ix
	ld	bc, -346
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lor
	push	hl
	pop	bc
	ld	a, e
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lxor
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	push	ix
	ld	bc, -275
	add	ix, bc
	ld	(ix + 0), iy
	pop	ix
	lea	hl, iy + 0
	ld	e, d
	ld	bc, (ix + -3)
	ld	(ix + -3), de
	push	ix
	ld	de, -290
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	dec	de
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._land
	ld	(ix + -3), bc
	push	ix
	ld	bc, -346
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	lea	hl, iy + 0
	ld	e, d
	ld	bc, (ix + -3)
	ld	bc, -1
	ld	a, -1
	call	ti._lxor
	push	hl
	pop	bc
	ld	a, e
	ld	(ix + -3), bc
	ld	bc, -295
	lea	iy, ix + 0
	add	iy, bc
	ld	hl, (iy + 0)
	push	ix
	ld	bc, -292
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._land
	ld	(ix + -3), de
	push	ix
	ld	de, -356
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	push	ix
	ld	de, -333
	add	ix, de
	ld	hl, (ix + 0)
	pop	ix
	ld	a, 2
	ld	c, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	iy, _k
	add	iy, bc
	ld	hl, (iy)
	push	ix
	ld	de, -353
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	ld	de, (ix + -3)
	ld	d, (iy + 3)
	ld	(ix + -3), de
	ld	de, -268
	lea	hl, ix + 0
	add	hl, de
	ld	iy, (hl)
	add	iy, bc
	ld	hl, (iy)
	push	ix
	ld	de, -350
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	ld	a, (iy + 3)
	ld	iyl, a
	ld	de, -356
	lea	hl, ix + 0
	add	hl, de
	ld	hl, (hl)
	push	ix
	ld	de, -302
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	dec	de
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(ix + -3), de
	push	ix
	ld	de, -346
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	dec	de
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(ix + -3), de
	push	ix
	ld	de, -342
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	dec	de
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(ix + -3), de
	push	ix
	ld	de, -353
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	ld	a, d
	call	ti._ladd
	ld	(ix + -3), de
	push	ix
	ld	de, -350
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	ld	a, iyl
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(ix + -3), bc
	ld	bc, -302
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), hl
	push	ix
	dec	bc
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	iy, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	lea	bc, iy + 0
	ld	(ix + -3), de
	push	ix
	ld	de, -265
	add	ix, de
	ld	h, (ix + 0)
	pop	ix
	ld	a, h
	ld	l, 30
	call	ti._lshl
	ld	de, (ix + -3)
	push	bc
	pop	de
	ld	(ix + -3), de
	push	ix
	ld	de, -342
	add	ix, de
	ld	(ix + 0), a
	pop	ix
	lea	bc, iy + 0
	ld	a, h
	ld	l, 2
	call	ti._lshru
	ld	de, (ix + -3)
	ex	de, hl
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lor
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	ld	bc, (ix + -3)
	lea	bc, iy + 0
	ld	(ix + -3), de
	push	ix
	ld	de, -265
	add	ix, de
	ld	h, (ix + 0)
	pop	ix
	ld	a, h
	ld	l, 19
	call	ti._lshl
	ld	de, (ix + -3)
	push	bc
	pop	de
	ld	(ix + -3), de
	push	ix
	ld	de, -346
	add	ix, de
	ld	(ix + 0), a
	pop	ix
	lea	bc, iy + 0
	ld	a, h
	ld	l, 13
	call	ti._lshru
	ld	de, (ix + -3)
	ex	de, hl
	ld	(ix + -3), bc
	push	ix
	ld	bc, -346
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lor
	push	hl
	pop	bc
	ld	a, e
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lxor
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	(ix + 0), iy
	pop	ix
	ld	bc, (ix + -3)
	lea	bc, iy + 0
	ld	(ix + -3), de
	push	ix
	ld	de, -265
	add	ix, de
	ld	h, (ix + 0)
	pop	ix
	ld	a, h
	ld	l, 10
	call	ti._lshl
	ld	de, (ix + -3)
	push	bc
	pop	de
	ld	(ix + -3), de
	push	ix
	ld	de, -346
	add	ix, de
	ld	(ix + 0), a
	pop	ix
	lea	bc, iy + 0
	ld	a, h
	ld	l, 22
	call	ti._lshru
	ld	de, (ix + -3)
	ex	de, hl
	ld	(ix + -3), bc
	ld	bc, -346
	lea	iy, ix + 0
	add	iy, bc
	ld	e, (iy + 0)
	ld	bc, (ix + -3)
	call	ti._lor
	push	hl
	pop	bc
	ld	a, e
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lxor
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	push	ix
	ld	bc, -284
	add	ix, bc
	ld	iy, (ix + 0)
	pop	ix
	lea	hl, iy + 0
	push	ix
	add	ix, bc
	ld	(ix + 0), iy
	pop	ix
	push	ix
	ld	bc, -287
	add	ix, bc
	ld	d, (ix + 0)
	pop	ix
	ld	e, d
	push	ix
	add	ix, bc
	ld	(ix + 0), d
	pop	ix
	ld	bc, (ix + -3)
	ld	(ix + -3), de
	push	ix
	ld	de, -278
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -281
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._lxor
	push	hl
	pop	bc
	ld	a, e
	ld	(ix + -3), bc
	push	ix
	ld	bc, -272
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	ld	bc, -265
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._land
	ld	(ix + -3), bc
	push	ix
	ld	bc, -346
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	lea	hl, iy + 0
	ld	e, d
	ld	bc, (ix + -3)
	ld	(ix + -3), de
	ld	de, -278
	lea	iy, ix + 0
	add	iy, de
	ld	bc, (iy + 0)
	push	ix
	ld	de, -281
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._land
	push	hl
	pop	bc
	ld	a, e
	ld	(ix + -3), bc
	push	ix
	ld	bc, -346
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._lxor
	push	hl
	pop	bc
	ld	a, e
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	call	ti._ladd
	ld	(ix + -3), bc
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	push	ix
	ld	bc, -302
	add	ix, bc
	ld	iy, (ix + 0)
	pop	ix
	lea	hl, iy + 0
	push	ix
	dec	bc
	add	ix, bc
	ld	d, (ix + 0)
	pop	ix
	ld	e, d
	ld	bc, (ix + -3)
	ld	(ix + -3), de
	push	ix
	ld	de, -298
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	dec	de
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(ix + -3), bc
	push	ix
	ld	bc, -298
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	(ix + 0), e
	pop	ix
	push	ix
	ld	bc, -342
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	dec	bc
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	lea	bc, iy + 0
	ld	a, d
	call	ti._ladd
	ld	(ix + -3), bc
	ld	bc, -342
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), hl
	ld	d, e
	push	ix
	ld	bc, -333
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	ld	bc, -330
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	ld	bc, 1
	xor	a, a
	call	ti._ladd
	ld	(ix + -3), de
	push	ix
	ld	de, -290
	add	ix, de
	ld	iy, (ix + 0)
	pop	ix
	push	ix
	dec	de
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	push	ix
	ld	de, -295
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -302
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	push	ix
	ld	de, -292
	add	ix, de
	ld	c, (ix + 0)
	pop	ix
	push	ix
	ld	de, -303
	add	ix, de
	ld	(ix + 0), c
	pop	ix
	push	ix
	ld	de, -275
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -290
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	push	ix
	ld	de, -269
	add	ix, de
	ld	c, (ix + 0)
	pop	ix
	push	ix
	ld	de, -291
	add	ix, de
	ld	(ix + 0), c
	pop	ix
	push	ix
	ld	de, -298
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -275
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	push	ix
	ld	de, -299
	add	ix, de
	ld	c, (ix + 0)
	pop	ix
	push	ix
	ld	de, -269
	add	ix, de
	ld	(ix + 0), c
	pop	ix
	push	ix
	ld	de, -278
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -298
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	push	ix
	ld	de, -281
	add	ix, de
	ld	c, (ix + 0)
	pop	ix
	push	ix
	ld	de, -299
	add	ix, de
	ld	(ix + 0), c
	pop	ix
	push	ix
	ld	de, -284
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -278
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	push	ix
	ld	de, -287
	add	ix, de
	ld	c, (ix + 0)
	pop	ix
	push	ix
	ld	de, -281
	add	ix, de
	ld	(ix + 0), c
	pop	ix
	push	ix
	ld	de, -272
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -284
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	push	ix
	ld	de, -265
	add	ix, de
	ld	c, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	ld	(ix + -3), de
	push	ix
	ld	de, -287
	add	ix, de
	ld	(ix + 0), c
	pop	ix
	push	ix
	ld	de, -342
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -272
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	ld	de, (ix + -3)
	push	ix
	ld	bc, -265
	add	ix, bc
	ld	(ix + 0), d
	pop	ix
	ld	d, 0
	jq	BB9_7
BB9_9:
	ld	bc, -272
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	ld	bc, -265
	lea	iy, ix + 0
	add	iy, bc
	ld	e, (iy + 0)
	ld	(ix + -3), de
	push	ix
	ld	de, -329
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -326
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._ladd
	ld	iy, (ix + 6)
	ld	(iy + 76), hl
	ld	(iy + 79), e
	ld	(ix + -3), bc
	ld	bc, -284
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	ix
	ld	bc, -287
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	ld	(ix + -3), de
	push	ix
	ld	de, -325
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -322
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(iy + 80), hl
	ld	(iy + 83), e
	ld	(ix + -3), bc
	ld	bc, -278
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	ix
	ld	bc, -281
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	ld	(ix + -3), de
	push	ix
	ld	de, -321
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -318
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(iy + 84), hl
	ld	(iy + 87), e
	ld	(ix + -3), bc
	ld	bc, -298
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	ix
	dec	bc
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	ld	(ix + -3), de
	push	ix
	ld	de, -317
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -314
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(iy + 88), hl
	ld	(iy + 91), e
	ld	(ix + -3), bc
	ld	bc, -275
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	ix
	ld	bc, -269
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	ld	(ix + -3), de
	push	ix
	ld	de, -313
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -310
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(iy + 92), hl
	ld	(iy + 95), e
	ld	(ix + -3), bc
	ld	bc, -290
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	ix
	dec	bc
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	ld	(ix + -3), de
	push	ix
	ld	de, -309
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -339
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(iy + 96), hl
	ld	(iy + 99), e
	ld	(ix + -3), bc
	ld	bc, -295
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	ix
	ld	bc, -292
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	ld	(ix + -3), de
	push	ix
	ld	de, -306
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -338
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(iy + 100), hl
	ld	(iy + 103), e
	ld	(ix + -3), bc
	ld	bc, -302
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	ix
	dec	bc
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, (ix + -3)
	ld	(ix + -3), de
	push	ix
	ld	de, -337
	add	ix, de
	ld	bc, (ix + 0)
	pop	ix
	push	ix
	ld	de, -334
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	de, (ix + -3)
	call	ti._ladd
	ld	(iy + 104), hl
	ld	(iy + 107), e
	ld	sp, ix
	pop	ix
	ret
 
; ----------------------------------------
; void hashlib_Sha256Init(SHA256_CTX *ctx);
hashlib_Sha256Init:
	call	ti._frameset0
	ld	iy, (ix + 6)
	or	a, a
	sbc	hl, hl
	xor	a, a
	ld	(iy + 64), hl
	ld	(iy + 67), a
	pea	iy + 68
	call	_zero64
	pop	hl
	ld	iy, (ix + 6)
	ld	hl, 648807
	ld	(iy + 76), hl
	ld	a, 106
	ld	(iy + 79), a
	ld	hl, 6794885
	ld	(iy + 80), hl
	ld	a, -69
	ld	(iy + 83), a
	ld	hl, 7271282
	ld	(iy + 84), hl
	ld	a, 60
	ld	(iy + 87), a
	ld	hl, 5240122
	ld	(iy + 88), hl
	ld	a, -91
	ld	(iy + 91), a
	ld	hl, 938623
	ld	(iy + 92), hl
	ld	a, 81
	ld	(iy + 95), a
	ld	hl, 354444
	ld	(iy + 96), hl
	ld	a, -101
	ld	(iy + 99), a
	ld	hl, -8136277
	ld	(iy + 100), hl
	ld	a, 31
	ld	(iy + 103), a
	ld	hl, -2044647
	ld	(iy + 104), hl
	ld	a, 91
	ld	(iy + 107), a
	pop	ix
	ret

;----------------------------------
;void hashlib_Sha256Update(SHA256_CTX *ctx, const BYTE data[], uint32_t len);
hashlib_Sha256Update:
	ld	hl, -4
	call	ti._frameset
	ld	bc, (ix + 12)
	ld	a, (ix + 15)
	ld	l, 0
	ld	de, 0
	ex	de, hl
	ld	iyl, e
	ex	de, hl
BB11_1:
	ld	(ix + -3), de
	ex	de, hl
	ld	e, iyl
	call	ti._lcmpu
	jq	nc, BB11_5
	push	af
	ld	a, iyl
	ld	(ix + -4), a
	pop	af
	ld	hl, (ix + 9)
	ld	de, (ix + -3)
	add	hl, de
	ld	l, (hl)
	ld	de, (ix + 6)
	push	de
	pop	iy
	lea	bc, iy + 64
	ld	de, (iy + 64)
	ld	iy, (ix + 6)
	add	iy, de
	xor	a, a
	ld	(iy), l
	ld	iy, (ix + 6)
	ld	hl, (iy + 64)
	push	bc
	pop	iy
	lea	iy, iy + 3
	ld	e, (iy)
	ld	iy, (ix + 6)
	ld	bc, 1
	call	ti._ladd
	ld	(iy + 64), hl
	ld	(iy + 67), e
	ld	bc, 64
	call	ti._lcmpu
	jq	nz, BB11_4
	ld	hl, (ix + 6)
	push	hl
	push	hl
	call	_sha256_transform
	pop	hl
	pop	hl
	ld	hl, 512
	push	hl
	ld	iy, (ix + 6)
	pea	iy + 68
	call	_add64iu
	xor	a, a
	ld	iy, (ix + 6)
	pop	hl
	pop	hl
	or	a, a
	sbc	hl, hl
	ld	(iy + 64), hl
	ld	(iy + 67), a
BB11_4:
	ld	hl, (ix + -3)
	ld	e, (ix + -4)
	ld	bc, 1
	call	ti._ladd
	ld	iyl, e
	ex	de, hl
	ld	bc, (ix + 12)
	ld	a, (ix + 15)
	jq	BB11_1
BB11_5:
	ld	sp, ix
	pop	ix
	ret
	
;----------------------------------
;void hashlib_Sha256Final(SHA256_CTX *ctx, BYTE hash[]);
hashlib_Sha256Final:
	ld	hl, -10
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	bc, 56
	xor	a, a
	ld	hl, (iy + 64)
	ld	d, (iy + 67)
	ld	(ix + -3), hl
	ld	e, d
	call	ti._lcmpu
	jq	c, BB12_1
	ld	a, 0
	jq	BB12_3
BB12_1:
	ld	a, 1
BB12_3:
	ld	iy, (ix + 6)
	ld	bc, (ix + -3)
	add	iy, bc
	ld	(iy), -128
	bit	0, a
	jq	z, BB12_4
	xor	a, a
BB12_6:
	push	bc
	pop	hl
	ld	e, d
	push	bc
	pop	iy
	ld	bc, 1
	call	ti._ladd
	ld	(ix + -6), hl
	ld	(ix + -3), e
	lea	hl, iy + 0
	ld	e, d
	ld	bc, 55
	call	ti._lcmpu
	jq	nc, BB12_11
	ld	iy, (ix + 6)
	ld	bc, (ix + -6)
	add	iy, bc
	ld	(iy), 0
	ld	d, (ix + -3)
	jq	BB12_6
BB12_4:
	ld	iy, 64
	xor	a, a
BB12_8:
	push	bc
	pop	hl
	ld	e, d
	ld	bc, 1
	call	ti._ladd
	ld	d, e
	ld	(ix + -3), hl
	lea	bc, iy + 0
	call	ti._lcmpu
	jq	nc, BB12_10
	lea	hl, iy + 0
	ld	iy, (ix + 6)
	ld	bc, (ix + -3)
	add	iy, bc
	ld	(iy), 0
	push	hl
	pop	iy
	jq	BB12_8
BB12_10:
	ld	hl, (ix + 6)
	push	hl
	push	hl
	call	_sha256_transform
	pop	hl
	pop	hl
	ld	hl, 56
	push	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
BB12_11:
	ld	hl, 68
	ld	(ix + -6), hl
	ld	hl, 63
	ld	(ix + -3), hl
	ld	iy, (ix + 6)
	ld	hl, (iy + 64)
	ld	c, 3
	call	ti._ishl
	push	hl
	pea	iy + 68
	call	_add64iu
	pop	hl
	pop	hl
	ld	de, 55
BB12_12:
	ld	hl, (ix + -3)
	or	a, a
	sbc	hl, de
	jq	z, BB12_14
	ld	hl, (ix + 6)
	push	hl
	pop	iy
	ld	bc, (ix + -6)
	add	iy, bc
	ld	a, (iy)
	push	hl
	pop	iy
	ex	de, hl
	ld	de, (ix + -3)
	add	iy, de
	ld	(iy), a
	dec	de
	ld	(ix + -3), de
	ex	de, hl
	inc	bc
	ld	(ix + -6), bc
	jq	BB12_12
BB12_14:
	ld	hl, (ix + 6)
	push	hl
	push	hl
	call	_sha256_transform
	pop	hl
	pop	hl
	xor	a, a
	ld	e, a
	ld	iy, 0
BB12_15:
	lea	hl, iy + 0
	ld	bc, 4
	call	ti._lcmpu
	jq	nc, BB12_17
	lea	hl, iy + 0
	ld	iy, (ix + 6)
	ld	bc, (iy + 76)
	ld	(ix + -10), bc
	ld	(ix + -7), e
	ld	iy, (ix + 6)
	ld	d, (iy + 79)
	push	hl
	pop	iy
	ld	bc, -8
	ld	a, -1
	call	ti._lmulu
	ld	bc, 24
	xor	a, a
	call	ti._ladd
	ld	(ix + -3), hl
	ld	bc, (ix + -10)
	ld	a, d
	call	ti._lshru
	ld	a, c
	lea	de, iy + 0
	ld	(ix + -6), de
	push	de
	pop	hl
	ld	bc, (ix + 9)
	push	bc
	pop	iy
	push	hl
	pop	bc
	add	iy, bc
	ld	(iy), a
	ld	iy, (ix + 6)
	ld	bc, (iy + 80)
	ld	a, (iy + 83)
	ld	hl, (ix + -3)
	call	ti._lshru
	ld	a, c
	push	de
	pop	iy
	ld	de, 4
	add	iy, de
	lea	de, iy + 0
	ld	iy, (ix + 9)
	add	iy, de
	ld	(iy), a
	ld	iy, (ix + 6)
	ld	bc, (iy + 84)
	ld	a, (iy + 87)
	ld	hl, (ix + -3)
	call	ti._lshru
	ld	a, c
	ld	iy, (ix + -6)
	ld	de, 8
	add	iy, de
	lea	de, iy + 0
	ld	iy, (ix + 9)
	add	iy, de
	ld	(iy), a
	ld	iy, (ix + 6)
	ld	bc, (iy + 88)
	ld	a, (iy + 91)
	ld	hl, (ix + -3)
	call	ti._lshru
	ld	a, c
	ld	iy, (ix + -6)
	ld	de, 12
	add	iy, de
	lea	de, iy + 0
	ld	iy, (ix + 9)
	add	iy, de
	ld	(iy), a
	ld	iy, (ix + 6)
	ld	bc, (iy + 92)
	ld	a, (iy + 95)
	ld	hl, (ix + -3)
	call	ti._lshru
	ld	a, c
	ld	iy, (ix + -6)
	ld	de, 16
	add	iy, de
	lea	de, iy + 0
	ld	iy, (ix + 9)
	add	iy, de
	ld	(iy), a
	ld	iy, (ix + 6)
	ld	bc, (iy + 96)
	ld	a, (iy + 99)
	ld	hl, (ix + -3)
	call	ti._lshru
	ld	a, c
	ld	iy, (ix + -6)
	ld	de, 20
	add	iy, de
	lea	de, iy + 0
	ld	bc, (ix + 9)
	push	bc
	pop	iy
	add	iy, de
	ld	(iy), a
	ld	iy, (ix + 6)
	ld	bc, (iy + 100)
	ld	a, (iy + 103)
	ld	hl, (ix + -3)
	call	ti._lshru
	ld	a, c
	ld	iy, (ix + -6)
	ld	de, 24
	add	iy, de
	lea	de, iy + 0
	ld	iy, (ix + 9)
	add	iy, de
	ld	(iy), a
	ld	iy, (ix + 6)
	ld	bc, (iy + 104)
	ld	a, (iy + 107)
	ld	hl, (ix + -3)
	call	ti._lshru
	ld	hl, (ix + -6)
	push	hl
	pop	iy
	ld	de, 28
	add	iy, de
	lea	de, iy + 0
	ld	iy, (ix + 9)
	add	iy, de
	xor	a, a
	ld	(iy), c
	ld	e, (ix + -7)
	ld	bc, 1
	call	ti._ladd
	push	hl
	pop	iy
	jq	BB12_15
BB12_17:
	ld	sp, ix
	pop	ix
	ret

    
hashlib_b64decode:
	ld	hl, -9
	call	ti._frameset
	ld	bc, (ix + 6)
	ld	hl, (ix + 12)
	ld	(ix + -3), hl
	ld	iy, -1
	push	bc
	pop	de
	push	bc
	pop	hl
	ld	bc, (ix + 9)
	add	hl, bc
	push	hl
	pop	bc
BB19_1:
	push	de
	pop	hl
	or	a, a
	sbc	hl, bc
	jq	nc, BB19_21
	ld	hl, (ix + -3)
	ld	a, (hl)
	cp	a, 0
	call	ti._setflag
	jq	m, BB19_24
	ld	(ix + -6), bc
	ld	bc, 0
	ld	c, a
	ld	hl, _index_64
	add	hl, bc
	ld	l, (hl)
	ld	a, l
	cp	a, -1
	jq	z, BB19_24
	ld	iy, (ix + -3)
	ld	a, (iy + 1)
	cp	a, 0
	call	ti._setflag
	jq	m, BB19_23
	ld	(ix + -9), de
	ld	bc, 0
	ld	c, a
	ld	iy, _index_64
	add	iy, bc
	ld	e, (iy)
	ld	a, e
	cp	a, -1
	jq	z, BB19_23
	ld	a, l
	ld	b, 2
	call	ti._bshl
	ld	l, a
	ld	a, e
	ld	b, 4
	call	ti._bshru
	and	a, 3
	add	a, l
	ld	iy, (ix + -9)
	ld	(iy), a
	inc	iy
	lea	hl, iy + 0
	ld	bc, (ix + -6)
	or	a, a
	sbc	hl, bc
	jq	nc, BB19_21
	ld	iy, (ix + -3)
	ld	a, (iy + 2)
	cp	a, 0
	call	ti._setflag
	jq	m, BB19_23
	or	a, a
	sbc	hl, hl
	push	hl
	pop	bc
	ld	c, a
	ld	hl, _index_64
	add	hl, bc
	ld	c, (hl)
	ld	a, c
	cp	a, -1
	ld	iy, -1
	jq	z, BB19_24
	ld	a, e
	ld	b, 4
	call	ti._bshl
	ld	l, a
	ld	a, c
	ld	b, 2
	call	ti._bshru
	and	a, 15
	add	a, l
	ld	iy, (ix + -9)
	ld	(iy + 1), a
	lea	hl, iy + 2
	ld	de, (ix + -6)
	or	a, a
	sbc	hl, de
	jq	nc, BB19_21
	ld	iy, (ix + -3)
	ld	a, (iy + 3)
	cp	a, 0
	call	ti._setflag
	jq	m, BB19_23
	or	a, a
	sbc	hl, hl
	ex	de, hl
	ld	e, a
	ld	hl, _index_64
	add	hl, de
	ld	l, (hl)
	ld	a, l
	cp	a, -1
	jq	z, BB19_23
	ld	a, c
	ld	b, 6
	call	ti._bshl
	ld	c, a
	ld	a, l
	or	a, c
	ld	bc, (ix + -6)
	ld	iy, (ix + -9)
	ld	(iy + 2), a
	lea	iy, iy + 3
	lea	de, iy + 0
	ld	iy, (ix + -3)
	lea	iy, iy + 4
	ld	(ix + -3), iy
	ld	iy, -1
	jq	BB19_1
BB19_21:
	ld	iy, 0
BB19_24:
	lea	hl, iy + 0
	ld	sp, ix
	pop	ix
	ret
BB19_23:
	ld	iy, -1
	jq	BB19_24


hashlib_b64encode:
	ld	hl, -10
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	hl, (ix + 9)
	ld	de, (ix + 12)
	ld	a, 2
	ld	bc, 0
	ld	(ix + -3), hl
	add	hl, de
	ex	de, hl
BB20_1:
	ld	hl, (ix + -3)
	or	a, a
	sbc	hl, de
	jq	nc, BB20_10
	ld	hl, (ix + -3)
	ld	b, a
	ld	a, (hl)
	ld	(ix + -10), a
	ld	(ix + -9), de
	call	ti._bshru
	ld	bc, 0
	ld	c, a
	lea	hl, iy + 0
	ld	iy, _Base64Code
	add	iy, bc
	ld	a, (iy)
	ld	(ix + -6), hl
	ld	(hl), a
	ld	a, (ix + -10)
	ld	b, 4
	call	ti._bshl
	and	a, 48
	ld	iy, (ix + -3)
	inc	iy
	lea	hl, iy + 0
	ld	de, (ix + -9)
	or	a, a
	sbc	hl, de
	jq	nc, BB20_6
	ld	iy, (ix + -3)
	ld	e, (iy + 1)
	ld	l, a
	ld	a, e
	call	ti._bshru
	add	a, l
	ld	bc, 0
	ld	c, a
	ld	hl, _Base64Code
	add	hl, bc
	ld	a, (hl)
	ld	iy, (ix + -6)
	ld	(iy + 1), a
	ld	a, e
	ld	b, 2
	call	ti._bshl
	and	a, 60
	ld	iy, (ix + -3)
	lea	hl, iy + 2
	ld	bc, (ix + -9)
	or	a, a
	sbc	hl, bc
	jq	nc, BB20_7
	ld	iy, (ix + -3)
	ld	c, (iy + 2)
	ld	l, a
	ld	a, c
	ld	b, 6
	call	ti._bshru
	add	a, l
	ld	de, 0
	ld	e, a
	ld	hl, _Base64Code
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + -6)
	ld	(iy + 2), a
	ld	a, c
	and	a, 63
	ld	de, 0
	ld	e, a
	ld	hl, _Base64Code
	add	hl, de
	ld	a, (hl)
	lea	hl, iy + 4
	ld	(iy + 3), a
	ld	iy, (ix + -3)
	lea	iy, iy + 3
	ld	(ix + -3), iy
	push	hl
	pop	iy
	ld	bc, 0
	ld	a, 2
	ld	de, (ix + -9)
	jq	BB20_1
BB20_6:
	ld	hl, (ix + -6)
	inc	hl
	ld	(ix + -3), hl
	ld	hl, 2
	jq	BB20_8
BB20_7:
	ld	iy, (ix + -6)
	lea	hl, iy + 2
	ld	(ix + -3), hl
	ld	hl, 3
BB20_8:
	ld	(ix + -9), hl
	ld	bc, 0
	ld	c, a
	ld	hl, _Base64Code
	add	hl, bc
	ld	a, (hl)
	ld	iy, (ix + -6)
	ld	de, (ix + -9)
	add	iy, de
	ld	hl, (ix + -3)
	ld	(hl), a
	ld	bc, 0
BB20_10:
	ld	(iy), 0
	push	bc
	pop	hl
	ld	sp, ix
	pop	ix
	ret
 
 
 ; hashlib_EraseContext(void* ptr, size_t len);
 ; throw this in at the end of cryptofunctions to wipe the context when you are done with them
 ; input hl = (void*) PTR
 ; input de = len to zero
 hashlib_EraseContext:
    pop de,hl,bc
    push bc
.eraseloop:
    ld (hl),0
    inc hl
    dec bc
    ld a,b
    or a,c
    jq nz,.eraseloop
    ex hl,de
    jp (hl)
    
    
_xor_buf:
	ld	hl, -3
	call	ti._frameset
	ld	de, (ix + 6)
	ld	iy, (ix + 9)
	ld	bc, (ix + 12)
BB50_1:
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB50_3
	ld	a, (iy)
	ld	(ix + -3), iy
	ex	de, hl
	xor	a, (hl)
	ld	iy, (ix + -3)
	ld	(iy), a
	dec	bc
	inc	hl
	ex	de, hl
	ld	iy, (ix + -3)
	inc	iy
	jq	BB50_1
BB50_3:
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
	
hashlib_AESLoadKey:
	ld	hl, -25
	call	ti._frameset
	ld	de, (ix + 12)
	xor	a, a
	ld	(ix + -19), a
	ld	bc, 128
	push	de
	pop	hl
	or	a, a
	sbc	hl, bc
	jq	nz, BB22_2
	ld	bc, 4
	ld	hl, 44
	ld	(ix + -9), hl
	jq	BB22_6
BB22_2:
	ld	bc, 192
	push	de
	pop	hl
	or	a, a
	sbc	hl, bc
	jq	nz, BB22_4
	ld	hl, 52
	ld	(ix + -9), hl
	ld	bc, 6
	jq	BB22_6
BB22_4:
	ld	bc, 256
	push	de
	pop	hl
	or	a, a
	sbc	hl, bc
	jq	nz, BB22_19
	ld	bc, 8
	ld	hl, 60
	ld	(ix + -9), hl
	ld	a, 1
	ld	(ix + -19), a
BB22_6:
	ld	iy, (ix + 9)
	ld	(iy), de
	ld	(ix + -3), iy
	lea	hl, iy + 3
	ld	(ix + -12), hl
	ld	iy, (ix + 6)
	lea	iy, iy + 3
	push	bc
	pop	de
	ld	(ix + -6), bc
BB22_7:
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB22_9
	ld	a, (iy + -3)
	ld	bc, 0
	ld	c, a
	ld	h, 0
	ld	a, h
	ld	l, 24
	call	ti._lshl
	ld	(ix + -18), bc
	ld	(ix + -15), de
	ld	d, a
	ld	a, (iy + -2)
	ld	bc, 0
	ld	c, a
	ld	a, h
	ld	l, 16
	call	ti._lshl
	push	bc
	pop	hl
	ld	e, a
	ld	bc, (ix + -18)
	ld	a, d
	call	ti._ladd
	ld	(ix + -18), hl
	ld	a, (iy + -1)
	ld	bc, 0
	ld	c, a
	xor	a, a
	ld	l, 8
	call	ti._lshl
	ld	hl, (ix + -18)
	call	ti._ladd
	ld	a, (iy)
	ld	bc, 0
	ld	c, a
	xor	a, a
	call	ti._ladd
	lea	bc, iy + 0
	ld	iy, (ix + -12)
	ld	(iy), hl
	ld	(iy + 3), e
	ld	de, (ix + -15)
	dec	de
	lea	iy, iy + 4
	ld	(ix + -12), iy
	push	bc
	pop	iy
	lea	iy, iy + 4
	jq	BB22_7
BB22_9:
	ld	c, 2
	ld	hl, (ix + -6)
	call	ti._ishl
	ld	bc, (ix + -6)
	dec	hl
	ld	(ix + -15), hl
	push	bc
	pop	de
	ld	hl, (ix + -9)
BB22_10:
	or	a, a
	sbc	hl, de
	jq	z, BB22_19
	ld	iy, (ix + -3)
	ex	de, hl
	ld	de, (ix + -15)
	add	iy, de
	ld	de, (iy)
	ld	a, (iy + 3)
	ld	(ix + -12), hl
	call	ti._iremu
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	(ix + -18), iy
	jq	nz, BB22_13
	ld	hl, (ix + -12)
	dec	hl
	ld	(ix + -22), hl
	push	de
	pop	bc
	ld	h, a
	ld	l, 8
	call	ti._lshl
	ld	(ix + -25), bc
	ld	iyl, a
	push	de
	pop	bc
	ld	a, h
	ld	l, 24
	call	ti._lshru
	ld	hl, (ix + -25)
	ld	e, iyl
	call	ti._lor
	push	de
	push	hl
	call	_aes_SubWord
	ld	(ix + -25), hl
	ld	a, e
	pop	hl
	pop	hl
	ld	hl, (ix + -22)
	ld	bc, (ix + -6)
	call	ti._idivu
	ld	c, 2
	call	ti._ishl
	push	hl
	pop	de
	ld	iy, L___const.hashlib_AESLoadKey.Rcon
	add	iy, de
	ld	hl, (iy)
	ld	e, (iy + 3)
	ld	bc, (ix + -25)
	call	ti._lxor
	push	hl
	pop	bc
	ld	a, e
	jq	BB22_18
BB22_13:
	ld	(ix + -25), a
	ld	(ix + -22), de
	ld	a, (ix + -19)
	ld	e, 1
	xor	a, e
	bit	0, a
	jq	nz, BB22_17
	ld	bc, 4
	or	a, a
	sbc	hl, bc
	jq	nz, BB22_17
	ld	a, (ix + -25)
	ld	l, a
	push	hl
	ld	hl, (ix + -22)
	push	hl
	call	_aes_SubWord
	push	hl
	pop	bc
	ld	a, e
	pop	hl
	pop	hl
	jq	BB22_18
BB22_17:
	ld	bc, (ix + -22)
	ld	a, (ix + -25)
BB22_18:
	ld	iy, (ix + -3)
	ld	hl, (iy + 3)
	ld	e, (iy + 6)
	call	ti._lxor
	ld	bc, (ix + -18)
	push	bc
	pop	iy
	ld	(iy + 4), hl
	ld	(iy + 7), e
	ld	de, (ix + -12)
	inc	de
	ld	iy, (ix + -3)
	lea	iy, iy + 4
	ld	(ix + -3), iy
	ld	bc, (ix + -6)
	ld	hl, (ix + -9)
	jq	BB22_10
BB22_19:
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
	
_aes_encrypt_block:
	ld	hl, -19
	call	ti._frameset
	ld	iy, (ix + 6)
	lea	hl, ix + -16
	ld	(ix + -19), hl
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
	ld	de, (ix + 12)
	push	de
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
	pea	iy + 16
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
	pea	iy + 32
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
	pea	iy + 48
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
	pea	iy + 64
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
	pea	iy + 80
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
	pea	iy + 96
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
	pea	iy + 112
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
	ld	de, 128
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
	ld	de, 144
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
	ld	hl, (ix + 15)
	or	a, a
	sbc	hl, de
	jq	nz, BB30_2
	ld	hl, 40
	jq	BB30_5
BB30_2:
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 160
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
	ld	de, 176
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
	ld	hl, (ix + 15)
	or	a, a
	sbc	hl, de
	jq	nz, BB30_4
	ld	hl, 48
	jq	BB30_5
BB30_4:
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 192
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
	ld	de, 208
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
	ld	hl, 56
	ld	(ix + -3), a
BB30_5:
	ld	c, 2
	call	ti._ishl
	push	hl
	pop	de
	ld	hl, (ix + 12)
	add	hl, de
	push	hl
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
	ret
	
_aes_decrypt_block:
	ld	hl, -19
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	hl, (ix + 15)
	lea	de, ix + -16
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
	push	hl
	pop	iy
	ld	(ix + -1), a
	ld	bc, 129
	or	a, a
	sbc	hl, bc
	call	ti._setflag
	ld	(ix + -19), de
	jq	m, BB31_3
	ld	bc, 193
	lea	hl, iy + 0
	or	a, a
	sbc	hl, bc
	call	ti._setflag
	ld	hl, (ix + 12)
	jq	m, BB31_4
	ld	bc, 224
	push	hl
	pop	iy
	add	iy, bc
	push	iy
	push	de
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
	ld	de, 208
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
	ld	de, 192
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
	jq	BB31_5
BB31_3:
	ex	de, hl
	ld	de, 160
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	jq	BB31_7
BB31_4:
	ld	bc, 192
	push	hl
	pop	iy
	add	iy, bc
	push	iy
	push	de
	call	_aes_AddRoundKey
	pop	hl
BB31_5:
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
	ld	de, 176
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
	ld	de, 160
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
BB31_7:
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
	ld	de, 144
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
	ld	de, 128
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
	pea	iy + 112
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
	pea	iy + 96
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
	pea	iy + 80
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
	pea	iy + 64
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
	pea	iy + 48
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
	pea	iy + 32
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
	pea	iy + 16
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
	ld	hl, (ix + 12)
	push	hl
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
	ret
	
hashlib_AESEncrypt:
    ld	hl, -69
	call	ti._frameset
	ld	de, (ix + 9)
	ld	bc, 0
	ld	a, e
	and	a, 15
	or	a, a
	jq	nz, BB32_8
	ld	hl, (ix + 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB32_9
	ld	iy, (ix + 12)
	lea	hl, iy + 0
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB32_10
	ld	hl, (ix + 15)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB32_7
	ld	(ix + -51), iy
	lea	bc, ix + -16
	ld	(ix + -54), bc
	lea	bc, ix + -32
	ld	(ix + -57), bc
	lea	iy, ix + -48
	ld	hl, (hl)
	ld	(ix + -69), hl
	ld	c, 4
	ex	de, hl
	call	ti._ishru
	ld	(ix + -60), hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + 18)
	push	hl
	ld	(ix + -63), iy
	push	iy
	call	ti._memcpy
	ld	de, (ix + -60)
	ld	iy, (ix + 6)
	pop	hl
	pop	hl
	pop	hl
BB32_5:
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB32_11
	ld	hl, 16
	push	hl
	push	iy
	ld	hl, (ix + -54)
	push	hl
	ld	(ix + -66), iy
	ld	(ix + -60), de
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -54)
	push	hl
	ld	hl, (ix + -63)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + -69)
	push	hl
	ld	iy, (ix + 15)
	pea	iy + 3
	ld	hl, (ix + -57)
	push	hl
	ld	hl, (ix + -54)
	push	hl
	call	_aes_encrypt_block
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -57)
	push	hl
	ld	hl, (ix + -51)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -57)
	push	hl
	ld	hl, (ix + -63)
	push	hl
	call	ti._memcpy
	ld	de, (ix + -60)
	ld	iy, (ix + -66)
	pop	hl
	pop	hl
	pop	hl
	dec	de
	lea	iy, iy + 16
	lea	hl, iy + 0
	ld	iy, (ix + -51)
	lea	iy, iy + 16
	ld	(ix + -51), iy
	push	hl
	pop	iy
	jq	BB32_5
BB32_8:
	jq	BB32_7
BB32_9:
	jq	BB32_7
BB32_10:
	jq	BB32_7
BB32_11:
	ld	bc, 1
BB32_7:
	push	bc
	pop	hl
	ld	sp, ix
	pop	ix
	ret
	
hashlib_AESDecrypt:
	ld	hl, -69
	call	ti._frameset
	ld	bc, (ix + 9)
	ld	de, 0
	ld	a, c
	and	a, 15
	or	a, a
	jq	nz, BB27_9
	ld	hl, (ix + 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB27_10
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB27_11
	ld	hl, (ix + 15)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB27_8
	lea	de, ix + -16
	ld	(ix + -51), de
	lea	de, ix + -32
	ld	(ix + -54), de
	lea	de, ix + -48
	ld	hl, (hl)
	ld	(ix + -69), hl
	push	bc
	pop	hl
	ld	c, 4
	call	ti._ishru
	ld	(ix + -57), hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + 18)
	push	hl
	ld	(ix + -63), de
	push	de
	call	ti._memcpy
	ld	de, (ix + -57)
	ld	iy, (ix + 6)
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 12)
	ld	(ix + -60), hl
BB27_5:
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB27_7
	ld	hl, 16
	push	hl
	push	iy
	ld	hl, (ix + -51)
	push	hl
	ld	(ix + -66), iy
	ld	(ix + -57), de
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + -69)
	push	hl
	ld	iy, (ix + 15)
	pea	iy + 3
	ld	hl, (ix + -54)
	push	hl
	ld	hl, (ix + -51)
	push	hl
	call	_aes_decrypt_block
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -54)
	push	hl
	ld	hl, (ix + -63)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -54)
	push	hl
	ld	hl, (ix + -60)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -51)
	push	hl
	ld	hl, (ix + -63)
	push	hl
	call	ti._memcpy
	ld	de, (ix + -57)
	ld	iy, (ix + -66)
	pop	hl
	pop	hl
	pop	hl
	dec	de
	lea	iy, iy + 16
	lea	hl, iy + 0
	ld	iy, (ix + -60)
	lea	iy, iy + 16
	ld	(ix + -60), iy
	push	hl
	pop	iy
	jq	BB27_5
BB27_9:
	jq	BB27_8
BB27_10:
	jq	BB27_8
BB27_11:
	jq	BB27_8
BB27_7:
	ld	bc, (ix + 9)
	ld	hl, (ix + 12)
	add	hl, bc
	ld	a, (hl)
	ld	de, 0
	ld	e, a
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	push	hl
	pop	de
BB27_8:
	ex	de, hl
	ld	sp, ix
	pop	ix
	ret
 
hashlib_PadMessage:
	ld	hl, -171
	call	ti._frameset
	ld	iy, (ix + 9)
	ld	bc, 0
	lea	hl, iy + 0
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB28_21
	ld	hl, (ix + 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB28_21
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, BB28_6
BB28_21:
	push	bc
	pop	hl
	ld	sp, ix
	pop	ix
	ret
BB28_6:
	ld	e, (ix + 15)
	ld	a, e
	or	a, a
	jq	nz, BB28_9
	ld	de, 16
	add	iy, de
	ld	de, 257
	lea	hl, iy + 0
	or	a, a
	sbc	hl, de
	jq	nc, BB28_21
	ld	hl, 256
	lea	de, ix + -114
	ld	bc, -165
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), de
	push	ix
	ld	bc, -130
	add	ix, bc
	lea	de, ix + 0
	pop	ix
	push	ix
	ld	bc, -171
	add	ix, bc
	ld	(ix + 0), de
	pop	ix
	push	ix
	ld	bc, -162
	add	ix, bc
	lea	de, ix + 0
	pop	ix
	push	ix
	ld	bc, -168
	add	ix, bc
	ld	(ix + 0), de
	pop	ix
	push	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, (ix + 12)
	push	hl
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix + 12)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	bc, -171
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_RandomBytes
	pop	hl
	pop	hl
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Init
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, 16
	push	hl
	ld	bc, -171
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -168
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	ld	de, 0
	pop	hl
	pop	hl
BB28_13:
	push	de
	pop	hl
	ld	bc, 240
	or	a, a
	sbc	hl, bc
	jq	z, BB28_16
	push	de
	pop	hl
	ld	bc, 31
	call	ti._iand
	push	hl
	pop	bc
	ld	(ix + -3), de
	ld	de, -168
	lea	iy, ix + 0
	add	iy, de
	ld	iy, (iy + 0)
	add	iy, bc
	ld	hl, (ix + 12)
	ld	de, (ix + -3)
	add	hl, de
	ld	a, (hl)
	xor	a, (iy)
	ld	(hl), a
	inc	de
	jq	BB28_13
BB28_9:
	ld	a, e
	cp	a, 1
	jq	nz, BB28_21
	ld	l, (ix + 18)
	ld	a, l
	or	a, a
	jq	nz, BB28_23
	ld	l, 1
BB28_23:
	ld	a, l
	cp	a, 5
	jq	nc, BB28_21
	push	ix
	ld	de, -168
	add	ix, de
	ld	(ix + 0), l
	pop	ix
	ld	bc, -16
	ld	a, iyl
	and	a, 15
	ld	de, 16
	add	iy, de
	lea	hl, iy + 0
	call	ti._iand
	or	a, a
	jq	z, BB28_26
	push	hl
	pop	iy
BB28_26:
	ld	bc, -168
	lea	hl, ix + 0
	add	hl, bc
	ld	a, (hl)
	cp	a, 1
	push	ix
	ld	bc, -165
	push	af
	add	ix, bc
	pop	af
	ld	(ix + 0), iy
	pop	ix
	jq	nz, BB28_28
	ld	hl, (ix + 9)
	ex	de, hl
	lea	hl, iy + 0
	ld	bc, (ix + 12)
	push	bc
	pop	iy
	add	iy, de
	or	a, a
	sbc	hl, de
	push	hl
	push	hl
	push	iy
	call	ti._memset
	ld	bc, (ix + 9)
	ld	de, (ix + 12)
	pop	hl
	jq	BB28_32
BB28_16:
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Init
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, 240
	push	hl
	ld	hl, (ix + 12)
	push	hl
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -168
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	ld	iy, (ix + 12)
	pop	hl
	pop	hl
	ld	de, 240
	add	iy, de
	ld	de, 16
	ld	bc, 0
BB28_17:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jq	z, BB28_19
	lea	de, iy + 0
	ld	(ix + -3), de
	ld	de, -171
	lea	hl, ix + 0
	add	hl, de
	ld	iy, (hl)
	add	iy, bc
	push	ix
	ld	de, -168
	add	ix, de
	ld	hl, (ix + 0)
	pop	ix
	add	hl, bc
	ld	a, (hl)
	xor	a, (iy)
	ld	de, (ix + -3)
	push	de
	pop	iy
	ld	de, 16
	lea	hl, iy + 0
	add	hl, bc
	ld	(hl), a
	inc	bc
	jq	BB28_17
BB28_19:
	ld	bc, 256
	jq	BB28_21
BB28_28:
	cp	a, 2
	jq	nz, BB28_30
	ld	hl, (ix + 9)
	ex	de, hl
	ld	hl, (ix + 12)
	add	hl, de
	push	ix
	ld	bc, -168
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	lea	hl, iy + 0
	or	a, a
	sbc	hl, de
	push	hl
	or	a, a
	sbc	hl, hl
	push	hl
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	ti._memset
	ld	bc, (ix + 9)
	ld	de, (ix + 12)
	pop	hl
	pop	hl
	pop	hl
	ld	(ix + -3), bc
	ld	bc, -168
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	set	7, (hl)
	ld	bc, (ix + -3)
	jq	BB28_33
BB28_30:
	cp	a, 4
	ld	de, (ix + 12)
	ld	bc, (ix + 9)
	jq	nz, BB28_33
	push	bc
	pop	de
	ld	iy, (ix + 12)
	add	iy, de
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	or	a, a
	sbc	hl, de
	push	hl
	push	iy
	call	hashlib_RandomBytes
	ld	bc, (ix + 9)
	ld	de, (ix + 12)
BB28_32:
	pop	hl
	pop	hl
BB28_33:
	push	bc
	ld	hl, (ix + 6)
	push	hl
	push	de
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	de, -165
	lea	hl, ix + 0
	add	hl, de
	ld	bc, (hl)
	jq	BB28_21
 
 hashlib_AESOutputMAC:
	ld	hl, -66
	call	ti._frameset
	ld	de, (ix + 9)
	ld	bc, 0
	ld	a, e
	and	a, 15
	or	a, a
	jq	nz, BB29_9
	ld	hl, (ix + 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB29_10
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB29_11
	ld	hl, (ix + 15)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB29_8
	lea	bc, ix + -16
	ld	(ix + -54), bc
	lea	bc, ix + -32
	ld	(ix + -51), bc
	lea	iy, ix + -48
	ld	hl, (hl)
	ld	(ix + -66), hl
	ld	c, 4
	ex	de, hl
	call	ti._ishru
	ld	(ix + -57), hl
	ld	hl, 16
	push	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	(ix + -60), iy
	push	iy
	call	ti._memset
	ld	de, (ix + -57)
	ld	iy, (ix + 6)
	pop	hl
	pop	hl
	pop	hl
BB29_5:
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB29_7
	ld	hl, 16
	push	hl
	push	iy
	ld	hl, (ix + -54)
	push	hl
	ld	(ix + -63), iy
	ld	(ix + -57), de
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -54)
	push	hl
	ld	hl, (ix + -60)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + -66)
	push	hl
	ld	iy, (ix + 15)
	pea	iy + 3
	ld	hl, (ix + -51)
	push	hl
	ld	hl, (ix + -54)
	push	hl
	call	_aes_encrypt_block
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -51)
	push	hl
	ld	hl, (ix + -60)
	push	hl
	call	ti._memcpy
	ld	de, (ix + -57)
	ld	iy, (ix + -63)
	pop	hl
	pop	hl
	pop	hl
	dec	de
	lea	iy, iy + 16
	jq	BB29_5
BB29_9:
	jq	BB29_8
BB29_10:
	jq	BB29_8
BB29_11:
	jq	BB29_8
BB29_7:
	ld	hl, 16
	push	hl
	ld	hl, (ix + -51)
	push	hl
	ld	hl, (ix + 12)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	bc, 1
BB29_8:
	push	bc
	pop	hl
	ld	sp, ix
	pop	ix
	ret
 
hashlib_StripPadding:
	ld	hl, -174
	call	ti._frameset
	ld	bc, (ix + 9)
	ld	de, 0
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB30_31
	ld	hl, (ix + 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB30_31
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, BB30_31
	push	bc
	ld	de, 0
	push	de
	push	hl
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	ld	l, (ix + 15)
	ld	a, l
	or	a, a
	jq	nz, BB30_10
	lea	hl, ix + -114
	ld	bc, -165
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), hl
	ld	bc, -130
	lea	hl, ix + 0
	add	hl, bc
	push	hl
	pop	de
	ld	bc, -162
	lea	hl, ix + 0
	add	hl, bc
	push	ix
	ld	bc, -168
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	iy, (ix + 9)
	lea	hl, iy + 0
	ld	bc, -16
	add	hl, bc
	push	ix
	ld	bc, -174
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	bc, -17
	add	iy, bc
	lea	bc, iy + 0
	ld	hl, (ix + 6)
	add	hl, bc
	ld	bc, 16
	push	bc
	push	hl
	ld	bc, -171
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), de
	push	de
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Init
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	bc, -174
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -168
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	pop	hl
	pop	hl
	ld	de, 16
	ld	bc, 0
BB30_8:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jq	z, BB30_13
	ld	(ix + -3), de
	ld	de, -171
	lea	hl, ix + 0
	add	hl, de
	ld	iy, (hl)
	add	iy, bc
	push	ix
	ld	de, -168
	add	ix, de
	ld	hl, (ix + 0)
	pop	ix
	add	hl, bc
	ld	a, (hl)
	xor	a, (iy)
	ld	(iy), a
	inc	bc
	ld	de, (ix + -3)
	jq	BB30_8
BB30_10:
	ld	bc, (ix + 9)
	ld	a, l
	cp	a, 1
	jq	nz, BB30_19
	ld	l, (ix + 18)
	ld	a, l
	or	a, a
	jq	nz, BB30_21
	ld	l, 1
BB30_21:
	ld	de, 0
	ld	iy, (ix + 6)
	ld	a, l
	cp	a, 5
	jq	nc, BB30_31
	ld	a, l
	cp	a, 1
	jq	nz, BB30_25
	push	bc
	pop	de
	dec	de
	lea	hl, iy + 0
	add	hl, de
	ld	de, 0
	ld	e, (hl)
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	push	hl
	pop	bc
	jq	BB30_30
BB30_13:
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Init
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, 16
	push	hl
	ld	bc, -171
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -168
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	pop	hl
	pop	hl
	ld	bc, 0
	ld	iy, (ix + 12)
BB30_14:
	push	bc
	pop	hl
	ld	de, 240
	or	a, a
	sbc	hl, de
	jq	z, BB30_16
	ld	hl, (ix + 6)
	add	hl, bc
	ld	a, (hl)
	ld	iyl, a
	push	bc
	pop	hl
	push	bc
	pop	de
	ld	bc, 31
	call	ti._iand
	push	hl
	pop	bc
	ld	(ix + -3), de
	push	ix
	ld	de, -168
	add	ix, de
	ld	hl, (ix + 0)
	pop	ix
	add	hl, bc
	ld	de, (ix + -3)
	push	de
	pop	bc
	ld	a, (hl)
	xor	a, iyl
	ld	iy, (ix + 12)
	add	iy, bc
	ld	(iy), a
	ld	iy, (ix + 12)
	inc	bc
	jq	BB30_14
BB30_16:
	lea	iy, iy + -17
	ld	de, (ix + 9)
BB30_17:
	lea	hl, iy + 0
	add	hl, de
	ld	a, (hl)
	ex	de, hl
	dec	hl
	or	a, a
	push	hl
	pop	de
	jq	nz, BB30_17
	ld	de, -15
	add	hl, de
	ex	de, hl
	jq	BB30_31
BB30_19:
	ld	de, 0
	jq	BB30_31
BB30_25:
	ld	a, l
	cp	a, 2
	jq	nz, BB30_30
	dec	iy
BB30_27:
	lea	hl, iy + 0
	add	hl, bc
	dec	bc
	ld	a, (hl)
	cp	a, -128
	jq	nz, BB30_27
	inc	bc
	ld	iy, (ix + 6)
BB30_30:
	ld	de, -165
	lea	hl, ix + 0
	add	hl, de
	ld	(hl), bc
	push	bc
	push	iy
	ld	hl, (ix + 12)
	push	hl
	call	ti._memcpy
	ld	bc, -165
	lea	hl, ix + 0
	add	hl, bc
	ld	de, (hl)
	pop	hl
	pop	hl
	pop	hl
BB30_31:
	ex	de, hl
	ld	sp, ix
	pop	ix
	ret

hashlib_AESVerifyMAC:
	ld	hl, -22
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	hl, (ix + 9)
	ld	bc, -16
	lea	de, ix + -16
	ld	(ix + -19), de
	add	hl, bc
	ld	(ix + -22), hl
	ld	bc, (ix + 12)
	push	bc
	push	de
	push	hl
	push	iy
	call	hashlib_AESOutputMAC
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	ld	de, (ix + -22)
	add	hl, de
	ld	de, 16
	push	de
	push	hl
	ld	hl, (ix + -19)
	push	hl
	call	hashlib_CompareDigest
	ld	sp, ix
	pop	ix
	ret
 
 hashlib_CompareDigest:
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
 
 _csprng_state:
	rb	195

_Base64Code:
	db	"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",000o
 
 _index_64:
	db	"",377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,377o,000o,001o,"6789:;<=>?",377o,377o,377o,377o,377o,377o,377o,002o,003o,004o,005o,006o,007o,010o,011o,012o,013o,014o,015o,016o,017o,020o,021o,022o,023o,024o,025o,026o,027o,030o,031o,032o,033o,377o,377o,377o,377o,377o,377o,034o,035o,036o,037o," !""#$%&'()*+,-./012345",377o,377o,377o,377o,377o
 
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
 
 
_k:
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

_add64iu:
	pop bc,de
	ex (sp),hl
	push de,bc
	ex hl,de
	ld bc,(hl)
	ex hl,de
	xor a,a
	adc hl,bc
	ex hl,de
	ld (hl),de
	inc hl
	inc hl
	ld b,5
	ld c,a
.loop:
	inc hl
	adc a,(hl)
	ld (hl),a
	ld a,c
	djnz .loop
	ret
