; HASHLIB
; Secure Random Number Generator (SPRNG)
; algorithms by ACagliano
; SPRNGInit code by beckadamtheinventor
; SPRNGAddEntropy and SPRNGRandom code by Acagliano
; SPRNRandom code fixed and optimized by jacobly


public hashlib_CSPRNGInit
public hashlib_CSPRNGAddEntropy

;---------------------------
; hashlib_SPRNGInit();
hashlib_SPRNGInit:
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
   
;--------------------------------
;_hashlib_SPRNGAddEntropy();
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


;--------------------------
; hashlib_SPRNGRandom();
hashlib_SPRNGRandom:
	ld e,5+1
	scf
.init:
	dec e
	ret z
	push de
	call nc, hashlib_SPRNGInit
	pop de
	ld hl, (_sprng_read_addr)
	add hl,de
	or a,a
	sbc hl,de
	jq z,.init
	
.have_addr:
; set rand to 0
	ld hl, 0
	ld a, l
	ld (_sprng_rand), hl
	ld (_sprng_rand), a
	call hashlib_SPRNGAddEntropy
; hash entropy pool
	ld hl, _sprng_sha_mbuffer
	push hl
	ld hl, _sprng_sha_ctx
	push hl
	call hashlib_Sha256Init
	pop bc, hl
	ld hl, 119
	push hl
	ld hl, _sprng_entropy_pool
	push hl
	push bc
	call hashlib_Sha256Update
	pop bc, hl, hl
	ld hl, _sprng_sha_digest
	push hl
	push bc
	call hashlib_Sha256Final
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
	
; add entropy
	call hashlib_SPRNGAddEntropy
	ld hl, (_sprng_rand)
	ld a, (_sprng_rand+3)
	ld e, a
	ret
	
	
	






_sprng_read_addr:		rb 3
_sprng_entropy_pool		:=	$E30800
_sprng_rand				:=	_sprng_entropy_pool + 119
_sprng_sha_digest		:=	_sprng_rand + 4
_sprng_sha_mbuffer		:=	_sprng_sha_digest + 32
_sprng_sha_ctx			:=	_sprng_sha_mbuffer + (64*4)
