
public hashlib_CSPRNGInit
public hashlib_CSPRNGAddEntropy

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
    
	
hashlib_SPRNGAddEntropy:
    ld hl, (_csprng_state)
    add	hl,de
	or	a,a
	sbc	hl,de
    ret z
    ld de, _csprng_state + 3
    ld b, 128
.byte_read_loop:
    ld a, (de)
    xor a, (hl)
    ld (de), a
    inc de
    inc de
    inc de
    djnz .byte_read_loop
    ret

hashlib_SPRNGRandom:
	ld b, 5
	
.init_loop
	ld hl, (_sprng_read_addr)
	add hl,de
	or a,a
	sbc hl,de
	jr nz, .have_addr
	
	call hashlib_SPRNGInit
	djnz .init_loop
	
	ld hl, (_sprng_read_addr)
	add hl,de
	or a,a
	sbc hl,de
	jr z, .error
	
.have_addr:
; set rand to 0
	ld hl, $E40000
	ld de, _sprng_rand
	ld bc, 4
	ldir
	
; hash entropy pool
	ld hl, _sprng_sha_ctx
	push hl
	ld hl, _sprng_sha_mbuffer
	push hl
	call hashlib_Sha256Init
	pop hl							; leave the context pointer on the stack
	ld hl, _sprng_entropy_pool		;  it's arg for next call
	push hl
	ld hl, 192
	push hl
	call hashlib_Sha256Update
	pop hl
	pop hl							; leave context pointer on stack again
	ld hl, _sprng_sha_digest
	push hl
	call hashlib_Sha256Final
	pop hl
	pop bc
	pop bc
	
; xor hash cyclically into _rand
	ld ix, _sprng_rand
	ld b, 8
	; hl = hash digest
.xor_loop:
	ld a, (ix + 0)
	xor a, (hl)
	ld (ix + 0), a
	inc hl
	ld a, (ix + 1)
	xor a, (hl)
	ld (ix + 1), a
	inc hl
	ld a, (ix + 2)
	xor a, (hl)
	ld (ix + 2), a
	inc hl
	ld a, (ix + 3)
	xor a, (hl)
	ld (ix + 3), a
	inc hl
	djnz .xor_loop
	
; add entropy
	call hashlib_SPRNGAddEntropy
	ld hl, (_sprng_rand)
	ld e, (_sprng_rand+3)
	ret
.error:
	sbc hl, hl
	ld e, l
	ret
	
	
	






_sprng_read_addr:		rb 3
	
_sprng_entropy_pool		:=	$E30800
_sprng_rand				:=	_sprng_entropy_pool + 192
_sprng_sha_digest		:=	_sprng_rand + 4
_sprng_sha_mbuffer		:=	_sprng_sha_digest + 32
_sprng_sha_ctx			:=	_sprng_sha_mbuffer + (64*4)
