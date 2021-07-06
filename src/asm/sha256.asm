offset_data         := 0
offset_datalen      := offset_data+64
offset_bitlen       := offset_datalen+1
offset_state        := offset_bitlen+8
_sha256ctx_size     := 4*8+offset_state

; void hashlib_Sha256Init(SHA256_CTX *ctx)
hashlib_Sha256Init:
    pop bc,de
    push de,bc
	ld hl,$FF0000           ; 64k of 0x00 bytes
    ld bc,_sha256ctx_size
	push de
	ldir
	pop de
    ld c,8*4                ; bc=0 prior to this, due to ldir
    ld hl,_sha256_state_init
	ldir
    ret
    
    
; void hashlib_Sha256Update(SHA256_CTX *ctx, const BYTE data[], size_t len)
hashlib_Sha256Update:
    call ti._frameset0
    ; (ix + 0) RV
    ; (ix + 3) old IX
    ; (ix + 6) arg1: ctx
    ; (ix + 9) arg2: data
    ; (ix + 12) arg3: len
    
    ; get pointers to the things
    lea bc, (ix + 12)           ; bc = len
    lea hl, (ix + 9)            ; hl = source data
    lea de, (ix + 6)            ; de = context, data ptr
    lea iy, (ix + 6)            ; iy = context, reference
    
    ; start writing data to the right location in the data block
    ld a, (iy + offset_datalen)
    ld b, 0
    ld c, a
    ex de, hl
    add hl, bc
    ex de, hl
   
_sha256_update_loop:
    push af                 ; we will wind up nuking a
        ld a, (hl)
        ld (de), a
    pop af
    inc a
    cp 64
    jr nz, _sha256_update_noblock
    ld iy, (ix + 6)
    call _sha256_transform      ; if we have one block (64-bytes), transform block
    ld iy, 512                  ; add 1 blocksize of bitlen to the bitlen field
    push af, hl, de, bc
    push iy
        ld iy, (ix + 6)
        pea iy + offset_bitlen
            call u64_addi
    pop hl,hl
    pop bc, de, hl, af
    ld a, 0                     ; reset datalen to 0
_sha256_update_noblock:
    inc de
    inc hl
    dec bc
    push af
        ld a,c
        or a,b
        jq z, _sha256_update_done
    pop af
    jr _sha256_update_loop
_sha256_update_done:
    pop af
    lea iy, (ix + 6)
    ld (iy + offset_datalen), a           save current datalen
    lea ix, (ix + 3)
    ret
    
    
 

; void hashlib_Sha256Final(SHA256_CTX *ctx, BYTE hash[])
hashlib_Sha256Final:
    call ti._frameset0
    ; (ix + 0) RV
    ; (ix + 3) old IX
    ; (ix + 6) arg1: ctx
    ; (ix + 9) arg2: outbuf
    
    lea iy, (ix + 6)                    ; iy =  context block
    ld a, (iy + offset_datalen)         ; a = datalen in block cache
    
    ; let DE = &ctx->data[datalen]
    ld b, 0
    ld c, a                             ; ld bc, a
    lea hl, (ix + 6)                    ; ld hl, context_block_cache_addr
    add hl, bc                          ; hl + bc (context_block_cache_addr + bytes cached)
    ex de, hl                           ; put into de
    
    cp 64
    jr nc, _sha256_skip_pad             ; if datalen equal to a block, skip init padding step
    cp 56
    jr nc, _sha256_pad_to_block
    
    ld b, 56
    sub a, b
    ld b, 0
    ld c, a
    ld a, 080h
    ld (de), a
    dec bc
    inc de
    ld hl,$FF0000                       ; 64k of 0x00 bytes
    ldir                                ; copy 56 - datalen bytes to &ctx->data
    jr _sha256_skip_pad
    
_sha256_pad_to_block:
    ld b, 64
    sub a, b
    ld b, 0
    ld c, a
    ld a, 080h
    ld (de), a
    dec bc
    inc de
    ld hl,$FF0000                       ; 64k of 0x00 bytes
    ldir                                ; copy 64 - datalen bytes to &ctx->data
    lea iy, (ix + 6)
    call _sha256_transform              ; hash the block
    ld hl,$FF0000                       ; 64k of 0x00 bytes
    ld bc,56
	lea de, (ix + 6)
	ldir                                ; zero the first 56 bytes of a new block
    
_sha256_skip_pad:
    lea iy, (ix + 6)
    ld a, (iy + offset_datalen)
    ld b, 0
    ld c, a
    push bc
    pop hl
    add hl, hl
    add hl, hl
    add hl, hl                      ; hl * 8
    push hl
        ld iy, (ix + 6)
        pea iy + offset_bitlen
            call u64_addi
    pop hl, hl
    lea hl, (ix + 6)
    ld bc, 63
    add hl, bc
    ex de, hl
    lea hl, (ix + 6)
    ld bc, offset_bitlen
    add hl, bc
    ld b, 8
_sha256_echobitlen:
    ld a, (hl)
    ld (de), a
    inc hl
    dec de
    djnz _sha256_echobitlen
    
    lea iy, (ix + 6)
    call _sha256_transform
    
    ld b, 8
    lea hl, (ix + 9)
    lea iy, (ix + 6)
    lea iy, iy + offset_state
_sha256_render_digest_loop:
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
    djnz sha256_render_digest_loop
    

_sha256_mblock          := 0
_sha256_state_vars      := 64 * 4 + mblock
_sha256_transform_stackmem_size    := 8 * 4 + state_vars

; iy = context pointer
call _sha256_transform:
    ld hl, _sha256_transform_stackmem_size
    call ti._frameset
    
    ; memset all stack mem to 0
    ld hl,$FF0000
    lea de, ix + 0
    ld bc, _sha256_transform_stackmem_size
    ldir
    
    lea hl, ix + 0
    ld b, 16
    push iy

_sha256_transform_loop1:
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
    djnz _sha256_transform_loop1
    
    pop iy
    push iy
    ld b, 64-16
_sha256_transform_loop2:
; m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    djnz _sha256_transform_loop2
    
    pop iy
    push iy
    lea hl, iy + offset_state
    lea de, ix + _sha256_state_vars
    ld bc, 32
    ldir                ; copy the state to scratch stack memory
    
    ld b, 64
_sha256_transform_loop3:
; tmp1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
; tmp2 = EP0(a) + MAJ(a,b,c);
; h = g;
; g = f;
; f = e;
; e = d + tmp1;
; d = c;
; c = b;
; b = a;
; a = tmp1 + tmp2;
    djnz _sha256_transform_loop3
    
    pop iy
    lea de, iy + offset_state
    lea hl, ix + _sha256_state_vars
    ld bc, 32
    ldir                ; copy scratch back to state
    ret

    
    
    
    
    
    
    
_sha256_sig0:
;   ix = address to whatever the F sig0 is
    ld ehl, 0
    xor ehl, (

_sha256_sig1:
;   ehl = 32-bit value to... whatever the F sig1 is
;   c = rotate this many times



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

