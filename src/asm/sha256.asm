offset_data         := 0
offset_datalen      := offset_data+64
offset_bitlen       := offset_datalen+1
offset_state        := offset_bitlen+8
_sha256ctx_size     := 4*8+offset_state

; void hashlib_Sha256Init(SHA256_CTX *ctx)
hashlib_Sha256Init:
    pop bc,de
    push de,bc
	ld hl,$FF0000 ;64k of 0x00 bytes
    ld bc,_sha256ctx_size
	push de
	ldir
	pop de
    ld c,8*4        ;bc=0 prior to this, due to ldir
    ld hl,_sha256_state_init
	ldir
    ret
    
    
; void hashlib_Sha256Update(SHA256_CTX *ctx, const BYTE data[], uint32_t len)
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
    
    
 


hashlib_Sha256Final:


; iy = context pointer
call _sha256_transform:
    
    
    



_sha256_state_init:
    dd 0x6a09e667
    dd 0xbb67ae85
    dd 0x3c6ef372
    dd 0xa54ff53a
    dd 0x510e527f
    dd 0x9b05688c
    dd 0x1f83d9ab
    dd 0x5be0cd19

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

