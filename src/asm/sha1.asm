

; perhaps we should prefix this for sha256 with sha256_?
virtual at 0
	sha1_offset_data		rb 64
	sha1_offset_bitlen		rb 8
	sha1_offset_datalen		rb 1
	sha1_ offset_state		rb 4*5
	sha1_offset_k			rb 4*4
end virtual
sha1_mbuffer_len	:=	80 * 4

; hashlib_Sha1Init(sha1_ctx *ctx);
hashlib_Sha1Init:
	pop bc,de
	ex (sp),hl
	push de,bc
	add hl,bc
	or a,a
	sbc hl,bc
	jr z,.dont_set_buffer
	ld (_sha1_m_buffer_ptr),hl

; this needs doing in asm, see state variables below
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	ctx->k[0] = 0x5a827999;
	ctx->k[1] = 0x6ed9eba1;
	ctx->k[2] = 0x8f1bbcdc;
	ctx->k[3] = 0xca62c1d6;
	ret

;------------------------------------------------------------------------------
; void hashlib_Sha1Update(SHA1_CTX *ctx, const BYTE data[], size_t len);
hashlib_Sha1Update:
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

	call _sha1_update_loop
	cp a,64
	call z,_sha1_update_apply_transform

	ld iy, (ix + 6)
	ld (iy + offset_datalen), a		   ;save current datalen
	pop ix
	ret

_sha1_update_loop:
	inc a
	ldi ;ld (de),(hl) / inc de / inc hl / dec bc
	ret po ;return if bc==0 (ldi decrements bc and updates parity flag)
	cp a,64
	call z,_sha1_update_apply_transform
	jq _sha1_update_loop
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
	

;--------------------------------------------------------
; void hashlib_Sha1Final(SHA1_CTX *ctx, BYTE hash[]);
hashlib_Sha1Final:
	call ti._frameset0
	; (ix + 0) Return address
	; (ix + 3) saved IX
	; (ix + 6) arg1: ctx
	; (ix + 9) arg2: outbuf
	
	; scf
	; sbc hl,hl
	; ld (hl),2

	ld iy, (ix + 6)					; iy =  context block

	ld bc, 0
	ld c, (iy + offset_datalen)     ; data length
	ld hl, (ix + 6)					; ld hl, context_block_cache_addr
	add hl, bc						; hl + bc (context_block_cache_addr + bytes cached)

	ld a,55
	sub a,c ;c is set to datalen earlier
	ld (hl),$80
	jq c,_sha1_final_over_56
	inc a
_sha1_final_under_56:
	ld b,a
	xor a,a
_sha1_final_pad_loop2:
	inc hl
	ld (hl),a
	djnz _sha1_final_pad_loop2
	jq _sha1_final_done_pad
_sha1_final_over_56:
	ld a,64
	sub a,c
	ld b,a
	xor a,a
_sha1_final_pad_loop1:
	inc hl
	ld (hl),a
	djnz _sha1_final_pad_loop1
	push iy
	call _sha1_transform
	pop de
	ld hl,$FF0000
	ld bc,56
	ldir
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
	
	; Then comes this, in asm
for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
	}


;------------------------------------------
; void _sha1_transform(SHA1_CTX *ctx);
_sha1_transform:
;	a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
._a := -4
._b := -8
._c := -12
._d := -16
._e := -20
._f := -24
._g := -28
._h := -32
._i := -36		; this is single byte counter
._j := -40
._tmp1 := -44
._tmp2 := -48
; ?._state_vars := -32		;??
._frame_offset := ._tmp2	;??
	ld hl,._frame_offset
	call ti._frameset
	ld hl,0
_sha1_m_buffer_ptr:=$-3
	add hl,bc
	or a,a
	sbc hl,bc
	jq z,._exit

; loop1
;	for (i = 0, j = 0; i < 16; ++i, j += 4)
;		m[i] = (data[j] << 24) + (data[j + 1] << 16) + (data[j + 2] << 8) + (data[j + 3]);

; loop2
;	for ( ; i < 80; ++i) {
;		m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
;		m[i] = (m[i] << 1) | (m[i] >> 31);
;	}

; load state
	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	
; loop 3
;	for (i = 0; i < 20; ++i) {
;		t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
;		e = d;
;		d = c;
;		c = ROTLEFT(b, 30);
;		b = a;
;		a = t;
;	}

; loop 4
;	for ( ; i < 40; ++i) {
;		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
;		e = d;
;		d = c;
;		c = ROTLEFT(b, 30);
;		b = a;
;		a = t;
;	}

; loop 5
;	for ( ; i < 60; ++i) {
;		t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d))  + e + ctx->k[2] + m[i];
;		e = d;
;		d = c;
;		c = ROTLEFT(b, 30);
;		b = a;
;		a = t;
;	}

; loop 6
;	for ( ; i < 80; ++i) {
;		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
;		e = d;
;		d = c;
;		c = ROTLEFT(b, 30);
;		b = a;
;		a = t;
;	}

; save state
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;

_sha1_state_init:
	
	
_sha1_k_init:
