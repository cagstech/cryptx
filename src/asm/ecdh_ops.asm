public _rmemcpy
public _bigint_lshift
public _bigint_rshift
public _bigint_add
public _bigint_mul

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


; bigint_lshift(void* arr, size_t len, uint8_t nbits)
bigint_lshift:
  call ti._frameset0
  ld a,(ix + 3)
  ld hl,(ix + 9)
  ld bc,(ix + 6)
  rra
  call nc,bigint_lshift1
  rra
  call nc,bigint_lshift2
  rra
  call nc,bigint_lshift4
  rra
  or a
  call nz,bigint_lshift_A_bytes
  ld sp, ix
  pop ix
  ret
 
; bigint_rshift(void* arr, size_t len, uint8_t nbits)
bigint_rshift:
  call ti._frameset0
  ld a,(ix + 3)
  ld hl,(ix + 9)
  ld bc,(ix + 6)
  rra
  call nc,bigint_rshift1
  rra
  call nc,bigint_rshift2
  rra
  call nc,bigint_rshift4
  rra
  or a
  call nz,bigint_rshift_A_bytes
  ld sp, ix
  pop ix
  ret
 
 
bigint_lshift_A_bytes:
; shifts the bigint left by A bytes:
; Inputs:
;   HL points to the int
;   BC is the size (in bytes), ** BC<65536 **
;   A is the number of bytes to shift
; Destroys:
;   DE
;
    ; or a
    ; ret z
    push hl
    push bc
    push af
 
    add hl,bc
    dec hl
    ex de,hl  ; DE points to the MSB, which is where we'll write
 
    or a,a
    sbc hl,hl
    ld l,a    ; HL is the number of bytes to shift by
 
    ; BC - A, guaranteed to not be 0
    ld a,c
    sub l
    ld c,a
    sbc a,a ; A = -carry
    add a,b
    ld b,a
    ; If BC is negative, just zero out the whole int
    ld a,l  ; restore A
    jp m,.zero_bytes
    ; If BC is 0, zero-out the whole int
    jr nz,.shift_bytes
    dec c
    inc c
    jr z,.zero_bytes
 
.shift_bytes:
    ; want HL = DE - HL
    ex de,hl
    or a,a
    sbc hl,de
    ex de,hl  ; HL is where to read from
 
    ; HL is where to read from
    ; DE is where to write to
    ; BC is size of the bigint, minus the number of bytes to shift
    ; A is the number of bytes to shift by
 
    lddr  ; copy bytes up
 
.zero_bytes:
    ; zero-out the remaining bytes, A is non-zero
    ld b,a
    xor a
.loop:
    ld (de),a
    dec de
    djnz .loop
 
    pop af
    pop bc
    pop hl
    ret
 
 
bigint_lshift4:
; shifts the bigint left by 4 bits
; Inputs:
;   HL points to the int
;   BC is the size (in bytes)
; Destroys:
;   None
    push hl
    push bc
    push af
    xor a
.loop
    rld
    cpi
    jp pe,.loop
    pop af
    pop bc
    pop hl
    ret
 
bigint_lshift2:
    call bigint_lshift1
bigint_lshift1:
    push hl
    push bc
    or a,a
.loop:
    rl (hl)
    cpi
    jp pe,.loop
    pop bc
    pop hl
    ret
 
 
bigint_rshift_A_bytes:
; shifts the bigint right by A bytes
; Inputs:
;   HL points to the int
;   BC is the size (in bytes), ** BC<65536 **
;   A is the number of bytes to shift
; Destroys:
;   DE
    ; or a
    ; ret z
 
    push hl
    push bc
    push af
    ex de,hl  ; DE points to the start of the string
 
    sbc hl,hl
    ld l,a    ; HL is the number of bytes to shift by
 
    ; BC - A, guaranteed to not be 0
    ld a,c
    sub l
    ld c,a
    sbc a,a ; A = -carry
    add a,b
    ld b,a
    ; If BC is negative, just zero out the whole int
    ld a,l  ; restore A
    jp m,.zero_bytes
    ; If BC is 0, zero-out the whole int
    jr nz,.shift_bytes
    dec c
    inc c
    jr z,.zero_bytes
 
.shift_bytes:
    add hl,de ; HL points to where to start reading
 
    ; HL is where to read from
    ; DE is where to write to
    ; BC is size of the bigint, minus the number of bytes to shift
    ; A is the number of bytes to shift by
 
    ldir  ; copy bytes down
 
.zero_bytes:
    ; zero-out the remaining bytes, A is non-zero
    ld b,a
    xor a
.loop:
    ld (de),a
    inc de
    djnz .loop
 
    pop af
    pop bc
    pop hl
    ret
 
bigint_rshift4:
; shifts the bigint right by 4 bits
; Inputs:
;   HL points to the int
;   BC is the size (in bytes)
; Destroys:
;   None
    push hl
    push bc
    push af
    add hl,bc
    dec hl
    xor a
.loop
    rrd
    cpd
    jp pe,.loop
    pop af
    pop bc
    pop hl
    ret
 
 
bigint_rshift2:
    call bigint_lshift1
bigint_rshift1:
    push hl
    push bc
    add hl,bc
    dec hl
    or a,a
.loop:
    rr (hl)
    cpd
    jp pe,.loop
    pop bc
    pop hl
    ret


; bigint_add(uint8_t *op1, uint8_t *op2);
; hard limit to 32 bytes
; output in op1
_bigint_add:
	ti._frameset0
	ld hl, (ix + 3)		; op2
	ld de, (ix + 6)		; op1
	ld b, 32
.loop:
	ld a,(de)
	adc sbc a,(hl)
	ld (de),a
	djnz .loop
	ld sp, ix
	pop ix
	ret


; bigint_mul(uint8_t *op1, uint8_t *op2)
_bigint_mul:
	ld hl, 32
	ti._frameset
	ld de, ix - 32		; stack mem?
	ld hl, (ix + 6)		; op1 (save a copy)
	ld bc, 32
	ldir
	ld de, (ix + 6)		; op1
	ld hl, (ix + 3)		; op2
	ld b, 32
.byteloop:
	push bc
	ld b, 8
.bitloop:
	ex de, hl
	push bc
	ld bc, 32
	call bigint_rshift1		; double
	pop bc
	ex de, hl
	ld a, (hl)
	rra
	jr nc, .bitloop
	push hl		; save current hl
	lea hl, ix - 32
	push hl
	ld hl, (ix + 6)
	push hl
	call bigint_add			; then add
	pop hl,hl,hl
	djnz .bitloop
	pop bc
	djnz .byteloop
	ld sp, ix
	pop ix
	ret


; bigint_sub(uint8_t *op1, uint8_t *op2);
_bigint_sub:
	ti._frameset0
	ld hl, (ix + 6)		; op1
	ld bc, 32
	add hl, bc
	ex de, hl
	ld hl, (ix + 3)		; op2
	add hl, bc
	ld b, c
; hl = op2 + 32, de = op1 + 32
.loop:
	ld a,(de)
	sbc a,(hl)
	ld (de),a
	djnz .loop
	ld sp, ix
	pop ix
	ret
	
	
	
