public _rmemcpy
public _bigint_lshift
public _bigint_rshift

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
_bigint_lshift:
	call ti._frameset0
	ld hl, (ix + 3)
	ld a, l
	ld hl, (ix + 9)
	ld bc, (ix + 6)
    rra
    call nc,bigint_lshift1
    rra
    call nc,bigint_lshift2
    rra
    call nc,bigint_lshift4
    rra
    and 0b00011111
    jq z, .exit
.shift_bytes:
	; do this
	
.exit:
	ld sp, ix
    pop ix
    ret
    
    
; bigint_rshift(void* arr, size_t len, uint8_t nbits)
_bigint_rshift:
	call ti._frameset0
	ld hl, (ix + 3)
	ld a, l
	ld hl, (ix + 9)
	ld bc, (ix + 6)
    rra
    call nc,bigint_rshift1
    rra
    call nc,bigint_rshift2
    rra
    call nc,bigint_rshift4
    rra
    and 0b00011111
    jq z, .exit
.shift_bytes:
	; do this
	
.exit:
	ld sp, ix
    pop ix
    ret



; HL points to start of the array, BC is # bytes
bigint_lshift2:
    call bigint_lshift1
bigint_lshift1:
    or a,a
    push bc
    push hl
.loop:
    rl (hl)
    cpi
    jp pe,.loop
    pop hl
    pop bc
    ret

bigint_rshift2:
    call bigint_rshift1
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
