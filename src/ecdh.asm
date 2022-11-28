; using sect233k1
; define curve T = (m,f(x),a,b,G,n,h), where
; m = 233 and finite field F(2^233) is defined by:
; f(x) = x^233 + x^74 + 1
; = curve E: y^2 + xy = ax^2 + b defined by:
; a = 0000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
; b = 0000 00000000 00000000 00000000 00000000 00000000 00000000 00000001
; G(comp) = 020172 32BA853A 7E731AF1 29F22FF4 149563A4 19C26BF5 0A4C9D6E EFAD6126
; G(ucomp) = 04 017232BA 853A7E73 1AF129F2 2FF41495 63A419C2 6BF50A4C 9D6EEFAD 6126'01DB 537DECE8 19B7F70F 555A67C4 27A8CD9B F18AEB9B 56E0C110 56FAE6A3
; n = 80 00000000 00000000 00000000 00069D5B B915BCD4 6EFB1AD5 F173ABDF
; h = 01
; ## KEYGEN ## generate key pair (d, Q)
; d is secret. Assert d in range [1, n-1] (random).
; Q = d*G
; output (d, Q)
; ## PUBKEY VALID ##
; assert Q != infinity point
; assert xQ, yQ are of degree <= m-1
; assert nQ = infinity point
; if h = 1, skip final assertion
; ## SECRET COMPUTE ##
; inputs:
;		private key d(alice) associated with T(alice)
;		public key Q(bob) associated with T(bob)
; P = (x, y) = h * d(alice) * Q(bob)
; if P = infinite point, invalid
; output x as shared secret field
; (optional, but recommended) pass x to a KDF to generate symmetric key

ecc_prv_key_size := 32
ecc_pub_key_size := ecc_prv_key_size * 2
curve_degree := 233

;----------------------------------------------
; structures
virtual at 0
	point_x		rb 	ecc_pub_key_size/2
	point_y		rb	ecc_pub_key_size/2
end virtual


ecdh_keygen:
; ecdh_pubkey(void *pubkey, void* prvkey);
; expects prvkey of len 32 bytes
; 1. check if prvkey less than n and greater than 0. Return error if false.
; 2. zero privkey bits >233 (this may serve role of #1 too)
; 3. treat prvkey as ec point (x, y)
; 4. multiply (x, y) by (Gx, Gy) mod m => pubkey
; 5. return pubkey, modded prvkey
	save_interrupts
	ld hl, 32
	call ti.frameset
; (ix + 3) = pubkey
; (ix + 6) = prvkey
	ld hl, (ix + 9)
	ld de, curve_order
	call _and_i32	; return with any high bytes in prvkey greater than degree 0'd?
.skip_zero_bits:

	ld hl, (ix + 3)
	push hl
	push hl
	ld hl, (ix + 6)
	push hl
	call _gf2point_mul
	
	
	
_gf2point_mul:
	
	
	
_bitvec_mul:
	


_and_i32:
; inputs: hl, bc = pointing to i32 operands
; outputs: hl = output
	ld b, 4
.loop:
	ld a, (de)
	and a, (hl)
	ld (hl), a
	djnz .loop
	ret
	


_i256_mul:
; integer-256-bit multiplication





curve_a
	dd 0x00000000
	dd 0x00000000
	dd 0x00000000
	dd 0x00000000
	dd 0x00000000
	dd 0x00000000
	dd 0x00000000
	dd 0x00000000
	
curve_b:
	dd 0x00000000
	dd 0x00000000
	dd 0x00000000
	dd 0x00000000
	dd 0x00000000
	dd 0x00000000
	dd 0x00000000
	dd 0x00000001
	
curve_G:
curve_basex:
	dd 0x017232BA,
	dd 0x853A7E73,
	dd 0x1AF129F2 2FF41495 63A419C2 6BF50A4C
9D6EEFAD 612601DB 537DECE8 19B7F70F 555A67C4 27A8CD9B F18AEB9B
56E0C11056FAE6A3
curve_basey:
	dd 0x612601DB,
	dd 0x537DECE8,
	dd 0x19B7F70F,
	dd 0x555A67C4,
	dd 0x27A8CD9B,
	dd 0xF18AEB9B,
	dd 0x56E0C110,
	dd 0x56FAE6A3

curve_order:	; n
	dd 0x00000080,
	dd 0x00000000,
	dd 0x00000000,
	dd 0x00000000,
	dd 0x00069D5B,
	dd 0xB915BCD4,
	dd 0x6EFB1AD5,
	dd 0xF173ABDF
	
curve_cofactor:	; h
	db 4
