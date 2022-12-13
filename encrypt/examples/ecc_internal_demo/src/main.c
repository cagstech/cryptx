/*
 *--------------------------------------
 * Program Name:
 * Author:
 * License:
 * Description:
 *--------------------------------------
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <hashlib.h>
#include <sys/timers.h>

#define ENCRYPT_ENABLE_ECC_INTERNAL
#include <encrypt.h>

#define CEMU_CONSOLE ((char*)0xFB0000)
void hexdump(uint8_t *addr, size_t len, uint8_t *label){
	if(label) sprintf(CEMU_CONSOLE, "\n%s\n", label);
	else sprintf(CEMU_CONSOLE, "\n");
	for(size_t rem_len = len, ct=1; rem_len>0; rem_len--, addr++, ct++){
		sprintf(CEMU_CONSOLE, "%02X ", *addr);
		if(!(ct%AES_BLOCKSIZE)) sprintf(CEMU_CONSOLE, "\n");
	}
	sprintf(CEMU_CONSOLE, "\n");
}


int main(void)
{
	uint8_t baseX[] = {0x00,0x00,0x01,0x72,0x32,0xBA,0x85,0x3A,0x7E,0x73,0x1A,0xF1,0x29,0xF2,0x2F,0xF4,
		0x14,0x95,0x63,0xA4,0x19,0xC2,0x6B,0xF5,0x0A,0x4C,0x9D,0x6E,0xEF,0xAD,0x61,0x26};
	uint8_t baseY[] = {0x00,0x00,0x01,0xDB,0x53,0x7D,0xEC,0xE8,0x19,0xB7,0xF7,0x0F,0x55,0x5A,0x67,0xC4,
		0x27,0xA8,0xCD,0x9B,0xF1,0x8A,0xEB,0x9B,0x56,0xE0,0xC1,0x10,0x56,0xFA,0xE6,0xA3};
	
	GF2_BIGINT test1 = {0};
	test1[0] = 3;
	
	ecc_point p1, p2;
	uint32_t timer_start, timer_stop;
	GF2_BIGINT res;
	
	gf2_bigint_frombytes(p1.x, baseX, sizeof baseX, false);
	gf2_bigint_frombytes(p1.y, baseY, sizeof baseY, false);
	memcpy(&p2, &p1, sizeof p2);
	
	timer_Disable(1);
	timer_Set(1, 0);
	timer_Enable(1, TIMER_32K, TIMER_0INT, TIMER_UP);
	
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nBIGINT Math Timing Checks\n");
	timer_start = timer_GetSafe(1, TIMER_UP);
	gf2_bigint_add(res, p1.x, p1.y);
	timer_stop = timer_GetSafe(1, TIMER_UP) - timer_start;
	sprintf(CEMU_CONSOLE, "BIGINT addition completed in %lu ms\n", timer_stop * 1000/ 32768);
	
	timer_start = timer_GetSafe(1, TIMER_UP);
	gf2_bigint_mul(res, p1.x, p1.y);
	timer_stop = timer_GetSafe(1, TIMER_UP) - timer_start;
	sprintf(CEMU_CONSOLE, "BIGINT multiplication completed in %lu ms\n", timer_stop * 1000/ 32768);
	
	timer_start = timer_GetSafe(1, TIMER_UP);
	test1[0] = 3;
	gf2_bigint_square(res, test1);
	timer_stop = timer_GetSafe(1, TIMER_UP) - timer_start;
	sprintf(CEMU_CONSOLE, "BIGINT squaring completed in %lu ms\n", timer_stop * 1000/ 32768);
	hexdump(test1, sizeof test1, "___3 ^ 2___");
	hexdump(res, sizeof res, "___3 ^ 2___");
	
	timer_start = timer_GetSafe(1, TIMER_UP);
	gf2_bigint_invert(res, p1.x);
	timer_stop = timer_GetSafe(1, TIMER_UP) - timer_start;
	sprintf(CEMU_CONSOLE, "BIGINT inversion completed in %lu ms\n", timer_stop * 1000/ 32768);
	
	
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nECC Point Math Timing Checks\n");
	
	timer_start = timer_GetSafe(1, TIMER_UP);
	ecc_point_double(&p1);
	timer_stop = timer_GetSafe(1, TIMER_UP) - timer_start;
	sprintf(CEMU_CONSOLE, "ECC point double completed in %lu ms\n", timer_stop * 1000/ 32768);
	hexdump(&p1, sizeof p1, "___p1 doubled___");
	
	timer_start = timer_GetSafe(1, TIMER_UP);
	ecc_point_add(&p1, &p2);
	timer_stop = timer_GetSafe(1, TIMER_UP) - timer_start;
	sprintf(CEMU_CONSOLE, "ECC point addition completed in %lu ms\n", timer_stop * 1000 / 32768);
	
}
