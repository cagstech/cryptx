/*
 *--------------------------------------
 * Program Name: DEMO
 * Author: Adam Beckingham
 * License: GPL3
 * Description: Encodex Bpp encode/decode test file
 *--------------------------------------
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <encodex.h>
#define CEMU_CONSOLE ((char*)0xFB0000)

const uint8_t encode = {
	0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
};

int main(void)
{
	char tempstr[16] = {0};
	uint8_t temp[8] = {0};
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nENCODEX Bpp Encoder Demo\n");

	digest_tostring(&tempstr, &encode, sizeof(encode));
	sprintf(CEMU_CONSOLE, "original data: %s\n", &tempstr);

	bpp_encode(&temp, &encode, (sizeof(encode) * 4) / 8, 1);
	digest_tostring(&tempstr, &temp, (sizeof(encode) * 4) / 8);
	sprintf(CEMU_CONSOLE, "4bpp encoded data: %s\n", &tempstr);

	bpp_encode(&temp, &encode, (sizeof(encode) * 2) / 8, 1);
	digest_tostring(&tempstr, &temp, (sizeof(encode) * 2) / 8);
	sprintf(CEMU_CONSOLE, "2bpp encoded data: %s\n", &tempstr);

	bpp_encode(&temp, &encode, (sizeof(encode) * 1) / 8, 1);
	digest_tostring(&tempstr, &temp, (sizeof(encode) * 1) / 8);
	sprintf(CEMU_CONSOLE, "1bpp encoded data: %s\n", &tempstr);

    return 0;
}
