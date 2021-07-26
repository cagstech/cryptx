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
#include <tice.h>

#define CEMU_CONSOLE ((char*)0xFB0000)
#define SALT_LEN 16     // for example, a salt that is an IV for AES is 16 bytes long
#define STRESS_BUF_LEN 1000

#define end_timer() timer_GetSafe(1, TIMER_UP)

void start_timer(void){
	timer_Disable(1);
    timer_Set(1, 0);
    timer_Enable(1, TIMER_32K, TIMER_NOINT, TIMER_UP);
}


int main(void)
{
    // reserve key schedule and key buffer, IV, and encrypt/decrypt buffers
    uint8_t salt[SALT_LEN];
    uint8_t stress_buf[STRESS_BUF_LEN];
    int time;
    hashlib_SPRNGInit();
    
    // generate some random uint32_ts
    for(uint8_t i=0; i<10; i++)
        sprintf(CEMU_CONSOLE, "The rand is %lu.\n", hashlib_SPRNGRandom());
    
    // or fill a buffer to size with random
    hashlib_RandomBytes(salt, SALT_LEN);
    strcpy(CEMU_CONSOLE, "The buffer contents are: \n");
    for(uint8_t i=0; i<SALT_LEN; i++)
        sprintf(CEMU_CONSOLE, "%02X ", salt[i]);
        
	start_timer();
	hashlib_RandomBytes(stress_buf, STRESS_BUF_LEN);
    strcpy(CEMU_CONSOLE, "\n");
    
    time = end_timer();
	sprintf(CEMU_CONSOLE, "Time taken to generate 1000 bytes of random data: %u/32768 seconds.\n", time);
    
    return 0;
    
}
