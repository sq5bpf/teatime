/* TEAtime v0.1 TEA1 short key recovery 
 * Jacek Lipkowski <sq5bpf@lipkowski.org>
 *
 * This is a very simple/naiive TEA1 short key recovery implementation.
 * It will just assume that the first 32 bits for some type2 frame are the same
 * if they belong to the same address.
 * So it finds the short key for which keystream1^frame1==keystream2^frame2
 *
 * But to save time, i do a simple trick: calculate x=frame1^frame2, and
 * then find the short key for which (keystream1^keystream2)==x.
 * This is equivalent to the above but faster.
 *
 * The TEA1 part contains mostly crypto/tea1.c and also random other stuff
 * copy-pasted from osmo-tetra, so the license is same as the tea1.c 
 * file: AGPL-3.0.
 *
 * Example keys taken from https://github.com/hassanTripleA/tea_crack_CT/ ,
 * which has since disappeared. And also it required an nvidia gpu and
 * i could not get it to work.
 * 
 */

/************  begining of copied osmo-tetra stuff *************/

/* TETRA TEA1 keystream generator implementation */
/*
 * Copyright (C) 2023 Midnight Blue B.V.
 *
 * Author: Wouter Bokslag <w.bokslag [ ] midnightblue [ ] nl>
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * NOTE: this has been patched from the original to support
 * 32bit TEA1 short key and interfacing with telive
 * Please don't bug the original authors about bugs resulting from these modifications
 * Jacek Lipkowski <sq5bpf@lipkowski.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * See the COPYING file in the main directory for details.
 */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include "tea1.h"

#include<pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>


const uint16_t g_awTea1LutA[8] = { 0xDA86, 0x85E9, 0x29B5, 0x2BC6, 0x8C6B, 0x974C, 0xC671, 0x93E2 };
const uint16_t g_awTea1LutB[8] = { 0x85D6, 0x791A, 0xE985, 0xC671, 0x2B9C, 0xEC92, 0xC62B, 0x9C47 };
const uint8_t g_abTea1Sbox[256] = {
	0x9B, 0xF8, 0x3B, 0x72, 0x75, 0x62, 0x88, 0x22, 0xFF, 0xA6, 0x10, 0x4D, 0xA9, 0x97, 0xC3, 0x7B,
	0x9F, 0x78, 0xF3, 0xB6, 0xA0, 0xCC, 0x17, 0xAB, 0x4A, 0x41, 0x8D, 0x89, 0x25, 0x87, 0xD3, 0xE3,
	0xCE, 0x47, 0x35, 0x2C, 0x6D, 0xFC, 0xE7, 0x6A, 0xB8, 0xB7, 0xFA, 0x8B, 0xCD, 0x74, 0xEE, 0x11,
	0x23, 0xDE, 0x39, 0x6C, 0x1E, 0x8E, 0xED, 0x30, 0x73, 0xBE, 0xBB, 0x91, 0xCA, 0x69, 0x60, 0x49,
	0x5F, 0xB9, 0xC0, 0x06, 0x34, 0x2A, 0x63, 0x4B, 0x90, 0x28, 0xAC, 0x50, 0xE4, 0x6F, 0x36, 0xB0,
	0xA4, 0xD2, 0xD4, 0x96, 0xD5, 0xC9, 0x66, 0x45, 0xC5, 0x55, 0xDD, 0xB2, 0xA1, 0xA8, 0xBF, 0x37,
	0x32, 0x2B, 0x3E, 0xB5, 0x5C, 0x54, 0x67, 0x92, 0x56, 0x4C, 0x20, 0x6B, 0x42, 0x9D, 0xA7, 0x58,
	0x0E, 0x52, 0x68, 0x95, 0x09, 0x7F, 0x59, 0x9C, 0x65, 0xB1, 0x64, 0x5E, 0x4F, 0xBA, 0x81, 0x1C,
	0xC2, 0x0C, 0x02, 0xB4, 0x31, 0x5B, 0xFD, 0x1D, 0x0A, 0xC8, 0x19, 0x8F, 0x83, 0x8A, 0xCF, 0x33,
	0x9E, 0x3A, 0x80, 0xF2, 0xF9, 0x76, 0x26, 0x44, 0xF1, 0xE2, 0xC4, 0xF5, 0xD6, 0x51, 0x46, 0x07,
	0x14, 0x61, 0xF4, 0xC1, 0x24, 0x7A, 0x94, 0x27, 0x00, 0xFB, 0x04, 0xDF, 0x1F, 0x93, 0x71, 0x53,
	0xEA, 0xD8, 0xBD, 0x3D, 0xD0, 0x79, 0xE6, 0x7E, 0x4E, 0x9A, 0xD7, 0x98, 0x1B, 0x05, 0xAE, 0x03,
	0xC7, 0xBC, 0x86, 0xDB, 0x84, 0xE8, 0xD1, 0xF7, 0x16, 0x21, 0x6E, 0xE5, 0xCB, 0xA3, 0x1A, 0xEC,
	0xA2, 0x7D, 0x18, 0x85, 0x48, 0xDA, 0xAA, 0xF0, 0x08, 0xC6, 0x40, 0xAD, 0x57, 0x0D, 0x29, 0x82,
	0x7C, 0xE9, 0x8C, 0xFE, 0xDC, 0x0F, 0x2D, 0x3C, 0x2E, 0xF6, 0x15, 0x2F, 0xAF, 0xE1, 0xEB, 0x3F,
	0x99, 0x43, 0x13, 0x0B, 0xE0, 0xA5, 0x12, 0x77, 0x5D, 0xB3, 0x38, 0xD9, 0xEF, 0x5A, 0x01, 0x70};

/* speedup: lookup tables replacing tea1_state_word_to_newbyte /
 * tea1_reorder_state_byte in the hot path (filled by tea1_build_tables) */
uint8_t tea1_lutA[65536];
uint8_t tea1_lutB[65536];
uint8_t tea1_reord[256];

uint64_t tea1_expand_iv(uint32_t dwShortIv)
{
	uint32_t dwXorred = dwShortIv ^ 0x96724FA1;
	dwXorred = (dwXorred << 8) | (dwXorred >> 24);
	uint64_t qwIv = ((uint64_t)dwShortIv << 32) | dwXorred;
	return (qwIv >> 8) | (qwIv << 56);
}

uint8_t tea1_state_word_to_newbyte(uint16_t wSt, const uint16_t *awLut)
{
	uint8_t bSt0 = wSt;
	uint8_t bSt1 = wSt >> 8;
	uint8_t bDist;
	uint8_t bOut = 0;

	for (int i = 0; i < 8; i++) {
		/* taps on bit 7,0 for bSt0 and bit 1,2 for bSt1 */
		bDist = ((bSt0 >> 7) & 1) | ((bSt0 << 1) & 2) | ((bSt1 << 1) & 12);
		if (awLut[i] & (1 << bDist))
			bOut |= 1 << i;

		/* rotate one position */
		bSt0 = ((bSt0 >> 1) | (bSt0 << 7));
		bSt1 = ((bSt1 >> 1) | (bSt1 << 7));
	}

	return bOut;
}

uint8_t tea1_reorder_state_byte(uint8_t bStByte)
{
	/* simple re-ordering of bits */
	uint8_t bOut = 0;
	bOut |= ((bStByte << 6) & 0x40);
	bOut |= ((bStByte << 1) & 0x20);
	bOut |= ((bStByte << 2) & 0x08);
	bOut |= ((bStByte >> 3) & 0x14);
	bOut |= ((bStByte >> 2) & 0x01);
	bOut |= ((bStByte >> 5) & 0x02);
	bOut |= ((bStByte << 4) & 0x80);
	return bOut;
}

/* speedup: precompute the two state functions into lookup tables.
 * Call once at startup before cracking. */
void tea1_build_tables(void)
{
	for (uint32_t w = 0; w < 65536; w++) {
		tea1_lutA[w] = tea1_state_word_to_newbyte(w, g_awTea1LutA);
		tea1_lutB[w] = tea1_state_word_to_newbyte(w, g_awTea1LutB);
	}
	for (uint32_t b = 0; b < 256; b++)
		tea1_reord[b] = tea1_reorder_state_byte(b);
}

int32_t tea1_init_key_register(const uint8_t *lpKey)
{
	int32_t dwResult = 0;
	for (int i = 0; i < 10; i++)
		dwResult = (dwResult << 8) | g_abTea1Sbox[((dwResult >> 24) ^ lpKey[i] ^ dwResult) & 0xff];

	return dwResult;
}

void tea1_inner(uint64_t qwIvReg, uint32_t dwKeyReg, uint32_t dwNumKsBytes, uint8_t *lpKsOut)
{
	uint32_t dwNumSkipRounds = 54;

	for (int i = 0; i < dwNumKsBytes; i++) {
		for (int j = 0; j < dwNumSkipRounds; j++) {
			/* Step 1: Derive a non-linear feedback byte through sbox and feed back into key register */
			uint8_t bSboxOut = g_abTea1Sbox[((dwKeyReg >> 24) ^ dwKeyReg) & 0xff];
			dwKeyReg = (dwKeyReg << 8) | bSboxOut;

			/* Step 2: Compute 3 bytes derived from current state */
			uint8_t bDerivByte12 = tea1_state_word_to_newbyte((qwIvReg >>  8) & 0xffff, g_awTea1LutA);
			uint8_t bDerivByte56 = tea1_state_word_to_newbyte((qwIvReg >> 40) & 0xffff, g_awTea1LutB);
			uint8_t bReordByte4  = tea1_reorder_state_byte((qwIvReg >> 32) & 0xff);

			/* Step 3: Combine current state with state derived values, and xor in key derived sbox output */
			uint8_t bNewByte = (bDerivByte56 ^ (qwIvReg >> 56) ^ bReordByte4 ^ bSboxOut) & 0xff;
			uint8_t bMixByte = bDerivByte12;

			/* Step 4: Update lfsr: leftshift 8, feed/mix in previously generated bytes */
			qwIvReg = ((qwIvReg << 8) ^ ((uint64_t)bMixByte << 32)) | bNewByte;
		}

		lpKsOut[i] = (qwIvReg >> 56);
		dwNumSkipRounds = 19;
	}
}

void tea1(uint32_t dwFrameNumbers, const uint8_t *lpKey, uint32_t dwNumKsBytes, uint8_t *lpKsOut, uint32_t short_key)
{
	/* Initialize IV and key register */
	uint64_t qwIvReg = tea1_expand_iv(dwFrameNumbers);
	uint32_t dwKeyReg;
	/* short key is the 32-bits of the key shortened by the key weakening function */
	if (short_key) {
		dwKeyReg=short_key;
	} else {
		dwKeyReg = tea1_init_key_register(lpKey);
	}
	//printf("SQ5BPF: TEA1 using key 0x%8.8x\n",dwKeyReg);
	/* Invoke actual TEA1 core function */
	tea1_inner(qwIvReg, dwKeyReg, dwNumKsBytes, lpKsOut);
}

struct tetra_tdma_time {
	uint16_t hn;    /* hyperframe number (1 ... 65535) */
	uint32_t sn;    /* symbol number (1 ... 255) */
	uint32_t tn;    /* timeslot number (1 .. 4) */
	uint32_t fn;    /* frame number (1 .. 18) */
	uint32_t mn;    /* multiframe number (1 .. 60) */
};


uint32_t tea_build_iv(struct tetra_tdma_time *tm, uint16_t hn, uint8_t dir)
{
	assert(1 <= tm->tn  && tm->tn  <= 4);
	assert(1 <= tm->fn  && tm->fn  <= 18);
	assert(1 <= tm->mn  && tm->mn  <= 60);
	assert(0 <= tm->hn  && tm->hn  <= 0xFFFF);
	assert(0 <= dir && dir <= 1); // 0 = downlink, 1 = uplink
	return ((tm->tn - 1) | (tm->fn << 2) | (tm->mn << 7) | ((hn & 0x7FFF) << 13) | (dir << 28));
}

/************  end of osmo-tetra stuff *************/

/************ begining of teatime stuff ************/
#define VERSION "0.1"

volatile int completed=0;
uint64_t eiv1,eiv2;
uint32_t xorct;
uint8_t xorctb[4];	/* xorct as bytes, for per-byte early-out */
int num_threads=0;

struct arg_struct { 
	uint32_t start;
	uint32_t stop;
	int thread;
};

/* speedup: test one short key against both frames.
 * The key register (sbox chain) evolves identically for both IVs, so it is
 * computed once and used to drive both IV registers in lockstep. The state
 * functions are table lookups, and we reject on the first keystream byte that
 * differs instead of always generating all 4 bytes. Equivalent to the original
 * (kss1^kss2)==xorct test. Returns non-zero on a match. */
static inline uint32_t fast_match(uint32_t short_key)
{
	uint64_t iv1 = eiv1, iv2 = eiv2;
	uint32_t keyreg = short_key;
	uint32_t skip = 54;

	for (int i = 0; i < 4; i++) {
		for (uint32_t j = 0; j < skip; j++) {
			uint8_t s = g_abTea1Sbox[((keyreg >> 24) ^ keyreg) & 0xff];
			keyreg = (keyreg << 8) | s;

			uint8_t n1 = tea1_lutB[(iv1 >> 40) & 0xffff] ^ (iv1 >> 56)
				   ^ tea1_reord[(iv1 >> 32) & 0xff] ^ s;
			iv1 = ((iv1 << 8) ^ ((uint64_t)tea1_lutA[(iv1 >> 8) & 0xffff] << 32)) | n1;

			uint8_t n2 = tea1_lutB[(iv2 >> 40) & 0xffff] ^ (iv2 >> 56)
				   ^ tea1_reord[(iv2 >> 32) & 0xff] ^ s;
			iv2 = ((iv2 << 8) ^ ((uint64_t)tea1_lutA[(iv2 >> 8) & 0xffff] << 32)) | n2;
		}
		if ((uint8_t)((iv1 >> 56) ^ (iv2 >> 56)) != xorctb[i])
			return 0;	/* this keystream byte already differs */
		skip = 19;
	}
	return 1;
}

void *bruteforce(void *arg) {

	uint32_t short_key;
	struct arg_struct *args = (struct arg_struct *)arg;
	uint32_t tid=args->thread;
	uint32_t tstart=args->start;
	uint32_t tstop=args->stop;
	uint32_t jobsize=tstop-tstart;
	time_t time_start,time_diff;
	int64_t perc,speed,eta;

	time_start=time(0);
	speed=0;
	eta=0;

	printf("[%2i] Starting thread  , %8.8x - %8.8x\n",tid,tstart,tstop);
	short_key=args->start;
	while(1) {
		if ((short_key&0x0000ffff)==0) {
			if (completed) break;
			if ((short_key&0x000fffff)==0) { 
				time_diff=time(0)-time_start;
				perc=(short_key-tstart)*(int64_t)100/jobsize;
				if (time_diff) {
					speed=(int64_t)(short_key-tstart)/time_diff;
					eta=(int64_t)(tstop-short_key)/speed;
				}
				printf("[%2i] %8.8x-%8.8x doing key %8.8x  speed:%li keys/s  done:%i%%  eta:%li s\n",tid,tstart,tstop,short_key,speed*num_threads,(int)perc,eta);
			}
		}
		if (fast_match(short_key)) {
			printf("\n!!!!!!!!!!!!!!!!   found key: %8.8x   !!!!!!!!!!!!!!!!\n\n",short_key);
			completed=1;
			break;
		}
		if (short_key==args->stop) {
			completed=1;
			break;
		}
		short_key++;
	}
}

void helpme() {
	printf("TEAtime " VERSION " TEA1 short key recovery\n");
	printf("(c) Jacek Lipkowski <sq5bpf@lipkowski.org>\n");

	printf("\nUsage:\n");
	printf("./teatime c hn1 mn1 fn1 tn1 ud1 ct1 hn2 mn2 fn2 tn2 ud2 ct2  - crack mode, takes data from two frames, calculates 32bit key and keystream xor cipertext\n");
	printf("./teatime v hn1 mn1 fn1 tn1 ud1 ct1 short_key                - verify mode, takes data from one frame and 32bit key, shows keystream xor cipertext\n");
	printf("hn - hyperframe number\nmn - multiframe number\ntn - frame number\nud - 0 - downlink, 1 uplink\nct - first 32 bits of ciphertext as hex\nshort_key - 32 bit TEA1 short key as hex\n");
	printf("\n\nExample test vectors:\n");
	printf("./teatime c 110 30 6 1 0 151ef027 110 30 7 1 0 4d00159e - crack and get key 00000111\n");
	printf("./teatime v 110 30 6 1 0 151ef027 00000111  or  ./teatime v 110 30 7 1 0 4d00159e 00000111 - verify ciphertext xor keystream is the same\n");
}

#define MODE_UNKNOWN 0
#define MODE_CRACK 1
#define MODE_VERIFY 2

int main(int argc,char **argv) {

	struct tetra_tdma_time t1,t2;
	uint8_t eck[10];
	uint32_t ct1;
	uint32_t ct2;
	int opt;

	int mode=MODE_UNKNOWN;
	int narg=0;

#ifdef _SC_NPROCESSORS_ONLN
	num_threads = sysconf(_SC_NPROCESSORS_ONLN);
#endif


	if (argc<2) { helpme(); exit(0); }

	if (strcmp(argv[1],"c")==0) { mode=MODE_CRACK; narg=14; } 
	else if (strcmp(argv[1],"v")==0) { mode=MODE_VERIFY; narg=9; } 

	if ((mode==MODE_UNKNOWN)||(argc<narg)) { helpme(); exit(0); }

	printf("TEAtime " VERSION " TEA1 short key recovery\n");

	if (getenv("NPROC")) num_threads=atoi(getenv("NPROC"));
	if (!num_threads) num_threads=8;



	t1.hn=atoi(argv[2]);
	t1.mn=atoi(argv[3]);
	t1.fn=atoi(argv[4]);
	t1.tn=atoi(argv[5]);
	int dir1=atoi(argv[6]);
	ct1=strtol(argv[7], NULL, 16);

	uint32_t iv1=tea_build_iv(&t1,t1.hn,dir1);
	eiv1 = tea1_expand_iv(iv1);

	if (mode==MODE_CRACK)
	{
		printf("Running %i threads in parallel\n\n",num_threads);
		t2.hn=atoi(argv[8]);
		t2.mn=atoi(argv[9]);
		t2.fn=atoi(argv[10]);
		t2.tn=atoi(argv[11]);
		int dir2=atoi(argv[12]);
		ct2=strtol(argv[13], NULL, 16);

		uint32_t iv2=tea_build_iv(&t2,t2.hn,dir2);
		eiv2 = tea1_expand_iv(iv2);

		//printf("iv1: %8.8x iv2: %8.8x\n",iv1,iv2);

		xorct=htonl(ct1^ct2);
		memcpy(xorctb,&xorct,4);	/* byte view for early-out */
		tea1_build_tables();		/* fill lookup tables once */

		pthread_t some_thread;
		struct arg_struct args;

		uint64_t jobsize=0x100000000/num_threads; 
		pthread_t *bruteforce_threads=malloc(num_threads*sizeof(pthread_t));

		uint32_t start=0;
		uint32_t stop=jobsize-1;
		int i;

		for (i=0;i<num_threads;i++) {
			struct arg_struct *args;

			args=malloc(sizeof(struct arg_struct));
			args->start=start;
			args->stop=stop;
			if ((i+1)==num_threads) args->stop=0xffffffff;
			args->thread=i;

			stop=stop+jobsize;
			start=start+jobsize;

			int result;
			if (!completed) result = pthread_create(&(bruteforce_threads[i]), NULL, bruteforce, (void *)args);
			if (result != 0) {
				perror("Could not create thread.");
			}

		}

		for (i=0;i<num_threads;i++) {
			pthread_join(bruteforce_threads[i], NULL);
		}

		if (completed) printf("completed!\n");
	}
	else if (mode==MODE_VERIFY) {
		uint32_t short_key=strtol(argv[8], NULL, 16);
		uint32_t kss1,kss2;
		tea1_inner(eiv1, short_key, 4, (uint8_t *)&kss1);
		kss2=ntohl(kss1);
		printf("\nkey:%8.8x keystream:%8.8x ciphertext^keystream:%8.8x\n",short_key,kss2,ct1^kss2);

	}


}
