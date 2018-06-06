#include "miner.h"

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdlib.h>

#include "yescrypt/yescrypt.h"

int scanhash_yescrypt(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done, uint32_t* target, uint32_t* best_hash)
{
	uint32_t _ALIGN(64) vhash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	if (target && fulltest(ptarget,target)) {
	  printf("use aux target since easier\n");
	  ptarget = target;
	}
	printf("target:\n");
	for (int i=0; i<32; i++) {
	  printf("%02x",((unsigned char *)ptarget)[i]);
	}
	printf("\n");
	
	do {
		be32enc(&endiandata[19], n);
		yescrypt_hash((char*) endiandata, (char*) vhash, 80);
		if (vhash[7] < ptarget[7] && fulltest(vhash, ptarget)) {
		  printf("good hash with input\n");
		  for (int i=0; i<80; i++) {
		    printf("%02x",((uchar*)pdata)[i]);
		  }
		  printf("\n");
		  char * hashhex = abin2hex((unsigned char *)vhash, 32);
		  printf("hash = %s\n",hashhex);
		  free(hashhex);
		  work_set_target_ratio(work, vhash);
		  *hashes_done = n - first_nonce + 1;
		  pdata[19] = n;
		  return true;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}
