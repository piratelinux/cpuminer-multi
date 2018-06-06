#include <miner.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <ar2/argon2.h>

void ar2hash(void *output, const void *input)
{
  int ret = argon2d_hash_raw(1,4096,1,input,80,input,80,output,32);
}

int scanhash_ar2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done, uint32_t* target, uint32_t* best_hash)
{
  
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) best_hash_thr[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	//printf("first_nonce = %d\n",first_nonce);
	//printf("max_nonce = %d\n",max_nonce);

	//printf("target = ");
	for (int i=7; i>=0; i--) {
	  //printf("%d ",ptarget[i]);
	}
	//printf("\n");
	char * target_hex = abin2hex((const unsigned char *)ptarget,32);
	//printf("target_hex = %s\n",target_hex);
	free(target_hex);

	if (opt_benchmark)
	  ptarget[7] = 0x0000ff;

	for (int k=0; k < 19; k++)
	  be32enc(&endiandata[k], pdata[k]);

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
	  be32enc(&endiandata[19], nonce);
	  /*printf("do ar2hash on\n");
	  for (int i=0; i<80; i++) {
	    printf("%02x",((uchar*)endiandata)[i]);
	  }
	  printf("\n");*/
	  ar2hash(hash, endiandata);
	  //char * hashhex = abin2hex((unsigned char *)hash, 32);
	  //printf("hash = %s\n",hashhex);
	  //free(hashhex);
	  if (hash[7] <= target[7] && fulltest(hash, ptarget)) {
	    printf("good hash with input\n");
	    for (int i=0; i<80; i++) {
	      printf("%02x",((uchar*)pdata)[i]);
	    }
	    printf("\n");
	    char * hashhex = abin2hex((unsigned char *)hash, 32);
	    printf("hash = %s\n",hashhex);
	    free(hashhex);
	    work_set_target_ratio(work, hash);
	    pdata[19] = nonce;
	    *hashes_done = pdata[19] - first_nonce;
	    if (target) memcpy(best_hash,hash,32);
	    return 1;
	  }
	  if (nonce==first_nonce) {
	    for (int i = 7; i >= 0; i--) {
	      best_hash_thr[i] = hash[i];
	    }
	  }
	  for (int i = 7; i >= 0; i--) {
	    if (hash[i] > best_hash_thr[i]) {
	      break;
	    }
	    if (hash[i] < best_hash_thr[i]) {
	      printf("best_hash_thr = ");
	      for (int j=7; j>=0; j--) {
		//printf("%d ",hash[j]);
		best_hash_thr[j] = hash[j];
	      }
	      for (int j=0; j<32; j++) {
		printf("%02x",((uchar*)best_hash_thr)[j]);
	      }
	      printf("\n");
	      break;
	    }
	  }
	  nonce++;

	  if (nonce % 10000 == 0) {
	    //printf("nonce = %d\n",nonce);
	  }
	  
	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
