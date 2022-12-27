#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"


const static unsigned char priv_key[] = {
    "-----BEGIN EC PRIVATE KEY-----\r\n"
    "MHQCAQEEIOWSZq9B+vOLUzeKdnjqB0hvBfgaVwIvgT8WyycFTNqAoAcGBSuBBAAK\r\n"
    "oUQDQgAEiduDHA4mt/1OUkfxisS2MVX0xsDPGKEtfNq6h+i48EkhHm+h7gONJesI\r\n"
    "asfiGFbm43XjHPjBabCszxqfBWWUoQ==\r\n"
    "-----END EC PRIVATE KEY-----\r\n"
};

const static unsigned char hash[] = {
    0x48, 0xd2, 0xb6, 0x75, 0xc8, 0xfa, 0xc1, 0xd7,
    0x8e, 0x42, 0xcb, 0xcc, 0xd9, 0x16, 0x8b, 0x6c,
    0x8a, 0x62, 0xa2, 0x06, 0x21, 0x71, 0x7f, 0x59,
    0xf4, 0x87, 0x62, 0x32, 0xbb, 0x8f, 0x03, 0xa7,
};

int main(void)
{
    fprintf(stdout, "sign start\n");
    mbedtls_pk_context       prikCtx;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char sig[1024];
    size_t        sig_len;
    int ret;
    const char *pers = "mbedtls_pk_sign";

    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_pk_init( &prikCtx );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        fprintf(stdout, " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int) -ret );
        goto exit;
    }
    
    if ( ( ret = mbedtls_pk_parse_key(&prikCtx, priv_key, sizeof(priv_key), NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg) ) != 0 )
    {
        fprintf(stdout, " failed\n  ! mbedtls_pk_parse_key returned -0x%04x\n", (unsigned int) -ret );
        goto exit;
    }

    if ( (ret = mbedtls_pk_sign(&prikCtx, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sizeof(sig), &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg) ) != 0 )
    {
        fprintf(stdout, " failed\n  ! mbedtls_pk_sign returned -0x%04x\n", (unsigned int) -ret );
        goto exit;
    }

    fprintf(stdout, "\nsig len=%ld\n", sig_len);
    fprintf(stdout, "\n---------sig---------\n");
    for (int i=0; i<sig_len; i++)
    {
        if (i % 16 == 0) fprintf(stdout, "\n");
        fprintf(stdout, "0x%02x ", sig[i]);
    }
    fprintf(stdout, "\n=========sig=========\n");
    fprintf(stdout, "sign success\n");

exit:
    mbedtls_pk_free( &prikCtx );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return ret;
}