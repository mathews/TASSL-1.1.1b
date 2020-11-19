/* 
Written by caichenghang for the TaSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 - 2018 Beijing JN TASS Technology Co.,Ltd.  All
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by Beijing JN TASS
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * 4. The name "TaSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    TaSSL@tass.com.cn.
 *
 * 5. Products derived from this software may not be called "TaSSL"
 *    nor may "TaSSL" appear in their names without prior written
 *    permission of the TaSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Beijing JN TASS
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE TASSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE TASSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes software developed by the TaSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#ifndef GU_NO_DEBUG
#define DEBUG_CHAR_HEX(buf_ptr, buf_len) \
		 printf("\n%s=[",#buf_ptr);\
		for(i = 0; i<(buf_len); i++){\
			printf("%02X", *((unsigned char *)(buf_ptr)+i));\
		}\
		printf("]\n");

#else
#define DEBUG_CHAR_HEX(buf_ptr, buf_len)
#endif

/**
 *  convert a string to base16 binary.
 *  @return converted char number
 */
 
int b2s(char *bin, char *outs)
{
        int i = 0;
        char tmpbuf[4];
        int iRet = 0;
        char *ptr = bin;
        for(i = 0; i<strlen(bin)/2; i++){
                memset(tmpbuf, 0x00, sizeof(tmpbuf));
                memcpy(tmpbuf, ptr, 2);
                ptr += 2;
                iRet = strtol(tmpbuf, NULL, 16);
                #ifndef NO_DEBUG
                //printf("the iRet =[%d]\n", iRet);
                #endif
                
                memset(outs++, iRet, 1);
        }
        return i;
}

void read_whole_file(char fileName[1000], char buffer[3072])
{
    FILE * file = fopen(fileName, "r");
    if(file == NULL)
    {
        puts("File not found");
        exit(1);
    }
    char  c;
    int idx=0;
    while (fscanf(file , "%c" ,&c) == 1)
    {
        buffer[idx] = c;
        idx++;
    }
    buffer[idx] = 0;
}

EC_KEY *CalculateKey(const EC_GROUP *ec_group, const char *privkey_hex_string)
{
    EC_KEY *ec_key = NULL;
    EC_POINT *pubkey = NULL;
    BIGNUM *privkey = NULL;

    if (!BN_hex2bn(&privkey, (const char *)privkey_hex_string)) return NULL;
    if ((pubkey = EC_POINT_new(ec_group)) == NULL) goto err;
    if (!ec_key)
    {
        ec_key = EC_KEY_new();
        if (!ec_key) goto err;
        if (!EC_KEY_set_group(ec_key, ec_group))
        {
            EC_KEY_free(ec_key);
            ec_key = NULL;
            goto err;
        }
    }

    if (!EC_POINT_mul(ec_group, pubkey, privkey, NULL, NULL, NULL))
    {
        EC_KEY_free(ec_key);
        ec_key = NULL;
        goto err;
    }

    if (!EC_KEY_set_private_key(ec_key, privkey) || !EC_KEY_set_public_key(ec_key, pubkey))
    {
        EC_KEY_free(ec_key);
        ec_key = NULL;
        goto err;
    }

err:
    if (privkey) BN_free(privkey);
    if (pubkey) EC_POINT_free(pubkey);

    return ec_key;
}

EC_KEY *CalcSm2PublicKey(const char *pubkey_hex_string, char* private_hex_x)
{

                int bn_len = 0;
    char raw_buf[128] ={0};
    BIGNUM *k = NULL;


    EC_KEY *ec_key = NULL;
    EC_POINT *pubkey = NULL;
    EC_GROUP *ec_group = NULL;

    ec_group = EC_GROUP_new_by_curve_name(OBJ_sn2nid("SM2"));
    if (ec_group == NULL)
        goto err;
    printf("ec_group\n");

     EC_POINT *ecp =NULL;

    pubkey = EC_POINT_hex2point(ec_group, (const char *)pubkey_hex_string, ecp, NULL);
    if (!pubkey)
        goto err;
    printf("EC_POINT_hex2point\n");

    ec_key = EC_KEY_new();
    if (!ec_key) goto err;
    printf("EC_KEY_new\n");

    if (!EC_KEY_set_group(ec_key, ec_group))
    {
        EC_KEY_free(ec_key);
        ec_key = NULL;
        goto err;
    }
     printf("EC_KEY_set_group\n");

    if (!EC_KEY_set_public_key(ec_key, pubkey))
    {
        EC_KEY_free(ec_key);
        ec_key = NULL;
        goto err;
    }
     printf("EC_KEY_set_public_key\n");
   
    if(private_hex_x != NULL){
        bn_len = b2s((char *)private_hex_x, raw_buf);
        printf("bn_len = [%d]\n", bn_len);

        k = BN_new();
        if(BN_bin2bn((const unsigned char*)raw_buf, bn_len, k) == NULL){
                        printf("bin2bn fail!\n");
                        exit(0);

        }


        if (!EC_KEY_set_private_key(ec_key, k))
        {
            EC_KEY_free(ec_key);
            ec_key = NULL;
            goto err;
        }

    }



err:
    if (pubkey) EC_POINT_free(pubkey);
    if (ec_group) EC_GROUP_free(ec_group);

    return ec_key;
}

EVP_PKEY *ReadEvpKeyFromPem(char fileName[1000]){
    EVP_PKEY *pkey = NULL;
    BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  int ret;

     OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the certificate from file (PEM).                      *
   * ---------------------------------------------------------- */
  ret = BIO_read_filename(certbio, fileName);
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading cert into memory\n");
    exit(-1);
  }

  /* ---------------------------------------------------------- *
   * Extract the certificate's public key data.                 *
   * ---------------------------------------------------------- */
  if ((pkey = X509_get_pubkey(cert)) == NULL)
    BIO_printf(outbio, "Error getting public key from certificate");

    return pkey;
}

EC_KEY *CalculatePubKey(const EC_GROUP *ec_group, const char *pub_hex_string)
{
    EC_KEY *ec_key = NULL;
    EC_POINT *pubkey = NULL;

    if ((pubkey = EC_POINT_new(ec_group)) == NULL) goto err;
    if (!EC_POINT_hex2point(ec_group, pub_hex_string, pubkey, NULL)) goto err;
    
    if (!ec_key)
    {
        ec_key = EC_KEY_new();
        if (!ec_key) goto err;
        if (!EC_KEY_set_group(ec_key, ec_group))
        {
            EC_KEY_free(ec_key);
            ec_key = NULL;
            goto err;
        }
    }

    if (!EC_KEY_set_public_key(ec_key, pubkey))
    {
        EC_KEY_free(ec_key);
        ec_key = NULL;
        goto err;
    }

err:
    if (pubkey) EC_POINT_free(pubkey);

    return ec_key;
}

int main(int argc, char *argv[])
{
    EC_KEY *sm2key = NULL;
    EC_GROUP *sm2group = NULL;
    size_t outlen;
    unsigned char *out = NULL;
    int retval, i;
    char ciphertext_buf[1024] = {0};
    size_t ciphertext_len = 0;


    if (argc < 4)
    {
        printf("Usage: \n\t%s e|E sm2pubkey text\n", argv[0]);
        printf("\t%s d|D sm2privatekey hex_ciphertext\n", argv[0]);
        return 0;
    }
    
    sm2group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (!sm2group)
    {
        goto err;
    }
    
    if (!strcasecmp(argv[1], "E"))
    {
        /*Encrypt*/
        // char cert_buf[3072] = {0};
        // read_whole_file(argv[2],cert_buf);
        // printf("certs: %s", cert_buf);
        // char cert_buf[] = "0488401CB3995DEBAEC11B891992C7E83675359D4A2C910EFF25DA17928B263B1E8D919A63AE4EED467E57DE41EAB96ED5085850BCEF0B480C5929CB3F1F1DDFE4";
        // sm2key = CalcSm2PublicKey(cert_buf, NULL);
        EVP_PKEY *eKey = ReadEvpKeyFromPem(argv[2]);
        if(eKey){
            sm2key = EVP_PKEY_get1_EC_KEY(eKey);
        }
        if (!sm2key)
        {
            printf("Error Of Calculate SM2 Public Key.\n");
            goto err;
        }
     
	    //sm2enc = sm2_encrypt((const unsigned char *)argv[3], (size_t)strlen(argv[3]), NULL/*EVP_sm3()*/, sm2key);
	    retval = sm2_encrypt(sm2key, EVP_sm3(), argv[3], strlen(argv[3]), ciphertext_buf, (size_t *)&ciphertext_len);
	    if (!retval)
        {
            printf("Error Of calculate cipher text length.\n");
            goto err;
        }
	    
	    
	  DEBUG_CHAR_HEX(ciphertext_buf, ciphertext_len);
	  exit(0);
	  
    }
    else if (!strcasecmp(argv[1], "D"))
    {
        unsigned char *in = NULL;
        size_t inlen = strlen(argv[3]) / 2;
        
        /*Decrypt*/
         char cert_buf[3072] = {0};
        read_whole_file(argv[2],cert_buf);
        sm2key = CalculateKey((const EC_GROUP *)sm2group, cert_buf);
        if (!sm2key)
        {
            printf("Error Of Calculate SM2 Private Key.\n");
            goto err;
        }
        
        in = OPENSSL_malloc(inlen);
        if (!in)
        {
            printf("Error Of Alloc Memory.\n");
            goto err;
        }
        
        ciphertext_len = b2s(argv[3], in);
	unsigned char ptext_buf[1024] = {0};
        size_t ptext_len = 0;

          retval = sm2_decrypt(sm2key, EVP_sm3(), in, ciphertext_len, ptext_buf, &ptext_len);
                if (!retval)
          {
              printf("Error Of sm2_decrypt.\n");
              goto err;
          }
          DEBUG_CHAR_HEX(ptext_buf, ptext_len);

    }
    else
    {
        printf("Error Of Option.\n");
    }
err:
    if (sm2group) EC_GROUP_free(sm2group);
    if (sm2key) EC_KEY_free(sm2key);
    if (out) OPENSSL_free(out);
    
	return 0;
}
