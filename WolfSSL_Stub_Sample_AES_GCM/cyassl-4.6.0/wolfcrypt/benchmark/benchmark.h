/* wolfcrypt/benchmark/benchmark.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * https://www.wolfssl.com
 */


#ifndef WOLFCRYPT_BENCHMARK_H
#define WOLFCRYPT_BENCHMARK_H


#ifdef __cplusplus
    extern "C" {
#endif

/* run all benchmark entry */
#ifdef HAVE_STACK_SIZE
THREAD_RETURN WOLFSSL_THREAD benchmark_test(void* args);
#else
int benchmark_test(void *args);
#endif

/* individual benchmarks */
int  benchmark_init(void);
int  benchmark_free(void);
void benchmark_configure(int block_size);

void bench_des(int);
void bench_idea(void);
void bench_arc4(int);
void bench_hc128(void);
void bench_rabbit(void);
void bench_chacha(void);
void bench_chacha20_poly1305_aead(void);
void bench_aescbc(int);
void bench_aesgcm(int);
void bench_aesccm(void);
void bench_aesecb(int);
void bench_aesxts(void);
void bench_aesctr(void);
void bench_aescfb(void);
void bench_aesofb(void);
void bench_poly1305(void);
void bench_camellia(void);
void bench_md5(int);
void bench_sha(int);
void bench_sha224(int);
void bench_sha256(int);
void bench_sha384(int);
void bench_sha512(int);
void bench_sha3_224(int);
void bench_sha3_256(int);
void bench_sha3_384(int);
void bench_sha3_512(int);
int  bench_ripemd(void);
void bench_cmac(void);
void bench_scrypt(void);
void bench_hmac_md5(int);
void bench_hmac_sha(int);
void bench_hmac_sha224(int);
void bench_hmac_sha256(int);
void bench_hmac_sha384(int);
void bench_hmac_sha512(int);
void bench_rsaKeyGen(int);
void bench_rsaKeyGen_size(int, int);
void bench_rsa(int);
void bench_rsa_key(int, int);
void bench_dh(int);
void bench_eccMakeKey(int);
void bench_ecc(int);
void bench_eccEncrypt(void);
void bench_curve25519KeyGen(void);
void bench_curve25519KeyAgree(void);
void bench_ed25519KeyGen(void);
void bench_ed25519KeySign(void);
void bench_curve448KeyGen(void);
void bench_curve448KeyAgree(void);
void bench_ed448KeyGen(void);
void bench_ed448KeySign(void);
void bench_ntru(void);
void bench_ntruKeyGen(void);
void bench_rng(void);
void bench_blake2b(void);
void bench_blake2s(void);
void bench_pbkdf2(void);

void bench_stats_print(void);


#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* WOLFCRYPT_BENCHMARK_H */

