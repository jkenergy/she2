// Test vectors for security module
//
// Copyright (C) 2016-2022 Canis Automotive Labs Ltd.
//
// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt
//
// Additional AEAD and KDF support Copyright (C) 2024 JK Energy Ltd.
//
// Compile this with:
//
// cc vectors.c ../swshe/libswshe.a -o vectors
//
// (libswshe.a is the library containing the software emulated SHE HSM)

#ifndef EMBEDDED
#include <stdio.h>
#endif

#include <stdint.h>
#include <stdlib.h>

// This vector test will check that the HSM library for a software HSM (with or without hardware
// acceleration) implements the test vectors properly.

// HSM API
#include "../she.h"
#include "../nvram.h"

#ifndef EMBEDDED
void printf_bytes(const uint8_t *b, size_t l)
{
    for (uint32_t i = 0; i < l; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

void printf_block(sm_block_t *block)
{
    uint8_t *b = (uint8_t *)(block->words);

    printf_bytes(b, 16U);
}

void printf_she_errorcode_t(she_errorcode_t code)
{
    switch (code) {
        case SHE_ERC_NO_ERROR:
            printf("SHE_ERC_NO_ERROR\n");
            break;
        case SHE_ERC_SEQUENCE_ERROR:
            printf("SHE_ERC_SEQUENCE_ERROR\n");
            break;
        case SHE_ERC_KEY_NOT_AVAILABLE:
            printf("SHE_ERC_KEY_NOT_AVAILABLE\n");
            break;
        case SHE_ERC_KEY_INVALID:
            printf("SHE_ERC_KEY_INVALID\n");
            break;
        case SHE_ERC_KEY_EMPTY:
            printf("SHE_ERC_KEY_EMPTY\n");
            break;
        case SHE_ERC_MEMORY_FAILURE:
            printf("SHE_ERC_MEMORY_FAILURE\n");
            break;
        case SHE_ERC_BUSY:
            printf("SHE_ERC_BUSY\n");
            break;
        case SHE_ERC_GENERAL_ERROR:
            printf("SHE_ERC_GENERAL_ERROR\n");
            break;
        case SHE_ERC_KEY_WRITE_PROTECTED:
            printf("SHE_ERC_KEY_WRITE_PROTECTED\n");
            break;
        case SHE_ERC_KEY_UPDATE_ERROR:
            printf("SHE_ERC_KEY_UPDATE_ERROR\n");
            break;
        case SHE_ERC_RNG_SEED:
            printf("SHE_ERC_RNG_SEED\n");
            break;
        case SHE_ERC_CTX_INVALID:
            printf("SHE_ERC_CTX_INVALID\n");
            break;
        case SHE_ERC_CTX_EMPTY:
            printf("SHE_ERC_CTX_EMPTY\n");
            break;
        case SHE_ERC_SIZE:
            printf("SHE_ERC_SIZE\n");
            break;
        default:
            printf("UNKNOWN ERROR CODE\n");
            break;
    }
}
#endif // EMBEDDED

bool bytes_equals(uint8_t *a, uint8_t *b, size_t l)
{
    for (size_t i = 0; i < l; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

bool block_equals(sm_block_t *a, sm_block_t *b)
{
    return bytes_equals(a->bytes, b->bytes, 16U);
}

#ifdef EMBEDDED
volatile uint32_t sm_breakpoint = 0; // Declared so that the compiler won't optimize away
#endif

// Test platform is OK
void test1(void)
{
    she_errorcode_t rc;
    rc = sm_platform_check();
    if (rc) {
 #ifdef EMBEDDED
        // In an embedded system, put a breakpoint here in this infinite loop to see a fail
        for(;;)
            sm_breakpoint++;
 #else       
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }
}

// Test AES encrypt and decrypt against standard test vectors
void test2(void)
{
    she_errorcode_t rc;

    // Set this key to 000102030405060708090a0b0c0d0e0f
    sm_block_t key = {.bytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}};

    // Set this plaintext to 00112233445566778899aabbccddeeff
    sm_block_t plaintext = {.bytes = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};

    // Expected ciphertext is 69c4e0d86a7b0430d8cdb78070b4c55a
    sm_block_t expected_ciphertext = {.bytes = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 
                                                0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}};

#ifndef EMBEDDED
    printf("Testing AES encrypt and decrypt\n");
    printf("===============================\n");
    printf("Key:                 ");
    printf_block(&key);
    printf("Plaintext:           ");
    printf_block(&plaintext);
    printf("Expected ciphertext: ");
    printf_block(&expected_ciphertext);
#endif

    sm_sw_nvram_backdoor_set_key(SHE_KEY_2, &key, 0);

    sm_block_t ciphertext;
    sm_init_rng();
    rc = sm_enc_ecb(SHE_KEY_2, &plaintext, &ciphertext);
    if (rc) {
#ifdef EMBEDDED 
        for(;;)
            sm_breakpoint++;
#else    
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }

#ifndef EMBEDDED
    printf("Actual ciphertext:   ");
    printf_block(&ciphertext);
#endif

    // Decrypt back to new plaintext
    sm_block_t plaintext2;

    rc = sm_dec_ecb(SHE_KEY_2, &ciphertext, &plaintext2);
    if (rc) {
#ifdef EMBEDDED 
        for(;;)
        ;  
#else    
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }

#ifndef EMBEDDED
    printf("Plaintext:           ");
    printf_block(&plaintext2);
#endif

    if (!block_equals(&plaintext, &plaintext2)) {
#ifdef EMBEDDED 
        for(;;)
            sm_breakpoint++; 
#else    
        printf("TEST FAILED: plaintext round trip failed\n");
        exit(1);
#endif
    }
}

typedef union {uint8_t bytes[16]; uint32_t word;} bytes16_t;
typedef union {uint8_t bytes[32]; uint32_t word;} bytes32_t;

// Test CMAC vectors
void test3(void)
{
#ifndef EMBEDDED
    printf("Testing CMAC checks\n");
    printf("===================\n");
#endif

    she_errorcode_t rc;

    sm_block_t cmac_key = {.bytes = {0x2b, 0x7e, 0x15, 0x16,
                                     0x28, 0xae, 0xd2, 0xa6,
                                     0xab, 0xf7, 0x15, 0x88,
                                     0x09, 0xcf, 0x4f, 0x3c}};

    sm_sw_nvram_backdoor_set_key(SHE_KEY_3, &cmac_key, SHE_FLAG_KEY_USAGE);

    bytes16_t message1 = {.bytes = {0x6b, 0xc1, 0xbe, 0xe2,                        
                                    0x2e, 0x40, 0x9f, 0x96,
                                    0xe9, 0x3d, 0x7e, 0x11,
                                    0x73, 0x93, 0x17, 0x2a}};

    sm_block_t mac;
    sm_init_rng();

#ifndef EMBEDDED
    printf("Generating MAC (1)\n");
#endif
    rc = sm_generate_mac(SHE_KEY_3, &message1.word, 128U, &mac);
    if (rc) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }

    sm_block_t expected_mac = {.bytes = {0x07, 0x0a, 0x16, 0xb4,
                                         0x6b, 0x4d, 0x41, 0x44,
                                         0xf7, 0x9b, 0xdd, 0x9d,
                                         0xd0, 0x4a, 0x28, 0x7c}};

#ifndef EMBEDDED
    printf("Expected MAC: ");
    printf_block(&expected_mac);
    printf("Actual MAC:   ");
    printf_block(&mac);
#endif

    if (!block_equals(&expected_mac, &mac)) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED\n");
        exit(1);
#endif
    }

    // MAC is ce0cbf17 38f4df64 28b1d93b f12081c9
    // for a 2 block message of:
    //
    // 6bc1bee2 2e409f96 e93d7e11 7393172a
    // ae2d8a57 1e03ac9c 9eb76fac 45af8e51

    bytes32_t message2 = {.bytes = {0x6b, 0xc1, 0xbe, 0xe2,
                                    0x2e, 0x40, 0x9f, 0x96,
                                    0xe9, 0x3d, 0x7e, 0x11,
                                    0x73, 0x93, 0x17, 0x2a,
                                    0xae, 0x2d, 0x8a, 0x57,
                                    0x1e, 0x03, 0xac, 0x9c,
                                    0x9e, 0xb7, 0x6f, 0xac,
                                    0x45, 0xaf, 0x8e, 0x51}};
                                                                                                                                                                                                                                                       
#ifndef EMBEDDED
    printf("Generating MAC (2)\n");
#endif

    rc = sm_generate_mac(SHE_KEY_3, &message2.word, 256U, &mac);
    if (rc) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }
    expected_mac = (sm_block_t) {.bytes = {0xce, 0x0c, 0xbf, 0x17,                                        
                                           0x38, 0xf4, 0xdf, 0x64,
                                           0x28, 0xb1, 0xd9, 0x3b,
                                           0xf1, 0x20, 0x81, 0xc9}};

#ifndef EMBEDDED
    printf("Expected MAC: ");
    printf_block(&expected_mac);
    printf("Actual MAC:   ");
    printf_block(&mac);
#endif
    if (!block_equals(&expected_mac, &mac)) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED\n");
        exit(1);
#endif
    }

#ifndef EMBEDDED
    printf("Generating MAC (3)\n");
#endif
    // Check that CMAC with the 0x87 tweak works
    expected_mac = (sm_block_t) {.bytes = {0xed, 0x3c, 0x4c, 0x25, 0xd3, 0x13, 0xb0, 0x24,
                                           0xf7, 0xed, 0x12, 0x70, 0xe7, 0xfe, 0x40, 0xe4}};

    sm_block_t key_0x87 = {.bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04}};

    message2 = (bytes32_t) {.bytes = {0x01, 0x02, 0x03, 0x04,
                                      0x05, 0x06, 0x07, 0x08,
                                      0x09, 0x0a, 0x0b, 0x0c,
                                      0x0d, 0x0e, 0x0f, 0x10,
                                      0x11, 0x12, 0x13, 0x14,
                                      0x15, 0x16, 0x17, 0x18,
                                      0x19, 0x1a, 0x1b, 0x1c,
                                      0x1d, 0x1e, 0x1f, 0x20}};

    sm_sw_nvram_backdoor_set_key(SHE_KEY_3, &key_0x87, SHE_FLAG_KEY_USAGE);
    rc = sm_generate_mac(SHE_KEY_3, &message2.word, 256U, &mac);
    if (rc) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }

#ifndef EMBEDDED
    printf_she_errorcode_t(rc);
    printf("Expected MAC: ");
    printf_block(&expected_mac);
    printf("Actual MAC:   ");
    printf_block(&mac);
#endif

    if (!block_equals(&expected_mac, &mac)) {
#ifdef EMBEDDED
        for(;;)
            ;
#else
        printf("TEST FAILED\n");
        exit(1);
#endif
    }
}

// Test AES-GCM vector
void test4(void)
{
#ifndef EMBEDDED
    printf("AES-GCM Test Case 1\n");
    printf("===================\n");
#endif
    she_errorcode_t rc;
    sm_init_rng();

    // KEY: 00000000000000000000000000000000
    // NONCE: 000000000000000000000000
    // IN: 00000000000000000000000000000000
    // CT: ""
    // AD: ""
    // TAG: 58 e2 fc ce fa 7e 30 61 36 7f 1d 57 a4 e7 45 5a

    sm_block_t gcm_key1 = {.bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    sm_block_t iv1 = {.bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    uint8_t plaintext1[] = {};
    uint8_t aad1[] = {};
    uint8_t ciphertext1[] = {};     
    sm_block_t expected_tag1 = {.bytes = {0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a}};

    sm_sw_nvram_backdoor_set_key(SHE_KEY_3, &gcm_key1, SHE_FLAG_AEAD);

    sm_block_t tag1;

    rc = sm_enc_aead(SHE_KEY_3, &iv1, aad1, sizeof(aad1), plaintext1, ciphertext1, sizeof(plaintext1), &tag1, false);
    if (rc) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }

#ifndef EMBEDDED
    printf("Expected tag1: ");
    printf_block(&expected_tag1);
    printf("Actual tag1:   ");
    printf_block(&tag1);
#endif

    if (!block_equals(&expected_tag1, &tag1)) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED\n");
        exit(1);
#endif
    }
}

// Test AES-GCM vector
void test5(void)
{
#ifndef EMBEDDED
    printf("AES-GCM Test Case 3\n");
    printf("===================\n");
#endif
    she_errorcode_t rc;
    sm_init_rng();

    // KEY: fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08
    // IV: ca fe ba be fa ce db ad de ca f8 88
    // IN: d9 31 32 25 f8 84 06 e5 a5 59 09 c5 af f5 26 9a 86 a7 a9 53 15 34 f7 da 2e 4c 30 3d 8a 31 8a 72 1c 3c 0c 95 95 68 09 53 2f cf 0e 24 49 a6 b5 25 b1 6a ed f5 aa 0d e6 57 ba 63 7b 39 1a af d2 55
    // CT: 42 83 1e c2 21 77 74 24 4b 72 21 b7 84 d0 d4 9c e3 aa 21 2f 2c 02 a4 e0 35 c1 7e 23 29 ac a1 2e 21 d5 14 b2 54 66 93 1c 7d 8f 6a 5a ac 84 aa 05 1b a3 0b 39 6a 0a ac 97 3d 58 e0 91 47 3f 59 85
    // AD: ""
    // TAG: 4d 5c 2a f3 27 cd 64 a6 2c f3 5a bd 2b a6 fa b4
    sm_block_t gcm_key2 = {.bytes = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08}};
    sm_block_t iv2 = {.bytes = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, 0x00, 0x00, 0x00, 0x00}};
    uint8_t plaintext2[] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55};
    uint8_t ciphertext2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t expected_output2[] = {0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85};
    uint8_t aad2[] = {};

    sm_block_t expected_tag2 = {.bytes = {0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6, 0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6, 0xfa, 0xb4}};

    sm_sw_nvram_backdoor_set_key(SHE_KEY_3, &gcm_key2, SHE_FLAG_AEAD);

    sm_block_t tag2;

#ifndef EMBEDDED
    if (sizeof(plaintext2) != sizeof(ciphertext2) || sizeof(ciphertext2) != sizeof(expected_output2)) {
        printf("ASSERT FAIL: plaintext and ciphertext size mismatch\n");
        exit(1);
    }
#endif
    rc = sm_enc_aead(SHE_KEY_3, &iv2, aad2, sizeof(aad2), plaintext2, ciphertext2, sizeof(plaintext2), &tag2, false);
    if (rc) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }

#ifndef EMBEDDED
    printf("Expected tag2: ");
    printf_block(&expected_tag2);
    printf("Actual tag2:   ");
    printf_block(&tag2);

    printf("Expected ciphertext: ");
    printf_bytes(expected_output2, sizeof(expected_output2));
    printf("Actual ciphertext:   ");
    printf_bytes(ciphertext2, sizeof(ciphertext2));
#endif

    if (!block_equals(&expected_tag2, &tag2) || !bytes_equals(ciphertext2, expected_output2, sizeof(ciphertext2))) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED\n");
        exit(1);
#endif
    }
    // Now decrypt and crosscheck
    bool verified2;
    rc = sm_dec_aead(SHE_KEY_3, &iv2, aad2, sizeof(aad2), ciphertext2, expected_output2, sizeof(plaintext2), &tag2, 128U, &verified2, false);
    if (rc != SHE_ERC_NO_ERROR || !bytes_equals(expected_output2, plaintext2, sizeof(plaintext2)) || !verified2) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("DECRYPT TEST FAILED\n");
        exit(1);
#endif
    }
}

// Test AES-GCM vector
void test6(void)
{
#ifndef EMBEDDED
    printf("AES-GCM Test Case 4\n");
    printf("===================\n");
#endif
    she_errorcode_t rc;
    sm_init_rng();

    // KEY: fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08
    // IV: ca fe ba be fa ce db ad de ca f8 88
    // IN: d9 31 32 25 f8 84 06 e5 a5 59 09 c5 af f5 26 9a 86 a7 a9 53 15 34 f7 da 2e 4c 30 3d 8a 31 8a 72 1c 3c 0c 95 95 68 09 53 2f cf 0e 24 49 a6 b5 25 b1 6a ed f5 aa 0d e6 57 ba 63 7b 39
    // CT: 42 83 1e c2 21 77 74 24 4b 72 21 b7 84 d0 d4 9c e3 aa 21 2f 2c 02 a4 e0 35 c1 7e 23 29 ac a1 2e 21 d5 14 b2 54 66 93 1c 7d 8f 6a 5a ac 84 aa 05 1b a3 0b 39 6a 0a ac 97 3d 58 e0 91
    // AD: fe ed fa ce de ad be ef fe ed fa ce de ad be ef ab ad da d2
    // TAG: 5b c9 4f bc 32 21 a5 db 94 fa e9 5a e7 12 1a 47
    sm_block_t gcm_key3 = {.bytes = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08}};
    sm_block_t iv3 = {.bytes = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, 0x00, 0x00, 0x00, 0x00}};
    uint8_t plaintext3[] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
    uint8_t ciphertext3[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t expected_output3[] = {0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91};
    uint8_t aad3[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};
    
    sm_block_t expected_tag3 = {.bytes = {0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47}};

    sm_sw_nvram_backdoor_set_key(SHE_KEY_3, &gcm_key3, SHE_FLAG_AEAD);

    sm_block_t tag3;

#ifndef EMBEDDED
    if (sizeof(plaintext3) != sizeof(ciphertext3) || sizeof(ciphertext3) != sizeof(expected_output3)) {
        printf("ASSERT FAIL: plaintext and ciphertext size mismatch\n");
        exit(1);
    }
#endif
    rc = sm_enc_aead(SHE_KEY_3, &iv3, aad3, sizeof(aad3), plaintext3, ciphertext3, sizeof(plaintext3), &tag3, false);
    if (rc) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }

#ifndef EMBEDDED
    printf("Expected tag3: ");
    printf_block(&expected_tag3);
    printf("Actual tag3:   ");
    printf_block(&tag3);

    printf("Expected ciphertext: ");
    printf_bytes(expected_output3, sizeof(expected_output3));
    printf("Actual ciphertext:   ");
    printf_bytes(ciphertext3, sizeof(ciphertext3));
#endif

    if (!block_equals(&expected_tag3, &tag3) || !bytes_equals(ciphertext3, expected_output3, sizeof(ciphertext3))) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("ENCRYPT TEST FAILED\n");
        exit(1);
#endif
    }

    // Now decrypt and crosscheck
    bool verified3;
    rc = sm_dec_aead(SHE_KEY_3, &iv3, aad3, sizeof(aad3), ciphertext3, expected_output3, sizeof(plaintext3), &tag3, 128U, &verified3, false);
    if (rc != SHE_ERC_NO_ERROR || !verified3 || !bytes_equals(expected_output3, plaintext3, sizeof(plaintext3))) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("DECRYPT TEST FAILED\n");
        exit(1);
#endif
    }

    // Corrupt tag and check now does not verify
    tag3.bytes[0] ^= 0x80U;
    rc = sm_dec_aead(SHE_KEY_3, &iv3, aad3, sizeof(aad3), ciphertext3, expected_output3, sizeof(plaintext3), &tag3, 128U, &verified3, false);
    if (verified3) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("DECRYPT BAD TAG TEST FAILED\n");
        exit(1);
#endif
    }
}

// Test KDF vector
void test7(void)
{
#ifndef EMBEDDED
    printf("NIST KDF Test Case\n");
    printf("==================\n");
#endif
    she_errorcode_t rc;
    sm_init_rng();

    // KEY: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    // CONTEXT: 01 02 03 04 05 06 07 08
    // COUNTER: 286397204 (11 12 13 14)
    // KEY OUT: d4 73 83 47 33 50 b8 82 3a 2e 1a 00 3e 04 c0 7c
    sm_block_t key_in4 = {.bytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}};
    sm_block_t expected_key_out4 = {.bytes = {0xd4, 0x73, 0x83, 0x47, 0x33, 0x50, 0xb8, 0x82, 0x3a, 0x2e, 0x1a, 0x00, 0x3e, 0x04, 0xc0, 0x7c}};
    sm_block_t counter4 = {.bytes = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x12, 0x13, 0x14}};
    uint8_t context4[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    // Install the key and counter values
    counter4.bytes[15]--; // Will be incremented after the back door is set (counts as a reset)
    sm_sw_nvram_backdoor_set_key(SHE_KEY_4, &counter4, SHE_FLAG_COUNTER);
    sm_sw_nvram_backdoor_set_key(SHE_KEY_3, &key_in4, 0);

    rc = sm_aead_kdf(SHE_KEY_3, context4, SHE_KEY_4);
    if (rc) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }

    sm_block_t *key_out = &sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].key;

#ifndef EMBEDDED
    printf("Counter value (Key 4): ");
    printf_block(&sm_sw_nvram_fs_ptr->key_slots[SHE_KEY_4].key);     
    printf("Expected key out: ");
    printf_block(&expected_key_out4);
    printf("Actual key out:   ");
    printf_block(key_out);
#endif

    if (!block_equals(&expected_key_out4, key_out)) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("NIST KDF TEST FAILED\n");
        exit(1);
#endif
    }
}

void test8(void)
{
#ifndef EMBEDDED
    printf("AES-GCM Test AO\n");
    printf("===============\n");
#endif
    she_errorcode_t rc;
    sm_init_rng();

    // KEY: fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08
    // IV: ca fe ba be fa ce db ad de ca f8 88
    // IN: d9 31 32 25 f8 84 06 e5 a5 59 09 c5 af f5 26 9a 86 a7 a9 53 15 34 f7 da 2e 4c 30 3d 8a 31 8a 72 1c 3c 0c 95 95 68 09 53 2f cf 0e 24 49 a6 b5 25 b1 6a ed f5 aa 0d e6 57 ba 63 7b 39
    // AD: fe ed fa ce de ad be ef fe ed fa ce de ad be ef ab ad da d2
    // TAG: 4b 28 35 7f 19 8f c8 34 46 18 fa 46 30 6b 82 7f
    sm_block_t gcm_key8 = {.bytes = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08}};
    sm_block_t iv8 = {.bytes = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, 0x00, 0x00, 0x00, 0x00}};
    uint8_t plaintext8[] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
    uint8_t ciphertext8[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t expected_output8[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t expected_output8_ao[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t aad8[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};
    uint8_t aad_ao8[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2, 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
    
    sm_block_t expected_tag8 = {.bytes = {0x4b, 0x28, 0x35, 0x7f, 0x19, 0x8f, 0xc8, 0x34, 0x46, 0x18, 0xfa, 0x46, 0x30, 0x6b, 0x82, 0x7f}};

    sm_sw_nvram_backdoor_set_key(SHE_KEY_3, &gcm_key8, SHE_FLAG_AEAD);

    sm_block_t tag_ao8;
    sm_block_t tag8;

#ifndef EMBEDDED
    if (sizeof(plaintext8) != sizeof(ciphertext8) || sizeof(ciphertext8) != sizeof(expected_output8)) {
        printf("ASSERT FAIL: plaintext and ciphertext size mismatch\n");
        exit(1);
    }
#endif
    // Two steps: one is a synthesised AO
    // Two steps: one is AO as a parameter
    rc = sm_enc_aead(SHE_KEY_3, &iv8, aad_ao8, sizeof(aad_ao8), NULL, ciphertext8, 0, &tag_ao8, false);
    if (rc) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }
#ifndef EMBEDDED
    printf("Synthetic AO tag: ");
    printf_block(&tag_ao8);
    printf("Expected ciphertext: ");
    printf_bytes(expected_output8, sizeof(expected_output8));
    printf("Actual ciphertext:   ");
    printf_bytes(ciphertext8, sizeof(ciphertext8));
#endif
    rc = sm_enc_aead(SHE_KEY_3, &iv8, aad8, sizeof(aad8), plaintext8, ciphertext8, sizeof(plaintext8), &tag8, true);
#ifndef EMBEDDED
    printf("AO tag: ");
    printf_block(&tag8);
    printf("Expected ciphertext: ");
    printf_bytes(expected_output8, sizeof(expected_output8));
    printf("Actual ciphertext:   ");
    printf_bytes(ciphertext8, sizeof(ciphertext8));
#endif

    if (!block_equals(&tag_ao8, &tag8) || !bytes_equals(ciphertext8, expected_output8, sizeof(ciphertext8))) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("AO ENCRYPT TEST FAILED\n");
        exit(1);
#endif
    }

    // Now decrypt and crosscheck
    bool verified8;

    rc = sm_dec_aead(SHE_KEY_3, &iv8, aad8, sizeof(aad8), plaintext8, expected_output8, sizeof(plaintext8), &tag8, 128U, &verified8, true);
    if (rc != SHE_ERC_NO_ERROR || !verified8) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("AO DECRYPT TEST FAILED\n");
        exit(1);
#endif
    }
}

#ifdef EMBEDDED
void sm_vector_test(void)
{
    test1();
    test2();
    test3();
    test4();
    test5();
    test6();
    test7();
    test8();
}

#else

int main(void)
{
    printf("Running tests..\n");

    test1();
    test2();
    test3();
    test4();
    test5();
    test6();
    test7();
    test8();

    printf("============\n");
    printf("TESTS PASSED\n");
}

#endif // EMBEDDED
