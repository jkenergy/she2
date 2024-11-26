// Addition of GCM support Copyright (C) 2024 JK Energy Ltd.
//
// GCM implementation to enhance SHE HSM emulator.

#include "swshe.h"

// Don't mark these as const because they should go into RAM to avoid flash memory delays
static uint32_t last4[16] = {
    0x00000000U, 0x1c200000U, 0x38400000U, 0x24600000U, 0x70800000U, 0x6ca00000U, 0x48c00000U, 0x54e00000U,
    0xe1000000U, 0xfd200000U, 0xd9400000U, 0xc5600000U, 0x91800000U, 0x8da00000U, 0xa9c00000U, 0xb5e00000U,
};

typedef struct {
    uint64_t htable_l[16];  // Precomputed GHASH tables
    uint64_t htable_h[16];
    sm_block_t y;
    const sm_aes_enc_roundkey_t *aes_key;
    sm_block_t enc_iv;
    sm_block_t buf;
    uint32_t len;
    uint32_t aad_len;
} gcm_context_t;

// Precompute the table for multiplying by H. This has to be run each time there
// might be a new AES-GCM key. It consists of one AES operation plus creating the
// key table.
static void gcm_setkey(gcm_context_t *ctx, const sm_aes_enc_roundkey_t *key)
{
    uint64_t vl, vh;

    ctx->aes_key = key;

    // encrypt the null 128-bit block to generate a key-based value
    // which is then used to initialize our GHASH lookup tables
    sm_block_t zero;
    BLOCK_ZERO(&zero);
    
    // AES with the key applied to a value of 0
    sm_block_t h;
    sm_aes_encrypt(ctx->aes_key, &zero, &h);
    vh =  ((uint64_t)(BIG_ENDIAN_WORD(h.words[0])) << 32U) | BIG_ENDIAN_WORD(h.words[1]);
    vl =  ((uint64_t)(BIG_ENDIAN_WORD(h.words[2])) << 32U) | BIG_ENDIAN_WORD(h.words[3]);

    ctx->htable_l[8] = vl;
    ctx->htable_h[8] = vh;
    ctx->htable_l[0] = 0;
    ctx->htable_h[0] = 0;

    for(uint32_t i = 4U; i > 0; i >>= 1U) {
        uint32_t t = (vl & 1U) * 0xe1000000U;
        vl  = (vh << 63U) | (vl >> 1U); // Rotate right: compiler should spot this
        vh  = (vh >> 1U) ^ ((uint64_t)t << 32U);
        ctx->htable_l[i] = vl;
        ctx->htable_h[i] = vh;
    }
    for (uint32_t i = 2U; i < 16U; i <<= 1U ) {
        uint64_t *hl = ctx->htable_l + i, *hh = ctx->htable_h + i;
        vh = *hh;
        vl = *hl;
        for(uint32_t j = 1U; j < i; j++) {
            hh[j] = vh ^ ctx->htable_h[j];
            hl[j] = vl ^ ctx->htable_l[j];
        }
    }
}

// Carryless multiply is used in GHASH to perform AEAD and AO encryption
static void FAST_CODE gcm_mult(gcm_context_t *ctx)
{
    uint64_t zh, zl;

    GCM_START();

    for(int i = 15; i >= 0; i--) {
        uint8_t lo = ctx->buf.bytes[i] & 0x0fU;
        uint8_t hi = ctx->buf.bytes[i] >> 4U;
        uint8_t rem;

        if(i != 15) {
            rem = (uint8_t)(zl & 0x0fU );
            zl = (zh << 60U) | (zl >> 4U ); // Rotate right by 4 bits
            zh = (zh >> 4U);
            zh ^= ((uint64_t)last4[rem]) << 32U;
            zh ^= ctx->htable_h[lo];
            zl ^= ctx->htable_l[lo];
        }
        else {
            zh = ctx->htable_h[lo];
            zl = ctx->htable_l[lo];
        }
        rem = (uint8_t)(zl & 0x0fU);
        zl = (zh << 60U) | (zl >> 4U); // Rotate right by 4 bits
        zh = (zh >> 4U);
        zh ^= ((uint64_t)last4[rem]) << 32U;
        zh ^= ctx->htable_h[hi];
        zl ^= ctx->htable_l[hi];
    }
    ctx->buf.words[0] = BIG_ENDIAN_WORD(zh >> 32U);
    ctx->buf.words[1] = BIG_ENDIAN_WORD(zh);
    ctx->buf.words[2] = BIG_ENDIAN_WORD(zl >> 32U);
    ctx->buf.words[3] = BIG_ENDIAN_WORD(zl);

    GCM_END();
}

static void FAST_CODE gcm_start(gcm_context_t *ctx,
                                const sm_block_t *iv,         // pointer to initialization vector (IV is in words[0-2])
                                const uint8_t *aad,           // Additional Authenticated Data
                                size_t aad_len,
                                const uint8_t *ao_plaintext,  // Authentication-only payload
                                size_t ao_plaintext_len)      // Length of AO payload
{
    const uint8_t *p = aad;

    ctx->len = 0;
    ctx->aad_len = aad_len + ao_plaintext_len;
    BLOCK_ZERO(&ctx->buf);
    size_t aad_total_len = aad_len + ao_plaintext_len;
    size_t seg_len = aad_len;

    BLOCK_COPY(iv, &ctx->y);
    // Set the counter part of the IV to 1
    ctx->y.words[3] = BIG_ENDIAN_WORD(1);
    // Encrypt the IV (used at the end)
    sm_aes_encrypt(ctx->aes_key, &ctx->y, &ctx->enc_iv);

    // Feed in the AAD to GHASH
    while(aad_total_len > 0) {
        size_t len = (aad_total_len < 16U) ? aad_total_len : 16U;  // Capped at a block size
        for(size_t i = 0; i < len; i++) {
            if (seg_len == 0) {
                seg_len = ao_plaintext_len;
                p = ao_plaintext;
            }
            // Have to do this byte-by-byte because we do not know if AAD is aligned
            // or a whole number of words
            ctx->buf.bytes[i] ^= *p;
            p++;
            seg_len--;
        }
        gcm_mult(ctx);
        aad_total_len -= len;
    }
}

static void FAST_CODE gcm_update(gcm_context_t *ctx,
                                 size_t length,          // length, in bytes, of data to process
                                 const uint8_t *input,   // pointer to source data
                                 uint8_t *output,        // pointer to destination data
                                 bool encrypt)        
{
    sm_block_t ectr;    // counter-mode cipher output for XORing

    ctx->len += length; // bump the GCM context's running length count

    while(length > 0) {
        // Process up to a block
        size_t use_len = ( length < 16U ) ? length : 16U;

        // Increment the counter part of the IV block
        uint32_t cnt = BIG_ENDIAN_WORD(ctx->y.words[3]);
        cnt++;
        ctx->y.words[3] = BIG_ENDIAN_WORD(cnt);

        // encrypt the context's 'y' vector under the established key
        sm_aes_encrypt(ctx->aes_key, &ctx->y, &ectr);

        // if( ( ret = aes_cipher( &ctx->aes_ctx, ctx->y, ectr ) ) != 0 )
        //     return( ret );

        // We use a byte-by-byte operation here because there might not be
        // a whole block of input/output, and the input and/or output might not be
        // word aligned.
        if (encrypt) {
            for(size_t i = 0; i < use_len; i++) {   
                // XOR the cipher's ouptut vector (ectr) with our input
                output[i] = ectr.bytes[i] ^ input[i];
                // now we mix in our data into the authentication hash.
                // if we're ENcrypting we XOR in the post-XOR (output) 
                // results, but if we're DEcrypting we XOR in the input 
                // data
                ctx->buf.bytes[i] ^= output[i];
            }
        }
        else {
            for(size_t i = 0; i < use_len; i++) {   
                // but if we're DEcrypting we XOR in the input data first, 
                // i.e. before saving to ouput data, otherwise if the input 
                // and output buffer are the same (inplace decryption) we 
                // would not get the correct auth tag
                ctx->buf.bytes[i] ^= input[i];
                // XOR the cipher's output vector (ectr) with our input
                output[i] = ectr.bytes[i] ^ input[i];
            }
        }

        gcm_mult(ctx);    // perform a carryless multiply operation

        length -= use_len;  // drop the remaining byte count to process
        input  += use_len;  // bump our input pointer forward
        output += use_len;  // bump our output pointer forward
    }
}

static void FAST_CODE gcm_finish(gcm_context_t *ctx, sm_block_t *tag)
{
    sm_block_t work_block;
    uint64_t orig_len     = (uint64_t)(ctx->len) << 3U;
    uint64_t orig_aad_len = (uint64_t)(ctx->aad_len) << 3U;

    BLOCK_COPY(&ctx->enc_iv, tag);

    if(orig_len || orig_aad_len) {
        work_block.words[0] = BIG_ENDIAN_WORD(orig_aad_len >> 32U);
        work_block.words[1] = BIG_ENDIAN_WORD(orig_aad_len);
        work_block.words[2] = BIG_ENDIAN_WORD(orig_len >> 32);
        work_block.words[3] = BIG_ENDIAN_WORD(orig_len);
     
        ctx->buf.words[0] ^= work_block.words[0];
        ctx->buf.words[1] ^= work_block.words[1];
        ctx->buf.words[2] ^= work_block.words[2];
        ctx->buf.words[3] ^= work_block.words[3];

        gcm_mult(ctx);

        tag->words[0] ^= ctx->buf.words[0];
        tag->words[1] ^= ctx->buf.words[1];
        tag->words[2] ^= ctx->buf.words[2];
        tag->words[3] ^= ctx->buf.words[3];
    }
}

//////////////////// AES-GCM API calls ////////////////////

she_errorcode_t sm_enc_aead(sm_key_id_t key_id,
                           sm_block_t *iv,
                           const uint8_t *aad,
                           size_t aad_length,
                           const uint8_t *plaintext,
                           uint8_t *ciphertext,
                           size_t length,
                           sm_block_t *tag,
                           bool ao)
{
    gcm_context_t ctx;
    ////// Cannot use API unless the SHE has been initialized //////
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }
    if (key_id >= SM_SW_NUM_KEYS) {
        return SHE_ERC_KEY_INVALID;
    }
    const uint16_t flags = sm_sw_nvram_fs_ptr->key_slots[key_id].flags;
    if (flags & SWSM_FLAG_EMPTY_SLOT) {
        return SHE_ERC_KEY_EMPTY;
    }
    // Verify-only key cannot be used, and counter key slots cannot be used
    if ((flags & SHE_FLAG_VERIFY_ONLY) || (flags & SHE_FLAG_COUNTER)) {  // Verify-only for an AEAD key means that encode is not permitted
        return SHE_ERC_KEY_INVALID;
    }
    if (((key_id < SHE_KEY_1) || (key_id > SHE_KEY_10) || (flags & SHE_FLAG_KEY_USAGE)) && (key_id != SHE_RAM_KEY)) {
        return SHE_ERC_KEY_INVALID;
    }
    if (!(flags & SHE_FLAG_AEAD) && (key_id != SHE_RAM_KEY)) {
        return SHE_ERC_KEY_INVALID;
    }
#ifdef SM_KEY_EXPANSION_CACHED
    const sm_aes_enc_roundkey_t *roundkey = &sm_cached_key_slots[key_id].enc_roundkey;
#else
    sm_aes_enc_roundkey_t expanded_roundkey;
    sm_aes_enc_roundkey_t *roundkey = &expanded_roundkey;
    sm_expand_key_enc(&sm_sw_nvram_fs_ptr->key_slots[key_id].key, roundkey);
#endif

    // Have the roundkey now for AES 
    gcm_setkey(&ctx, roundkey);
    if (ao) {
        gcm_start(&ctx, iv, aad, aad_length, plaintext, length);
        // Don't call update because no encryption takes place
    }
    else {
        gcm_start(&ctx, iv, aad, aad_length, NULL, 0);
        gcm_update(&ctx, length, plaintext, ciphertext, true);
    }
    gcm_finish(&ctx, tag);

    return SHE_ERC_NO_ERROR;
}

she_errorcode_t sm_dec_aead(sm_key_id_t key_id,
                            sm_block_t *iv,
                            const uint8_t *aad,
                            size_t aad_length,
                            const uint8_t *ciphertext,
                            uint8_t *plaintext,
                            size_t length,
                            sm_block_t *tag,
                            size_t tag_length,
                            bool *verified,
                            bool ao)
{
    uint32_t tag_mask[4];
    asrm_128(tag_mask, tag_length);

    ////// Cannot use API unless the SHE has been initialized //////
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }
    if (key_id >= SM_SW_NUM_KEYS) {
        return SHE_ERC_KEY_INVALID;
    }
    uint16_t flags = sm_sw_nvram_fs_ptr->key_slots[key_id].flags;
    if (flags & SWSM_FLAG_EMPTY_SLOT) {
        return SHE_ERC_KEY_EMPTY;
    }
    // Must be an AEAD key
    if (flags & SHE_FLAG_COUNTER) {  // Verify-only for an AEAD key means that encode is not permitted
        return SHE_ERC_KEY_INVALID;
    }
    if ((key_id < SHE_KEY_1 || key_id > SHE_KEY_10 || (sm_sw_nvram_fs_ptr->key_slots[key_id].flags & SHE_FLAG_KEY_USAGE)) && key_id != SHE_RAM_KEY) {
        return SHE_ERC_KEY_INVALID;
    }
    if (!(flags & SHE_FLAG_AEAD) && key_id != SHE_RAM_KEY) {
        return SHE_ERC_KEY_INVALID;
    }
#ifdef SM_KEY_EXPANSION_CACHED
    const sm_aes_enc_roundkey_t *roundkey = &sm_cached_key_slots[key_id].enc_roundkey;
#else
    sm_aes_enc_roundkey_t expanded_roundkey;
    sm_aes_enc_roundkey_t *roundkey = &expanded_roundkey;
    sm_expand_key_enc(&sm_sw_nvram_fs_ptr->key_slots[key_id].key, roundkey);
#endif

    sm_block_t calculated_tag;
    gcm_context_t ctx;

    gcm_setkey (&ctx, roundkey);
    if (ao) {
        gcm_start(&ctx, iv, aad, aad_length, ciphertext, length);
        // Don't call update because no encryption takes place
    }
    else {
        gcm_start(&ctx, iv, aad, aad_length, NULL, 0);
        gcm_update(&ctx, length, ciphertext, plaintext, false);
    }
    gcm_finish (&ctx, &calculated_tag);

    uint32_t cmp = sm_compare_mac(tag, &calculated_tag, tag_mask);

    *verified = cmp == 0;

    return SHE_ERC_NO_ERROR;
}                           
