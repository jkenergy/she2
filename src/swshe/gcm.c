// Addition of GCM support Copyright (C) 2024 JK Energy Ltd.
//
// GCM implementation to enhance SHE HSM emulator.
//
// TODO create an unset API call to stop using the context
// TODO check in sm_set_aead_ctx that the context is unset (i.e. not in use)
// TODO check that AAD is 16 bytes except for the last AAD (i.e. when < 16 bytes, set an aad_done flag)
// FIXME change enc/dec AEAD API to use a GCM context

#include "swshe.h"

// FIXME remove
// #include <stdio.h>
// void printf_block(sm_block_t *block);
// void printf_bytes(const uint8_t *b, size_t l);

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
    bool set;
} gcm_context_t;

// This will store the GCM contexts, binding to an AES-GCM key. Once a context
// is initialized, the source key is no longer needed, so a RAM key slot can be used.
static gcm_context_t gcm_context_table[NUM_GCM_CONTEXTS];

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
    ctx->set = true;
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
                         const sm_block_t *iv)
{
    ctx->len = 0;
    ctx->aad_len = 0;
    BLOCK_ZERO(&ctx->buf);
    BLOCK_COPY(iv, &ctx->y);
    // Set the counter part of the IV to 1
    ctx->y.words[3] = BIG_ENDIAN_WORD(1);
    // Encrypt the IV (used at the end)
    sm_aes_encrypt(ctx->aes_key, &ctx->y, &ctx->enc_iv);
}

// Called repeatedly with data, up to 16 bytes in length. Must only
// call with less than 16 bytes if this is the last part of the AAD,
// and THE BLOCK MUST BE 0 PADDED.
static void FAST_CODE gcm_add_aad(gcm_context_t *ctx,
                                  sm_block_t *aad,              // Additional Authenticated Data
                                  uint8_t aad_len)               // Must be <= 16, and if < 16 then this is the final part of AAD
{
    // Feed in the AAD to GHASH
    ctx->buf.words[0] ^= aad->words[0];
    ctx->buf.words[1] ^= aad->words[1];
    ctx->buf.words[2] ^= aad->words[2];
    ctx->buf.words[3] ^= aad->words[3]; 
    gcm_mult(ctx);
    ctx->aad_len += aad_len;
}

// Called repeatedly with data, up to 16 bytes in length. Must only
// call with less than 16 bytes if this is the last part of the data.
// No padding is necessary.
void FAST_CODE gcm_add_data(gcm_context_t *ctx,
                            uint8_t length,          // length, in bytes, of data to process
                            const uint8_t *input,   // pointer to source data
                            uint8_t *output,        // pointer to destination data
                            bool encrypt)        
{
    sm_block_t ectr;    // counter-mode cipher output for XORing
    ctx->len += length; // bump the GCM context's running length count

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
        for(size_t i = 0; i < length; i++) {   
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
        for(size_t i = 0; i < length; i++) {   
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

////////////////// Incremental AEAD API ///////////////////

// Set a GCM context from a key (typically the RAM key)
she_errorcode_t FAST_CODE sm_set_aead_ctx(sm_key_id_t key_id, sm_aead_ctx_id_t ctx_id)
{
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
    if (ctx_id >= NUM_GCM_CONTEXTS) {
        return SHE_ERC_CTX_INVALID;
    }

#ifdef SM_KEY_EXPANSION_CACHED
    const sm_aes_enc_roundkey_t *roundkey = &sm_cached_key_slots[key_id].enc_roundkey;
#else
    sm_aes_enc_roundkey_t expanded_roundkey;
    sm_aes_enc_roundkey_t *roundkey = &expanded_roundkey;
    sm_expand_key_enc(&sm_sw_nvram_fs_ptr->key_slots[key_id].key, roundkey);
#endif
    gcm_context_t *ctx = &gcm_context_table[ctx_id];

    // Have the roundkey now for AES, set the key into the GCM context
    gcm_setkey(ctx, roundkey);

    return SHE_ERC_NO_ERROR;
}

// Starts an AEAD context for encrypt or decrypt
she_errorcode_t FAST_CODE sm_start_aead(sm_aead_ctx_id_t ctx_id, sm_block_t *iv)
{
    ////// Cannot use API unless the SHE has been initialized //////
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }
    if (ctx_id >= SM_SW_NUM_AEAD_CTX) {
        return SHE_ERC_CTX_INVALID;
    }
    gcm_context_t *ctx = &gcm_context_table[ctx_id];
    if (!ctx->set) {
        return SHE_ERC_CTX_EMPTY;
    }
    gcm_start(ctx, iv);

    return SHE_ERC_NO_ERROR;
}

// Adds some AAD. Length must be 16 bytes except for the last AAD.
// This API call is used for encrypt or decrypt.
she_errorcode_t FAST_CODE sm_aad_aead(sm_aead_ctx_id_t ctx_id, const uint8_t *aad, size_t aad_length)
{
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }
    if (ctx_id >= SM_SW_NUM_AEAD_CTX) {
        return SHE_ERC_CTX_INVALID;
    }
    gcm_context_t *ctx = &gcm_context_table[ctx_id];
    if (!ctx->set) {
        return SHE_ERC_CTX_EMPTY;
    }
    if (aad_length > 16) {
        return SHE_ERC_SIZE;
    }
    sm_block_t tmp;
    BLOCK_ZERO(&tmp);
    // We don't know alignment of the source data, so copy byte-by-byte
    for(size_t i = 0; i < aad_length; i++) {
        tmp.bytes[i] ^= aad[i];
    }
    gcm_add_aad(ctx, &tmp, aad_length); // The total AAD length will be accumulated in the context

    return SHE_ERC_NO_ERROR;
}

// Adds some data. Length must be 16 bytes except for the last data.
// This API call is used for encrypt or decrypt.
she_errorcode_t FAST_CODE sm_data_aead(sm_aead_ctx_id_t ctx_id, uint8_t *plaintext, uint8_t *ciphertext, size_t data_length, bool encrypt)
{
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }
    if (ctx_id >= SM_SW_NUM_AEAD_CTX) {
        return SHE_ERC_CTX_INVALID;
    }
    gcm_context_t *ctx = &gcm_context_table[ctx_id];
    if (!ctx->set) {
        return SHE_ERC_CTX_EMPTY;
    }
    if (data_length > 16) {
        return SHE_ERC_SIZE;
    }
    if (encrypt) {
        gcm_add_data(ctx, data_length, plaintext, ciphertext, true);
    }
    else {
        gcm_add_data(ctx, data_length, ciphertext, plaintext, false);
    }

    return SHE_ERC_NO_ERROR;
}

// Finish up and verify the tag
she_errorcode_t FAST_CODE sm_verify_aead_tag(sm_aead_ctx_id_t ctx_id, const uint8_t *tag, uint8_t tag_length, bool *verified)
{
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }
    if (ctx_id >= SM_SW_NUM_AEAD_CTX) {
        return SHE_ERC_CTX_INVALID;
    }
    gcm_context_t *ctx = &gcm_context_table[ctx_id];
    if (!ctx->set) {
        return SHE_ERC_CTX_EMPTY;
    }
    if (tag_length > 128U) {
        return SHE_ERC_SIZE;
    }
    uint8_t tag_bytes = (tag_length + 7U) >> 3;
    sm_block_t tmp_tag;
    for (uint8_t i = 0; i < tag_bytes; i++) {
        tmp_tag.bytes[i] = tag[i];
    }
    sm_block_t calculated_tag;
    uint32_t tag_mask[4];
    asrm_128(tag_mask, tag_length); // Produce a mask equal to the tag size in bits

    gcm_finish (ctx, &calculated_tag);
    uint32_t cmp = sm_compare_mac(&tmp_tag, &calculated_tag, tag_mask);

    *verified = cmp == 0;

    return SHE_ERC_NO_ERROR;
}

she_errorcode_t FAST_CODE sm_generate_aead_tag(sm_aead_ctx_id_t ctx_id, uint8_t *tag, uint8_t tag_length)
{
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }
    if (ctx_id >= SM_SW_NUM_AEAD_CTX) {
        return SHE_ERC_CTX_INVALID;
    }
    gcm_context_t *ctx = &gcm_context_table[ctx_id];
    if (!ctx->set) {
        return SHE_ERC_CTX_EMPTY;
    }
    if (tag_length > 16U) {
        return SHE_ERC_SIZE;
    }

    sm_block_t tmp_tag;
    // Finish up and generate the tag of a certain size
    gcm_finish(ctx, &tmp_tag);
    for (uint8_t i = 0; i < tag_length; i++) {
        tag[i] = tmp_tag.bytes[i];
    }

    return SHE_ERC_NO_ERROR;
}

///////////// Classic AEAD API /////////////
she_errorcode_t sm_enc_aead(sm_key_id_t key_id,
                            sm_block_t *iv,
                            const uint8_t *aad,
                            size_t aad_length,
                            uint8_t *plaintext,
                            uint8_t *ciphertext,
                            size_t length,
                            sm_block_t *tag,
                            bool ao)
{
    she_errorcode_t ec;

    ec = sm_set_aead_ctx(key_id, 0);
    if (ec != SHE_ERC_NO_ERROR) {
        return ec;
    }

    ec = sm_start_aead(0, iv);
    if (ec != SHE_ERC_NO_ERROR) {
        return ec;
    }

    // Now fill in multiple 16 byte blocks of AAD and AO plaintext, except for the last one
    size_t ao_length = ao ? length : 0;
    const uint8_t *p = aad;
    size_t aad_total_len = aad_length + ao_length;
    size_t seg_len = aad_length;

    // Feed in the AAD and payload byte-by-byte (because alignment is not known)
    while(aad_total_len > 0) {
        size_t len = (aad_total_len < 16U) ? aad_total_len : 16U;  // Capped at a block size
        uint8_t tmp[16];
        for(size_t i = 0; i < len; i++) {
            if (seg_len == 0) {
                seg_len = ao_length; // Payload length
                p = plaintext;
            }
            // Have to do this byte-by-byte because we do not know if AAD is aligned
            // or a whole number of words
            tmp[i] = *p;
            p++;
            seg_len--;
        }
        ec = sm_aad_aead(0, tmp, len);
        if (ec != SHE_ERC_NO_ERROR) {
            return ec;
        }
        aad_total_len -= len;
    }

    // Feed in the data byte-by-byte
    size_t data_length = ao ? 0 : length;
    while(data_length > 0) {
        size_t len = (data_length < 16U) ? data_length : 16U;  // Capped at a block size
        // Input = plaintext, output = ciphertext
        ec = sm_data_aead(0, plaintext, ciphertext, len, true);
        if (ec != SHE_ERC_NO_ERROR) {
            return ec;
        }
        data_length -= len;
        plaintext += len;
        ciphertext += len;
    }

    ec = sm_generate_aead_tag(0, tag->bytes, 16U);

    return ec;
}

she_errorcode_t sm_dec_aead(sm_key_id_t key_id,
                            sm_block_t *iv,
                            const uint8_t *aad,
                            size_t aad_length,
                            uint8_t *ciphertext,
                            uint8_t *plaintext,
                            size_t length,
                            sm_block_t *tag,
                            uint8_t tag_length,
                            bool *verified,
                            bool ao)
{
    she_errorcode_t ec;

    ec = sm_set_aead_ctx(key_id, 0);
    if (ec != SHE_ERC_NO_ERROR) {
        return ec;
    }

    ec = sm_start_aead(0, iv);
    if (ec != SHE_ERC_NO_ERROR) {
        return ec;
    }

    // Now fill in multiple 16 byte blocks of AAD and AO plaintext, except for the last one
    size_t ao_length = ao ? length : 0;
    const uint8_t *p = aad;
    size_t aad_total_len = aad_length + ao_length;
    size_t seg_len = aad_length;

    // Feed in the AAD and payload byte-by-byte (because alignment is not known)
    while(aad_total_len > 0) {
        size_t len = (aad_total_len < 16U) ? aad_total_len : 16U;  // Capped at a block size
        uint8_t tmp[16];
        for(size_t i = 0; i < len; i++) {
            if (seg_len == 0) {
                seg_len = ao_length; // Payload length
                p = ciphertext;
            }
            // Have to do this byte-by-byte because we do not know if AAD is aligned
            // or a whole number of words
            tmp[i] = *p;
            p++;
            seg_len--;
        }
        ec = sm_aad_aead(0, tmp, len);
        if (ec != SHE_ERC_NO_ERROR) {
            return ec;
        }
        aad_total_len -= len;
    }

    // Feed in the data byte-by-byte
    size_t data_length = ao ? 0 : length;
    while(data_length > 0) {
        size_t len = (data_length < 16U) ? data_length : 16U;  // Capped at a block size
        ec = sm_data_aead(0, plaintext, ciphertext, len, false);
        if (ec != SHE_ERC_NO_ERROR) {
            return ec;
        }
        data_length -= len;
        plaintext += len;
        ciphertext += len;
    }

    ec = sm_verify_aead_tag(0, tag->bytes, tag_length, verified);

    return ec;
}
