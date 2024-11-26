// NIST KDF, with counter taken from a counter slot
//
// Copyright (C) 2024 JK Energy Ltd.
//
// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt

#include "swshe.h"

//////////////////// KDF API calls ////////////////////

static uint32_t m2_words[16];

// Generate a key using counter mode KDF, putting result into the RAM key slot.
she_errorcode_t FAST_CODE sm_aead_kdf(sm_key_id_t key_id, uint8_t *context, sm_key_id_t counter_id)
{
    ////// Cannot use API unless the SHE has been initialized //////
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }
    if ((key_id >= SM_SW_NUM_KEYS) || (counter_id >= SM_SW_NUM_KEYS)) {
        return SHE_ERC_KEY_INVALID;
    }

    const uint16_t key_flags = sm_sw_nvram_fs_ptr->key_slots[key_id].flags;
    const uint16_t counter_flags = sm_sw_nvram_fs_ptr->key_slots[counter_id].flags;

    if ((key_flags & SWSM_FLAG_EMPTY_SLOT)){
        return SHE_ERC_KEY_EMPTY;
    }
    if (((key_id < SHE_KEY_1) || (key_id > SHE_KEY_10) || (key_flags & SHE_FLAG_AEAD) || (key_flags & SHE_FLAG_COUNTER) || (key_flags & SHE_FLAG_KEY_USAGE)) && key_id != SHE_RAM_KEY) {
        return SHE_ERC_KEY_INVALID;
    }
    if (!(counter_flags & SHE_FLAG_COUNTER)) {
        return SHE_ERC_KEY_INVALID;
    }

#ifdef SM_KEY_EXPANSION_CACHED
    sm_aes_enc_roundkey_t *roundkey = &sm_cached_key_slots[key_id].enc_roundkey;
#else
    sm_aes_enc_roundkey_t expanded_roundkey;
    sm_aes_enc_roundkey_t *roundkey = &expanded_roundkey;
    sm_expand_key_enc(&sm_sw_nvram_fs_ptr->key_slots[key_id].key, roundkey);
#endif

    KDF_START(); // Start measuring from here for the KDF (ignore error checking etc.)

    // KDF is:
    //
    // key = CMAC(M1 || K0)
    // M1 = 0x01 || 0x49 || context || counter || 0x0080
    // where context = 8 bytes, counter = big endian 32-bit counter (from key slot)
    // and K0 = CMAC(M0) (M0 = 0x01 || 0x49 || context || counter || 0x0080)
    //
    // This is two CMAC operations. 
    // The k1 tweak must exist, so the key cannot be a counter or AEAD key
    const sm_block_t *k1 = &sm_cached_key_slots[key_id].k1;    // Cached K1 tweak of CMAC key
    
    // First calculate K0 of the KDF
    sm_block_t k0;
    sm_block_t m;
    const sm_block_t *counter = &sm_sw_nvram_fs_ptr->key_slots[counter_id].key;

    // M0
    m.bytes[0] = 0x00U;
    m.bytes[1] = 0x49U;
    m.bytes[2] = context[0];
    m.bytes[3] = context[1];
    m.bytes[4] = context[2];
    m.bytes[5] = context[3];
    m.bytes[6] = context[4];
    m.bytes[7] = context[5];
    m.bytes[8] = context[6];
    m.bytes[9] = context[7];
    m.bytes[10] = counter->bytes[12];
    m.bytes[11] = counter->bytes[13];
    m.bytes[12] = counter->bytes[14];
    m.bytes[13] = counter->bytes[15];
    m.bytes[14] = 0x00U;
    m.bytes[15] = 0x80U;
    
    sm_aes_cmac(roundkey, m.words, 1U, &k0, k1);

    // Make a second message, of two blocks
    // M1
    m.bytes[0] = 0x01U;
     
    m2_words[0] = m.words[0];
    m2_words[1] = m.words[1];
    m2_words[2] = m.words[2];
    m2_words[3] = m.words[3];
    m2_words[4] = k0.words[0];
    m2_words[5] = k0.words[1];
    m2_words[6] = k0.words[2];
    m2_words[7] = k0.words[3];        

    sm_sw_nvram_key_slot_t *ram_key_slot = &sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY];

    // Apply the second CMAC step, putting the result into the RAM key slot
    sm_aes_cmac(roundkey, m2_words, 2U, &ram_key_slot->key, k1);

    KDF_END();

    // Mark the RAM slot as being used for an AEAD key so that it cannot be used except for AEAD encryption
    ram_key_slot->flags = SHE_FLAG_AEAD;
    // (Implicitly marks it as not a plain key, so cannot be exported)

    // Clear the slot counter (to ensure load key API for RAM key slot still works)
    ram_key_slot->counter = 0;
    
    // Update the cached roundkey but no need to updated K1 tweak because marked AEAD-only
#ifdef SM_KEY_EXPANSION_CACHED
    roundkey = &sm_cached_key_slots[SHE_RAM_KEY].enc_roundkey;
    sm_expand_key_enc(&ram_key_slot->key, roundkey);
#endif
    
    return SHE_ERC_NO_ERROR;
}

//////////////////// Counter API calls ////////////////////

she_errorcode_t sm_update_counter(sm_key_id_t counter_id, uint32_t value)
{
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }
    if (counter_id >= SM_SW_NUM_KEYS) {
        return SHE_ERC_KEY_INVALID;
    }
    sm_sw_nvram_key_slot_t *key_slot = &sm_sw_nvram_fs_ptr->key_slots[counter_id];
    if ((counter_id < SHE_KEY_1) || (counter_id > SHE_KEY_10)) {
        return SHE_ERC_KEY_INVALID;
    }
    if (key_slot->flags & SWSM_FLAG_EMPTY_SLOT) {
        return SHE_ERC_KEY_EMPTY;
    }
    if (!(key_slot->flags & SHE_FLAG_COUNTER)) {
        // A key slot must be used as a counter
        return SHE_ERC_KEY_INVALID;
    }

    // The counter is increased to a higher value
    if (value <= BIG_ENDIAN_WORD(key_slot->key.words[3])) {
        return SHE_ERC_KEY_UPDATE_ERROR;
    }
    key_slot->key.words[3] = BIG_ENDIAN_WORD(value);

    // Flush new counter value back to the NVRAM file store
    she_errorcode_t rc = sm_sw_callback_nvram_store_key_slots();
    return rc;
}
