#include "wg_internal.h"
#include <string.h>

#define BITS_PER_WORD (sizeof(uint64_t) * 8)

bool wg_counter_validate(WgReplayCounter* rc, uint64_t counter) {
    if (counter >= WG_REJECT_AFTER_MESSAGES)
        return false;

    if (rc->counter >= WG_COUNTER_WINDOW_SIZE &&
        counter < rc->counter - WG_COUNTER_WINDOW_SIZE)
        return false;

    uint64_t word_idx = (counter / BITS_PER_WORD) % WG_COUNTER_WORDS;
    uint64_t bit_mask = (uint64_t)1 << (counter % BITS_PER_WORD);

    if (counter > rc->counter) {
        uint64_t new_word = counter / BITS_PER_WORD;
        uint64_t old_word = rc->counter / BITS_PER_WORD;
        uint64_t diff = new_word - old_word;

        if (diff >= WG_COUNTER_WORDS) {
            memset(rc->backtrack, 0, sizeof(rc->backtrack));
        } else {
            for (uint64_t i = 1; i <= diff; i++)
                rc->backtrack[(old_word + i) % WG_COUNTER_WORDS] = 0;
        }
        rc->counter = counter;
    }

    if (rc->backtrack[word_idx] & bit_mask)
        return false;

    rc->backtrack[word_idx] |= bit_mask;
    return true;
}
