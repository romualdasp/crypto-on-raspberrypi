#include "crypto.h"

// getbit retrieves one bit from a byte 
static uint8_t getbit(uint8_t v, uint8_t bit)
{
	return (v >> bit) & 0x1;
}

// cpybit sets one bit in a byte to a specific value bitv, either 0 or 1
static uint8_t cpybit(uint8_t v, uint8_t bit, uint8_t bitv)
{
	uint8_t mask = ~(1 << bit);
	v = (v & mask); // clear bit using the mask
	return (v | (bitv << bit)); // set bit to the value bitv
}

/* 
 * add_round_key applies the roundkey to the plaintext. It
 * iterates over all the bytes in the plaintext and XORs them
 * with the corresponding bytes in the roundkey.
 */
static void add_round_key(uint8_t pt[CRYPTO_IN_SIZE], uint8_t roundkey[CRYPTO_IN_SIZE])
{
	for (uint8_t i = 0; i < 8; i++)
	{
		pt[i] ^= roundkey[i];
	}
}

static const uint8_t sbox[16] = {
	0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
};

/*
 * sbox_layer applies the sbox transformation to the state s. It
 * splits the state into two 4-bit nibbles: ln lower nibble, and un upper nibble.
 * These nibbles are then passed through the 4-bit SBox separately,
 * and the result is recombined into 8-bit chunks and stored back in the state s.
 */ 
static void sbox_layer(uint8_t s[CRYPTO_IN_SIZE])
{
	for (uint8_t i = 0; i < 8; i++)
	{
		uint8_t ln = s[i] & 0xf;
		uint8_t un = s[i] >> 4;
		s[i] = sbox[ln] | (sbox[un] << 4); // recombine two 4-bit nibbles
	}
}

/*
 * pbox_layer applies the permutation transformation to the state s. It
 * retrieves an individual bit from the state array, computes the permuted
 * position of the bit (uint8_t out), and stores the bit in the appropriate position
 * in an output array (uint8_t state_out). Once all bits have been permuted,
 * the output array is copied back into the state array s to prevent overwriting the bits.
 */
static void pbox_layer(uint8_t s[CRYPTO_IN_SIZE])
{
	uint8_t state_out[8] = {0};

	for (uint8_t b = 0; b < 64; b++)
	{
		uint8_t val = getbit(s[b / 8], b % 8);
		uint8_t out = (b / 4) + (b % 4) * 16; // compute the permuted position
		state_out[out / 8] = cpybit(state_out[out / 8], out % 8, val);
	}

	// copy the output back into the state array s to reflect the changes
	// and prevent overwriting bits
	for (uint8_t i = 0; i < 8; i++)
	{
		s[i] = state_out[i];
	}
}

static void update_round_key(uint8_t key[CRYPTO_KEY_SIZE], const uint8_t r)
{
	uint8_t tmp = 0;
	const uint8_t tmp2 = key[2];
	const uint8_t tmp1 = key[1];
	const uint8_t tmp0 = key[0];
	
	// rotate right by 19 bit
	key[0] = key[2] >> 3 | key[3] << 5;
	key[1] = key[3] >> 3 | key[4] << 5;
	key[2] = key[4] >> 3 | key[5] << 5;
	key[3] = key[5] >> 3 | key[6] << 5;
	key[4] = key[6] >> 3 | key[7] << 5;
	key[5] = key[7] >> 3 | key[8] << 5;
	key[6] = key[8] >> 3 | key[9] << 5;
	key[7] = key[9] >> 3 | tmp0 << 5;
	key[8] = tmp0 >> 3   | tmp1 << 5;
	key[9] = tmp1 >> 3   | tmp2 << 5;
	
	// perform sbox lookup on MSbits
	tmp = sbox[key[9] >> 4];
	key[9] &= 0x0F;
	key[9] |= tmp << 4;
	
	// XOR round counter k19 ... k15
	key[1] ^= r << 7;
	key[2] ^= r >> 1;
}

void crypto_func(uint8_t pt[CRYPTO_IN_SIZE], uint8_t key[CRYPTO_KEY_SIZE])
{
	uint8_t i = 0;
	
	for(i = 1; i <= 31; i++)
	{
		add_round_key(pt, key + 2);
		sbox_layer(pt);
		pbox_layer(pt);
		update_round_key(key, i);
	}
	
	add_round_key(pt, key + 2);
}
