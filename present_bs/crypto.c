#include "crypto.h"

/**
 * Bring normal buffer into bitsliced form
 * @param pt Input: state_bs in normal form
 * @param state_bs Output: Bitsliced state
 * 
 * enslice turns a normal buffer pt into an ensliced form, which gets stored in state_bs.
 * The outer for loop iterates over all the entries in the permuted state state_bs,
 * and fills each entry one by one by grabbing the appropriate bits.
 * The inner loop fills up the individual bits within each entry by taking the
 * appropriate bit from the pt state array. The appropriate bit is found as follows:
 * 
 * 0. pt[i / 8 + bit * 8] retrieves the correct pt entry that holds the appropriate bit.
 * 1. Each entry within the pt array is 8-bit, therefore pt[...] >> (i % 8) to retrieve one bit
 * 2. (... & 1) is used to mask the shifted bit, the rest of the bits become 0
 * 3. (... << bit) shifts the retrieved bit to an appropriate bit position in state_bs[i].
 * 4. The shifted bit can be safely ORed with state_bs[i] as all the un-used bits are 0.
 */
static void enslice(const uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT])
{
	for (uint8_t i = 0; i < CRYPTO_IN_SIZE_BIT; i++)
	{
		bs_reg_t temp = 0;

		for (uint8_t bit = 0; bit < BITSLICE_WIDTH; bit++)
		{
			temp |= ((pt[i / 8 + bit * 8] >> (i % 8)) & 1) << bit;
		}

		state_bs[i] = temp;
	}
}

/**
 * Bring bitsliced buffer into normal form
 * @param state_bs Input: Bitsliced state
 * @param pt Output: state_bs in normal form
 * 
 * The unslice function is an inverse function to enslice. It converts a bitsliced
 * buffer state_bs back into the standard buffer pt. The outer loop interates over all
 * the entries in the output array pt, and fills each entry one by one.
 * The inner loop iterates over each individual bit of one entry of pt, and sets these
 * bits one by one by using OR to combine them. The bits are set as follows:
 * 
 * 0. state_bs[((i * 8) % CRYPTO_IN_SIZE_BIT) + bit] retrieves the correct state_bs that holds the appropriate bit.
 * 1. For pt[0] through pt[7] we need to take the first bit of each entry in state_bs, and so on. state_bs[...] >> (i / 8) does this.
 * 2. (... & 1) is used to mask the shifted bit, the rest of the bits become 0
 * 3. (... << bit) shifts the retrieved bit to an appropriate bit position in pt[i].
 * 4. The shifted bit can be safely ORed with pt[i] as all the un-used bits are 0.
 */
static void unslice(const bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT], uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH])
{
	for (uint32_t i = 0; i < (CRYPTO_IN_SIZE * BITSLICE_WIDTH); i++)
	{
		uint8_t temp = 0;
		
		for (uint8_t bit = 0; bit < 8; bit++)
		{
			temp |= ((state_bs[((i * 8) % CRYPTO_IN_SIZE_BIT) + bit] >> (i / 8)) & 1) << bit;
		}

		pt[i] = temp;
	}

}

/*
 * The sbox0, sbox1, sbox2 and sbox3 compute the SBoxes for bitsliced PRESENT.
 * These SBoxes have been optimised to reduce redundacy, therefore some computations
 * have been rearranged, and some intermediate computations have been introduced to store
 * and re-use the same computation in multiple places, which speeds up the bitsliced implementation.
 * Constant BS_INV helps to compute the negation.
 */
#define BS_INV 0xFFFFFFFF

static bs_reg_t sbox0(bs_reg_t x0, bs_reg_t x1, bs_reg_t x2, bs_reg_t x3)
{
	return x0 ^ (x1 & x2) ^ x2 ^ x3;
}

static bs_reg_t sbox1(bs_reg_t x0, bs_reg_t x1, bs_reg_t x2, bs_reg_t x3)
{
	bs_reg_t c = x2 & x3;
	return ((x0 & x1) & (x2 ^ x3)) ^ (x3 & x1) ^ x1 ^ (x0 & c) ^ c ^ x3;
}

static bs_reg_t sbox2(bs_reg_t x0, bs_reg_t x1, bs_reg_t x2, bs_reg_t x3)
{
	bs_reg_t c = x0 & x3;
	return (x0 & x1) ^ (c & x1) ^ (x3 & x1) ^ x2 ^ c ^ (c & x2) ^ x3 ^ BS_INV;
}

static bs_reg_t sbox3(bs_reg_t x0, bs_reg_t x1, bs_reg_t x2, bs_reg_t x3)
{
	bs_reg_t c = x1 & x2;
	return (c & x0) ^ ((x3 & x0) & (x1 ^ x2)) ^ x0 ^ x1 ^ c ^ x3 ^ BS_INV;
}

/*
 * add_round_key adds the roundkey to the bitsliced implementation of PRESENT.
 * It iterates over every entry in state_bs one by one, and XORs the whole entry
 * with either 0xFFFFFFFF or 0x00000000, depending on the appropriate bit within the roundkey.
 * This roundkey conversion is needed because the roundkey is not stored in bitsliced form.
 * 
 * The (uint8_t key_bit) retrieves the appropriate bit within the roundkey, and masks it with 1
 * so only that bit remains. If the key bit is one, the state_bs is XORed with 0xFFFFFFFF, and vice versa.
 * As such, all bits within one state_bs entry are XORed with the same roundkey bit.
 * 
 * roundkey[bit / CRYPTO_IN_SIZE] gets the appropriate byte of the roundkey.
 * roundkey[...] >> (bit % CRYPTO_IN_SIZE) gets the appropriate bit of the roundkey.
 */
static void add_round_key(bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT], uint8_t roundkey[CRYPTO_IN_SIZE])
{
	for (uint8_t bit = 0; bit < CRYPTO_IN_SIZE_BIT; bit++)
	{
		uint8_t key_bit = (roundkey[bit / CRYPTO_IN_SIZE] >> (bit % CRYPTO_IN_SIZE)) & 1;
		state_bs[bit] ^= (key_bit ? 0xFFFFFFFF : 0);
	}
}

/*
 * sbox_layer applies the sbox transformation. This bitsliced implementation
 * is very different from the standard implementation, as it no longer uses lookup tables.
 * Instead, it uses four functions sbox0, sbox1, sbox2, sbox3 to compute the SBox.
 * 
 * It retrieves chunks of 4 bits in every iteration of the for loop, and passes these chunks
 * of 4 bits into the SBox. The SBox is computed for all 32 bits of one state_bs entry in one iteration.
 * Therefore, only 16 iterations are needed to loop over the entire state_bs array and apply SBox to all bits.
 * 
 * The outputs are stored in the temporary output state_out in the same order but with SBox applied.
 */
static void sbox_layer(bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT])
{
	bs_reg_t state_out[CRYPTO_IN_SIZE_BIT] = { 0 };

	for (uint8_t i = 0; i < 16; i++)
	{
		bs_reg_t in0 = state_bs[i * 4 + 0];
		bs_reg_t in1 = state_bs[i * 4 + 1];
		bs_reg_t in2 = state_bs[i * 4 + 2];
		bs_reg_t in3 = state_bs[i * 4 + 3];

		state_out[i * 4 + 0] = sbox0(in0, in1, in2, in3);
		state_out[i * 4 + 1] = sbox1(in0, in1, in2, in3);
		state_out[i * 4 + 2] = sbox2(in0, in1, in2, in3);
		state_out[i * 4 + 3] = sbox3(in0, in1, in2, in3);
	}
	
	// copy the temporary output state_out into the bitsliced state state_bs
	// to reflect the changes and prevent overwriting entries.
	for (uint8_t i = 0; i < CRYPTO_IN_SIZE_BIT; i++)
	{
		state_bs[i] = state_out[i];
	}
}

/*
 * pbox_layer applies the permutation transformation. The bitsliced implementation of PRESENT
 * allows for an extremely fast and simple permutation implementation.
 * The pbox_layer no longer has to extract individual bits, therefore it is much faster.
 * 
 * It only computes the permuted position of the bit, and moves the whole state_bs entry into
 * the permuted position. This permutes all 32 states at once.
 */
static void pbox_layer(bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT])
{
	bs_reg_t state_out[CRYPTO_IN_SIZE_BIT] = { 0 };

	for (uint8_t bit = 0; bit < CRYPTO_IN_SIZE_BIT; bit++)
	{
		uint8_t out = (bit / 4) + (bit % 4) * 16; // compute the permuted position
		state_out[out] = state_bs[bit];
	}

	// copy the temporary output state_out into the bitsliced state state_bs
	// to reflect the changes and prevent overwriting entries.
	for (uint8_t i = 0; i < CRYPTO_IN_SIZE_BIT; i++)
	{
		state_bs[i] = state_out[i];
	}
}

/**
 * Perform next key schedule step
 * @param key Key register to be updated
 * @param r Round counter
 * @warning For correct function, has to be called with incremented r each time
 * @note You are free to change or optimize this function
 */
static void update_round_key(uint8_t key[CRYPTO_KEY_SIZE], const uint8_t r)
{
	const uint8_t sbox[16] = {
		0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
	};

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

void crypto_func(uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], uint8_t key[CRYPTO_KEY_SIZE])
{
	// State buffer and additional backbuffer of same size
	bs_reg_t state[CRYPTO_IN_SIZE_BIT];
	bs_reg_t bb[CRYPTO_IN_SIZE_BIT];
	
	uint8_t round;
	uint8_t i;
	
	// Bring into bitslicing form
	enslice(pt, state);
	
	// PRESENT main code, nearly identical to the PRESENT paper
	// although instead of the original state s, a bitsliced state is used
	for(i = 1; i <= 31; i++)
	{
		add_round_key(state, key + 2);
		sbox_layer(state);
		pbox_layer(state);
		update_round_key(key, i);
	}
	
	add_round_key(state, key + 2);
		
	// Convert back to normal form
	unslice(state, pt);
}