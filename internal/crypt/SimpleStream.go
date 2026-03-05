package crypt

import "encoding/binary"

const (
	KEY_MASK  = 0x53351D9C
	KEY_DELTA = 0x63CAACE3
)

func SimpleStreamEncrypt(plain []byte, seqSnd uint32) []byte {
	length := len(plain)
	if length == 0 {
		return nil
	}

	blockCount := length >> 2 // Number of 4-byte blocks
	remain := length & 3      // Trailing bytes (0-3)
	cipher := make([]byte, length)

	// Initial key derivation based on the sequence number
	key := seqSnd ^ KEY_MASK
	var lastPlain uint32 = key

	if blockCount > 0 {
		// --- Block 0 Processing ---
		// The first block is XORed directly with the initial key.
		p0 := binary.LittleEndian.Uint32(plain[0:4])
		c0 := p0 ^ lastPlain
		binary.LittleEndian.PutUint32(cipher[0:4], c0)

		// Update the seed with the current plaintext for the next block.
		lastPlain = p0

		// --- Blocks 1 to N Processing ---
		for i := 1; i < blockCount; i++ {
			// Key transformation: Decrease by the constant 0x63CAACE3 (1674226915)
			key -= KEY_DELTA

			offset := i * 4
			pi := binary.LittleEndian.Uint32(plain[offset : offset+4])

			// Encryption Formula: Cipher[i] = Plain[i] ^ Key ^ Plain[i-1]
			// This allows the decoder to perform: Plain[i] = Cipher[i] ^ Key ^ Plain[i-1]
			ci := pi ^ key ^ lastPlain
			binary.LittleEndian.PutUint32(cipher[offset:offset+4], ci)

			// Update the seed with the current plaintext for the next iteration
			lastPlain = pi
		}
	}

	// --- Handling Trailing Bytes ---
	// They are XORed with the last calculated plaintext or the initial key.
	if remain > 0 {
		offset := blockCount * 4
		for i := range remain {
			// XOR each trailing byte with the corresponding byte from the last seed (lastPlain)
			cipher[offset+i] = plain[offset+i] ^ byte(lastPlain>>(8*i))
		}
	}

	return cipher
}

func SimpleStreamDecrypt(cipher []byte, seqRcv uint32) []byte {
	length := len(cipher)
	if length == 0 {
		return nil
	}

	blockCount := length >> 2 // Number of 4-byte blocks
	remain := length & 3      // Remaining bytes (0-3)
	plain := make([]byte, length)

	// Initial encryption key derivation
	key := seqRcv ^ KEY_MASK

	if blockCount > 0 {
		// --- Block 0 Processing ---
		// The first block is XORed with the initial key only.
		c0 := binary.LittleEndian.Uint32(cipher[0:4])
		p0 := c0 ^ key
		binary.LittleEndian.PutUint32(plain[0:4], p0)
		prevPlain := p0

		// --- Blocks 1 to N Processing ---
		for i := 1; i < blockCount; i++ {
			// Key transformation: Decrease by the constant 0x63CAACE3 (1674226915)
			key -= KEY_DELTA
			offset := i * 4
			ci := binary.LittleEndian.Uint32(cipher[offset : offset+4])

			// Decryption Formula: P[i] = C[i] ^ Key ^ P[i-1]
			pi := ci ^ key ^ prevPlain
			binary.LittleEndian.PutUint32(plain[offset:offset+4], pi)

			// Update the seed for the next iteration
			prevPlain = pi
		}

		// --- Handling Trailing Bytes (Data length % 4 != 0) ---
		// The key for trailing bytes is the last processed full PLAINTEXT block.
		lastFullKey := prevPlain
		offset := blockCount * 4
		for i := range remain {
			// XOR remaining bytes with bits from the last plaintext block
			plain[offset+i] = cipher[offset+i] ^ byte(lastFullKey>>(8*i))
		}
	} else if remain > 0 {
		// --- Handling Short Data (Length < 4 bytes) ---
		// If no full blocks exist, XOR directly with the initial key bytes.
		for i := range remain {
			plain[i] = cipher[i] ^ byte(key>>(8*i))
		}
	}

	return plain
}
