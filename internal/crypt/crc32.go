package crypt

type crc32 struct {
	table [256]uint32
}

func newCRC32() CRC {
	c := &crc32{}
	c.GenCRCTable()
	return c
}

// GenCRCTable implements [CRC].
func (c *crc32) GenCRCTable() {
	const poly uint32 = 0x04C11DB7
	for i := range 256 {
		reg := uint32(i) << 24
		for range 8 {
			if (reg & 0x80000000) != 0 {
				reg = (reg << 1) ^ poly
			} else {
				reg = reg << 1
			}
		}
		c.table[i] = reg
	}
}

// UpdateCRC implements [CRC].
func (c *crc32) UpdateCRC(seq uint32, data []byte) int {
	updated := seq
	for _, b := range data {
		idx := (updated >> 24) ^ uint32(b)
		updated = c.table[idx] ^ (updated << 8)
	}
	return int(updated)
}
