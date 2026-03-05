package crypt

type crc8 struct {
	table [256]uint8
}

func newCRC8() CRC {
	c := &crc8{}
	c.GenCRCTable()
	return c
}

// GenCRCTable implements [CRC].
func (c *crc8) GenCRCTable() {
	const poly = 0x07
	for i := range 256 {
		reg := uint8(i)
		for range 8 {
			if reg&0x80 != 0 {
				reg = (reg << 1) ^ poly
			} else {
				reg <<= 1
			}
		}
		c.table[i] = reg
	}
}

// UpdateCRC implements [CRC].
func (c *crc8) UpdateCRC(seq uint32, data []byte) int {
	updated := uint8(seq)
	for _, b := range data {
		updated = c.table[updated^b]
	}
	return int(updated)
}
