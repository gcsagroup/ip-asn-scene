package firewall

import (
	"fmt"
	"math/big"
	"net/netip"
)

func rangeToPrefixes(startText, endText string) ([]string, error) {
	start, err := netip.ParseAddr(startText)
	if err != nil {
		return nil, err
	}
	end, err := netip.ParseAddr(endText)
	if err != nil {
		return nil, err
	}
	start = start.Unmap()
	end = end.Unmap()
	if start.Is4() != end.Is4() {
		return nil, fmt.Errorf("mixed IP versions: %s-%s", startText, endText)
	}
	bits := 128
	if start.Is4() {
		bits = 32
	}
	s := addrToBig(start, bits)
	e := addrToBig(end, bits)
	if s.Cmp(e) > 0 {
		return nil, fmt.Errorf("range start greater than end: %s-%s", startText, endText)
	}

	out := []string{}
	one := big.NewInt(1)
	for s.Cmp(e) <= 0 {
		remaining := new(big.Int).Sub(e, s)
		remaining.Add(remaining, one)

		tz := trailingZeroBits(s, bits)
		blockSize := new(big.Int).Lsh(big.NewInt(1), uint(tz))
		for blockSize.Cmp(remaining) > 0 {
			tz--
			blockSize.Rsh(blockSize, 1)
		}

		prefixBits := bits - tz
		addr, err := bigToAddr(s, bits)
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(addr, prefixBits).Masked().String())
		s = new(big.Int).Add(s, blockSize)
	}
	return out, nil
}

func trailingZeroBits(value *big.Int, bits int) int {
	if value.Sign() == 0 {
		return bits
	}
	for i := 0; i < bits; i++ {
		if value.Bit(i) == 1 {
			return i
		}
	}
	return bits
}

func addrToBig(addr netip.Addr, bits int) *big.Int {
	if bits == 32 {
		raw := addr.As4()
		return new(big.Int).SetBytes(raw[:])
	}
	raw := addr.As16()
	return new(big.Int).SetBytes(raw[:])
}

func bigToAddr(value *big.Int, bits int) (netip.Addr, error) {
	size := bits / 8
	raw := value.Bytes()
	if len(raw) > size {
		return netip.Addr{}, fmt.Errorf("value does not fit in %d bits", bits)
	}
	padded := make([]byte, size)
	copy(padded[size-len(raw):], raw)
	if bits == 32 {
		var arr [4]byte
		copy(arr[:], padded)
		return netip.AddrFrom4(arr), nil
	}
	var arr [16]byte
	copy(arr[:], padded)
	return netip.AddrFrom16(arr), nil
}
