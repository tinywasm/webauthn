//go:build wasm

package webauthn

const base64URLTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func base64URLEncode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	out := make([]byte, 0, ((len(data)+2)/3)*4)
	i := 0
	for ; i+2 < len(data); i += 3 {
		v := uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
		out = append(out,
			base64URLTable[(v>>18)&0x3f],
			base64URLTable[(v>>12)&0x3f],
			base64URLTable[(v>>6)&0x3f],
			base64URLTable[v&0x3f],
		)
	}
	rem := len(data) - i
	if rem == 1 {
		v := uint32(data[i]) << 16
		out = append(out,
			base64URLTable[(v>>18)&0x3f],
			base64URLTable[(v>>12)&0x3f],
		)
	} else if rem == 2 {
		v := uint32(data[i])<<16 | uint32(data[i+1])<<8
		out = append(out,
			base64URLTable[(v>>18)&0x3f],
			base64URLTable[(v>>12)&0x3f],
			base64URLTable[(v>>6)&0x3f],
		)
	}
	return string(out)
}

func decodeBase64URLChar(c byte) byte {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A'
	case c >= 'a' && c <= 'z':
		return c - 'a' + 26
	case c >= '0' && c <= '9':
		return c - '0' + 52
	case c == '-':
		return 62
	case c == '_':
		return 63
	default:
		return 0xff
	}
}

func base64URLDecode(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	// Strip any trailing '=' padding if present
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	out := make([]byte, 0, (len(s)*3)/4)
	i := 0
	for ; i+3 < len(s); i += 4 {
		v0, v1, v2, v3 := decodeBase64URLChar(s[i]), decodeBase64URLChar(s[i+1]), decodeBase64URLChar(s[i+2]), decodeBase64URLChar(s[i+3])
		if v0 == 0xff || v1 == 0xff || v2 == 0xff || v3 == 0xff {
			return nil
		}
		v := uint32(v0)<<18 | uint32(v1)<<12 | uint32(v2)<<6 | uint32(v3)
		out = append(out, byte(v>>16), byte(v>>8), byte(v))
	}
	rem := len(s) - i
	if rem == 2 {
		v0, v1 := decodeBase64URLChar(s[i]), decodeBase64URLChar(s[i+1])
		if v0 == 0xff || v1 == 0xff {
			return nil
		}
		v := uint32(v0)<<18 | uint32(v1)<<12
		out = append(out, byte(v>>16))
	} else if rem == 3 {
		v0, v1, v2 := decodeBase64URLChar(s[i]), decodeBase64URLChar(s[i+1]), decodeBase64URLChar(s[i+2])
		if v0 == 0xff || v1 == 0xff || v2 == 0xff {
			return nil
		}
		v := uint32(v0)<<18 | uint32(v1)<<12 | uint32(v2)<<6
		out = append(out, byte(v>>16), byte(v>>8))
	}
	return out
}
