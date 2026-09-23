package token

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
)

// CanonicalJSON encodes v with sorted object keys and no whitespace. Values
// are first round-tripped through encoding/json so structs and maps agree.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	writeCanon(&buf, x)
	return buf.Bytes(), nil
}

func writeCanon(buf *bytes.Buffer, v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			writeCanon(buf, t[k])
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanon(buf, e)
		}
		buf.WriteByte(']')
	case json.Number:
		// normalise 1.0 / 1 / 1e0 to the same text
		if f, err := strconv.ParseFloat(string(t), 64); err == nil {
			buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
		} else {
			buf.WriteString(string(t))
		}
	default:
		b, _ := json.Marshal(t)
		buf.Write(b)
	}
}

// ActionHash is sha256hex(canonical_json({"tool":..,"resource":..,"args":..})).
// Approvals sign this value, so an approval is valid only for that exact call.
func ActionHash(c Call) string {
	args := c.Args
	if args == nil {
		args = map[string]any{}
	}
	b, _ := CanonicalJSON(map[string]any{"tool": c.Tool, "resource": c.Resource, "args": args})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
