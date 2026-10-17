// test789c : USAG-Lib bencode

package Bencode

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"
)

var splitable = map[string]bool{
	"!": true, "@": true, "#": true, "$": true, "%": true,
	"^": true, "&": true, "*": true, "~": true, "|": true,
}

func Encode64(data []byte, spliter string, linenum int, colnum int) (string, error) {
	if linenum <= 0 {
		linenum = 40
	}
	if colnum <= 0 {
		colnum = 10
	}
	raw := ""
	if len(data) > 0 {
		raw = base64.StdEncoding.EncodeToString(data)
	}

	// check spliter
	if spliter == "" {
		return raw, nil
	}
	if !splitable[spliter] {
		return "", errors.New("invalid spliter option")
	}

	// split raw text
	var lines []string
	for i := 0; i < len(raw); i += linenum {
		end := min(i+linenum, len(raw))
		lines = append(lines, raw[i:end])
	}
	var cols [][]string
	for i := 0; i < len(lines); i += colnum {
		end := min(i+colnum, len(lines))
		cols = append(cols, lines[i:end])
	}

	// assemble text
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%sSTART%s\n", spliter, spliter))
	for i, col := range cols {
		builder.WriteString(fmt.Sprintf("%s%d/%d%s\n", spliter, i+1, len(cols), spliter))
		builder.WriteString(strings.Join(col, "\n"))
		builder.WriteString("\n")
	}
	builder.WriteString(fmt.Sprintf("%sEND%s", spliter, spliter))
	return builder.String(), nil
}

// Encode64h is a helper function for Encode64 with default options
func Encode64h(data []byte) string {
	result, _ := Encode64(data, "", 0, 0)
	return result
}

func Decode64(data string, spliter string) ([]byte, error) {
	data = strings.ReplaceAll(data, "\r", "")
	data = strings.ReplaceAll(data, "\n", "")
	data = strings.ReplaceAll(data, " ", "")
	data = strings.ReplaceAll(data, "\t", "")
	if spliter != "" && !splitable[spliter] {
		return nil, errors.New("invalid spliter option")
	}

	// remove comments
	if spliter != "" {
		parts := strings.Split(data, spliter)
		var pureData strings.Builder
		for i := 0; i < len(parts); i += 2 {
			pureData.WriteString(parts[i])
		}
		data = pureData.String()
	}

	if data == "" {
		return []byte{}, nil
	}
	return base64.StdEncoding.DecodeString(data)
}

func NormPW(pw string) []byte {
	if pw == "" {
		return []byte{}
	}
	return []byte(norm.NFC.String(pw))
}
