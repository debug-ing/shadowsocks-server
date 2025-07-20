package core

import (
	"encoding/hex"
	"testing"
)

func TestKDF(t *testing.T) {
	type args struct {
		password string
		keyLen   int
	}
	tests := []struct {
		name    string
		args    args
		wantHex string // expected hex representation
	}{
		{
			name: "16 bytes key",
			args: args{
				password: "password123",
				keyLen:   16,
			},
			wantHex: "482c811da5d5b4bc6d497ffa98491e38", // md5("password123")
		},
		{
			name: "32 bytes key",
			args: args{
				password: "password123",
				keyLen:   32,
			},
			wantHex: "482c811da5d5b4bc6d497ffa98491e38b07b0eb6035570ade095cea982c8b1eb", // 2 * md5
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := kdf(tt.args.password, tt.args.keyLen)
			gotHex := hex.EncodeToString(got)
			if gotHex != tt.wantHex {
				t.Errorf("kdf() = %v, want %v", gotHex, tt.wantHex)
			}
		})
	}
}
