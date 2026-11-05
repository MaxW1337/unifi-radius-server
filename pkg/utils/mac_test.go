package utils

import (
	"testing"
)

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "Standard colon lowercase",
			input:   "00:11:22:33:44:55",
			want:    "00:11:22:33:44:55",
			wantErr: false,
		},
		{
			name:    "Standard colon mixed case",
			input:   "0a:1B:2c:3D:4e:5F",
			want:    "0A:1B:2C:3D:4E:5F",
			wantErr: false,
		},
		{
			name:    "Hyphen notation",
			input:   "00-11-22-33-44-55",
			want:    "00:11:22:33:44:55",
			wantErr: false,
		},
		{
			name:    "Cisco dot notation",
			input:   "0011.2233.4455",
			want:    "00:11:22:33:44:55",
			wantErr: false,
		},
		{
			name:    "Plain hex string lowercase",
			input:   "aabbccddeeff",
			want:    "AA:BB:CC:DD:EE:FF",
			wantErr: false,
		},
		{
			name:    "With surrounding spaces",
			input:   "  00:11:22:33:44:55  \n",
			want:    "00:11:22:33:44:55",
			wantErr: false,
		},
		{
			name:    "Too short",
			input:   "00:11:22:33:44",
			wantErr: true,
		},
		{
			name:    "Too long",
			input:   "00:11:22:33:44:55:66",
			wantErr: true,
		},
		{
			name:    "Invalid characters",
			input:   "00:11:22:33:44:ZZ",
			wantErr: true,
		},
		{
			name:    "Empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeMAC(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizeMAC(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("NormalizeMAC(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsValidMAC(t *testing.T) {
	if !IsValidMAC("AA:BB:CC:DD:EE:FF") {
		t.Error("Expected AA:BB:CC:DD:EE:FF to be valid")
	}
	if !IsValidMAC("aabbccddeeff") {
		t.Error("Expected aabbccddeeff to be valid")
	}
	if IsValidMAC("invalid-mac") {
		t.Error("Expected invalid-mac to be invalid")
	}
}

func TestIsRandomizedMAC(t *testing.T) {
	tests := []struct {
		mac  string
		want bool
	}{
		{"02:00:00:00:00:00", true},  // 0x02 has bit 1 set
		{"06:12:34:56:78:9A", true},  // 0x06 has bit 1 set
		{"0A:BB:CC:DD:EE:FF", true},  // 0x0A has bit 1 set
		{"0E:00:11:22:33:44", true},  // 0x0E has bit 1 set
		{"DA:A1:19:12:34:56", true},  // 0xDA = 11011010b, bit 1 set
		{"00:11:22:33:44:55", false}, // 0x00 = standard universal hardware OUI
		{"FC:EC:DA:11:22:33", false}, // 0xFC = 11111100b, bit 1 is 0
		{"70:A8:E3:AA:BB:CC", false}, // 0x70 = 01110000b, bit 1 is 0
		{"invalid", false},
	}

	for _, tt := range tests {
		got := IsRandomizedMAC(tt.mac)
		if got != tt.want {
			t.Errorf("IsRandomizedMAC(%q) = %v, want %v", tt.mac, got, tt.want)
		}
	}
}


