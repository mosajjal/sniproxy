package acl

import "testing"

// TestReverse tests the reverse function
func TestReverse(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{name: "test1", s: "abc", want: "cba"},
		{name: "test2", s: "a", want: "a"},
		{name: "test3", s: "aab", want: "baa"},
		{name: "test4", s: "zzZ", want: "Zzz"},
		{name: "test5", s: "ab2", want: "2ba"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reverse(tt.s); got != tt.want {
				t.Errorf("reverse() = %v, want %v", got, tt.want)
			}
		})
	}
}
