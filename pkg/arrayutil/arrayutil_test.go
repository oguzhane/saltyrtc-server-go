package arrayutil

import (
	"reflect"
	"testing"
)

func TestIntersectionStr(t *testing.T) {
	tests := []struct {
		input  [2][]string
		output []string
	}{
		{[2][]string{{"a", "b", "c"}, {"b", "c", "d"}}, []string{"b", "c"}},
		{[2][]string{{"a", "c", "b"}, {"b", "c", "d"}}, []string{"b", "c"}},
		{[2][]string{{}, {"b", "c", "d"}}, []string{}},
		{[2][]string{{"b"}, {"b", "c", "d"}}, []string{"b"}},
		{[2][]string{{"e"}, {"b", "c", "d"}}, []string{}},
	}
	for _, tt := range tests {
		out := IntersectionStr(tt.input[0], tt.input[1])
		if !reflect.DeepEqual(out, tt.output) {
			t.Fatalf("bad:\nInput:\n%s\nOutput:\n%#v\nExpected output:\n%#v", tt.input, out, tt.output)
		}
	}
}
