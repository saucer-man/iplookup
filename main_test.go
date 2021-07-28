package iplookup

import "testing"

func TestAdd(t *testing.T) {
	err := LookUp("1.1.1.1")
	if err != nil {
		t.Log(err)
	}
}
