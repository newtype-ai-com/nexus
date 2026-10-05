package core

import "testing"

func TestSetLanguage(t *testing.T) {
	e := &Engine{opts: Options{Language: "ko"}}
	if e.Language() != "ko" {
		t.Fatal(e.Language())
	}
	e.SetLanguage("en")
	if e.Language() != "en" {
		t.Fatal(e.Language())
	}
	e.SetLanguage("fr")
	if e.Language() != "ko" {
		t.Fatal(e.Language())
	}
	if (&Engine{}).Language() != "ko" {
		t.Fatal("zero engine")
	}
}
