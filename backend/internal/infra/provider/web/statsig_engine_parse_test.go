package web

import (
	"strings"
	"testing"
)

func TestParseStatsigCurvesAcceptsDirectAndRSCEncodedPayloads(t *testing.T) {
	direct := `[[{"color":[1,2,3,4,5,6],"deg":90,"bezier":[7,8,9,10]}]]`
	escaped := strings.ReplaceAll(direct, `"`, `\"`)

	want := direct
	for name, home := range map[string]string{
		"direct":  `<html>` + direct + `</html>`,
		"escaped": `<script>self.__next_f.push([1,"` + escaped + `"])</script>`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseStatsigCurves(home)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Fatalf("curves = %s, want %s", got, want)
			}
		})
	}
}

func TestParseStatsigCurvesRejectsInvalidPayloads(t *testing.T) {
	valid := `[[{"color":[1,2,3,4,5,6],"deg":90,"bezier":[7,8,9,10]}]]`
	tests := map[string]string{
		"truncated escaped":  strings.ReplaceAll(strings.TrimSuffix(valid, "]]"), `"`, `\"`),
		"wrong color width":  `[[{"color":[1,2,3],"deg":90,"bezier":[7,8,9,10]}]]`,
		"wrong bezier width": `[[{"color":[1,2,3,4,5,6],"deg":90,"bezier":[7]}]]`,
		"unknown field":      `[[{"color":[1,2,3,4,5,6],"deg":90,"bezier":[7,8,9,10],"extra":1}]]`,
		"empty group":        `[[]]`,
	}
	for name, home := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseStatsigCurves(home); err == nil {
				t.Fatal("parseStatsigCurves unexpectedly succeeded")
			}
		})
	}
}

func TestParseStatsigCurvesRejectsOversizedPayload(t *testing.T) {
	curve := `{"color":[1,2,3,4,5,6],"deg":90,"bezier":[7,8,9,10]}`
	home := `[[` + strings.Repeat(curve+`,`, 65) + curve + `]]`
	if _, err := parseStatsigCurves(home); err == nil {
		t.Fatal("parseStatsigCurves unexpectedly accepted too many curves")
	}
}
