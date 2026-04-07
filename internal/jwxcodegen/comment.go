package jwxcodegen

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/lestrrat-go/codegen"
)

var reLooksLikeCodeBlock = regexp.MustCompile(`^\s+`)

// WriteComment formats a multi-line YAML comment string as Go doc
// comment lines on the given output. Returns true if any comment
// was written, false if the comment was empty.
func WriteComment(o *codegen.Output, comment string) bool {
	comment = strings.TrimSpace(comment)
	if comment == "" {
		return false
	}
	for i, line := range strings.Split(comment, "\n") {
		if reLooksLikeCodeBlock.MatchString(line) {
			o.L("//")
			var nonSpace int
			for j, r := range line {
				if !unicode.IsSpace(r) {
					nonSpace = j
					break
				}
				o.R("\t")
			}
			o.R(line[nonSpace:])
			continue
		}

		if i == 0 {
			o.LL(`// %s`, line)
		} else {
			o.L(`// %s`, line)
		}
	}
	return true
}
