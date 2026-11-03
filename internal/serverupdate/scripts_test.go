package serverupdate

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// heredoc starts a here-document (<<EOF, <<-'EOF').
var heredoc = regexp.MustCompile(`<<-?\s*'?([A-Za-z_]+)'?`)

// doubleQuoted is a double-quoted string; comment a comment (at the start of
// a line or after a space).
var (
	doubleQuoted = regexp.MustCompile(`"(\\.|[^"\\])*"`)
	comment      = regexp.MustCompile(`(^|\s)#.*$`)
)

// openQuotes lists the lines of a shell script that leave a single-quoted
// string open: an odd number of single quotes outside comments and
// here-documents. The deploy scripts never continue a single-quoted string
// over lines, and bash -n accepts such a line when a later quote closes it,
// silently turning the commands in between into text.
func openQuotes(script string) []int {
	var out []int
	term := ""
	for i, line := range strings.Split(script, "\n") {
		if term != "" {
			if strings.TrimSpace(line) == term {
				term = ""
			}
			continue
		}
		// Apostrophes in double-quoted text and comments do not count.
		code := doubleQuoted.ReplaceAllString(line, "")
		code = comment.ReplaceAllString(code, "")
		if (strings.Count(code, "'")-strings.Count(code, `\'`))%2 != 0 {
			out = append(out, i+1)
		}
		if m := heredoc.FindStringSubmatch(code); m != nil {
			term = m[1]
		}
	}
	return out
}

// The install and update scripts have no single-quoted string left open,
// as install.sh had from 0.1.4 to 0.4.0-rc.1: an empty assignment written
// with one quote swallowed the Docker checks and the compose helper.
func TestDeployScriptQuotes(t *testing.T) {
	if got := openQuotes("a=1\n[ \"$x\" != none ] || x='\nb() { :; }\nc='done'\n"); len(got) != 1 || got[0] != 2 {
		t.Fatal("the check misses an open quote", got)
	}
	scripts, _ := filepath.Glob(filepath.Join("..", "..", "deploy", "*.sh"))
	if len(scripts) == 0 {
		t.Fatal("no deploy scripts found")
	}
	for _, path := range scripts {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if lines := openQuotes(string(b)); len(lines) > 0 {
			t.Errorf("%s: a single-quoted string is left open on lines %v", filepath.Base(path), lines)
		}
	}
}
