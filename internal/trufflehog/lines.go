package trufflehog

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
)

// maxFile is the largest file Lines reads a context line from.
const maxFile = 8 << 20

// Lines reads the source line of a result, for its context: the file on disk for a filesystem result,
// "git show commit:file" for a result in a local (file://) repository. Files are read once.
type Lines struct {
	files map[string][]string
}

// Line returns the text of the line a result was found on, or false when it cannot be read: a remote
// repository, a file that moved since the scan, a replay on another machine.
func (l *Lines) Line(r Result) (string, bool) {
	if r.Line <= 0 || r.File == "" {
		return "", false
	}
	if l.files == nil {
		l.files = map[string][]string{}
	}
	key := r.Repository + "\x00" + r.Commit + "\x00" + r.File
	lines, ok := l.files[key]
	if !ok {
		lines = read(r)
		l.files[key] = lines
	}
	if r.Line > len(lines) {
		return "", false
	}
	return lines[r.Line-1], true
}

func read(r Result) []string {
	var b []byte
	switch {
	case r.Commit != "":
		repo, ok := strings.CutPrefix(r.Repository, "file://")
		if !ok {
			return nil
		}
		out, err := exec.Command("git", "-C", repo, "show", r.Commit+":"+r.File).Output()
		if err != nil {
			return nil
		}
		b = out
	case r.Source == "Filesystem" || r.Source == "":
		fi, err := os.Stat(r.File)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxFile {
			return nil
		}
		if b, err = os.ReadFile(r.File); err != nil {
			return nil
		}
	default:
		return nil
	}
	if len(b) > maxFile || bytes.IndexByte(b, 0) >= 0 {
		return nil // binary: no line worth showing
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}
