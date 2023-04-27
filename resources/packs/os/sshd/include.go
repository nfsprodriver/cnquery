package sshd

import (
	"bufio"
	"fmt"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/afero"

	"go.mondoo.com/cnquery/llx"
	"go.mondoo.com/cnquery/motor/providers/os"
	"go.mondoo.com/cnquery/resources"
	"go.mondoo.com/cnquery/resources/packs/core"
)

var (
	// includeStatement is a regexp for checking whether a given sshd configuration line
	// is an 'Include' statement
	includeStatement = regexp.MustCompile(`^[I|i]nclude\s+(.*)$`)
	// includeStatementHasGlob is a regext for checking whether the contents of an 'Include'
	// statement have a wildcard/glob (ie. a literal '*')
	includeStatementHasGlob = regexp.MustCompile(`.*\*.*`)
)

// When an Include lists a relative path, it is interpreted as relative to /etc/ssh/
const relativePathPrefix = "/etc/ssh/"

func getBaseDirectory(filePath string) string {
	baseDirectoryPath := filepath.Dir(filePath)
	// insert the /etc/ssh path prefix if a relative path is specified
	if baseDirectoryPath == "." {
		baseDirectoryPath = relativePathPrefix
	}
	if !strings.HasPrefix(baseDirectoryPath, "/") {
		baseDirectoryPath = relativePathPrefix + baseDirectoryPath
	}

	return baseDirectoryPath
}

func getFullPath(filePath string) string {
	dir := getBaseDirectory(filePath)
	fileName := filepath.Base(filePath)
	return filepath.Join(dir, fileName)
}

// ReadSshdConfig will traverse the provided path to an sshd config file and return
// the list of all depended files encountered while recursively traversing the
// sshd 'Include' statements, and the unified sshd configuration where all the
// sshd 'Include' statements have been replaced with the referenced file's content
// in place of the 'Include'.
func ReadSshdConfig(filePath string, runtime *resources.Runtime, osProvider os.OperatingSystemProvider) (string, RangeContext, error) {
	ctx := RangeContext{
		Files: map[string]core.File{},
	}
	var res strings.Builder

	baseDirectoryPath := getBaseDirectory(filePath)

	// 1: check if the Include path has a wildcard/glob
	m := includeStatementHasGlob.FindStringSubmatch(filePath)
	if m != nil {
		glob := filepath.Base(filePath)

		// List all the files in lexical order and check whether any match the glob
		afs := &afero.Afero{Fs: osProvider.FS()}

		wErr := afs.Walk(baseDirectoryPath, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// don't recurse down further directories (as that matches sshd behavior)
			if info.IsDir() {
				return nil
			}
			match, err := filepath.Match(glob, info.Name())
			if err != nil {
				return err
			}
			if !match {
				return nil
			}

			fullFilepath := filepath.Join(baseDirectoryPath, info.Name())

			// Now search through that file for any more Include statements
			s, c, err := ReadSshdConfig(fullFilepath, runtime, osProvider)
			if err != nil {
				return err
			}
			ctx.AddRange(c)
			res.WriteString(s)

			return nil
		})
		if wErr != nil {
			return "", ctx, fmt.Errorf("error while walking through sshd config directory: %s", wErr)
		}

		return res.String(), ctx, nil
	}

	// 2: See if we're dealing with a directory
	fullFilePath := getFullPath(filePath)
	f, err := osProvider.FS().Open(fullFilePath)
	if err != nil {
		return "", ctx, err
	}

	fileInfo, err := f.Stat()
	if err != nil {
		return "", ctx, err
	}
	if fileInfo.IsDir() {
		// Again list all files in lexical order
		afs := &afero.Afero{Fs: osProvider.FS()}

		wErr := afs.Walk(fullFilePath, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			// Now check this very file for any 'Include' statements
			s, c, err := ReadSshdConfig(path, runtime, osProvider)
			if err != nil {
				return err
			}
			ctx.AddRange(c)
			res.WriteString(s)

			return nil
		})
		if wErr != nil {
			return "", ctx, fmt.Errorf("error while walking through sshd config directory: %s", wErr)
		}

		return res.String(), ctx, nil
	}

	// 3: If here, we must be dealing with neither a wildcard nor directory
	// so just consume the file's contents
	rawFile, err := ioutil.ReadAll(f)
	if err != nil {
		return "", ctx, err
	}

	rFile, err := runtime.CreateResource("file", "path", filePath, "content", string(rawFile))
	if err != nil {
		return "", ctx, err
	}
	coreFile := rFile.(core.File)
	ctx.Files[coreFile.MqlResource().Id] = coreFile

	scanner := bufio.NewScanner(strings.NewReader(string(rawFile)))
	lines := 0
	startLine := 1
	for scanner.Scan() {
		line := scanner.Text()
		lines++
		m := includeStatement.FindStringSubmatch(line)
		if m != nil {
			includeList := strings.Split(m[1], " ") // TODO: what about files with actual spaces in their names?
			for _, file := range includeList {
				ctx.Ranges = append(ctx.Ranges, ContextInfo{
					File:  coreFile,
					Range: llx.NewRange().AddLineRange(uint32(startLine), uint32(lines)),
				})

				s, c, err := ReadSshdConfig(file, runtime, osProvider)
				if err != nil {
					return "", ctx, err
				}
				ctx.AddRange(c)
				res.WriteString(s)

				startLine = lines + 1
			}
			continue
		}

		res.WriteString(line)
		res.WriteByte('\n')
	}

	ctx.Ranges = append(ctx.Ranges, ContextInfo{
		File:  coreFile,
		Range: llx.NewRange().AddLineRange(uint32(startLine), uint32(lines)),
	})

	return res.String(), ctx, nil
}
