// copyright: 2019, Dominik Richter and Christoph Hartmann
// author: Dominik Richter
// author: Christoph Hartmann

package os

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mondoo.com/cnquery/resources"
	"go.mondoo.com/cnquery/resources/packs/core"
	"go.mondoo.com/cnquery/resources/packs/os/sshd"
)

func (s *mqlSshd) id() (string, error) {
	return "sshd", nil
}

func (s *mqlSshdConfig) init(args *resources.Args) (*resources.Args, SshdConfig, error) {
	if x, ok := (*args)["path"]; ok {
		path, ok := x.(string)
		if !ok {
			return nil, nil, errors.New("Wrong type for 'path' in sshd.config initialization, it must be a string")
		}

		f, err := s.MotorRuntime.CreateResource("file", "path", path)
		if err != nil {
			return nil, nil, err
		}
		(*args)["file"] = f

		files, err := s.getFiles(path)
		if err != nil {
			return nil, nil, err
		}
		(*args)["files"] = files
		delete(*args, "path")
	}

	return args, nil, nil
}

const defaultSshdConfig = "/etc/ssh/sshd_config"

func (s *mqlSshdConfig) id() (string, error) {
	r, err := s.File()
	if err != nil {
		return "", err
	}
	return r.Path()
}

func (s *mqlSshdConfig) getFiles(confPath string) ([]interface{}, error) {
	lumiFile, err := s.MotorRuntime.CreateResource("file", "path", confPath)
	if err != nil {
		return nil, err
	}
	f := lumiFile.(core.File)
	exists, err := f.Exists()
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, errors.New("could not load sshd configuration: " + confPath)
	}

	osProv, err := osProvider(s.MotorRuntime.Motor)
	if err != nil {
		return nil, err
	}

	// Get the list of all files involved in defining the runtime sshd configuration
	content, ctx, err := sshd.ReadSshdConfig(confPath, s.MotorRuntime, osProv)
	if err != nil {
		return nil, err
	}

	// Return a list of lumi files
	lumiFiles := make([]interface{}, len(ctx.Files))
	idx := 0
	for _, v := range ctx.Files {
		lumiFiles[idx] = v
		idx++
	}

	// we use this during params parsing to get file context
	s.Cache.Store("_ctx", &resources.CacheEntry{
		Valid:     true,
		Timestamp: time.Now().Unix(),
		Data:      ctx,
	})

	// We may as well store this, since we just read it all [Note#1]
	s.Cache.Store("content", &resources.CacheEntry{
		Valid:     true,
		Timestamp: time.Now().Unix(),
		Data:      content,
	})

	return lumiFiles, nil
}

func (s *mqlSshdConfig) GetFile() (core.File, error) {
	f, err := s.MotorRuntime.CreateResource("file", "path", defaultSshdConfig)
	if err != nil {
		return nil, err
	}
	return f.(core.File), nil
}

func (s *mqlSshdConfig) GetFiles() ([]interface{}, error) {
	lumiFile, err := s.MotorRuntime.CreateResource("file", "path", defaultSshdConfig)
	if err != nil {
		return nil, err
	}
	f := lumiFile.(core.File)
	exists, err := f.Exists()
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, errors.New(fmt.Sprintf(" could not read sshd config file %s", defaultSshdConfig))
	}
	files, err := s.getFiles(defaultSshdConfig)
	if err != nil {
		return nil, err
	}

	return files, nil
}

func (s *mqlSshdConfig) GetContent(files []interface{}) (string, error) {
	// TODO: this can be heavily improved once we do it right, since this is constantly
	// re-registered as the file changes.

	// This method is not called if GetFiles was executed (and not pre-cached),
	// in which case we get the content for free. See [Note#1]

	// files is in the "dependency" order that files were discovered while
	// parsing the base/root config file. We will essentially re-parse the
	// config and insert the contents of those dependent files in-place where
	// they appear in the base/root config.
	if len(files) < 1 {
		return "", fmt.Errorf("no base sshd config file to read")
	}

	lumiFiles := make([]core.File, len(files))
	for i, file := range files {
		lumiFile, ok := file.(core.File)
		if !ok {
			return "", fmt.Errorf("failed to type assert list of files to File interface")
		}
		lumiFiles[i] = lumiFile
	}

	// The first entry in our list is the base/root of the sshd configuration tree
	baseConfigFilePath, err := lumiFiles[0].Path()
	if err != nil {
		return "", err
	}

	osProv, err := osProvider(s.MotorRuntime.Motor)
	if err != nil {
		return "", err
	}

	// In this second pass we will get the files that matter from the
	// root file's perspective.
	content, ctx, err := sshd.ReadSshdConfig(baseConfigFilePath, s.MotorRuntime, osProv)
	if err != nil {
		return "", err
	}

	// we use this during params parsing to get file context
	s.Cache.Store("_ctx", &resources.CacheEntry{
		Valid:     true,
		Timestamp: time.Now().Unix(),
		Data:      ctx,
	})

	return content, nil
}

func (s *mqlSshdConfig) GetParams(content string) (map[string]interface{}, error) {
	cache, ok := s.Cache.Load("_ctx")
	var contentCtx sshd.RangeContext
	if ok {
		contentCtx = cache.Data.(sshd.RangeContext)
	}

	params, paramsContext, err := sshd.Params(content, contentCtx)
	if err != nil {
		return nil, err
	}

	// convert  map
	res := map[string]interface{}{}
	for k, v := range params {
		res[k] = v
	}

	ctx := make(map[string]sshd.ContextInfo, len(paramsContext))
	for k, v := range paramsContext {
		ctx["params.[\""+k+"\"]"] = v
	}

	s.Cache.Store("_context", &resources.CacheEntry{
		Timestamp: time.Now().Unix(),
		Valid:     true,
		Data:      ctx,
	})

	return res, nil
}

func (s *mqlSshdConfig) parseConfigEntrySlice(raw interface{}) ([]interface{}, error) {
	strCipher, ok := raw.(string)
	if !ok {
		return nil, errors.New("value is not a valid string")
	}

	res := []interface{}{}
	entries := strings.Split(strCipher, ",")
	for i := range entries {
		val := strings.TrimSpace(entries[i])
		res = append(res, val)
	}

	return res, nil
}

func (s *mqlSshdConfig) GetCiphers(params map[string]interface{}) ([]interface{}, error) {
	rawCiphers, ok := params["Ciphers"]
	if !ok {
		return nil, nil
	}

	return s.parseConfigEntrySlice(rawCiphers)
}

func (s *mqlSshdConfig) GetMacs(params map[string]interface{}) ([]interface{}, error) {
	rawMacs, ok := params["MACs"]
	if !ok {
		return nil, nil
	}

	return s.parseConfigEntrySlice(rawMacs)
}

func (s *mqlSshdConfig) GetKexs(params map[string]interface{}) ([]interface{}, error) {
	rawkexs, ok := params["KexAlgorithms"]
	if !ok {
		return nil, nil
	}

	return s.parseConfigEntrySlice(rawkexs)
}

func (s *mqlSshdConfig) GetHostkeys(params map[string]interface{}) ([]interface{}, error) {
	rawHostKeys, ok := params["HostKey"]
	if !ok {
		return nil, nil
	}

	return s.parseConfigEntrySlice(rawHostKeys)
}

func (s *mqlSshdConfig) GetContext(calls []string) (interface{}, error) {
	entry, ok := s.Cache.Load("_context")
	if !ok || entry == nil {
		return nil, errors.New("no file context found for sshd.config")
	}

	contexts, ok := entry.Data.(map[string]sshd.ContextInfo)
	if !ok {
		return nil, errors.New("internal error, cannot map calls to context in sshd.config")
	}

	sCalls := strings.Join(calls, ".")
	context, ok := contexts[sCalls]
	if !ok {
		return nil, nil
	}

	r, err := s.MotorRuntime.CreateResource("file.context",
		"file", context.File,
		"range", []byte(context.Range),
	)
	if err != nil {
		return nil, err
	}

	return r, nil
}
