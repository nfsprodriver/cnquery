package leise

import (
	"errors"
	"sort"

	"go.mondoo.io/mondoo/leise/parser"
	"go.mondoo.io/mondoo/lumi"
	"go.mondoo.io/mondoo/types"
)

type compileHandler struct {
	typ       func(types.Type) types.Type
	signature FunctionSignature
	compile   func(*compiler, types.Type, int32, string, *parser.Call) (types.Type, error)
}

var childType = func(t types.Type) types.Type { return t.Child() }
var arrayBlockType = func(t types.Type) types.Type { return types.Array(types.Map(types.Int, types.Any)) }
var intType = func(t types.Type) types.Type { return types.Int }

var builtinFunctions map[types.Type]map[string]compileHandler

func init() {
	builtinFunctions = map[types.Type]map[string]compileHandler{
		types.ArrayLike: {
			"[]":     {typ: childType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Int}}},
			"{}":     {typ: arrayBlockType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"length": {typ: intType, signature: FunctionSignature{}},
		},
		types.MapLike: {
			"[]":     {typ: childType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.String}}},
			"length": {typ: intType, signature: FunctionSignature{}},
		},
		types.ResourceLike: {
			// "":       compileHandler{compile: compileResourceDefault},
			"where":  {compile: compileResourceWhere, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"length": {compile: compileResourceLength, signature: FunctionSignature{}},
		},
	}
}

func builtinFunction(typ types.Type, id string) (*compileHandler, error) {
	fh, ok := builtinFunctions[typ.Underlying()]
	if !ok {
		return nil, errors.New("Cannot find any functions for type '" + typ.Label() + "'")
	}
	c, ok := fh[id]
	if !ok {
		c, ok = fh[""]
		if !ok {
			return nil, errors.New("Cannot find function '" + id + "' for type '" + typ.Label() + "'")
		}
	}
	return &c, nil
}

func fieldNames(resource *lumi.ResourceInfo) []string {
	res := make([]string, len(resource.Fields))
	idx := 0
	for k := range resource.Fields {
		res[idx] = k
		idx++
	}
	return res
}

func availableFields(c *compiler, typ types.Type) []string {
	m, ok := builtinFunctions[typ.Underlying()]
	if !ok {
		return nil
	}

	res := make([]string, len(m))
	idx := 0
	for k := range m {
		res[idx] = k
		idx++
	}

	if typ.IsResource() {
		fieldNames := fieldNames(c.Schema.Resources[typ.Name()])
		res = append(res, fieldNames...)
	}
	sort.Strings(res)

	return res
}
