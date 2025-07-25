// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ottlfuncs

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/pdata/pcommon"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
)

func Test_replaceAllMatches(t *testing.T) {
	input := pcommon.NewMap()
	input.PutStr("test", "hello world")
	input.PutStr("test2", "hello")
	input.PutStr("test3", "goodbye")
	input.PutStr("test4", "")
	input.PutInt("test5", 123)

	ottlValue := ottl.StandardFunctionGetter[pcommon.Map]{
		FCtx: ottl.FunctionContext{
			Set: componenttest.NewNopTelemetrySettings(),
		},
		Fact: optionalFnTestFactory[pcommon.Map](),
	}
	prefix := ottl.StandardStringGetter[pcommon.Map]{
		Getter: func(context.Context, pcommon.Map) (any, error) {
			return "prefix=%s", nil
		},
	}
	optionalArg := ottl.NewTestingOptional[ottl.FunctionGetter[pcommon.Map]](ottlValue)

	tests := []struct {
		name              string
		pattern           string
		replacement       ottl.StringGetter[pcommon.Map]
		function          ottl.Optional[ottl.FunctionGetter[pcommon.Map]]
		replacementFormat ottl.Optional[ottl.StringGetter[pcommon.Map]]
		want              func(pcommon.Map)
	}{
		{
			name:    "replace only matches (with hash function)",
			pattern: "hello*",
			replacement: ottl.StandardStringGetter[pcommon.Map]{
				Getter: func(context.Context, pcommon.Map) (any, error) {
					return "hello {universe}", nil
				},
			},
			function:          optionalArg,
			replacementFormat: ottl.NewTestingOptional[ottl.StringGetter[pcommon.Map]](prefix),
			want: func(expectedMap pcommon.Map) {
				expectedMap.PutStr("test", "prefix=hash(hello {universe})")
				expectedMap.PutStr("test2", "prefix=hash(hello {universe})")
				expectedMap.PutStr("test3", "goodbye")
				expectedMap.PutStr("test4", "")
				expectedMap.PutInt("test5", 123)
			},
		},
		{
			name:    "replace only matches",
			pattern: "hello*",
			replacement: ottl.StandardStringGetter[pcommon.Map]{
				Getter: func(context.Context, pcommon.Map) (any, error) {
					return "hello {universe}", nil
				},
			},
			function:          ottl.Optional[ottl.FunctionGetter[pcommon.Map]]{},
			replacementFormat: ottl.Optional[ottl.StringGetter[pcommon.Map]]{},
			want: func(expectedMap pcommon.Map) {
				expectedMap.PutStr("test", "hello {universe}")
				expectedMap.PutStr("test2", "hello {universe}")
				expectedMap.PutStr("test3", "goodbye")
				expectedMap.PutStr("test4", "")
				expectedMap.PutInt("test5", 123)
			},
		},
		{
			name:    "no matches",
			pattern: "nothing*",
			replacement: ottl.StandardStringGetter[pcommon.Map]{
				Getter: func(context.Context, pcommon.Map) (any, error) {
					return "nothing {matches}", nil
				},
			},
			function:          ottl.Optional[ottl.FunctionGetter[pcommon.Map]]{},
			replacementFormat: ottl.Optional[ottl.StringGetter[pcommon.Map]]{},
			want: func(expectedMap pcommon.Map) {
				expectedMap.PutStr("test", "hello world")
				expectedMap.PutStr("test2", "hello")
				expectedMap.PutStr("test3", "goodbye")
				expectedMap.PutStr("test4", "")
				expectedMap.PutInt("test5", 123)
			},
		},
		{
			name:    "replace empty string",
			pattern: "",
			replacement: ottl.StandardStringGetter[pcommon.Map]{
				Getter: func(context.Context, pcommon.Map) (any, error) {
					return "empty_string_replacement", nil
				},
			},
			function:          ottl.Optional[ottl.FunctionGetter[pcommon.Map]]{},
			replacementFormat: ottl.Optional[ottl.StringGetter[pcommon.Map]]{},
			want: func(expectedMap pcommon.Map) {
				expectedMap.PutStr("test", "hello world")
				expectedMap.PutStr("test2", "hello")
				expectedMap.PutStr("test3", "goodbye")
				expectedMap.PutStr("test4", "empty_string_replacement")
				expectedMap.PutInt("test5", 123)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scenarioMap := pcommon.NewMap()
			input.CopyTo(scenarioMap)

			setterWasCalled := false
			target := &ottl.StandardPMapGetSetter[pcommon.Map]{
				Getter: func(_ context.Context, tCtx pcommon.Map) (pcommon.Map, error) {
					return tCtx, nil
				},
				Setter: func(_ context.Context, tCtx pcommon.Map, m any) error {
					setterWasCalled = true
					if v, ok := m.(pcommon.Map); ok {
						v.CopyTo(tCtx)
						return nil
					}
					return errors.New("expected pcommon.Map")
				},
			}

			exprFunc, err := replaceAllMatches(target, tt.pattern, tt.replacement, tt.function, tt.replacementFormat)
			assert.NoError(t, err)

			_, err = exprFunc(nil, scenarioMap)
			assert.NoError(t, err)
			assert.True(t, setterWasCalled)

			expected := pcommon.NewMap()
			tt.want(expected)

			assert.Equal(t, expected, scenarioMap)
		})
	}
}

func Test_replaceAllMatches_bad_input(t *testing.T) {
	input := pcommon.NewValueStr("not a map")
	target := &ottl.StandardPMapGetSetter[any]{
		Getter: func(_ context.Context, tCtx any) (pcommon.Map, error) {
			if v, ok := tCtx.(pcommon.Map); ok {
				return v, nil
			}
			return pcommon.Map{}, errors.New("expected pcommon.Map")
		},
	}
	replacement := &ottl.StandardStringGetter[any]{
		Getter: func(context.Context, any) (any, error) {
			return "{replacement}", nil
		},
	}
	function := ottl.Optional[ottl.FunctionGetter[any]]{}
	replacementFormat := ottl.Optional[ottl.StringGetter[any]]{}

	exprFunc, err := replaceAllMatches[any](target, "*", replacement, function, replacementFormat)
	assert.NoError(t, err)
	_, err = exprFunc(nil, input)
	assert.Error(t, err)
}

func Test_replaceAllMatches_bad_function_input(t *testing.T) {
	input := pcommon.NewValueInt(1)
	target := &ottl.StandardPMapGetSetter[any]{
		Getter: func(_ context.Context, tCtx any) (pcommon.Map, error) {
			if v, ok := tCtx.(pcommon.Map); ok {
				return v, nil
			}
			return pcommon.Map{}, errors.New("expected pcommon.Map")
		},
	}
	replacement := &ottl.StandardStringGetter[any]{
		Getter: func(context.Context, any) (any, error) {
			return nil, nil
		},
	}
	function := ottl.Optional[ottl.FunctionGetter[any]]{}
	replacementFormat := ottl.Optional[ottl.StringGetter[any]]{}

	exprFunc, err := replaceAllMatches[any](target, "regexp", replacement, function, replacementFormat)
	assert.NoError(t, err)

	result, err := exprFunc(nil, input)
	require.Error(t, err)
	assert.ErrorContains(t, err, "expected pcommon.Map")
	assert.Nil(t, result)
}

func Test_replaceAllMatches_bad_function_result(t *testing.T) {
	input := pcommon.NewValueInt(1)
	target := &ottl.StandardPMapGetSetter[any]{
		Getter: func(_ context.Context, tCtx any) (pcommon.Map, error) {
			if v, ok := tCtx.(pcommon.Map); ok {
				return v, nil
			}
			return pcommon.Map{}, errors.New("expected pcommon.Map")
		},
	}
	replacement := &ottl.StandardStringGetter[any]{
		Getter: func(context.Context, any) (any, error) {
			return "{replacement}", nil
		},
	}
	ottlValue := ottl.StandardFunctionGetter[any]{
		FCtx: ottl.FunctionContext{
			Set: componenttest.NewNopTelemetrySettings(),
		},
		Fact: StandardConverters[any]()["IsString"],
	}
	function := ottl.NewTestingOptional[ottl.FunctionGetter[any]](ottlValue)
	replacementFormat := ottl.Optional[ottl.StringGetter[any]]{}

	exprFunc, err := replaceAllMatches[any](target, "regexp", replacement, function, replacementFormat)
	assert.NoError(t, err)

	result, err := exprFunc(nil, input)
	require.Error(t, err)
	assert.Nil(t, result)
}

func Test_replaceAllMatches_get_nil(t *testing.T) {
	target := &ottl.StandardPMapGetSetter[any]{
		Getter: func(_ context.Context, tCtx any) (pcommon.Map, error) {
			if v, ok := tCtx.(pcommon.Map); ok {
				return v, nil
			}
			return pcommon.Map{}, errors.New("expected pcommon.Map")
		},
	}
	replacement := &ottl.StandardStringGetter[any]{
		Getter: func(context.Context, any) (any, error) {
			return "{anything}", nil
		},
	}
	function := ottl.Optional[ottl.FunctionGetter[any]]{}
	replacementFormat := ottl.Optional[ottl.StringGetter[any]]{}

	exprFunc, err := replaceAllMatches[any](target, "*", replacement, function, replacementFormat)
	assert.NoError(t, err)
	_, err = exprFunc(nil, nil)
	assert.Error(t, err)
}
