package parser

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"

	"github.com/stretchr/testify/require"
)

func TestOverrideAnyTLSOptions(t *testing.T) {
	testCases := []struct {
		name                   string
		clientMetadata         *string
		override               *option.OverrideAnyTLSOptions
		expectedClientMetadata string
	}{
		{name: "preserve unset"},
		{
			name:                   "preserve value",
			clientMetadata:         common.Ptr("original-client/1.0"),
			expectedClientMetadata: "original-client/1.0",
		},
		{
			name:           "clear",
			clientMetadata: common.Ptr("original-client/1.0"),
			override: &option.OverrideAnyTLSOptions{
				ClientMetadata: common.Ptr(""),
			},
		},
		{
			name: "replace",
			override: &option.OverrideAnyTLSOptions{
				ClientMetadata: common.Ptr("custom-client/1.0"),
			},
			expectedClientMetadata: "custom-client/1.0",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			outbounds := overrideOutbounds([]option.Outbound{{
				Type: C.TypeAnyTLS,
				Options: &option.AnyTLSOutboundOptions{
					ClientMetadata: valueOrEmpty(testCase.clientMetadata),
				},
			}}, nil, nil, testCase.override, nil, "")
			options := outbounds[0].Options.(*option.AnyTLSOutboundOptions)
			require.Equal(t, testCase.expectedClientMetadata, options.ClientMetadata)
		})
	}
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
