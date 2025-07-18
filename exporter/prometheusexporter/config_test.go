// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prometheusexporter

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"go.opentelemetry.io/collector/confmap/xconfmap"
	"go.opentelemetry.io/collector/featuregate"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusexporter/internal/metadata"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
	require.NoError(t, err)

	tests := []struct {
		id       component.ID
		expected component.Config
	}{
		{
			id:       component.NewIDWithName(metadata.Type, ""),
			expected: createDefaultConfig(),
		},
		{
			id: component.NewIDWithName(metadata.Type, "2"),
			expected: &Config{
				ServerConfig: confighttp.ServerConfig{
					Endpoint: "1.2.3.4:1234",
					TLS: configoptional.Some(configtls.ServerConfig{
						Config: configtls.Config{
							CertFile: "certs/server.crt",
							KeyFile:  "certs/server.key",
							CAFile:   "certs/ca.crt",
						},
					}),
				},
				Namespace: "test-space",
				ConstLabels: map[string]string{
					"label1":        "value1",
					"another label": "spaced value",
				},
				SendTimestamps:      true,
				MetricExpiration:    60 * time.Minute,
				AddMetricSuffixes:   false,
				TranslationStrategy: UnderscoreEscapingWithSuffixes,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.id.String(), func(t *testing.T) {
			factory := NewFactory()
			cfg := factory.CreateDefaultConfig()

			sub, err := cm.Sub(tt.id.String())
			require.NoError(t, err)
			require.NoError(t, sub.Unmarshal(cfg))

			assert.NoError(t, xconfmap.Validate(cfg))
			assert.Equal(t, tt.expected, cfg)
		})
	}
}

func TestTranslationStrategyValidation(t *testing.T) {
	tests := []struct {
		name          string
		strategy      TranslationStrategy
		featureGateOn bool
		wantErr       bool
	}{
		{
			name:          "Valid strategy with feature gate enabled",
			strategy:      UnderscoreEscapingWithSuffixes,
			featureGateOn: true,
			wantErr:       false,
		},
		{
			name:          "Valid strategy NoTranslation with feature gate enabled",
			strategy:      NoTranslation,
			featureGateOn: true,
			wantErr:       false,
		},
		{
			name:          "Invalid strategy with feature gate enabled",
			strategy:      "InvalidStrategy",
			featureGateOn: true,
			wantErr:       true,
		},
		{
			name:          "Empty strategy with feature gate enabled",
			strategy:      "",
			featureGateOn: true,
			wantErr:       true,
		},
		{
			name:          "Any strategy with feature gate disabled",
			strategy:      "InvalidStrategy",
			featureGateOn: false,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set feature gate state
			originalState := translationStrategyFeatureGate.IsEnabled()
			err := featuregate.GlobalRegistry().Set("exporter.prometheusexporter.UseTranslationStrategy", tt.featureGateOn)
			require.NoError(t, err)
			defer func() {
				err := featuregate.GlobalRegistry().Set("exporter.prometheusexporter.UseTranslationStrategy", originalState)
				require.NoError(t, err)
			}()

			cfg := &Config{
				TranslationStrategy: tt.strategy,
			}

			err = cfg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultConfigTranslationStrategy(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	assert.Equal(t, UnderscoreEscapingWithSuffixes, cfg.TranslationStrategy)
	assert.True(t, cfg.AddMetricSuffixes) // Legacy field should still default to true
}
