// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prometheusexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusexporter"

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/resourcetotelemetry"
)

// TranslationStrategy defines how OpenTelemetry metrics are translated to Prometheus format
type TranslationStrategy string

const (
	// TranslationStrategyUnderscoreEscapingWithSuffixes fully escapes metric names for classic Prometheus 
	// metric name compatibility, and includes appending type and unit suffixes. This is the default.
	TranslationStrategyUnderscoreEscapingWithSuffixes TranslationStrategy = "UnderscoreEscapingWithSuffixes"
	
	// TranslationStrategyNoUTF8EscapingWithSuffixes disables changing special characters to `_`. 
	// Special suffixes like units and `_total` for counters will be attached.
	TranslationStrategyNoUTF8EscapingWithSuffixes TranslationStrategy = "NoUTF8EscapingWithSuffixes"
	
	// TranslationStrategyNoTranslation bypasses all metric and label name translation, 
	// passing them through unaltered.
	TranslationStrategyNoTranslation TranslationStrategy = "NoTranslation"
)

// Config defines configuration for Prometheus exporter.
type Config struct {
	confighttp.ServerConfig `mapstructure:",squash"`

	// Namespace if set, exports metrics under the provided value.
	Namespace string `mapstructure:"namespace"`

	// ConstLabels are values that are applied for every exported metric.
	ConstLabels prometheus.Labels `mapstructure:"const_labels"`

	// SendTimestamps will send the underlying scrape timestamp with the export
	SendTimestamps bool `mapstructure:"send_timestamps"`

	// MetricExpiration defines how long metrics are kept without updates
	MetricExpiration time.Duration `mapstructure:"metric_expiration"`

	// ResourceToTelemetrySettings defines configuration for converting resource attributes to metric labels.
	ResourceToTelemetrySettings resourcetotelemetry.Settings `mapstructure:"resource_to_telemetry_conversion"`

	// EnableOpenMetrics enables the use of the OpenMetrics encoding option for the prometheus exporter.
	EnableOpenMetrics bool `mapstructure:"enable_open_metrics"`

	// TranslationStrategy defines how OpenTelemetry metrics are translated to Prometheus format.
	// - "UnderscoreEscapingWithSuffixes": (default) Fully escapes metric names for classic Prometheus compatibility and adds type/unit suffixes
	// - "NoUTF8EscapingWithSuffixes": Disables UTF-8 character escaping but still adds type/unit suffixes  
	// - "NoTranslation": Bypasses all metric and label name translation
	// Defaults to "UnderscoreEscapingWithSuffixes" for backward compatibility.
	TranslationStrategy TranslationStrategy `mapstructure:"translation_strategy"`

	// AddMetricSuffixes controls whether suffixes are added to metric names. Defaults to true.
	// DEPRECATED: Use TranslationStrategy instead. This field will be removed in a future version.
	// When both fields are specified, TranslationStrategy takes precedence.
	AddMetricSuffixes bool `mapstructure:"add_metric_suffixes"`
}

var _ component.Config = (*Config)(nil)

// Validate checks if the exporter configuration is valid
func (cfg *Config) Validate() error {
	return nil
}

// GetTranslationStrategy returns the effective translation strategy.
// If TranslationStrategy is set, it takes precedence over the deprecated AddMetricSuffixes field.
// If only AddMetricSuffixes is set, it is used for backward compatibility.
// If neither is set, defaults to UnderscoreEscapingWithSuffixes for backward compatibility.
func (cfg *Config) GetTranslationStrategy() TranslationStrategy {
	// If TranslationStrategy is explicitly set, use it
	if cfg.TranslationStrategy != "" {
		return cfg.TranslationStrategy
	}
	
	// Fall back to AddMetricSuffixes for backward compatibility
	if cfg.AddMetricSuffixes {
		return TranslationStrategyUnderscoreEscapingWithSuffixes
	}
	return TranslationStrategyNoTranslation
}

// ShouldAddMetricSuffixes returns true if metric suffixes should be added based on the translation strategy
func (cfg *Config) ShouldAddMetricSuffixes() bool {
	strategy := cfg.GetTranslationStrategy()
	return strategy == TranslationStrategyUnderscoreEscapingWithSuffixes || strategy == TranslationStrategyNoUTF8EscapingWithSuffixes
}
