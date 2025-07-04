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
	// TranslationStrategyPreserveOTel preserves the original OpenTelemetry metric names
	TranslationStrategyPreserveOTel TranslationStrategy = "preserve_otel"
	// TranslationStrategyPrometheusCompliant translates metric names to be Prometheus compliant (adds suffixes)
	TranslationStrategyPrometheusCompliant TranslationStrategy = "prometheus_compliant"
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
	// - "preserve_otel": Preserves the original OpenTelemetry metric names (equivalent to add_metric_suffixes=false)
	// - "prometheus_compliant": Translates metric names to be Prometheus compliant by adding type and unit suffixes (equivalent to add_metric_suffixes=true)
	// Defaults to "prometheus_compliant" for backward compatibility.
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
// If neither is set, defaults to prometheus_compliant for backward compatibility.
func (cfg *Config) GetTranslationStrategy() TranslationStrategy {
	// If TranslationStrategy is explicitly set, use it
	if cfg.TranslationStrategy != "" {
		return cfg.TranslationStrategy
	}
	
	// Fall back to AddMetricSuffixes for backward compatibility
	if cfg.AddMetricSuffixes {
		return TranslationStrategyPrometheusCompliant
	}
	return TranslationStrategyPreserveOTel
}

// ShouldAddMetricSuffixes returns true if metric suffixes should be added based on the translation strategy
func (cfg *Config) ShouldAddMetricSuffixes() bool {
	strategy := cfg.GetTranslationStrategy()
	return strategy == TranslationStrategyPrometheusCompliant
}
