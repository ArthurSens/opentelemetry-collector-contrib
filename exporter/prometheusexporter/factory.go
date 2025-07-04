// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prometheusexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusexporter"

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusexporter/internal/metadata"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/resourcetotelemetry"
)

// NewFactory creates a new Prometheus exporter factory.
func NewFactory() exporter.Factory {
	return exporter.NewFactory(
		metadata.Type,
		createDefaultConfig,
		exporter.WithMetrics(createMetricsExporter, metadata.MetricsStability))
}

func createDefaultConfig() component.Config {
	return &Config{
		ConstLabels:       map[string]string{},
		SendTimestamps:    false,
		MetricExpiration:  time.Minute * 5,
		EnableOpenMetrics: false,
		// TranslationStrategy and AddMetricSuffixes are not set explicitly
		// The effective behavior is determined by GetTranslationStrategy()
	}
}

func createMetricsExporter(
	ctx context.Context,
	set exporter.Settings,
	cfg component.Config,
) (exporter.Metrics, error) {
	pcfg := cfg.(*Config)

	// Warn about deprecated configuration
	if pcfg.TranslationStrategy == "" && pcfg.AddMetricSuffixes != true {
		// Only warn if AddMetricSuffixes is explicitly set to false (non-default)
		if set.Logger != nil {
			set.Logger.Warn(
				"The 'add_metric_suffixes' configuration option is deprecated. " +
				"Please use 'translation_strategy' instead. " +
				"Use 'translation_strategy: NoTranslation' for add_metric_suffixes: false, " +
				"or 'translation_strategy: UnderscoreEscapingWithSuffixes' for add_metric_suffixes: true.",
			)
		}
	}

	prometheus, err := newPrometheusExporter(pcfg, set)
	if err != nil {
		return nil, err
	}

	exporter, err := exporterhelper.NewMetrics(
		ctx,
		set,
		cfg,
		prometheus.ConsumeMetrics,
		exporterhelper.WithStart(prometheus.Start),
		exporterhelper.WithShutdown(prometheus.Shutdown),
		exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}),
	)
	if err != nil {
		return nil, err
	}

	return &wrapMetricsExporter{
		Metrics:  resourcetotelemetry.WrapMetricsExporter(pcfg.ResourceToTelemetrySettings, exporter),
		exporter: prometheus,
	}, nil
}

type wrapMetricsExporter struct {
	exporter.Metrics
	exporter *prometheusExporter
}
