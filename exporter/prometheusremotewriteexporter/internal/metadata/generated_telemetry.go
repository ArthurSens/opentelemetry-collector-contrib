// Code generated by mdatagen. DO NOT EDIT.

package metadata

import (
	"errors"
	"sync"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/collector/component"
)

func Meter(settings component.TelemetrySettings) metric.Meter {
	return settings.MeterProvider.Meter("github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusremotewriteexporter")
}

func Tracer(settings component.TelemetrySettings) trace.Tracer {
	return settings.TracerProvider.Tracer("github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusremotewriteexporter")
}

// TelemetryBuilder provides an interface for components to report telemetry
// as defined in metadata and user config.
type TelemetryBuilder struct {
	meter                                             metric.Meter
	mu                                                sync.Mutex
	registrations                                     []metric.Registration
	ExporterPrometheusremotewriteConsumers            metric.Int64UpDownCounter
	ExporterPrometheusremotewriteFailedTranslations   metric.Int64Counter
	ExporterPrometheusremotewriteSentBatches          metric.Int64Counter
	ExporterPrometheusremotewriteTranslatedTimeSeries metric.Int64Counter
	ExporterPrometheusremotewriteWalBytesRead         metric.Int64Counter
	ExporterPrometheusremotewriteWalBytesWritten      metric.Int64Counter
	ExporterPrometheusremotewriteWalLag               metric.Int64Gauge
	ExporterPrometheusremotewriteWalReadLatency       metric.Int64Histogram
	ExporterPrometheusremotewriteWalReads             metric.Int64Counter
	ExporterPrometheusremotewriteWalReadsFailures     metric.Int64Counter
	ExporterPrometheusremotewriteWalWriteLatency      metric.Int64Histogram
	ExporterPrometheusremotewriteWalWrites            metric.Int64Counter
	ExporterPrometheusremotewriteWalWritesFailures    metric.Int64Counter
	ExporterPrometheusremotewriteWrittenExemplars     metric.Int64Counter
	ExporterPrometheusremotewriteWrittenHistograms    metric.Int64Counter
	ExporterPrometheusremotewriteWrittenSamples       metric.Int64Counter
}

// TelemetryBuilderOption applies changes to default builder.
type TelemetryBuilderOption interface {
	apply(*TelemetryBuilder)
}

type telemetryBuilderOptionFunc func(mb *TelemetryBuilder)

func (tbof telemetryBuilderOptionFunc) apply(mb *TelemetryBuilder) {
	tbof(mb)
}

// Shutdown unregister all registered callbacks for async instruments.
func (builder *TelemetryBuilder) Shutdown() {
	builder.mu.Lock()
	defer builder.mu.Unlock()
	for _, reg := range builder.registrations {
		reg.Unregister()
	}
}

// NewTelemetryBuilder provides a struct with methods to update all internal telemetry
// for a component
func NewTelemetryBuilder(settings component.TelemetrySettings, options ...TelemetryBuilderOption) (*TelemetryBuilder, error) {
	builder := TelemetryBuilder{}
	for _, op := range options {
		op.apply(&builder)
	}
	builder.meter = Meter(settings)
	var err, errs error
	builder.ExporterPrometheusremotewriteConsumers, err = builder.meter.Int64UpDownCounter(
		"otelcol_exporter_prometheusremotewrite_consumers",
		metric.WithDescription("Number of configured workers to use to fan out the outgoing requests"),
		metric.WithUnit("{consumer}"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteFailedTranslations, err = builder.meter.Int64Counter(
		"otelcol_exporter_prometheusremotewrite_failed_translations",
		metric.WithDescription("Number of translation operations that failed to translate metrics from Otel to Prometheus"),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteSentBatches, err = builder.meter.Int64Counter(
		"otelcol_exporter_prometheusremotewrite_sent_batches",
		metric.WithDescription("Number of remote write request batches sent to the remote write endpoint regardless of success or failure"),
		metric.WithUnit("{batch}"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteTranslatedTimeSeries, err = builder.meter.Int64Counter(
		"otelcol_exporter_prometheusremotewrite_translated_time_series",
		metric.WithDescription("Number of Prometheus time series that were translated from OTel metrics"),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteWalBytesRead, err = builder.meter.Int64Counter(
		"otelcol_exporter_prometheusremotewrite_wal_bytes_read",
		metric.WithDescription("Total number of bytes read from the WAL"),
		metric.WithUnit("By"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteWalBytesWritten, err = builder.meter.Int64Counter(
		"otelcol_exporter_prometheusremotewrite_wal_bytes_written",
		metric.WithDescription("Total number of bytes written to the WAL"),
		metric.WithUnit("By"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteWalLag, err = builder.meter.Int64Gauge(
		"otelcol_exporter_prometheusremotewrite_wal_lag",
		metric.WithDescription("WAL lag"),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteWalReadLatency, err = builder.meter.Int64Histogram(
		"otelcol_exporter_prometheusremotewrite_wal_read_latency",
		metric.WithDescription("Response latency in ms for the WAL reads."),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries([]float64{5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000}...),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteWalReads, err = builder.meter.Int64Counter(
		"otelcol_exporter_prometheusremotewrite_wal_reads",
		metric.WithDescription("Number of WAL reads"),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteWalReadsFailures, err = builder.meter.Int64Counter(
		"otelcol_exporter_prometheusremotewrite_wal_reads_failures",
		metric.WithDescription("Number of WAL reads that failed"),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteWalWriteLatency, err = builder.meter.Int64Histogram(
		"otelcol_exporter_prometheusremotewrite_wal_write_latency",
		metric.WithDescription("Response latency in ms for the WAL writes."),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries([]float64{5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000}...),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteWalWrites, err = builder.meter.Int64Counter(
		"otelcol_exporter_prometheusremotewrite_wal_writes",
		metric.WithDescription("Number of WAL writes"),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteWalWritesFailures, err = builder.meter.Int64Counter(
		"otelcol_exporter_prometheusremotewrite_wal_writes_failures",
		metric.WithDescription("Number of WAL writes that failed"),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteWrittenExemplars, err = builder.meter.Int64Counter(
		"otelcol_exporter_prometheusremotewrite_written_exemplars",
		metric.WithDescription("Number of Prometheus Exemplars that were successfully written to the remote write endpoint (only available when using remote write v2)"),
		metric.WithUnit("{exemplar}"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteWrittenHistograms, err = builder.meter.Int64Counter(
		"otelcol_exporter_prometheusremotewrite_written_histograms",
		metric.WithDescription("Number of Prometheus Histograms that were successfully written to the remote write endpoint (only available when using remote write v2)"),
		metric.WithUnit("{histogram}"),
	)
	errs = errors.Join(errs, err)
	builder.ExporterPrometheusremotewriteWrittenSamples, err = builder.meter.Int64Counter(
		"otelcol_exporter_prometheusremotewrite_written_samples",
		metric.WithDescription("Number of Prometheus Samples that were successfully written to the remote write endpoint (only available when using remote write v2)"),
		metric.WithUnit("{sample}"),
	)
	errs = errors.Join(errs, err)
	return &builder, errs
}
