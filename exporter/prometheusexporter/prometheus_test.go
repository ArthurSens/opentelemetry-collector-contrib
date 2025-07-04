// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prometheusexporter

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	conventions "go.opentelemetry.io/otel/semconv/v1.25.0"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusexporter/internal/metadata"
	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/common/testutil"
	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal/testdata"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/resourcetotelemetry"
)

func TestPrometheusExporter(t *testing.T) {
	tests := []struct {
		config       func() *Config
		wantErr      string
		wantStartErr string
	}{
		{
			config: func() *Config {
				return &Config{
					Namespace: "test",
					ConstLabels: map[string]string{
						"foo0":  "bar0",
						"code0": "one0",
					},
					ServerConfig: confighttp.ServerConfig{
						Endpoint: testutil.GetAvailableLocalAddress(t),
					},
					SendTimestamps:   false,
					MetricExpiration: 60 * time.Second,
				}
			},
		},
		{
			config: func() *Config {
				return &Config{
					ServerConfig: confighttp.ServerConfig{
						Endpoint: "localhost:88999",
					},
				}
			},
			wantStartErr: "listen tcp: address 88999: invalid port",
		},
		{
			config:  func() *Config { return &Config{} },
			wantErr: "expecting a non-blank address to run the Prometheus metrics handler",
		},
	}

	factory := NewFactory()
	set := exportertest.NewNopSettings(metadata.Type)
	for _, tt := range tests {
		// Run it a few times to ensure that shutdowns exit cleanly.
		for j := 0; j < 3; j++ {
			cfg := tt.config()
			exp, err := factory.CreateMetrics(context.Background(), set, cfg)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err.Error())
				continue
			}
			require.NoError(t, err)

			assert.NotNil(t, exp)
			err = exp.Start(context.Background(), componenttest.NewNopHost())

			if tt.wantStartErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.wantStartErr, err.Error())
			} else {
				require.NoError(t, err)
			}

			require.NoError(t, exp.Shutdown(context.Background()))
		}
	}
}

func TestPrometheusExporter_WithTLS(t *testing.T) {
	addr := testutil.GetAvailableLocalAddress(t)
	cfg := &Config{
		Namespace: "test",
		ConstLabels: map[string]string{
			"foo2":  "bar2",
			"code2": "one2",
		},
		ServerConfig: confighttp.ServerConfig{
			Endpoint: addr,
			TLS: &configtls.ServerConfig{
				Config: configtls.Config{
					CertFile: "./testdata/certs/server.crt",
					KeyFile:  "./testdata/certs/server.key",
					CAFile:   "./testdata/certs/ca.crt",
				},
			},
		},
		SendTimestamps:   true,
		MetricExpiration: 120 * time.Minute,
		ResourceToTelemetrySettings: resourcetotelemetry.Settings{
			Enabled: true,
		},
	}
	factory := NewFactory()
	set := exportertest.NewNopSettings(metadata.Type)
	exp, err := factory.CreateMetrics(context.Background(), set, cfg)
	require.NoError(t, err)

	tlscs := configtls.ClientConfig{
		Config: configtls.Config{
			CAFile:   "./testdata/certs/ca.crt",
			CertFile: "./testdata/certs/client.crt",
			KeyFile:  "./testdata/certs/client.key",
		},
		ServerName: "localhost",
	}
	tls, err := tlscs.LoadTLSConfig(context.Background())
	assert.NoError(t, err)
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tls,
		},
	}

	t.Cleanup(func() {
		require.NoError(t, exp.Shutdown(context.Background()))
	})

	assert.NotNil(t, exp)

	require.NoError(t, exp.Start(context.Background(), componenttest.NewNopHost()))

	md := testdata.GenerateMetricsOneMetric()
	assert.NotNil(t, md)

	assert.NoError(t, exp.ConsumeMetrics(context.Background(), md))

	rsp, err := httpClient.Get("https://" + addr + "/metrics")
	require.NoError(t, err, "Failed to perform a scrape")

	assert.Equal(t, http.StatusOK, rsp.StatusCode, "Mismatched HTTP response status code")

	blob, _ := io.ReadAll(rsp.Body)
	_ = rsp.Body.Close()

	want := []string{
		`# HELP test_counter_int`,
		`# TYPE test_counter_int counter`,
		`test_counter_int{code2="one2",foo2="bar2",label_1="label-value-1",otel_scope_name="",otel_scope_schema_url="",otel_scope_version="",resource_attr="resource-attr-val-1"} 123 1581452773000`,
		`test_counter_int{code2="one2",foo2="bar2",label_2="label-value-2",otel_scope_name="",otel_scope_schema_url="",otel_scope_version="",resource_attr="resource-attr-val-1"} 456 1581452773000`,
	}

	for _, w := range want {
		assert.Contains(t, string(blob), w, "Missing %v from response:\n%v", w, string(blob))
	}
}

// See: https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/4986
func TestPrometheusExporter_endToEndMultipleTargets(t *testing.T) {
	addr := testutil.GetAvailableLocalAddress(t)
	cfg := &Config{
		Namespace: "test",
		ConstLabels: map[string]string{
			"foo1":  "bar1",
			"code1": "one1",
		},
		ServerConfig: confighttp.ServerConfig{
			Endpoint: addr,
		},
		MetricExpiration: 120 * time.Minute,
	}

	factory := NewFactory()
	set := exportertest.NewNopSettings(metadata.Type)
	exp, err := factory.CreateMetrics(context.Background(), set, cfg)
	assert.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, exp.Shutdown(context.Background()))
	})

	assert.NotNil(t, exp)

	require.NoError(t, exp.Start(context.Background(), componenttest.NewNopHost()))

	// Should accumulate multiple metrics from different targets
	assert.NoError(t, exp.ConsumeMetrics(context.Background(), metricBuilder(128, "metric_1_", "cpu-exporter", "localhost:8080")))
	assert.NoError(t, exp.ConsumeMetrics(context.Background(), metricBuilder(128, "metric_1_", "cpu-exporter", "localhost:8081")))

	for delta := 0; delta <= 20; delta += 10 {
		assert.NoError(t, exp.ConsumeMetrics(context.Background(), metricBuilder(int64(delta), "metric_2_", "cpu-exporter", "localhost:8080")))
		assert.NoError(t, exp.ConsumeMetrics(context.Background(), metricBuilder(int64(delta), "metric_2_", "cpu-exporter", "localhost:8081")))

		res, err1 := http.Get("http://" + addr + "/metrics")
		require.NoError(t, err1, "Failed to perform a scrape")

		assert.Equal(t, http.StatusOK, res.StatusCode, "Mismatched HTTP response status code")
		blob, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		want := []string{
			`# HELP test_metric_1_this_one_there_where Extra ones`,
			`# TYPE test_metric_1_this_one_there_where counter`,
			fmt.Sprintf(`test_metric_1_this_one_there_where{arch="x86",code1="one1",foo1="bar1",instance="localhost:8080",job="cpu-exporter",os="windows",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v`, 99+128),
			fmt.Sprintf(`test_metric_1_this_one_there_where{arch="x86",code1="one1",foo1="bar1",instance="localhost:8080",job="cpu-exporter",os="linux",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v`, 100+128),
			fmt.Sprintf(`test_metric_1_this_one_there_where{arch="x86",code1="one1",foo1="bar1",instance="localhost:8081",job="cpu-exporter",os="windows",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v`, 99+128),
			fmt.Sprintf(`test_metric_1_this_one_there_where{arch="x86",code1="one1",foo1="bar1",instance="localhost:8081",job="cpu-exporter",os="linux",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v`, 100+128),
			`# HELP test_metric_2_this_one_there_where Extra ones`,
			`# TYPE test_metric_2_this_one_there_where counter`,
			fmt.Sprintf(`test_metric_2_this_one_there_where{arch="x86",code1="one1",foo1="bar1",instance="localhost:8080",job="cpu-exporter",os="windows",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v`, 99+delta),
			fmt.Sprintf(`test_metric_2_this_one_there_where{arch="x86",code1="one1",foo1="bar1",instance="localhost:8080",job="cpu-exporter",os="linux",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v`, 100+delta),
			fmt.Sprintf(`test_metric_2_this_one_there_where{arch="x86",code1="one1",foo1="bar1",instance="localhost:8081",job="cpu-exporter",os="windows",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v`, 99+delta),
			fmt.Sprintf(`test_metric_2_this_one_there_where{arch="x86",code1="one1",foo1="bar1",instance="localhost:8081",job="cpu-exporter",os="linux",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v`, 100+delta),
		}

		for _, w := range want {
			assert.Contains(t, string(blob), w, "Missing %v from response:\n%v", w, string(blob))
		}
	}

	// Expired metrics should be removed during first scrape
	exp.(*wrapMetricsExporter).exporter.collector.accumulator.(*lastValueAccumulator).metricExpiration = 1 * time.Millisecond
	time.Sleep(10 * time.Millisecond)

	res, err := http.Get("http://" + addr + "/metrics")
	require.NoError(t, err, "Failed to perform a scrape")

	assert.Equal(t, http.StatusOK, res.StatusCode, "Mismatched HTTP response status code")
	blob, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	require.Emptyf(t, string(blob), "Metrics did not expire")
}

func TestPrometheusExporter_endToEnd(t *testing.T) {
	addr := testutil.GetAvailableLocalAddress(t)
	cfg := &Config{
		Namespace: "test",
		ConstLabels: map[string]string{
			"foo1":  "bar1",
			"code1": "one1",
		},
		ServerConfig: confighttp.ServerConfig{
			Endpoint: addr,
		},
		MetricExpiration: 120 * time.Minute,
	}

	factory := NewFactory()
	set := exportertest.NewNopSettings(metadata.Type)
	exp, err := factory.CreateMetrics(context.Background(), set, cfg)
	assert.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, exp.Shutdown(context.Background()))
	})

	assert.NotNil(t, exp)

	require.NoError(t, exp.Start(context.Background(), componenttest.NewNopHost()))

	// Should accumulate multiple metrics
	assert.NoError(t, exp.ConsumeMetrics(context.Background(), metricBuilder(128, "metric_1_", "cpu-exporter", "localhost:8080")))

	for delta := 0; delta <= 20; delta += 10 {
		assert.NoError(t, exp.ConsumeMetrics(context.Background(), metricBuilder(int64(delta), "metric_2_", "cpu-exporter", "localhost:8080")))

		res, err1 := http.Get("http://" + addr + "/metrics")
		require.NoError(t, err1, "Failed to perform a scrape")

		assert.Equal(t, http.StatusOK, res.StatusCode, "Mismatched HTTP response status code")
		blob, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		want := []string{
			`# HELP test_metric_1_this_one_there_where Extra ones`,
			`# TYPE test_metric_1_this_one_there_where counter`,
			fmt.Sprintf(`test_metric_1_this_one_there_where{arch="x86",code1="one1",foo1="bar1",instance="localhost:8080",job="cpu-exporter",os="windows",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v`, 99+128),
			fmt.Sprintf(`test_metric_1_this_one_there_where{arch="x86",code1="one1",foo1="bar1",instance="localhost:8080",job="cpu-exporter",os="linux",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v`, 100+128),
			`# HELP test_metric_2_this_one_there_where Extra ones`,
			`# TYPE test_metric_2_this_one_there_where counter`,
			fmt.Sprintf(`test_metric_2_this_one_there_where{arch="x86",code1="one1",foo1="bar1",instance="localhost:8080",job="cpu-exporter",os="windows",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v`, 99+delta),
			fmt.Sprintf(`test_metric_2_this_one_there_where{arch="x86",code1="one1",foo1="bar1",instance="localhost:8080",job="cpu-exporter",os="linux",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v`, 100+delta),
		}

		for _, w := range want {
			assert.Contains(t, string(blob), w, "Missing %v from response:\n%v", w, string(blob))
		}
	}

	// Expired metrics should be removed during first scrape
	exp.(*wrapMetricsExporter).exporter.collector.accumulator.(*lastValueAccumulator).metricExpiration = 1 * time.Millisecond
	time.Sleep(10 * time.Millisecond)

	res, err := http.Get("http://" + addr + "/metrics")
	require.NoError(t, err, "Failed to perform a scrape")

	assert.Equal(t, http.StatusOK, res.StatusCode, "Mismatched HTTP response status code")
	blob, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	require.Emptyf(t, string(blob), "Metrics did not expire")
}

func TestPrometheusExporter_endToEndWithTimestamps(t *testing.T) {
	addr := testutil.GetAvailableLocalAddress(t)
	cfg := &Config{
		Namespace: "test",
		ConstLabels: map[string]string{
			"foo2":  "bar2",
			"code2": "one2",
		},
		ServerConfig: confighttp.ServerConfig{
			Endpoint: addr,
		},
		SendTimestamps:   true,
		MetricExpiration: 120 * time.Minute,
	}

	factory := NewFactory()
	set := exportertest.NewNopSettings(metadata.Type)
	exp, err := factory.CreateMetrics(context.Background(), set, cfg)
	assert.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, exp.Shutdown(context.Background()))
	})

	assert.NotNil(t, exp)
	require.NoError(t, exp.Start(context.Background(), componenttest.NewNopHost()))

	// Should accumulate multiple metrics

	assert.NoError(t, exp.ConsumeMetrics(context.Background(), metricBuilder(128, "metric_1_", "node-exporter", "localhost:8080")))

	for delta := 0; delta <= 20; delta += 10 {
		assert.NoError(t, exp.ConsumeMetrics(context.Background(), metricBuilder(int64(delta), "metric_2_", "node-exporter", "localhost:8080")))

		res, err1 := http.Get("http://" + addr + "/metrics")
		require.NoError(t, err1, "Failed to perform a scrape")

		assert.Equal(t, http.StatusOK, res.StatusCode, "Mismatched HTTP response status code")
		blob, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		want := []string{
			`# HELP test_metric_1_this_one_there_where Extra ones`,
			`# TYPE test_metric_1_this_one_there_where counter`,
			fmt.Sprintf(`test_metric_1_this_one_there_where{arch="x86",code2="one2",foo2="bar2",instance="localhost:8080",job="node-exporter",os="windows",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v %v`, 99+128, 1543160298100+128000),
			fmt.Sprintf(`test_metric_1_this_one_there_where{arch="x86",code2="one2",foo2="bar2",instance="localhost:8080",job="node-exporter",os="linux",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v %v`, 100+128, 1543160298100),
			`# HELP test_metric_2_this_one_there_where Extra ones`,
			`# TYPE test_metric_2_this_one_there_where counter`,
			fmt.Sprintf(`test_metric_2_this_one_there_where{arch="x86",code2="one2",foo2="bar2",instance="localhost:8080",job="node-exporter",os="windows",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v %v`, 99+delta, 1543160298100+delta*1000),
			fmt.Sprintf(`test_metric_2_this_one_there_where{arch="x86",code2="one2",foo2="bar2",instance="localhost:8080",job="node-exporter",os="linux",otel_scope_name="",otel_scope_schema_url="",otel_scope_version=""} %v %v`, 100+delta, 1543160298100),
		}

		for _, w := range want {
			assert.Contains(t, string(blob), w, "Missing %v from response:\n%v", w, string(blob))
		}
	}

	// Expired metrics should be removed during first scrape
	exp.(*wrapMetricsExporter).exporter.collector.accumulator.(*lastValueAccumulator).metricExpiration = 1 * time.Millisecond
	time.Sleep(10 * time.Millisecond)

	res, err := http.Get("http://" + addr + "/metrics")
	require.NoError(t, err, "Failed to perform a scrape")

	assert.Equal(t, http.StatusOK, res.StatusCode, "Mismatched HTTP response status code")
	blob, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	require.Emptyf(t, string(blob), "Metrics did not expire")
}

func TestPrometheusExporter_endToEndWithResource(t *testing.T) {
	addr := testutil.GetAvailableLocalAddress(t)
	cfg := &Config{
		Namespace: "test",
		ConstLabels: map[string]string{
			"foo2":  "bar2",
			"code2": "one2",
		},
		ServerConfig: confighttp.ServerConfig{
			Endpoint: addr,
		},
		SendTimestamps:   true,
		MetricExpiration: 120 * time.Minute,
		ResourceToTelemetrySettings: resourcetotelemetry.Settings{
			Enabled: true,
		},
	}

	factory := NewFactory()
	set := exportertest.NewNopSettings(metadata.Type)
	exp, err := factory.CreateMetrics(context.Background(), set, cfg)
	assert.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, exp.Shutdown(context.Background()))
	})

	assert.NotNil(t, exp)
	require.NoError(t, exp.Start(context.Background(), componenttest.NewNopHost()))

	md := testdata.GenerateMetricsOneMetric()
	assert.NotNil(t, md)

	assert.NoError(t, exp.ConsumeMetrics(context.Background(), md))

	rsp, err := http.Get("http://" + addr + "/metrics")
	require.NoError(t, err, "Failed to perform a scrape")

	assert.Equal(t, http.StatusOK, rsp.StatusCode, "Mismatched HTTP response status code")

	blob, _ := io.ReadAll(rsp.Body)
	_ = rsp.Body.Close()

	want := []string{
		`# HELP test_counter_int`,
		`# TYPE test_counter_int counter`,
		`test_counter_int{code2="one2",foo2="bar2",label_1="label-value-1",otel_scope_name="",otel_scope_schema_url="",otel_scope_version="",resource_attr="resource-attr-val-1"} 123 1581452773000`,
		`test_counter_int{code2="one2",foo2="bar2",label_2="label-value-2",otel_scope_name="",otel_scope_schema_url="",otel_scope_version="",resource_attr="resource-attr-val-1"} 456 1581452773000`,
	}

	for _, w := range want {
		assert.Contains(t, string(blob), w, "Missing %v from response:\n%v", w, string(blob))
	}
}

func metricBuilder(delta int64, prefix, job, instance string) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rms := md.ResourceMetrics().AppendEmpty()
	rms0 := md.ResourceMetrics().At(0)
	rms0.Resource().Attributes().PutStr(string(conventions.ServiceNameKey), job)
	rms0.Resource().Attributes().PutStr(string(conventions.ServiceInstanceIDKey), instance)

	ms := rms.ScopeMetrics().AppendEmpty().Metrics()

	m1 := ms.AppendEmpty()
	m1.SetName(prefix + "this/one/there(where)")
	m1.SetDescription("Extra ones")
	m1.SetUnit("1")
	d1 := m1.SetEmptySum()
	d1.SetIsMonotonic(true)
	d1.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	dp1 := d1.DataPoints().AppendEmpty()
	dp1.SetStartTimestamp(pcommon.NewTimestampFromTime(time.Unix(1543160298+delta, 100000090)))
	dp1.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(1543160298+delta, 100000997)))
	dp1.Attributes().PutStr("os", "windows")
	dp1.Attributes().PutStr("arch", "x86")
	dp1.SetIntValue(99 + delta)

	m2 := ms.AppendEmpty()
	m2.SetName(prefix + "this/one/there(where)")
	m2.SetDescription("Extra ones")
	m2.SetUnit("1")
	d2 := m2.SetEmptySum()
	d2.SetIsMonotonic(true)
	d2.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	dp2 := d2.DataPoints().AppendEmpty()
	dp2.SetStartTimestamp(pcommon.NewTimestampFromTime(time.Unix(1543160298, 100000090)))
	dp2.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(1543160298, 100000997)))
	dp2.Attributes().PutStr("os", "linux")
	dp2.Attributes().PutStr("arch", "x86")
	dp2.SetIntValue(100 + delta)

	return md
}

// TestPrometheusExporter_TranslationStrategies tests that the different translation strategies
// are properly configured and that the ShouldAddMetricSuffixes method works correctly.
// NOTE: The actual metric name translation logic implementation in the core Prometheus translator
// is beyond the scope of this configuration change. This test validates that:
// 1. Different translation strategies can be configured
// 2. The ShouldAddMetricSuffixes method returns the correct values
// 3. The exporter can be created and started with different strategies
// 4. Metrics are exported (even if translation logic isn't fully implemented yet)
func TestPrometheusExporter_TranslationStrategies(t *testing.T) {
	tests := []struct {
		name                    string
		config                  func(addr string) *Config
		expectedSuffixes        bool
		expectsUnderscoreEscape bool // Currently all strategies escape to underscores
	}{
		{
			name: "UnderscoreEscapingWithSuffixes strategy",
			config: func(addr string) *Config {
				return &Config{
					ServerConfig: confighttp.ServerConfig{
						Endpoint: addr,
					},
					TranslationStrategy: TranslationStrategyUnderscoreEscapingWithSuffixes,
					MetricExpiration:    120 * time.Minute,
				}
			},
			expectedSuffixes:        true,
			expectsUnderscoreEscape: true,
		},
		{
			name: "NoUTF8EscapingWithSuffixes strategy",
			config: func(addr string) *Config {
				return &Config{
					ServerConfig: confighttp.ServerConfig{
						Endpoint: addr,
					},
					TranslationStrategy: TranslationStrategyNoUTF8EscapingWithSuffixes,
					MetricExpiration:    120 * time.Minute,
				}
			},
			expectedSuffixes:        true,
			expectsUnderscoreEscape: true, // TODO: Should preserve UTF-8 chars when implemented
		},
		{
			name: "NoTranslation strategy",
			config: func(addr string) *Config {
				return &Config{
					ServerConfig: confighttp.ServerConfig{
						Endpoint: addr,
					},
					TranslationStrategy: TranslationStrategyNoTranslation,
					MetricExpiration:    120 * time.Minute,
				}
			},
			expectedSuffixes:        false,
			expectsUnderscoreEscape: true, // TODO: Should preserve original names when implemented
		},
		{
			name: "Legacy AddMetricSuffixes=true (backward compatibility)",
			config: func(addr string) *Config {
				return &Config{
					ServerConfig: confighttp.ServerConfig{
						Endpoint: addr,
					},
					AddMetricSuffixes: true, // Legacy field
					MetricExpiration:  120 * time.Minute,
				}
			},
			expectedSuffixes:        true,
			expectsUnderscoreEscape: true,
		},
		{
			name: "Legacy AddMetricSuffixes=false (backward compatibility)",
			config: func(addr string) *Config {
				return &Config{
					ServerConfig: confighttp.ServerConfig{
						Endpoint: addr,
					},
					AddMetricSuffixes: false, // Legacy field
					MetricExpiration:  120 * time.Minute,
				}
			},
			expectedSuffixes:        false,
			expectsUnderscoreEscape: true, // TODO: Should preserve original names when implemented
		},
	}

			for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := testutil.GetAvailableLocalAddress(t)
			cfg := tt.config(addr)

			factory := NewFactory()
			set := exportertest.NewNopSettings(metadata.Type)
			exp, err := factory.CreateMetrics(context.Background(), set, cfg)
			require.NoError(t, err)
			require.NotNil(t, exp)

			t.Cleanup(func() {
				require.NoError(t, exp.Shutdown(context.Background()))
			})

			require.NoError(t, exp.Start(context.Background(), componenttest.NewNopHost()))

			// Create test metrics with different types and special characters
			md := createTestMetrics()
			require.NoError(t, exp.ConsumeMetrics(context.Background(), md))

			// Scrape the metrics endpoint
			res, err := http.Get("http://" + addr + "/metrics")
			require.NoError(t, err, "Failed to perform a scrape")
			require.Equal(t, http.StatusOK, res.StatusCode, "Mismatched HTTP response status code")

			blob, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			_ = res.Body.Close()

			metricsOutput := string(blob)
			t.Logf("Metrics output for %s:\n%s", tt.name, metricsOutput)

			// Verify the config's ShouldAddMetricSuffixes method matches expected behavior
			assert.Equal(t, tt.expectedSuffixes, cfg.ShouldAddMetricSuffixes(),
				"ShouldAddMetricSuffixes() returned unexpected value for strategy %s", tt.name)

			// Verify that metrics are being exported (basic functionality test)
			assert.Contains(t, metricsOutput, "test_counter_bytes", 
				"Counter metric not found in output for strategy %s", tt.name)
			assert.Contains(t, metricsOutput, "test_gauge_temperature", 
				"Gauge metric not found in output for strategy %s", tt.name)
			assert.Contains(t, metricsOutput, "test_histogram_duration_seconds", 
				"Histogram metric not found in output for strategy %s", tt.name)

			// Verify that the exporter is working with the configured strategy
			if tt.expectedSuffixes {
				// Strategies that should add suffixes
				assert.Contains(t, metricsOutput, "_total", 
					"Expected suffix '_total' not found for strategy %s that should add suffixes", tt.name)
			} else {
				// For NoTranslation strategy, verify ShouldAddMetricSuffixes returns false
				// (The actual metric name preservation will be implemented in the core translator)
				assert.False(t, cfg.ShouldAddMetricSuffixes(),
					"NoTranslation strategy should return false for ShouldAddMetricSuffixes")
			}

			// Verify the translation strategy is correctly set
			expectedStrategy := cfg.GetTranslationStrategy()
			switch tt.name {
			case "UnderscoreEscapingWithSuffixes strategy":
				assert.Equal(t, TranslationStrategyUnderscoreEscapingWithSuffixes, expectedStrategy)
			case "NoUTF8EscapingWithSuffixes strategy":
				assert.Equal(t, TranslationStrategyNoUTF8EscapingWithSuffixes, expectedStrategy)
			case "NoTranslation strategy":
				assert.Equal(t, TranslationStrategyNoTranslation, expectedStrategy)
			case "Legacy AddMetricSuffixes=true (backward compatibility)":
				assert.Equal(t, TranslationStrategyUnderscoreEscapingWithSuffixes, expectedStrategy)
			case "Legacy AddMetricSuffixes=false (backward compatibility)":
				assert.Equal(t, TranslationStrategyNoTranslation, expectedStrategy)
			}
		})
	}
}

// createTestMetrics creates a set of test metrics with various types and special characters
// to test the translation strategies.
func createTestMetrics() pmetric.Metrics {
	md := pmetric.NewMetrics()
	rms := md.ResourceMetrics().AppendEmpty()
	rms.Resource().Attributes().PutStr(string(conventions.ServiceNameKey), "test-service")
	rms.Resource().Attributes().PutStr(string(conventions.ServiceInstanceIDKey), "test-instance")

	ms := rms.ScopeMetrics().AppendEmpty().Metrics()

	// Counter with special characters and unit
	counter := ms.AppendEmpty()
	counter.SetName("test.counter.bytes")  // Has dots
	counter.SetDescription("Test counter with bytes")
	counter.SetUnit("By")  // Bytes unit
	counterSum := counter.SetEmptySum()
	counterSum.SetIsMonotonic(true)
	counterSum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	counterDP := counterSum.DataPoints().AppendEmpty()
	counterDP.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	counterDP.SetIntValue(42)

	// Gauge with slashes
	gauge := ms.AppendEmpty()
	gauge.SetName("test/gauge/temperature")  // Has slashes
	gauge.SetDescription("Test gauge with temperature")
	gauge.SetUnit("Cel")  // Celsius unit
	gaugeGauge := gauge.SetEmptyGauge()
	gaugeDP := gaugeGauge.DataPoints().AppendEmpty()
	gaugeDP.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	gaugeDP.SetDoubleValue(23.5)

	// Histogram with dots and unit
	histogram := ms.AppendEmpty()
	histogram.SetName("test.histogram.duration.seconds")  // Has dots and unit in name
	histogram.SetDescription("Test histogram with duration")
	histogram.SetUnit("s")  // Seconds unit
	histogramHist := histogram.SetEmptyHistogram()
	histogramHist.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	histogramDP := histogramHist.DataPoints().AppendEmpty()
	histogramDP.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	histogramDP.SetCount(10)
	histogramDP.SetSum(100.0)
	histogramDP.BucketCounts().FromRaw([]uint64{1, 2, 3, 4})
	histogramDP.ExplicitBounds().FromRaw([]float64{0.1, 1.0, 10.0})

	return md
}
