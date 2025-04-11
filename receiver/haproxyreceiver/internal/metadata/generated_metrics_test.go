// Code generated by mdatagen. DO NOT EDIT.

package metadata

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type testDataSet int

const (
	testDataSetDefault testDataSet = iota
	testDataSetAll
	testDataSetNone
)

func TestMetricsBuilder(t *testing.T) {
	tests := []struct {
		name        string
		metricsSet  testDataSet
		resAttrsSet testDataSet
		expectEmpty bool
	}{
		{
			name: "default",
		},
		{
			name:        "all_set",
			metricsSet:  testDataSetAll,
			resAttrsSet: testDataSetAll,
		},
		{
			name:        "none_set",
			metricsSet:  testDataSetNone,
			resAttrsSet: testDataSetNone,
			expectEmpty: true,
		},
		{
			name:        "filter_set_include",
			resAttrsSet: testDataSetAll,
		},
		{
			name:        "filter_set_exclude",
			resAttrsSet: testDataSetAll,
			expectEmpty: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := pcommon.Timestamp(1_000_000_000)
			ts := pcommon.Timestamp(1_000_001_000)
			observedZapCore, observedLogs := observer.New(zap.WarnLevel)
			settings := receivertest.NewNopSettings(receivertest.NopType)
			settings.Logger = zap.New(observedZapCore)
			mb := NewMetricsBuilder(loadMetricsBuilderConfig(t, tt.name), settings, WithStartTime(start))

			expectedWarnings := 0

			assert.Equal(t, expectedWarnings, observedLogs.Len())

			defaultMetricsCount := 0
			allMetricsCount := 0

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyBytesInputDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyBytesOutputDataPoint(ts, "1")

			allMetricsCount++
			mb.RecordHaproxyClientsCanceledDataPoint(ts, "1")

			allMetricsCount++
			mb.RecordHaproxyCompressionBypassDataPoint(ts, "1")

			allMetricsCount++
			mb.RecordHaproxyCompressionCountDataPoint(ts, "1")

			allMetricsCount++
			mb.RecordHaproxyCompressionInputDataPoint(ts, "1")

			allMetricsCount++
			mb.RecordHaproxyCompressionOutputDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyConnectionsErrorsDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyConnectionsRateDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyConnectionsRetriesDataPoint(ts, "1")

			allMetricsCount++
			mb.RecordHaproxyConnectionsTotalDataPoint(ts, "1")

			allMetricsCount++
			mb.RecordHaproxyDowntimeDataPoint(ts, "1")

			allMetricsCount++
			mb.RecordHaproxyFailedChecksDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyRequestsDeniedDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyRequestsErrorsDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyRequestsQueuedDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyRequestsRateDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyRequestsRedispatchedDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyRequestsTotalDataPoint(ts, "1", AttributeStatusCode1xx)

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyResponsesDeniedDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyResponsesErrorsDataPoint(ts, 1)

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxyServerSelectedTotalDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxySessionsAverageDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxySessionsCountDataPoint(ts, "1")

			defaultMetricsCount++
			allMetricsCount++
			mb.RecordHaproxySessionsRateDataPoint(ts, "1")

			allMetricsCount++
			mb.RecordHaproxySessionsTotalDataPoint(ts, "1")

			rb := mb.NewResourceBuilder()
			rb.SetHaproxyAddr("haproxy.addr-val")
			rb.SetHaproxyProxyName("haproxy.proxy_name-val")
			rb.SetHaproxyServiceName("haproxy.service_name-val")
			res := rb.Emit()
			metrics := mb.Emit(WithResource(res))

			if tt.expectEmpty {
				assert.Equal(t, 0, metrics.ResourceMetrics().Len())
				return
			}

			assert.Equal(t, 1, metrics.ResourceMetrics().Len())
			rm := metrics.ResourceMetrics().At(0)
			assert.Equal(t, res, rm.Resource())
			assert.Equal(t, 1, rm.ScopeMetrics().Len())
			ms := rm.ScopeMetrics().At(0).Metrics()
			if tt.metricsSet == testDataSetDefault {
				assert.Equal(t, defaultMetricsCount, ms.Len())
			}
			if tt.metricsSet == testDataSetAll {
				assert.Equal(t, allMetricsCount, ms.Len())
			}
			validatedMetrics := make(map[string]bool)
			for i := 0; i < ms.Len(); i++ {
				switch ms.At(i).Name() {
				case "haproxy.bytes.input":
					assert.False(t, validatedMetrics["haproxy.bytes.input"], "Found a duplicate in the metrics slice: haproxy.bytes.input")
					validatedMetrics["haproxy.bytes.input"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Bytes in. Corresponds to HAProxy's `bin` metric.", ms.At(i).Description())
					assert.Equal(t, "by", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.bytes.output":
					assert.False(t, validatedMetrics["haproxy.bytes.output"], "Found a duplicate in the metrics slice: haproxy.bytes.output")
					validatedMetrics["haproxy.bytes.output"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Bytes out. Corresponds to HAProxy's `bout` metric.", ms.At(i).Description())
					assert.Equal(t, "by", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.clients.canceled":
					assert.False(t, validatedMetrics["haproxy.clients.canceled"], "Found a duplicate in the metrics slice: haproxy.clients.canceled")
					validatedMetrics["haproxy.clients.canceled"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Number of data transfers aborted by the client. Corresponds to HAProxy's `cli_abrt` metric", ms.At(i).Description())
					assert.Equal(t, "{cancellations}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.compression.bypass":
					assert.False(t, validatedMetrics["haproxy.compression.bypass"], "Found a duplicate in the metrics slice: haproxy.compression.bypass")
					validatedMetrics["haproxy.compression.bypass"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Number of bytes that bypassed the HTTP compressor (CPU/BW limit). Corresponds to HAProxy's `comp_byp` metric.", ms.At(i).Description())
					assert.Equal(t, "by", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.compression.count":
					assert.False(t, validatedMetrics["haproxy.compression.count"], "Found a duplicate in the metrics slice: haproxy.compression.count")
					validatedMetrics["haproxy.compression.count"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Number of HTTP responses that were compressed. Corresponds to HAProxy's `comp_rsp` metric.", ms.At(i).Description())
					assert.Equal(t, "{responses}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.compression.input":
					assert.False(t, validatedMetrics["haproxy.compression.input"], "Found a duplicate in the metrics slice: haproxy.compression.input")
					validatedMetrics["haproxy.compression.input"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Number of HTTP response bytes fed to the compressor. Corresponds to HAProxy's `comp_in` metric.", ms.At(i).Description())
					assert.Equal(t, "by", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.compression.output":
					assert.False(t, validatedMetrics["haproxy.compression.output"], "Found a duplicate in the metrics slice: haproxy.compression.output")
					validatedMetrics["haproxy.compression.output"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Number of HTTP response bytes emitted by the compressor. Corresponds to HAProxy's `comp_out` metric.", ms.At(i).Description())
					assert.Equal(t, "by", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.connections.errors":
					assert.False(t, validatedMetrics["haproxy.connections.errors"], "Found a duplicate in the metrics slice: haproxy.connections.errors")
					validatedMetrics["haproxy.connections.errors"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Number of requests that encountered an error trying to connect to a backend server. The backend stat is the sum of the stat. Corresponds to HAProxy's `econ` metric", ms.At(i).Description())
					assert.Equal(t, "{errors}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.connections.rate":
					assert.False(t, validatedMetrics["haproxy.connections.rate"], "Found a duplicate in the metrics slice: haproxy.connections.rate")
					validatedMetrics["haproxy.connections.rate"] = true
					assert.Equal(t, pmetric.MetricTypeGauge, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Gauge().DataPoints().Len())
					assert.Equal(t, "Number of connections over the last elapsed second (frontend). Corresponds to HAProxy's `conn_rate` metric.", ms.At(i).Description())
					assert.Equal(t, "{connections}", ms.At(i).Unit())
					dp := ms.At(i).Gauge().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.connections.retries":
					assert.False(t, validatedMetrics["haproxy.connections.retries"], "Found a duplicate in the metrics slice: haproxy.connections.retries")
					validatedMetrics["haproxy.connections.retries"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Number of times a connection to a server was retried. Corresponds to HAProxy's `wretr` metric.", ms.At(i).Description())
					assert.Equal(t, "{retries}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.connections.total":
					assert.False(t, validatedMetrics["haproxy.connections.total"], "Found a duplicate in the metrics slice: haproxy.connections.total")
					validatedMetrics["haproxy.connections.total"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Cumulative number of connections (frontend). Corresponds to HAProxy's `conn_tot` metric.", ms.At(i).Description())
					assert.Equal(t, "{connections}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.downtime":
					assert.False(t, validatedMetrics["haproxy.downtime"], "Found a duplicate in the metrics slice: haproxy.downtime")
					validatedMetrics["haproxy.downtime"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Total downtime (in seconds). The value for the backend is the downtime for the whole backend, not the sum of the server downtime. Corresponds to HAProxy's `downtime` metric", ms.At(i).Description())
					assert.Equal(t, "s", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.failed_checks":
					assert.False(t, validatedMetrics["haproxy.failed_checks"], "Found a duplicate in the metrics slice: haproxy.failed_checks")
					validatedMetrics["haproxy.failed_checks"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Number of failed checks. (Only counts checks failed when the server is up). Corresponds to HAProxy's `chkfail` metric.", ms.At(i).Description())
					assert.Equal(t, "{checks}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.requests.denied":
					assert.False(t, validatedMetrics["haproxy.requests.denied"], "Found a duplicate in the metrics slice: haproxy.requests.denied")
					validatedMetrics["haproxy.requests.denied"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Requests denied because of security concerns. Corresponds to HAProxy's `dreq` metric", ms.At(i).Description())
					assert.Equal(t, "{requests}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.requests.errors":
					assert.False(t, validatedMetrics["haproxy.requests.errors"], "Found a duplicate in the metrics slice: haproxy.requests.errors")
					validatedMetrics["haproxy.requests.errors"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Cumulative number of request errors. Corresponds to HAProxy's `ereq` metric.", ms.At(i).Description())
					assert.Equal(t, "{errors}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.requests.queued":
					assert.False(t, validatedMetrics["haproxy.requests.queued"], "Found a duplicate in the metrics slice: haproxy.requests.queued")
					validatedMetrics["haproxy.requests.queued"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Current queued requests. For the backend this reports the number queued without a server assigned. Corresponds to HAProxy's `qcur` metric.", ms.At(i).Description())
					assert.Equal(t, "{requests}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.requests.rate":
					assert.False(t, validatedMetrics["haproxy.requests.rate"], "Found a duplicate in the metrics slice: haproxy.requests.rate")
					validatedMetrics["haproxy.requests.rate"] = true
					assert.Equal(t, pmetric.MetricTypeGauge, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Gauge().DataPoints().Len())
					assert.Equal(t, "HTTP requests per second over last elapsed second. Corresponds to HAProxy's `req_rate` metric.", ms.At(i).Description())
					assert.Equal(t, "{requests}", ms.At(i).Unit())
					dp := ms.At(i).Gauge().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeDouble, dp.ValueType())
					assert.InDelta(t, float64(1), dp.DoubleValue(), 0.01)
				case "haproxy.requests.redispatched":
					assert.False(t, validatedMetrics["haproxy.requests.redispatched"], "Found a duplicate in the metrics slice: haproxy.requests.redispatched")
					validatedMetrics["haproxy.requests.redispatched"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Number of times a request was redispatched to another server. Corresponds to HAProxy's `wredis` metric.", ms.At(i).Description())
					assert.Equal(t, "{requests}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.requests.total":
					assert.False(t, validatedMetrics["haproxy.requests.total"], "Found a duplicate in the metrics slice: haproxy.requests.total")
					validatedMetrics["haproxy.requests.total"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Total number of HTTP requests received. Corresponds to HAProxy's `req_tot`, `hrsp_1xx`, `hrsp_2xx`, `hrsp_3xx`, `hrsp_4xx`, `hrsp_5xx` and `hrsp_other` metrics.", ms.At(i).Description())
					assert.Equal(t, "{requests}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
					attrVal, ok := dp.Attributes().Get("status_code")
					assert.True(t, ok)
					assert.Equal(t, "1xx", attrVal.Str())
				case "haproxy.responses.denied":
					assert.False(t, validatedMetrics["haproxy.responses.denied"], "Found a duplicate in the metrics slice: haproxy.responses.denied")
					validatedMetrics["haproxy.responses.denied"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Responses denied because of security concerns. Corresponds to HAProxy's `dresp` metric", ms.At(i).Description())
					assert.Equal(t, "{responses}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.responses.errors":
					assert.False(t, validatedMetrics["haproxy.responses.errors"], "Found a duplicate in the metrics slice: haproxy.responses.errors")
					validatedMetrics["haproxy.responses.errors"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Cumulative number of response errors. Corresponds to HAProxy's `eresp` metric, `srv_abrt` will be counted here also.", ms.At(i).Description())
					assert.Equal(t, "{errors}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.server_selected.total":
					assert.False(t, validatedMetrics["haproxy.server_selected.total"], "Found a duplicate in the metrics slice: haproxy.server_selected.total")
					validatedMetrics["haproxy.server_selected.total"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Number of times a server was selected, either for new sessions or when re-dispatching. Corresponds to HAProxy's `lbtot` metric.", ms.At(i).Description())
					assert.Equal(t, "{selections}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.sessions.average":
					assert.False(t, validatedMetrics["haproxy.sessions.average"], "Found a duplicate in the metrics slice: haproxy.sessions.average")
					validatedMetrics["haproxy.sessions.average"] = true
					assert.Equal(t, pmetric.MetricTypeGauge, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Gauge().DataPoints().Len())
					assert.Equal(t, "Average total session time in ms over the last 1024 requests. Corresponds to HAProxy's `ttime` metric.", ms.At(i).Description())
					assert.Equal(t, "ms", ms.At(i).Unit())
					dp := ms.At(i).Gauge().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeDouble, dp.ValueType())
					assert.InDelta(t, float64(1), dp.DoubleValue(), 0.01)
				case "haproxy.sessions.count":
					assert.False(t, validatedMetrics["haproxy.sessions.count"], "Found a duplicate in the metrics slice: haproxy.sessions.count")
					validatedMetrics["haproxy.sessions.count"] = true
					assert.Equal(t, pmetric.MetricTypeGauge, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Gauge().DataPoints().Len())
					assert.Equal(t, "Current sessions. Corresponds to HAProxy's `scur` metric.", ms.At(i).Description())
					assert.Equal(t, "{sessions}", ms.At(i).Unit())
					dp := ms.At(i).Gauge().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				case "haproxy.sessions.rate":
					assert.False(t, validatedMetrics["haproxy.sessions.rate"], "Found a duplicate in the metrics slice: haproxy.sessions.rate")
					validatedMetrics["haproxy.sessions.rate"] = true
					assert.Equal(t, pmetric.MetricTypeGauge, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Gauge().DataPoints().Len())
					assert.Equal(t, "Number of sessions per second over last elapsed second. Corresponds to HAProxy's `rate` metric.", ms.At(i).Description())
					assert.Equal(t, "{sessions}", ms.At(i).Unit())
					dp := ms.At(i).Gauge().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeDouble, dp.ValueType())
					assert.InDelta(t, float64(1), dp.DoubleValue(), 0.01)
				case "haproxy.sessions.total":
					assert.False(t, validatedMetrics["haproxy.sessions.total"], "Found a duplicate in the metrics slice: haproxy.sessions.total")
					validatedMetrics["haproxy.sessions.total"] = true
					assert.Equal(t, pmetric.MetricTypeSum, ms.At(i).Type())
					assert.Equal(t, 1, ms.At(i).Sum().DataPoints().Len())
					assert.Equal(t, "Cumulative number of sessions. Corresponds to HAProxy's `stot` metric.", ms.At(i).Description())
					assert.Equal(t, "{sessions}", ms.At(i).Unit())
					assert.True(t, ms.At(i).Sum().IsMonotonic())
					assert.Equal(t, pmetric.AggregationTemporalityCumulative, ms.At(i).Sum().AggregationTemporality())
					dp := ms.At(i).Sum().DataPoints().At(0)
					assert.Equal(t, start, dp.StartTimestamp())
					assert.Equal(t, ts, dp.Timestamp())
					assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
					assert.Equal(t, int64(1), dp.IntValue())
				}
			}
		})
	}
}
