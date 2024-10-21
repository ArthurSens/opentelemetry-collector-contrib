// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prometheus // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/translator/prometheus"

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/common/testutil"
)

func TestByte(t *testing.T) {

	require.Equal(t, "system_filesystem_usage_bytes", normalizeName(createGauge("system.filesystem.usage", "By"), "", false))

}

func TestByteCounter(t *testing.T) {

	require.Equal(t, "system_io_bytes_total", normalizeName(createCounter("system.io", "By"), "", false))
	require.Equal(t, "network_transmitted_bytes_total", normalizeName(createCounter("network_transmitted_bytes_total", "By"), "", false))

}

func TestWhiteSpaces(t *testing.T) {

	require.Equal(t, "system_filesystem_usage_bytes", normalizeName(createGauge("\t system.filesystem.usage       ", "  By\t"), "", false))

}

func TestNonStandardUnit(t *testing.T) {

	require.Equal(t, "system_network_dropped", normalizeName(createGauge("system.network.dropped", "{packets}"), "", false))

}

func TestNonStandardUnitCounter(t *testing.T) {

	require.Equal(t, "system_network_dropped_total", normalizeName(createCounter("system.network.dropped", "{packets}"), "", false))

}

func TestBrokenUnit(t *testing.T) {

	require.Equal(t, "system_network_dropped_packets", normalizeName(createGauge("system.network.dropped", "packets"), "", false))
	require.Equal(t, "system_network_packets_dropped", normalizeName(createGauge("system.network.packets.dropped", "packets"), "", false))
	require.Equal(t, "system_network_packets", normalizeName(createGauge("system.network.packets", "packets"), "", false))

}

func TestBrokenUnitCounter(t *testing.T) {

	require.Equal(t, "system_network_dropped_packets_total", normalizeName(createCounter("system.network.dropped", "packets"), "", false))
	require.Equal(t, "system_network_packets_dropped_total", normalizeName(createCounter("system.network.packets.dropped", "packets"), "", false))
	require.Equal(t, "system_network_packets_total", normalizeName(createCounter("system.network.packets", "packets"), "", false))

}

func TestRatio(t *testing.T) {

	require.Equal(t, "hw_gpu_memory_utilization_ratio", normalizeName(createGauge("hw.gpu.memory.utilization", "1"), "", false))
	require.Equal(t, "hw_fan_speed_ratio", normalizeName(createGauge("hw.fan.speed_ratio", "1"), "", false))
	require.Equal(t, "objects_total", normalizeName(createCounter("objects", "1"), "", false))

}

func TestHertz(t *testing.T) {

	require.Equal(t, "hw_cpu_speed_limit_hertz", normalizeName(createGauge("hw.cpu.speed_limit", "Hz"), "", false))

}

func TestPer(t *testing.T) {

	require.Equal(t, "broken_metric_speed_km_per_hour", normalizeName(createGauge("broken.metric.speed", "km/h"), "", false))
	require.Equal(t, "astro_light_speed_limit_meters_per_second", normalizeName(createGauge("astro.light.speed_limit", "m/s"), "", false))

}

func TestPercent(t *testing.T) {

	require.Equal(t, "broken_metric_success_ratio_percent", normalizeName(createGauge("broken.metric.success_ratio", "%"), "", false))
	require.Equal(t, "broken_metric_success_percent", normalizeName(createGauge("broken.metric.success_percent", "%"), "", false))

}

func TestEmpty(t *testing.T) {

	require.Equal(t, "test_metric_no_unit", normalizeName(createGauge("test.metric.no_unit", ""), "", false))
	require.Equal(t, "test_metric_spaces", normalizeName(createGauge("test.metric.spaces", "   \t  "), "", false))

}

func TestAllowUTF8(t *testing.T) {
	for _, allowUTF8 := range []bool{true, false} {
		if allowUTF8 {
			require.Equal(t, "unsupported.metric.temperature_°F", normalizeName(createGauge("unsupported.metric.temperature", "°F"), "", allowUTF8))
			require.Equal(t, "unsupported.metric.weird_+=.:,!* & #", normalizeName(createGauge("unsupported.metric.weird", "+=.:,!* & #"), "", allowUTF8))
			require.Equal(t, "unsupported.metric.redundant___test $_per_°C", normalizeName(createGauge("unsupported.metric.redundant", "__test $/°C"), "", allowUTF8))
		} else {
			require.Equal(t, "unsupported_metric_temperature_F", normalizeName(createGauge("unsupported.metric.temperature", "°F"), "", allowUTF8))
			require.Equal(t, "unsupported_metric_weird", normalizeName(createGauge("unsupported.metric.weird", "+=.:,!* & #"), "", allowUTF8))
			require.Equal(t, "unsupported_metric_redundant_test_per_C", normalizeName(createGauge("unsupported.metric.redundant", "__test $/°C"), "", allowUTF8))
		}
	}
}

func TestOtelReceivers(t *testing.T) {

	require.Equal(t, "active_directory_ds_replication_network_io_bytes_total", normalizeName(createCounter("active_directory.ds.replication.network.io", "By"), "", false))
	require.Equal(t, "active_directory_ds_replication_sync_object_pending_total", normalizeName(createCounter("active_directory.ds.replication.sync.object.pending", "{objects}"), "", false))
	require.Equal(t, "active_directory_ds_replication_object_rate_per_second", normalizeName(createGauge("active_directory.ds.replication.object.rate", "{objects}/s"), "", false))
	require.Equal(t, "active_directory_ds_name_cache_hit_rate_percent", normalizeName(createGauge("active_directory.ds.name_cache.hit_rate", "%"), "", false))
	require.Equal(t, "active_directory_ds_ldap_bind_last_successful_time_milliseconds", normalizeName(createGauge("active_directory.ds.ldap.bind.last_successful.time", "ms"), "", false))
	require.Equal(t, "apache_current_connections", normalizeName(createGauge("apache.current_connections", "connections"), "", false))
	require.Equal(t, "apache_workers_connections", normalizeName(createGauge("apache.workers", "connections"), "", false))
	require.Equal(t, "apache_requests_total", normalizeName(createCounter("apache.requests", "1"), "", false))
	require.Equal(t, "bigip_virtual_server_request_count_total", normalizeName(createCounter("bigip.virtual_server.request.count", "{requests}"), "", false))
	require.Equal(t, "system_cpu_utilization_ratio", normalizeName(createGauge("system.cpu.utilization", "1"), "", false))
	require.Equal(t, "system_disk_operation_time_seconds_total", normalizeName(createCounter("system.disk.operation_time", "s"), "", false))
	require.Equal(t, "system_cpu_load_average_15m_ratio", normalizeName(createGauge("system.cpu.load_average.15m", "1"), "", false))
	require.Equal(t, "memcached_operation_hit_ratio_percent", normalizeName(createGauge("memcached.operation_hit_ratio", "%"), "", false))
	require.Equal(t, "mongodbatlas_process_asserts_per_second", normalizeName(createGauge("mongodbatlas.process.asserts", "{assertions}/s"), "", false))
	require.Equal(t, "mongodbatlas_process_journaling_data_files_mebibytes", normalizeName(createGauge("mongodbatlas.process.journaling.data_files", "MiBy"), "", false))
	require.Equal(t, "mongodbatlas_process_network_io_bytes_per_second", normalizeName(createGauge("mongodbatlas.process.network.io", "By/s"), "", false))
	require.Equal(t, "mongodbatlas_process_oplog_rate_gibibytes_per_hour", normalizeName(createGauge("mongodbatlas.process.oplog.rate", "GiBy/h"), "", false))
	require.Equal(t, "mongodbatlas_process_db_query_targeting_scanned_per_returned", normalizeName(createGauge("mongodbatlas.process.db.query_targeting.scanned_per_returned", "{scanned}/{returned}"), "", false))
	require.Equal(t, "nginx_requests", normalizeName(createGauge("nginx.requests", "requests"), "", false))
	require.Equal(t, "nginx_connections_accepted", normalizeName(createGauge("nginx.connections_accepted", "connections"), "", false))
	require.Equal(t, "nsxt_node_memory_usage_kilobytes", normalizeName(createGauge("nsxt.node.memory.usage", "KBy"), "", false))
	require.Equal(t, "redis_latest_fork_microseconds", normalizeName(createGauge("redis.latest_fork", "us"), "", false))

}

func TestTrimPromSuffixes(t *testing.T) {
	assert.Equal(t, "active_directory_ds_replication_network_io", TrimPromSuffixes("active_directory_ds_replication_network_io_bytes_total", pmetric.MetricTypeSum, "bytes"))
	assert.Equal(t, "active_directory_ds_name_cache_hit_rate", TrimPromSuffixes("active_directory_ds_name_cache_hit_rate_percent", pmetric.MetricTypeGauge, "percent"))
	assert.Equal(t, "active_directory_ds_ldap_bind_last_successful_time", TrimPromSuffixes("active_directory_ds_ldap_bind_last_successful_time_milliseconds", pmetric.MetricTypeGauge, "milliseconds"))
	assert.Equal(t, "apache_requests", TrimPromSuffixes("apache_requests_total", pmetric.MetricTypeSum, "1"))
	assert.Equal(t, "system_cpu_utilization", TrimPromSuffixes("system_cpu_utilization_ratio", pmetric.MetricTypeGauge, "ratio"))
	assert.Equal(t, "mongodbatlas_process_journaling_data_files", TrimPromSuffixes("mongodbatlas_process_journaling_data_files_mebibytes", pmetric.MetricTypeGauge, "mebibytes"))
	assert.Equal(t, "mongodbatlas_process_network_io", TrimPromSuffixes("mongodbatlas_process_network_io_bytes_per_second", pmetric.MetricTypeGauge, "bytes_per_second"))
	assert.Equal(t, "mongodbatlas_process_oplog_rate", TrimPromSuffixes("mongodbatlas_process_oplog_rate_gibibytes_per_hour", pmetric.MetricTypeGauge, "gibibytes_per_hour"))
	assert.Equal(t, "nsxt_node_memory_usage", TrimPromSuffixes("nsxt_node_memory_usage_kilobytes", pmetric.MetricTypeGauge, "kilobytes"))
	assert.Equal(t, "redis_latest_fork", TrimPromSuffixes("redis_latest_fork_microseconds", pmetric.MetricTypeGauge, "microseconds"))
	assert.Equal(t, "up", TrimPromSuffixes("up", pmetric.MetricTypeGauge, ""))

	// These are not necessarily valid OM units, only tested for the sake of completeness.
	assert.Equal(t, "active_directory_ds_replication_sync_object_pending", TrimPromSuffixes("active_directory_ds_replication_sync_object_pending_total", pmetric.MetricTypeSum, "{objects}"))
	assert.Equal(t, "apache_current", TrimPromSuffixes("apache_current_connections", pmetric.MetricTypeGauge, "connections"))
	assert.Equal(t, "bigip_virtual_server_request_count", TrimPromSuffixes("bigip_virtual_server_request_count_total", pmetric.MetricTypeSum, "{requests}"))
	assert.Equal(t, "mongodbatlas_process_db_query_targeting_scanned_per_returned", TrimPromSuffixes("mongodbatlas_process_db_query_targeting_scanned_per_returned", pmetric.MetricTypeGauge, "{scanned}/{returned}"))
	assert.Equal(t, "nginx_connections_accepted", TrimPromSuffixes("nginx_connections_accepted", pmetric.MetricTypeGauge, "connections"))
	assert.Equal(t, "apache_workers", TrimPromSuffixes("apache_workers_connections", pmetric.MetricTypeGauge, "connections"))
	assert.Equal(t, "nginx", TrimPromSuffixes("nginx_requests", pmetric.MetricTypeGauge, "requests"))

	// Units shouldn't be trimmed if the unit is not a direct match with the suffix, i.e, a suffix "_seconds" shouldn't be removed if unit is "sec" or "s"
	assert.Equal(t, "system_cpu_load_average_15m_ratio", TrimPromSuffixes("system_cpu_load_average_15m_ratio", pmetric.MetricTypeGauge, "1"))
	assert.Equal(t, "mongodbatlas_process_asserts_per_second", TrimPromSuffixes("mongodbatlas_process_asserts_per_second", pmetric.MetricTypeGauge, "{assertions}/s"))
	assert.Equal(t, "memcached_operation_hit_ratio_percent", TrimPromSuffixes("memcached_operation_hit_ratio_percent", pmetric.MetricTypeGauge, "%"))
	assert.Equal(t, "active_directory_ds_replication_object_rate_per_second", TrimPromSuffixes("active_directory_ds_replication_object_rate_per_second", pmetric.MetricTypeGauge, "{objects}/s"))
	assert.Equal(t, "system_disk_operation_time_seconds", TrimPromSuffixes("system_disk_operation_time_seconds_total", pmetric.MetricTypeSum, "s"))

}

func TestNamespace(t *testing.T) {
	require.Equal(t, "space_test", normalizeName(createGauge("test", ""), "space", false))
	require.Equal(t, "space_test", normalizeName(createGauge("#test", ""), "space", false))
}

func TestCleanUpString(t *testing.T) {
	for _, allowUTF8 := range []bool{true, false} {
		if allowUTF8 {
			require.Equal(t, "", CleanUpString("", allowUTF8))
			require.Equal(t, "a b", CleanUpString("a b", allowUTF8))
			require.Equal(t, "hello, world!", CleanUpString("hello, world!", allowUTF8))
			require.Equal(t, "hello you 2", CleanUpString("hello you 2", allowUTF8))
			require.Equal(t, "$1000", CleanUpString("$1000", allowUTF8))
			require.Equal(t, "*+$^=)", CleanUpString("*+$^=)", allowUTF8))
		} else {
			require.Equal(t, "", CleanUpString("", allowUTF8))
			require.Equal(t, "a_b", CleanUpString("a b", allowUTF8))
			require.Equal(t, "hello_world", CleanUpString("hello, world!", allowUTF8))
			require.Equal(t, "hello_you_2", CleanUpString("hello you 2", allowUTF8))
			require.Equal(t, "1000", CleanUpString("$1000", allowUTF8))
			require.Equal(t, "", CleanUpString("*+$^=)", allowUTF8))
		}
	}
}

func TestUnitMapGetOrDefault(t *testing.T) {

	require.Equal(t, "", unitMapGetOrDefault(""))
	require.Equal(t, "seconds", unitMapGetOrDefault("s"))
	require.Equal(t, "invalid", unitMapGetOrDefault("invalid"))

}

func TestPerUnitMapGetOrDefault(t *testing.T) {

	require.Equal(t, "", perUnitMapGetOrDefault(""))
	require.Equal(t, "second", perUnitMapGetOrDefault("s"))
	require.Equal(t, "invalid", perUnitMapGetOrDefault("invalid"))

}

func TestRemoveItem(t *testing.T) {

	require.Equal(t, []string{}, removeItem([]string{}, "test"))
	require.Equal(t, []string{}, removeItem([]string{}, ""))
	require.Equal(t, []string{"a", "b", "c"}, removeItem([]string{"a", "b", "c"}, "d"))
	require.Equal(t, []string{"a", "b", "c"}, removeItem([]string{"a", "b", "c"}, ""))
	require.Equal(t, []string{"a", "b"}, removeItem([]string{"a", "b", "c"}, "c"))
	require.Equal(t, []string{"a", "c"}, removeItem([]string{"a", "b", "c"}, "b"))
	require.Equal(t, []string{"b", "c"}, removeItem([]string{"a", "b", "c"}, "a"))

}

func TestBuildCompliantNameWithNormalize(t *testing.T) {

	defer testutil.SetFeatureGateForTest(t, normalizeNameGate, true)()
	addUnitAndTypeSuffixes := true
	require.Equal(t, "system_io_bytes_total", BuildCompliantName(createCounter("system.io", "By"), "", addUnitAndTypeSuffixes, false))
	require.Equal(t, "system_network_io_bytes_total", BuildCompliantName(createCounter("network.io", "By"), "system", addUnitAndTypeSuffixes, false))
	require.Equal(t, "_3_14_digits", BuildCompliantName(createGauge("3.14 digits", ""), "", addUnitAndTypeSuffixes, false))
	require.Equal(t, "envoy_rule_engine_zlib_buf_error", BuildCompliantName(createGauge("envoy__rule_engine_zlib_buf_error", ""), "", addUnitAndTypeSuffixes, false))
	require.Equal(t, "foo_bar", BuildCompliantName(createGauge(":foo::bar", ""), "", addUnitAndTypeSuffixes, false))
	require.Equal(t, "foo_bar_total", BuildCompliantName(createCounter(":foo::bar", ""), "", addUnitAndTypeSuffixes, false))

}

func TestBuildCompliantNameWithSuffixesFeatureGateDisabled(t *testing.T) {

	defer testutil.SetFeatureGateForTest(t, normalizeNameGate, false)()
	addUnitAndTypeSuffixes := true
	require.Equal(t, "system_io", BuildCompliantName(createCounter("system.io", "By"), "", addUnitAndTypeSuffixes, false))
	require.Equal(t, "system_network_io", BuildCompliantName(createCounter("network.io", "By"), "system", addUnitAndTypeSuffixes, false))
	require.Equal(t, "system_network_I_O", BuildCompliantName(createCounter("network (I/O)", "By"), "system", addUnitAndTypeSuffixes, false))
	require.Equal(t, "_3_14_digits", BuildCompliantName(createGauge("3.14 digits", "By"), "", addUnitAndTypeSuffixes, false))
	require.Equal(t, "envoy__rule_engine_zlib_buf_error", BuildCompliantName(createGauge("envoy__rule_engine_zlib_buf_error", ""), "", addUnitAndTypeSuffixes, false))
	require.Equal(t, ":foo::bar", BuildCompliantName(createGauge(":foo::bar", ""), "", addUnitAndTypeSuffixes, false))
	require.Equal(t, ":foo::bar", BuildCompliantName(createCounter(":foo::bar", ""), "", addUnitAndTypeSuffixes, false))

}

func TestBuildCompliantNameWithoutSuffixes(t *testing.T) {

	defer testutil.SetFeatureGateForTest(t, normalizeNameGate, false)()
	addUnitAndTypeSuffixes := false
	require.Equal(t, "system_io", BuildCompliantName(createCounter("system.io", "By"), "", addUnitAndTypeSuffixes, false))
	require.Equal(t, "system_network_io", BuildCompliantName(createCounter("network.io", "By"), "system", addUnitAndTypeSuffixes, false))
	require.Equal(t, "system_network_I_O", BuildCompliantName(createCounter("network (I/O)", "By"), "system", addUnitAndTypeSuffixes, false))
	require.Equal(t, "_3_14_digits", BuildCompliantName(createGauge("3.14 digits", "By"), "", addUnitAndTypeSuffixes, false))
	require.Equal(t, "envoy__rule_engine_zlib_buf_error", BuildCompliantName(createGauge("envoy__rule_engine_zlib_buf_error", ""), "", addUnitAndTypeSuffixes, false))
	require.Equal(t, ":foo::bar", BuildCompliantName(createGauge(":foo::bar", ""), "", addUnitAndTypeSuffixes, false))
	require.Equal(t, ":foo::bar", BuildCompliantName(createCounter(":foo::bar", ""), "", addUnitAndTypeSuffixes, false))

}
