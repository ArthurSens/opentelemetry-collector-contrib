// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prometheus // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/translator/prometheus"

import (
	"strings"
	"unicode"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

// The map to translate OTLP units to Prometheus units
// OTLP metrics use the c/s notation as specified at https://ucum.org/ucum.html
// (See also https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/semantic_conventions/README.md#instrument-units)
// Prometheus best practices for units: https://prometheus.io/docs/practices/naming/#base-units
// OpenMetrics specification for units: https://github.com/OpenObservability/OpenMetrics/blob/main/specification/OpenMetrics.md#units-and-base-units
var unitMap = map[string]string{

	// Time
	"d":   "days",
	"h":   "hours",
	"min": "minutes",
	"s":   "seconds",
	"ms":  "milliseconds",
	"us":  "microseconds",
	"ns":  "nanoseconds",

	// Bytes
	"By":   "bytes",
	"KiBy": "kibibytes",
	"MiBy": "mebibytes",
	"GiBy": "gibibytes",
	"TiBy": "tibibytes",
	"KBy":  "kilobytes",
	"MBy":  "megabytes",
	"GBy":  "gigabytes",
	"TBy":  "terabytes",

	// SI
	"m": "meters",
	"V": "volts",
	"A": "amperes",
	"J": "joules",
	"W": "watts",
	"g": "grams",

	// Misc
	"Cel": "celsius",
	"Hz":  "hertz",
	"1":   "",
	"%":   "percent",
}

// The map that translates the "per" unit
// Example: s => per second (singular)
var perUnitMap = map[string]string{
	"s":  "second",
	"m":  "minute",
	"h":  "hour",
	"d":  "day",
	"w":  "week",
	"mo": "month",
	"y":  "year",
}

// BuildCompliantName builds a Prometheus-compliant metric name for the specified metric
//
// Metric name is prefixed with specified namespace and underscore (if any).
// Namespace is not cleaned up. Make sure specified namespace follows Prometheus
// naming convention.
//
// See rules at https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels
// and https://prometheus.io/docs/practices/naming/#metric-and-label-naming
func BuildCompliantName(metric pmetric.Metric, namespace string, addMetricSuffixes bool) string {
	var metricName string

	// Full normalization following standard Prometheus naming conventions
	if addMetricSuffixes && normalizeNameGate.IsEnabled() {
		return normalizeName(metric, namespace)
	}

	if !AllowUTF8FeatureGate.IsEnabled() {
		// Simple case (no full normalization, no units, etc.), we simply trim out forbidden chars
		metricName = RemovePromForbiddenRunes(metric.Name())
	} else {
		metricName = metric.Name()
	}

	// Namespace?
	if namespace != "" {
		return namespace + "_" + metricName
	}

	// Metric name starts with a digit? Prefix it with an underscore
	if metricName != "" && unicode.IsDigit(rune(metricName[0])) {
		metricName = "_" + metricName
	}

	return metricName
}

// Build a normalized name for the specified metric
func normalizeName(metric pmetric.Metric, namespace string) string {
	allowUTF8 := AllowUTF8FeatureGate.IsEnabled()
	// Split metric name in "tokens" (remove all non-alphanumeric)
	nameTokens, separators := fieldsFunc(
		metric.Name(),
		func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) },
	)

	// Split unit at the '/' if any
	unitTokens := strings.SplitN(metric.Unit(), "/", 2)

	// Main unit
	// Append if not blank, doesn't contain '{}', and is not present in metric name already
	if len(unitTokens) > 0 {
		mainUnitOtel := strings.TrimSpace(unitTokens[0])
		if mainUnitOtel != "" && !strings.ContainsAny(mainUnitOtel, "{}") {
			mainUnitProm := CleanUpString(unitMapGetOrDefault(mainUnitOtel))
			if mainUnitProm != "" && !contains(nameTokens, mainUnitProm) {
				nameTokens = append(nameTokens, mainUnitProm)
			}
		}

		// Per unit
		// Append if not blank, doesn't contain '{}', and is not present in metric name already
		if len(unitTokens) > 1 && unitTokens[1] != "" {
			perUnitOtel := strings.TrimSpace(unitTokens[1])
			if perUnitOtel != "" && !strings.ContainsAny(perUnitOtel, "{}") {
				perUnitProm := CleanUpString(perUnitMapGetOrDefault(perUnitOtel))
				if perUnitProm != "" && !contains(nameTokens, perUnitProm) {
					nameTokens = append(append(nameTokens, "per"), perUnitProm)
				}
			}
		}

	}

	// Append _total for Counters
	if metric.Type() == pmetric.MetricTypeSum && metric.Sum().IsMonotonic() {
		nameTokens = append(removeItem(nameTokens, "total"), "total")
	}

	// Append _ratio for metrics with unit "1"
	// Some Otel receivers improperly use unit "1" for counters of objects
	// See https://github.com/open-telemetry/opentelemetry-collector-contrib/issues?q=is%3Aissue+some+metric+units+don%27t+follow+otel+semantic+conventions
	// Until these issues have been fixed, we're appending `_ratio` for gauges ONLY
	// Theoretically, counters could be ratios as well, but it's absurd (for mathematical reasons)
	if metric.Unit() == "1" && metric.Type() == pmetric.MetricTypeGauge {
		nameTokens = append(removeItem(nameTokens, "ratio"), "ratio")
	}

	// Namespace?
	if namespace != "" {
		nameTokens = append([]string{namespace}, nameTokens...)
	}

	// Build the string from the tokens + separators.
	// If UTF-8 isn't enabled, we'll use underscores as separators.
	if !allowUTF8 {
		separators = []string{}
	}
	normalizedName := join(nameTokens, separators, "_")

	// Metric name cannot start with a digit, so prefix it with "_" in this case
	if normalizedName != "" && unicode.IsDigit(rune(normalizedName[0])) {
		normalizedName = "_" + normalizedName
	}

	return normalizedName
}

// fieldsFunc is a copy of strings.FieldsFunc from the Go standard library,
// but it also returns the separators as part of the result.
func fieldsFunc(s string, f func(rune) bool) ([]string, []string) {
	// A span is used to record a slice of s of the form s[start:end].
	// The start index is inclusive and the end index is exclusive.
	type span struct {
		start int
		end   int
	}
	spans := make([]span, 0, 32)
	separators := make([]string, 0, 32)

	// Find the field start and end indices.
	// Doing this in a separate pass (rather than slicing the string s
	// and collecting the result substrings right away) is significantly
	// more efficient, possibly due to cache effects.
	start := -1 // valid span start if >= 0
	for end, rune := range s {
		if f(rune) {
			if start >= 0 {
				spans = append(spans, span{start, end})
				// Set start to a negative value.
				// Note: using -1 here consistently and reproducibly
				// slows down this code by a several percent on amd64.
				start = ^start
				separators = append(separators, string(s[end]))
			}
		} else {
			if start < 0 {
				start = end
			}
		}
	}

	// Last field might end at EOF.
	if start >= 0 {
		spans = append(spans, span{start, len(s)})
	}

	// Create strings from recorded field indices.
	a := make([]string, len(spans))
	for i, span := range spans {
		a[i] = s[span.start:span.end]
	}

	return a, separators
}

// join is a copy of strings.Join from the Go standard library,
// but it also accepts a slice of separators to join the elements with.
// If the slice of separators is shorter than the slice of elements, use a default value.
// We also don't check for integer overflow.
func join(elems []string, separators []string, def string) string {
	switch len(elems) {
	case 0:
		return ""
	case 1:
		return elems[0]
	}

	var n int
	var sep string
	sepLen := len(separators)
	for i, elem := range elems {
		if i >= sepLen {
			sep = def
		} else {
			sep = separators[i]
		}
		n += len(sep) + len(elem)
	}

	var b strings.Builder
	b.Grow(n)
	b.WriteString(elems[0])
	for i, s := range elems[1:] {
		if i >= sepLen {
			sep = def
		} else {
			sep = separators[i]
		}
		b.WriteString(sep)
		b.WriteString(s)
	}
	return b.String()
}

// TrimPromSuffixes trims type and unit prometheus suffixes from a metric name.
// Following the [OpenTelemetry specs] for converting Prometheus Metric points to OTLP.
//
// [OpenTelemetry specs]: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/data-model.md#metric-metadata
func TrimPromSuffixes(promName string, metricType pmetric.MetricType, unit string) string {
	nameTokens := strings.Split(promName, "_")
	if len(nameTokens) == 1 {
		return promName
	}

	nameTokens = removeTypeSuffixes(nameTokens, metricType)
	nameTokens = removeUnitSuffixes(nameTokens, unit)

	return strings.Join(nameTokens, "_")
}

func removeTypeSuffixes(tokens []string, metricType pmetric.MetricType) []string {
	switch metricType {
	case pmetric.MetricTypeSum:
		// Only counters are expected to have a type suffix at this point.
		// for other types, suffixes are removed during scrape.
		return removeSuffix(tokens, "total")
	default:
		return tokens
	}
}

func removeUnitSuffixes(nameTokens []string, unit string) []string {
	l := len(nameTokens)
	unitTokens := strings.Split(unit, "_")
	lu := len(unitTokens)

	if lu == 0 || l <= lu {
		return nameTokens
	}

	suffixed := true
	for i := range unitTokens {
		if nameTokens[l-i-1] != unitTokens[lu-i-1] {
			suffixed = false
			break
		}
	}

	if suffixed {
		return nameTokens[:l-lu]
	}

	return nameTokens
}

func removeSuffix(tokens []string, suffix string) []string {
	l := len(tokens)
	if tokens[l-1] == suffix {
		return tokens[:l-1]
	}

	return tokens
}

// Clean up specified string so it's Prometheus compliant
func CleanUpString(s string) string {
	if !AllowUTF8FeatureGate.IsEnabled() {
		return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }), "_")
	}
	return s
}

func RemovePromForbiddenRunes(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != ':' }), "_")
}

// Retrieve the Prometheus "basic" unit corresponding to the specified "basic" unit
// Returns the specified unit if not found in unitMap
func unitMapGetOrDefault(unit string) string {
	if promUnit, ok := unitMap[unit]; ok {
		return promUnit
	}
	return unit
}

// Retrieve the Prometheus "per" unit corresponding to the specified "per" unit
// Returns the specified unit if not found in perUnitMap
func perUnitMapGetOrDefault(perUnit string) string {
	if promPerUnit, ok := perUnitMap[perUnit]; ok {
		return promPerUnit
	}
	return perUnit
}

// Returns whether the slice contains the specified value
func contains(slice []string, value string) bool {
	for _, sliceEntry := range slice {
		if sliceEntry == value {
			return true
		}
	}
	return false
}

// Remove the specified value from the slice
func removeItem(slice []string, value string) []string {
	newSlice := make([]string, 0, len(slice))
	for _, sliceEntry := range slice {
		if sliceEntry != value {
			newSlice = append(newSlice, sliceEntry)
		}
	}
	return newSlice
}
