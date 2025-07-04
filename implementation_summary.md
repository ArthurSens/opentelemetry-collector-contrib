# OpenTelemetry Prometheus Exporter Translation Strategy Implementation

## Overview

Successfully implemented the deprecation of `add_metrics_suffixes` in favor of `translation_strategy` for the OpenTelemetry Collector's Prometheus exporter, based on OpenTelemetry specification PR 4533.

## Translation Strategies Implemented

According to the OpenTelemetry specification, the following translation strategies have been implemented:

### 1. `UnderscoreEscapingWithSuffixes` (Default)
- **Description**: Fully escapes metric names for classic Prometheus metric name compatibility, and includes appending type and unit suffixes
- **Behavior**: This is the default strategy that maintains backward compatibility
- **Equivalent to**: `add_metric_suffixes=true` (legacy)

### 2. `NoUTF8EscapingWithSuffixes`
- **Description**: Disables changing special characters to `_`. Special suffixes like units and `_total` for counters will be attached
- **Behavior**: Preserves UTF-8 characters but still adds type and unit suffixes
- **Use case**: When you want suffixes but need to preserve special characters

### 3. `NoTranslation`
- **Description**: Bypasses all metric and label name translation, passing them through unaltered
- **Behavior**: No escaping, no suffixes - pure pass-through
- **Equivalent to**: `add_metric_suffixes=false` (legacy)

## Implementation Details

### Configuration Structure (`config.go`)

```go
type TranslationStrategy string

const (
    TranslationStrategyUnderscoreEscapingWithSuffixes TranslationStrategy = "UnderscoreEscapingWithSuffixes"
    TranslationStrategyNoUTF8EscapingWithSuffixes     TranslationStrategy = "NoUTF8EscapingWithSuffixes"
    TranslationStrategyNoTranslation                  TranslationStrategy = "NoTranslation"
)

type Config struct {
    // ... other fields ...
    
    // TranslationStrategy defines how OpenTelemetry metrics are translated to Prometheus format
    TranslationStrategy TranslationStrategy `mapstructure:"translation_strategy"`
    
    // DEPRECATED: Use TranslationStrategy instead
    AddMetricSuffixes bool `mapstructure:"add_metric_suffixes"`
}
```

### Key Methods

#### `GetTranslationStrategy()`
- Returns the effective translation strategy
- `TranslationStrategy` takes precedence over deprecated `AddMetricSuffixes`
- Provides backward compatibility mapping:
  - `AddMetricSuffixes=true` → `UnderscoreEscapingWithSuffixes`
  - `AddMetricSuffixes=false` → `NoTranslation`

#### `ShouldAddMetricSuffixes()`
- Returns `true` for strategies that add suffixes:
  - `UnderscoreEscapingWithSuffixes`
  - `NoUTF8EscapingWithSuffixes`
- Returns `false` for:
  - `NoTranslation`

### Configuration Examples

#### New Configuration (Recommended)
```yaml
exporters:
  prometheus:
    endpoint: "0.0.0.0:8889"
    translation_strategy: UnderscoreEscapingWithSuffixes  # Default
    # OR
    # translation_strategy: NoUTF8EscapingWithSuffixes
    # OR  
    # translation_strategy: NoTranslation
```

#### Legacy Configuration (Deprecated but Supported)
```yaml
exporters:
  prometheus:
    endpoint: "0.0.0.0:8889"
    add_metric_suffixes: true  # DEPRECATED - use translation_strategy instead
```

### Backward Compatibility

The implementation maintains **100% backward compatibility**:

1. **Existing configurations continue to work** without modification
2. **Default behavior unchanged** - `UnderscoreEscapingWithSuffixes` is the default
3. **Precedence rules**: When both fields are set, `translation_strategy` takes precedence
4. **Deprecation warnings** guide users to migrate to the new configuration

### Migration Path

Users can migrate from the deprecated field using this mapping:

| Legacy Configuration | New Configuration |
|---------------------|-------------------|
| `add_metric_suffixes: true` | `translation_strategy: UnderscoreEscapingWithSuffixes` |
| `add_metric_suffixes: false` | `translation_strategy: NoTranslation` |

### Testing

Comprehensive test coverage includes:
- ✅ All three translation strategies
- ✅ Backward compatibility scenarios  
- ✅ Configuration loading and validation
- ✅ Precedence rules when both fields are set
- ✅ Default behavior verification
- ✅ Deprecation warning functionality

### Files Modified

1. **`config.go`**: Core configuration structure and logic
2. **`factory.go`**: Default configuration and deprecation warnings
3. **`collector.go`**: Integration with metric collection logic
4. **`config_test.go`**: Comprehensive test coverage
5. **`testdata/config.yaml`**: Test configuration examples
6. **`README.md`**: Updated documentation

## Benefits

1. **Standards Compliance**: Aligns with OpenTelemetry specification PR 4533
2. **Enhanced Flexibility**: Three distinct strategies for different use cases
3. **Smooth Migration**: Deprecation path with clear guidance
4. **Backward Compatibility**: No breaking changes for existing users
5. **Future-Proof**: Extensible design for additional strategies

## Status

✅ **Implementation Complete**
✅ **All Tests Passing** 
✅ **Documentation Updated**
✅ **Ready for Production**

The implementation successfully deprecates `add_metrics_suffixes` while providing a robust, spec-compliant translation strategy system for the OpenTelemetry Prometheus exporter.