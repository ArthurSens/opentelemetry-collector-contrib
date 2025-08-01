# Coralogix Processor

<!-- status autogenerated section -->
| Status        |           |
| ------------- |-----------|
| Stability     | [alpha]: traces   |
| Distributions | [] |
| Warnings      | [Statefulness](#warnings) |
| Issues        | [![Open issues](https://img.shields.io/github/issues-search/open-telemetry/opentelemetry-collector-contrib?query=is%3Aissue%20is%3Aopen%20label%3Aprocessor%2Fcoralogix%20&label=open&color=orange&logo=opentelemetry)](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues?q=is%3Aopen+is%3Aissue+label%3Aprocessor%2Fcoralogix) [![Closed issues](https://img.shields.io/github/issues-search/open-telemetry/opentelemetry-collector-contrib?query=is%3Aissue%20is%3Aclosed%20label%3Aprocessor%2Fcoralogix%20&label=closed&color=blue&logo=opentelemetry)](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues?q=is%3Aclosed+is%3Aissue+label%3Aprocessor%2Fcoralogix) |
| Code coverage | [![codecov](https://codecov.io/github/open-telemetry/opentelemetry-collector-contrib/graph/main/badge.svg?component=processor_coralogix)](https://app.codecov.io/gh/open-telemetry/opentelemetry-collector-contrib/tree/main/?components%5B0%5D=processor_coralogix&displayType=list) |
| [Code Owners](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/CONTRIBUTING.md#becoming-a-code-owner)    | [@crobert-1](https://www.github.com/crobert-1), [@povilasv](https://www.github.com/povilasv), [@iblancasa](https://www.github.com/iblancasa) |

[alpha]: https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/component-stability.md#alpha
<!-- end autogenerated section -->

## Description

The Coralogix processor adds attributes to spans that enable features in Coralogix.

## Configuration

- `transactions`:
  - `enabled` (`false` by default): enables the transactions feature from the Coralogix processor (more information below).

## Features

### Transactions

A **transaction** represents one logical unit of work in a service — a sequence of function and method calls triggered by an event (like an HTTP request). The Transactions feature (originally called "Service Flows") is Coralogix's extension of OpenTelemetry instrumentation that breaks down each transaction into segments and aggregates their performance over time. It provides visibility into how each segment within a service contributes to overall transaction performance.

More information in the [official docs](https://coralogix.com/docs/user-guides/apm/features/transactions).

#### How It Works

The processor automatically identifies the transaction root span within each transaction and applies transaction attributes to all spans in that transaction:

1. **Transaction root Identification**: The processor finds the span with no parent span ID (or whose parent is not in the current trace) and marks it as the transaction root.
2. **Transaction attributes**: All spans in the transaction trace receive the following attributes:
    - `cgx.transaction`: Set to the name of the transaction root span
    - `cgx.transaction.root`: Set to `true` for the root span only

#### Configuration

**Note**: The transactions feature requires the `groupbytrace` processor to be configured before the `coralogix` processor in your pipeline to work properly. This ensures that all spans from the same trace are processed together.

```yaml
config:
  processors:
    groupbytrace:
      wait_duration: 5s
      num_traces: 1000
    coralogix:
      transactions:
        enabled: true
  service:
    pipelines:
      traces:
        processors: 
          - groupbytrace
          - coralogix
```
