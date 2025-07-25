INSERT INTO "%s"."%s" (
    ResourceAttributes,
    ResourceSchemaUrl,
    ScopeName,
    ScopeVersion,
    ScopeAttributes,
    ScopeDroppedAttrCount,
    ScopeSchemaUrl,
    ServiceName,
    MetricName,
    MetricDescription,
    MetricUnit,
    Attributes,
    StartTimeUnix,
    TimeUnix,
    Count,
    Sum,
    BucketCounts,
    ExplicitBounds,
    Exemplars.FilteredAttributes,
    Exemplars.TimeUnix,
    Exemplars.Value,
    Exemplars.SpanId,
    Exemplars.TraceId,
    Flags,
    Min,
    Max,
    AggregationTemporality) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
