module github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kafkametricsreceiver

go 1.23.0

require (
	github.com/IBM/sarama v1.45.1
	github.com/google/go-cmp v0.7.0
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka v0.123.0
	github.com/stretchr/testify v1.10.0
	go.opentelemetry.io/collector/component v1.29.1-0.20250411074447-4fb7c24ebecc
	go.opentelemetry.io/collector/component/componenttest v0.123.1-0.20250411074447-4fb7c24ebecc
	go.opentelemetry.io/collector/confmap v1.29.1-0.20250411074447-4fb7c24ebecc
	go.opentelemetry.io/collector/consumer v1.29.1-0.20250411074447-4fb7c24ebecc
	go.opentelemetry.io/collector/consumer/consumertest v0.123.1-0.20250411074447-4fb7c24ebecc
	go.opentelemetry.io/collector/filter v0.123.1-0.20250411074447-4fb7c24ebecc
	go.opentelemetry.io/collector/pdata v1.29.1-0.20250411074447-4fb7c24ebecc
	go.opentelemetry.io/collector/receiver v1.29.1-0.20250411074447-4fb7c24ebecc
	go.opentelemetry.io/collector/receiver/receivertest v0.123.1-0.20250411074447-4fb7c24ebecc
	go.opentelemetry.io/collector/scraper v0.123.1-0.20250411074447-4fb7c24ebecc
	go.opentelemetry.io/collector/scraper/scraperhelper v0.123.1-0.20250411074447-4fb7c24ebecc
	go.uber.org/goleak v1.3.0
	go.uber.org/multierr v1.11.0
	go.uber.org/zap v1.27.0
)

require (
	github.com/aws/aws-msk-iam-sasl-signer-go v1.0.1 // indirect
	github.com/aws/aws-sdk-go-v2 v1.36.3 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.28.2 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.66 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.30.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.18 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/eapache/go-resiliency v1.7.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20230731223053-c322873962e3 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/knadh/koanf/maps v0.1.2 // indirect
	github.com/knadh/koanf/providers/confmap v0.1.0 // indirect
	github.com/knadh/koanf/v2 v2.1.2 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/collector/config/configopaque v1.29.1-0.20250411074447-4fb7c24ebecc // indirect
	go.opentelemetry.io/collector/config/configtls v1.29.1-0.20250411074447-4fb7c24ebecc // indirect
	go.opentelemetry.io/collector/consumer/consumererror v0.123.1-0.20250411074447-4fb7c24ebecc // indirect
	go.opentelemetry.io/collector/consumer/xconsumer v0.123.1-0.20250411074447-4fb7c24ebecc // indirect
	go.opentelemetry.io/collector/featuregate v1.29.1-0.20250411074447-4fb7c24ebecc // indirect
	go.opentelemetry.io/collector/internal/telemetry v0.123.1-0.20250411074447-4fb7c24ebecc // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.123.1-0.20250411074447-4fb7c24ebecc // indirect
	go.opentelemetry.io/collector/pipeline v0.123.1-0.20250411074447-4fb7c24ebecc // indirect
	go.opentelemetry.io/collector/receiver/receiverhelper v0.123.1-0.20250411074447-4fb7c24ebecc // indirect
	go.opentelemetry.io/collector/receiver/xreceiver v0.123.1-0.20250411074447-4fb7c24ebecc // indirect
	go.opentelemetry.io/contrib/bridges/otelzap v0.10.0 // indirect
	go.opentelemetry.io/otel v1.35.0 // indirect
	go.opentelemetry.io/otel/log v0.11.0 // indirect
	go.opentelemetry.io/otel/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/sdk v1.35.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/trace v1.35.0 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/net v0.37.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f // indirect
	google.golang.org/grpc v1.71.1 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka => ../../internal/kafka

// see https://github.com/distribution/distribution/issues/3590
exclude github.com/docker/distribution v2.8.0+incompatible

retract (
	v0.76.2
	v0.76.1
	v0.65.0
)
