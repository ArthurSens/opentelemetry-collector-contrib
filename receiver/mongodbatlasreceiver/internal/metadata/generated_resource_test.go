// Code generated by mdatagen. DO NOT EDIT.

package metadata

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResourceBuilder(t *testing.T) {
	for _, tt := range []string{"default", "all_set", "none_set"} {
		t.Run(tt, func(t *testing.T) {
			cfg := loadResourceAttributesConfig(t, tt)
			rb := NewResourceBuilder(cfg)
			rb.SetMongodbAtlasClusterName("mongodb_atlas.cluster.name-val")
			rb.SetMongodbAtlasDbName("mongodb_atlas.db.name-val")
			rb.SetMongodbAtlasDiskPartition("mongodb_atlas.disk.partition-val")
			rb.SetMongodbAtlasHostName("mongodb_atlas.host.name-val")
			rb.SetMongodbAtlasOrgName("mongodb_atlas.org_name-val")
			rb.SetMongodbAtlasProcessID("mongodb_atlas.process.id-val")
			rb.SetMongodbAtlasProcessPort("mongodb_atlas.process.port-val")
			rb.SetMongodbAtlasProcessTypeName("mongodb_atlas.process.type_name-val")
			rb.SetMongodbAtlasProjectID("mongodb_atlas.project.id-val")
			rb.SetMongodbAtlasProjectName("mongodb_atlas.project.name-val")
			rb.SetMongodbAtlasProviderName("mongodb_atlas.provider.name-val")
			rb.SetMongodbAtlasRegionName("mongodb_atlas.region.name-val")
			rb.SetMongodbAtlasUserAlias("mongodb_atlas.user.alias-val")

			res := rb.Emit()
			assert.Equal(t, 0, rb.Emit().Attributes().Len()) // Second call should return empty Resource

			switch tt {
			case "default":
				assert.Equal(t, 9, res.Attributes().Len())
			case "all_set":
				assert.Equal(t, 13, res.Attributes().Len())
			case "none_set":
				assert.Equal(t, 0, res.Attributes().Len())
				return
			default:
				assert.Failf(t, "unexpected test case: %s", tt)
			}

			val, ok := res.Attributes().Get("mongodb_atlas.cluster.name")
			assert.Equal(t, tt == "all_set", ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.cluster.name-val", val.Str())
			}
			val, ok = res.Attributes().Get("mongodb_atlas.db.name")
			assert.True(t, ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.db.name-val", val.Str())
			}
			val, ok = res.Attributes().Get("mongodb_atlas.disk.partition")
			assert.True(t, ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.disk.partition-val", val.Str())
			}
			val, ok = res.Attributes().Get("mongodb_atlas.host.name")
			assert.True(t, ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.host.name-val", val.Str())
			}
			val, ok = res.Attributes().Get("mongodb_atlas.org_name")
			assert.True(t, ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.org_name-val", val.Str())
			}
			val, ok = res.Attributes().Get("mongodb_atlas.process.id")
			assert.True(t, ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.process.id-val", val.Str())
			}
			val, ok = res.Attributes().Get("mongodb_atlas.process.port")
			assert.True(t, ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.process.port-val", val.Str())
			}
			val, ok = res.Attributes().Get("mongodb_atlas.process.type_name")
			assert.True(t, ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.process.type_name-val", val.Str())
			}
			val, ok = res.Attributes().Get("mongodb_atlas.project.id")
			assert.True(t, ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.project.id-val", val.Str())
			}
			val, ok = res.Attributes().Get("mongodb_atlas.project.name")
			assert.True(t, ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.project.name-val", val.Str())
			}
			val, ok = res.Attributes().Get("mongodb_atlas.provider.name")
			assert.Equal(t, tt == "all_set", ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.provider.name-val", val.Str())
			}
			val, ok = res.Attributes().Get("mongodb_atlas.region.name")
			assert.Equal(t, tt == "all_set", ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.region.name-val", val.Str())
			}
			val, ok = res.Attributes().Get("mongodb_atlas.user.alias")
			assert.Equal(t, tt == "all_set", ok)
			if ok {
				assert.Equal(t, "mongodb_atlas.user.alias-val", val.Str())
			}
		})
	}
}
