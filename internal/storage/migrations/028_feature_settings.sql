-- Phase 0.6c: agent feature switches. A monitoring policy may turn features
-- off (object of feature name to false; missing means on), and each device
-- records the features its local administrator locked off.
ALTER TABLE monitoring_policies ADD COLUMN features_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(features_json));
ALTER TABLE devices ADD COLUMN feature_locks_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(feature_locks_json));
