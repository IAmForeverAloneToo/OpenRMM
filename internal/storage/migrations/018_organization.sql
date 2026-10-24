CREATE TABLE organization_state (
 id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL CHECK(revision>0)
);
INSERT INTO organization_state VALUES(1,1);
CREATE TABLE monitoring_policies (
 id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 32),
 name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 80),
 rules_json TEXT NOT NULL CHECK(json_valid(rules_json))
);
CREATE TABLE device_groups (
 id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 32),
 name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 80),
 policy_id TEXT REFERENCES monitoring_policies(id)
);
CREATE TABLE device_organization (
 device_id TEXT PRIMARY KEY REFERENCES devices(id),
 group_id TEXT REFERENCES device_groups(id),
 policy_id TEXT REFERENCES monitoring_policies(id),
 tags_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(tags_json))
);
CREATE INDEX organization_group ON device_organization(group_id);
CREATE INDEX organization_policy ON device_organization(policy_id);
