-- SENTINEL AI — Auto-generated schema
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Alembic version tracking table
CREATE TABLE IF NOT EXISTS alembic_version (
    version_num VARCHAR(32) NOT NULL,
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

CREATE TABLE IF NOT EXISTS alerts_dlq (
	id VARCHAR(36) NOT NULL, 
	scan_id VARCHAR(36), 
	alert_type VARCHAR(50) NOT NULL, 
	payload JSON NOT NULL, 
	error_message TEXT, 
	retry_count INTEGER NOT NULL, 
	last_attempt_at TIMESTAMP WITH TIME ZONE, 
	status VARCHAR(20) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE, 
	updated_at TIMESTAMP WITH TIME ZONE, 
	org_id VARCHAR(36), 
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS assets (
	id VARCHAR(36) NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	asset_type VARCHAR(50) NOT NULL, 
	target VARCHAR(500) NOT NULL, 
	environment VARCHAR(50) NOT NULL, 
	criticality VARCHAR(20) NOT NULL, 
	os_info VARCHAR(200), 
	tags JSON NOT NULL, 
	is_active BOOLEAN NOT NULL, 
	last_scan_at TIMESTAMP WITH TIME ZONE, 
	risk_score FLOAT NOT NULL, 
	location VARCHAR(200), 
	created_at TIMESTAMP WITH TIME ZONE, 
	updated_at TIMESTAMP WITH TIME ZONE, 
	org_id VARCHAR(36), 
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS attack_paths (
	id VARCHAR(36) NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	description TEXT, 
	severity VARCHAR(20) NOT NULL, 
	risk_score FLOAT NOT NULL, 
	chain_steps JSON NOT NULL, 
	entry_point VARCHAR(500), 
	final_impact VARCHAR(500), 
	affected_assets JSON NOT NULL, 
	related_vulns JSON NOT NULL, 
	ai_analysis TEXT, 
	mitigation_steps JSON NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE, 
	updated_at TIMESTAMP WITH TIME ZONE, 
	org_id VARCHAR(36), 
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS kafka_dlq (
	id VARCHAR(36) NOT NULL, 
	topic VARCHAR(255) NOT NULL, 
	message_key VARCHAR(255), 
	payload JSON NOT NULL, 
	error TEXT, 
	retry_count INTEGER NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE, 
	org_id VARCHAR(36), 
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS organizations (
	id VARCHAR(36) NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	slug VARCHAR(100) NOT NULL, 
	plan VARCHAR(50) NOT NULL, 
	is_active BOOLEAN NOT NULL, 
	max_scans_per_day INTEGER NOT NULL, 
	max_assets INTEGER NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE, 
	updated_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (slug)
);

CREATE TABLE IF NOT EXISTS prediction_logs (
	id VARCHAR(36) NOT NULL, 
	model_version VARCHAR(100) NOT NULL, 
	model_hash VARCHAR(100), 
	input_features JSON NOT NULL, 
	output_score FLOAT NOT NULL, 
	confidence FLOAT NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE, 
	updated_at TIMESTAMP WITH TIME ZONE, 
	org_id VARCHAR(36), 
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
	id VARCHAR(36) NOT NULL, 
	title VARCHAR(500) NOT NULL, 
	description TEXT, 
	severity VARCHAR(20) NOT NULL, 
	cvss_score FLOAT, 
	cve_id VARCHAR(50), 
	cwe_id VARCHAR(50), 
	risk_score FLOAT NOT NULL, 
	exploitability FLOAT NOT NULL, 
	asset_criticality FLOAT NOT NULL, 
	exposure_level FLOAT NOT NULL, 
	affected_assets JSON NOT NULL, 
	related_findings JSON NOT NULL, 
	remediation TEXT, 
	ai_summary TEXT, 
	first_seen TIMESTAMP WITH TIME ZONE, 
	last_seen TIMESTAMP WITH TIME ZONE, 
	status VARCHAR(20) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE, 
	updated_at TIMESTAMP WITH TIME ZONE, 
	org_id VARCHAR(36), 
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS users (
	id VARCHAR(36) NOT NULL, 
	email VARCHAR(255) NOT NULL, 
	username VARCHAR(100) NOT NULL, 
	hashed_password VARCHAR(255) NOT NULL, 
	full_name VARCHAR(255), 
	role VARCHAR(20) NOT NULL, 
	is_active BOOLEAN NOT NULL, 
	last_login TIMESTAMP WITH TIME ZONE, 
	avatar_url VARCHAR(500), 
	org_id VARCHAR(36) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE, 
	updated_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (username), 
	FOREIGN KEY(org_id) REFERENCES organizations (id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
	id VARCHAR(36) NOT NULL, 
	user_id VARCHAR(36), 
	org_id VARCHAR(36) NOT NULL, 
	action VARCHAR(100) NOT NULL, 
	resource_type VARCHAR(50), 
	resource_id VARCHAR(36), 
	details VARCHAR(2000), 
	ip_address VARCHAR(45), 
	created_at TIMESTAMP WITH TIME ZONE, 
	updated_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id), 
	FOREIGN KEY(org_id) REFERENCES organizations (id)
);

CREATE TABLE IF NOT EXISTS scans (
	id VARCHAR(36) NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	scan_type VARCHAR(50) NOT NULL, 
	mode VARCHAR(20) NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	progress INTEGER NOT NULL, 
	target_id VARCHAR(36), 
	target_raw VARCHAR(500), 
	initiated_by VARCHAR(36), 
	tools_used JSON NOT NULL, 
	config JSON NOT NULL, 
	started_at TIMESTAMP WITH TIME ZONE, 
	completed_at TIMESTAMP WITH TIME ZONE, 
	total_findings INTEGER NOT NULL, 
	critical_count INTEGER NOT NULL, 
	high_count INTEGER NOT NULL, 
	medium_count INTEGER NOT NULL, 
	low_count INTEGER NOT NULL, 
	error_message TEXT, 
	schedule_cron VARCHAR(100), 
	is_recurring BOOLEAN NOT NULL, 
	security_score FLOAT, 
	risk_grade VARCHAR(20), 
	input_type VARCHAR(30), 
	drift_summary JSON, 
	report_s3_key VARCHAR(500), 
	created_at TIMESTAMP WITH TIME ZONE, 
	updated_at TIMESTAMP WITH TIME ZONE, 
	org_id VARCHAR(36), 
	PRIMARY KEY (id), 
	FOREIGN KEY(target_id) REFERENCES assets (id), 
	FOREIGN KEY(initiated_by) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS findings (
	id VARCHAR(36) NOT NULL, 
	scan_id VARCHAR(36) NOT NULL, 
	asset_id VARCHAR(36), 
	title VARCHAR(500) NOT NULL, 
	description TEXT, 
	severity VARCHAR(20) NOT NULL, 
	cvss_score FLOAT, 
	cvss_vector VARCHAR(200), 
	cve_id VARCHAR(50), 
	cwe_id VARCHAR(50), 
	tool_name VARCHAR(50) NOT NULL, 
	tool_output JSON NOT NULL, 
	affected_component VARCHAR(500), 
	affected_url VARCHAR(1000), 
	remediation TEXT, 
	"references" JSON NOT NULL, 
	is_false_positive BOOLEAN NOT NULL, 
	is_duplicate BOOLEAN NOT NULL, 
	duplicate_of VARCHAR(36), 
	ai_risk_score FLOAT, 
	ai_analysis JSON, 
	exploit_available BOOLEAN NOT NULL, 
	exploit_details TEXT, 
	created_at TIMESTAMP WITH TIME ZONE, 
	updated_at TIMESTAMP WITH TIME ZONE, 
	org_id VARCHAR(36), 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id), 
	FOREIGN KEY(asset_id) REFERENCES assets (id)
);

CREATE TABLE IF NOT EXISTS ai_feedback (
	id VARCHAR(36) NOT NULL, 
	finding_id VARCHAR(36) NOT NULL, 
	user_id VARCHAR(36), 
	predicted_is_fp BOOLEAN, 
	actual_is_fp BOOLEAN NOT NULL, 
	predicted_risk_score FLOAT, 
	actual_risk_score FLOAT, 
	analyst_notes TEXT, 
	retrained BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE, 
	updated_at TIMESTAMP WITH TIME ZONE, 
	org_id VARCHAR(36), 
	PRIMARY KEY (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);

INSERT INTO alembic_version (version_num) VALUES ('initial_manual') ON CONFLICT DO NOTHING;