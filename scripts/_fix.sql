ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
INSERT INTO users (id,email,username,hashed_password,full_name,role,is_active,org_id,created_at,updated_at) VALUES ('bbbbbbbb-0000-4000-8000-000000000001','admin@sentinel.ai','admin','\\\/cDxzwD22u1/e6icqKYh66Me1Zwtj3FdFuNAuXJvPtTW','Sentinel Admin','admin',TRUE,'aaaaaaaa-0000-4000-8000-000000000001',NOW(),NOW()) ON CONFLICT (email) DO NOTHING;
SELECT 'org'  AS type, id, name  AS val FROM organizations WHERE slug='sentinel-security' UNION ALL SELECT 'user',id,email FROM users WHERE email='admin@sentinel.ai';
