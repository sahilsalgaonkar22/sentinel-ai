-- SENTINEL AI — Bootstrap Seed
-- Idempotent: safe to run multiple times

-- Organisation
INSERT INTO organizations (id, name, slug, plan, is_active, max_scans_per_day, max_assets, created_at, updated_at)
VALUES (
    'aaaaaaaa-0000-4000-8000-000000000001',
    'Sentinel Security',
    'sentinel-security',
    'enterprise',
    TRUE,
    100,
    10000,
    NOW(),
    NOW()
) ON CONFLICT (slug) DO NOTHING;

-- Admin user  (password: Sentinel2024!)
INSERT INTO users (id, email, username, hashed_password, full_name, role, is_active, org_id, created_at, updated_at)
VALUES (
    'bbbbbbbb-0000-4000-8000-000000000001',
    'admin@sentinel.ai',
    'admin',
    '$2b$12$2wPHm3kgR/cDxzwD22u1/e6icqKYh66Me1Zwtj3FdFuNAuXJvPtTW',
    'Sentinel Admin',
    'admin',
    TRUE,
    'aaaaaaaa-0000-4000-8000-000000000001',
    NOW(),
    NOW()
) ON CONFLICT (email) DO NOTHING;

-- Verify
SELECT 'org' AS type, id, name FROM organizations WHERE slug = 'sentinel-security'
UNION ALL
SELECT 'user', id, email FROM users WHERE email = 'admin@sentinel.ai';
