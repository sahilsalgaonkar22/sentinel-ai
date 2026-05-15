import sys, os
sys.path.insert(0, '.')

print('=== SENTINEL AI CLEANUP VERIFICATION ===')
print()

exists = os.path.exists('workers')
print('STEP 1 - Mock workers/ deleted:', 'FAIL' if exists else 'PASS')

from backend.common.config import settings
print('STEP 2 - MOCK_WORKERS=False:', 'PASS' if not settings.MOCK_WORKERS else 'FAIL - still True')
print('STEP 3 - JWT_SECRET strong:', 'PASS (' + str(len(settings.JWT_SECRET)) + ' chars)' if len(settings.JWT_SECRET) > 32 else 'FAIL')

try:
    import defusedxml
    print('STEP 4 - defusedxml B314 fix: PASS v' + defusedxml.__version__)
except ImportError:
    print('STEP 4 - defusedxml: FAIL - not installed')

with open('backend/services/scan_control/tool_executor.py') as f:
    content = f.read()
ssl_fixed = 'use_verify = url.startswith' in content
xml_fixed = 'defusedxml' in content
print('STEP 5a - SSL verify fix: ' + ('PASS' if ssl_fixed else 'FAIL'))
print('STEP 5b - XML defusedxml: ' + ('PASS' if xml_fixed else 'FAIL'))

with open('backend/gateway/routes/ai.py') as f:
    ai_content = f.read()
apt28_removed = 'APT-28 (Fancy Bear)' not in ai_content
print('STEP 6 - APT-28 demo removed: ' + ('PASS' if apt28_removed else 'FAIL'))

with open('backend/gateway/main.py') as f:
    main_content = f.read()
cors_fixed = 'allow_origins=["*"]' not in main_content
print('STEP 7 - CORS restrict: ' + ('PASS' if cors_fixed else 'FAIL'))

print()
print('=== COMPLETE ===')
