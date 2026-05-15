import shutil, socket, sys
sys.path.insert(0, '.')

tools = ['nmap', 'bandit', 'semgrep', 'nikto', 'trivy', 'masscan', 'pip-audit', 'docker']
print('TOOL AVAILABILITY')
for t in tools:
    path = shutil.which(t)
    if path:
        print('  ' + t + ': FOUND ' + path)
    else:
        print('  ' + t + ': NOT FOUND (fallback)')

print('\nPYTHON PACKAGES')
pkgs = ['confluent_kafka', 'fastapi', 'sqlalchemy', 'httpx', 'faiss', 'bandit', 'numpy', 'pandas', 'xgboost', 'reportlab', 'boto3']
for p in pkgs:
    try:
        __import__(p)
        print('  ' + p + ': OK')
    except ImportError:
        print('  ' + p + ': MISSING')

print('\nNETWORK PORTS')
checks = [('localhost', 9092, 'Kafka'), ('localhost', 5432, 'PostgreSQL'), ('localhost', 6379, 'Redis'), ('localhost', 9000, 'MinIO'), ('localhost', 8000, 'API-Gateway'), ('localhost', 9200, 'Elasticsearch'), ('localhost', 3001, 'Grafana'), ('localhost', 9090, 'Prometheus')]
for host, port, name in checks:
    s = socket.socket()
    s.settimeout(1)
    r = s.connect_ex((host, port))
    s.close()
    status = 'OPEN' if r == 0 else 'CLOSED'
    print('  ' + name + ' :' + str(port) + ': ' + status)

print('\nCONFIG')
try:
    from backend.common.config import settings
    print('  EXECUTION_MODE: ' + settings.EXECUTION_MODE)
    print('  MOCK_WORKERS: ' + str(settings.MOCK_WORKERS))
    print('  DB: ' + settings.DATABASE_URL[:50])
    print('  KAFKA: ' + settings.KAFKA_BOOTSTRAP_SERVERS)
    print('  S3: ' + settings.S3_ENDPOINT)
    print('  PENTAGI: ' + str(settings.PENTAGI_ENABLED))
    print('  LLM_KEY: ' + ('SET' if settings.LLM_API_KEY else 'EMPTY'))
    print('  SMTP: ' + settings.SENTINEL_SMTP_HOST[:20] if settings.SENTINEL_SMTP_HOST else '  SMTP: NOT SET')
    print('  SLACK: ' + ('SET' if settings.SENTINEL_SLACK_WEBHOOK else 'NOT SET'))
except Exception as e:
    print('  ERROR: ' + str(e))
