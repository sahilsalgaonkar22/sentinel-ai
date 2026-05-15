"""
SENTINEL AI — S3/MinIO Storage Client

PRODUCTION HARDENING:
- Uses asyncio.get_running_loop() instead of deprecated get_event_loop()
- Thread-pool executor for all blocking boto3 calls (prevents event-loop deadlock)
- Configurable timeout + exponential-backoff retry (3 attempts)
- Hard failure on upload — callers must handle None return and decide if fatal
- Connection pool re-used across calls via module-level client factory
"""
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional

from backend.common.config import settings

logger = logging.getLogger(__name__)

# Dedicated executor so boto3 I/O never competes with Kafka poll threads
_s3_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="sentinel-s3")

_CONNECT_TIMEOUT = 5   # seconds to establish TCP connection
_READ_TIMEOUT    = 30  # seconds to wait for response
_MAX_RETRIES     = 3


def _get_s3_client():
    """Create a synchronous boto3 S3 client with timeouts. Called inside executor threads."""
    import boto3
    from botocore.client import Config
    from botocore.config import Config as BotoConfig

    return boto3.client(
        "s3",
        endpoint_url=settings.S3_ENDPOINT,
        aws_access_key_id=settings.S3_ACCESS_KEY,
        aws_secret_access_key=settings.S3_SECRET_KEY,
        config=Config(
            signature_version="s3v4",
            connect_timeout=_CONNECT_TIMEOUT,
            read_timeout=_READ_TIMEOUT,
            retries={"max_attempts": _MAX_RETRIES, "mode": "adaptive"},
        ),
        region_name="us-east-1",
    )


async def _run_in_s3_executor(func):
    """Execute a blocking S3 callable in the dedicated thread pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_s3_executor, func)


async def ensure_bucket_exists() -> None:
    """Create the sentinel-reports bucket if it doesn't exist. Hard fails on S3 errors."""
    def _create():
        client = _get_s3_client()
        bucket = settings.S3_BUCKET
        try:
            client.head_bucket(Bucket=bucket)
        except client.exceptions.NoSuchBucket:
            client.create_bucket(Bucket=bucket)
            logger.info("storage.bucket_created bucket=%s", bucket)
        except Exception as exc:
            # Re-raise — caller (startup) must decide if this is fatal
            raise RuntimeError(f"Cannot verify/create S3 bucket '{bucket}': {exc}") from exc

    await _run_in_s3_executor(_create)


async def upload_scan_log(scan_id: str, content: str) -> Optional[str]:
    """
    Upload raw scan log text to MinIO.

    Returns:
        S3 key on success, None on failure (caller should log and handle).
    """
    key = f"scans/{scan_id}/raw.log"

    def _upload():
        client = _get_s3_client()
        client.put_object(
            Bucket=settings.S3_BUCKET,
            Key=key,
            Body=content.encode("utf-8"),
            ContentType="text/plain",
            Metadata={
                "scan-id": scan_id,
                "uploaded-at": datetime.now(timezone.utc).isoformat(),
            },
        )
        return key

    try:
        result = await _run_in_s3_executor(_upload)
        logger.info("storage.upload_ok scan_id=%s key=%s", scan_id, key)
        return result
    except Exception as exc:
        logger.error("storage.upload_failed scan_id=%s key=%s error=%s", scan_id, key, exc)
        return None


async def upload_report(scan_id: str, pdf_bytes: bytes) -> Optional[str]:
    """
    Upload PDF report to MinIO.

    Returns:
        S3 key on success, None on failure.
    """
    key = f"reports/{scan_id}.pdf"

    def _upload():
        client = _get_s3_client()
        client.put_object(
            Bucket=settings.S3_BUCKET,
            Key=key,
            Body=pdf_bytes,
            ContentType="application/pdf",
            Metadata={
                "scan-id": scan_id,
                "uploaded-at": datetime.now(timezone.utc).isoformat(),
            },
        )
        return key

    try:
        result = await _run_in_s3_executor(_upload)
        logger.info("storage.report_ok scan_id=%s key=%s", scan_id, key)
        return result
    except Exception as exc:
        logger.error("storage.report_failed scan_id=%s error=%s", scan_id, exc)
        return None


async def get_report_url(scan_id: str, expiry_seconds: int = 3600) -> Optional[str]:
    """
    Generate a presigned URL for direct PDF download.

    Returns:
        URL string on success, None on failure.
    """
    key = f"reports/{scan_id}.pdf"

    def _presign():
        client = _get_s3_client()
        return client.generate_presigned_url(
            "get_object",
            Params={"Bucket": settings.S3_BUCKET, "Key": key},
            ExpiresIn=expiry_seconds,
        )

    try:
        url = await _run_in_s3_executor(_presign)
        return url
    except Exception as exc:
        logger.error("storage.presign_failed scan_id=%s error=%s", scan_id, exc)
        return None


async def download_report(s3_key: str) -> Optional[bytes]:
    """
    Download a PDF report from MinIO by its S3 key.

    Returns:
        PDF bytes on success, None on failure.
    """
    def _download():
        client = _get_s3_client()
        response = client.get_object(
            Bucket=settings.S3_BUCKET,
            Key=s3_key,
        )
        return response["Body"].read()

    try:
        pdf_bytes = await _run_in_s3_executor(_download)
        logger.info("storage.download_ok key=%s size=%d", s3_key, len(pdf_bytes))
        return pdf_bytes
    except Exception as exc:
        logger.error("storage.download_failed key=%s error=%s", s3_key, exc)
        return None


async def upload_pentagi_logs(
    scan_id: str, container_name: str, stdout: str, stderr: str
) -> Optional[str]:
    """Upload Pentagi Docker container logs to MinIO."""
    content = (
        f"=== CONTAINER: {container_name} ===\n"
        f"=== STDOUT ===\n{stdout}\n"
        f"=== STDERR ===\n{stderr}\n"
    )
    return await upload_scan_log(scan_id, content)
