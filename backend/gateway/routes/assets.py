"""
SENTINEL AI — Asset Routes
CRUD for asset inventory management.
All routes query the real DB. No demo fallbacks. No random data.
Empty DB → empty response with descriptive message.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException

logger = logging.getLogger(__name__)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case

from backend.common.database import get_db
from backend.services.scan_control.models import Asset
from backend.schemas.asset import AssetResponse, AssetCreate, AssetListResponse
from backend.gateway.middleware.auth import get_current_user

router = APIRouter()


async def _get_db(user: dict = Depends(get_current_user)):
    async for session in get_db(user):
        yield session


@router.get("/")
async def list_assets(
    page: int = 1, per_page: int = 50,
    db: AsyncSession = Depends(_get_db), user: dict = Depends(get_current_user)
):
    org_id = user["org_id"]
    try:
        total = (await db.execute(
            select(func.count()).select_from(Asset).where(Asset.org_id == org_id)
        )).scalar() or 0
        result = await db.execute(
            select(Asset).where(Asset.org_id == org_id)
            .order_by(Asset.risk_score.desc())
            .offset((page - 1) * per_page).limit(per_page)
        )
        assets = result.scalars().all()
        return {
            "items": [AssetResponse.model_validate(a) for a in assets],
            "total": total,
            "page": page,
            "per_page": per_page,
            "message": "No assets found. Add an asset and run a scan to populate." if total == 0 else None,
        }
    except Exception as e:
        logger.error("assets.list_query_failed error=%s", e)
        return {
            "items": [],
            "total": 0,
            "page": page,
            "per_page": per_page,
            "message": "Database unavailable. Start infrastructure with: docker-compose up -d",
        }


@router.post("/")
async def create_asset(asset_in: AssetCreate, db: AsyncSession = Depends(_get_db), user: dict = Depends(get_current_user)):
    org_id = user["org_id"]
    new_asset = Asset(
        name=asset_in.name,
        asset_type=asset_in.asset_type,
        target=asset_in.target,
        environment=asset_in.environment,
        criticality=asset_in.criticality,
        org_id=org_id
    )
    db.add(new_asset)
    await db.commit()
    await db.refresh(new_asset)
    return new_asset


@router.get("/stats")
async def asset_stats(db: AsyncSession = Depends(_get_db), user: dict = Depends(get_current_user)):
    """Real asset statistics from DB."""
    org_id = user["org_id"]
    try:
        total = (await db.execute(
            select(func.count()).select_from(Asset).where(Asset.org_id == org_id)
        )).scalar() or 0

        # Environment breakdown
        env_rows = (await db.execute(
            select(Asset.environment, func.count().label("cnt"))
            .where(Asset.org_id == org_id)
            .group_by(Asset.environment)
        )).all()
        by_environment = {row.environment or "unknown": row.cnt for row in env_rows}

        # Type breakdown
        type_rows = (await db.execute(
            select(Asset.asset_type, func.count().label("cnt"))
            .where(Asset.org_id == org_id)
            .group_by(Asset.asset_type)
        )).all()
        by_type = {row.asset_type or "unknown": row.cnt for row in type_rows}

        # High-risk count (risk_score > 70)
        high_risk = (await db.execute(
            select(func.count()).select_from(Asset).where(
                Asset.org_id == org_id, Asset.risk_score > 70
            )
        )).scalar() or 0

        # Average risk score
        avg_risk_row = (await db.execute(
            select(func.avg(Asset.risk_score)).where(Asset.org_id == org_id)
        )).scalar()
        avg_risk = round(float(avg_risk_row), 1) if avg_risk_row else 0.0

        return {
            "total": total,
            "by_environment": by_environment,
            "by_type": by_type,
            "high_risk_count": high_risk,
            "avg_risk_score": avg_risk,
        }
    except Exception as e:
        logger.error("assets.stats_query_failed error=%s", e)
        return {
            "total": 0,
            "by_environment": {},
            "by_type": {},
            "high_risk_count": 0,
            "avg_risk_score": 0.0,
        }


@router.get("/stats/summary")
async def asset_stats_summary(db: AsyncSession = Depends(_get_db), user: dict = Depends(get_current_user)):
    """Alias for /stats — the frontend calls /stats/summary."""
    return await asset_stats(db=db, user=user)


@router.get("/{asset_id}")
async def get_asset(asset_id: str, db: AsyncSession = Depends(_get_db), user: dict = Depends(get_current_user)):
    try:
        org_id = user["org_id"]
        asset = await db.get(Asset, asset_id)
        if asset and asset.org_id == org_id:
            return AssetResponse.model_validate(asset)
    except Exception:
        pass
    raise HTTPException(status_code=404, detail="Asset not found")
