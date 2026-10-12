"""Super-admin control of the request rate-limit policy (docs/context/architecture/rate-limit.md)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..application.ratelimit import admin as rl_admin
from ..application.ratelimit import config_state
from ..domain.identity.access import require_superadmin
from ..infra.db import get_admin_session

router = APIRouter()


class ConfigWrite(BaseModel):
    config: dict
    note: str = Field(min_length=1, max_length=500)
    enforce_approval: str | None = Field(default=None, max_length=500)
    # The version this write was based on; a different current version is a 409, not a lost update.
    base_version: int | None = None


class RevertIn(BaseModel):
    note: str = Field(default="", max_length=500)


def _process_view() -> dict:
    state = config_state.current()
    return {"version": state.version, "source": state.source, "fallback": state.fallback,
            "mode": state.config.mode}


@router.get("/admin/rate-limit/config", include_in_schema=False)
async def admin_rate_limit_config(
    _: str = Depends(require_superadmin), db: AsyncSession = Depends(get_admin_session),
) -> dict:
    rows = await rl_admin.history(db)
    return {"current": rows[0] if rows else None, "history": rows, "this_process": _process_view()}


@router.put("/admin/rate-limit/config", include_in_schema=False)
async def admin_rate_limit_config_write(
    body: ConfigWrite, principal: str = Depends(require_superadmin),
    db: AsyncSession = Depends(get_admin_session),
) -> dict:
    try:
        return await rl_admin.write(db, body.config, actor=principal, note=body.note,
                                    enforce_approval=body.enforce_approval,
                                    base_version=body.base_version)
    except config_state.InvalidConfig as exc:
        raise HTTPException(status_code=422, detail={"error": "invalid_config", "errors": exc.errors})
    except rl_admin.VersionConflict as exc:
        raise HTTPException(status_code=409, detail={"error": "version_conflict",
                                                     "current_version": exc.current})


@router.post("/admin/rate-limit/config/revert-to-shadow", include_in_schema=False)
async def admin_rate_limit_revert_to_shadow(
    body: RevertIn | None = None, principal: str = Depends(require_superadmin),
    db: AsyncSession = Depends(get_admin_session),
) -> dict:
    return await rl_admin.revert_to_shadow(db, actor=principal, note=body.note if body else "")


@router.post("/admin/rate-limit/config/republish", include_in_schema=False)
async def admin_rate_limit_republish(
    principal: str = Depends(require_superadmin), db: AsyncSession = Depends(get_admin_session),
) -> dict:
    try:
        return await rl_admin.republish(db, actor=principal)
    except rl_admin.NothingToPublish:
        raise HTTPException(status_code=404, detail="no rate-limit config has been written")
