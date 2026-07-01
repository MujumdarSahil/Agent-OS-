"""Packaging API routes — build, sign, verify, install .agentpack files."""
import logging
import os

from fastapi import APIRouter, HTTPException, Request

from agentos.server.models import (
    PackBuildRequest, PackSignRequest, PackVerifyRequest,
    PackVerifyResponse, PackInstallRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/packaging", tags=["packaging"])


def _project(request: Request) -> str:
    return request.app.state.project_path


@router.post("/build")
async def build_pack(body: PackBuildRequest, request: Request):
    from agentos.packaging.pack_format import build_pack
    p = _project(request)
    try:
        out_path = os.path.join(p, body.output_name)
        build_pack(
            project_path=p,
            include={
                "agents": body.include_agents,
                "tools": body.include_tools,
                "crews": body.include_crews,
            },
            output_path=out_path,
        )
        return {"pack_path": out_path, "size_bytes": os.path.getsize(out_path)}
    except Exception as e:
        logger.exception("build_pack failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sign")
async def sign_pack(body: PackSignRequest, request: Request):
    from agentos.packaging.signer import sign_pack
    try:
        sign_pack(body.pack_path, body.private_key_path)
        return {"detail": f"Pack signed: {body.pack_path}"}
    except Exception as e:
        logger.exception("sign_pack failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify", response_model=PackVerifyResponse)
async def verify_pack(body: PackVerifyRequest, request: Request):
    from agentos.packaging.signer import verify_pack, get_signer_fingerprint
    try:
        valid = verify_pack(body.pack_path)
        fingerprint = None
        if valid:
            try:
                fingerprint = get_signer_fingerprint(body.pack_path)
            except Exception:
                pass
        return PackVerifyResponse(
            valid=valid,
            signer_fingerprint=fingerprint,
            detail="Signature valid" if valid else "Signature invalid or pack unsigned",
        )
    except Exception as e:
        logger.exception("verify_pack failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/install")
async def install_pack(body: PackInstallRequest, request: Request):
    from agentos.packaging.pack_format import install_pack
    try:
        result = install_pack(
            pack_path=body.pack_path,
            target_project=body.target_project_path,
            force=body.force,
            license_key=body.license_key,
        )
        return result
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        logger.exception("install_pack failed")
        raise HTTPException(status_code=500, detail=str(e))
