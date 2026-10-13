import os
import platform
import shutil
from pathlib import Path
from typing import Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

APP_VERSION = "0.1.0"
DATA_DIR = Path(os.getenv("NOVAPANEL_DATA_DIR", "./data")).expanduser()


class Capability(BaseModel):
    status: Literal["available", "unavailable", "unknown"]
    detail: str


class HostReport(BaseModel):
    platform: str
    python_version: str
    data_directory: str
    capabilities: dict[str, Capability]


app = FastAPI(
    title="NovaPanel API",
    description="Early development API for NovaPanel.",
    version=APP_VERSION,
)

origins = [
    origin.strip()
    for origin in os.getenv(
        "NOVAPANEL_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Content-Type"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "app": "NovaPanel", "version": APP_VERSION}


@app.get("/api/host", response_model=HostReport)
def host_report() -> HostReport:
    data_dir_writable = DATA_DIR.exists() and os.access(DATA_DIR, os.W_OK)
    if not DATA_DIR.exists():
        data_dir_writable = os.access(DATA_DIR.parent, os.W_OK)

    engine_path = shutil.which("xray")
    return HostReport(
        platform=platform.system() or "unknown",
        python_version=platform.python_version(),
        data_directory=str(DATA_DIR),
        capabilities={
            "persistent_storage": Capability(
                status="available" if data_dir_writable else "unknown",
                detail=(
                    "The configured data path appears writable."
                    if data_dir_writable
                    else "Persistence has not been verified. Configure and test a data volume."
                ),
            ),
            "separate_processes": Capability(
                status="unknown",
                detail="Process supervision has not been tested in this environment.",
            ),
            "xray_binary": Capability(
                status="available" if engine_path else "unknown",
                detail=(
                    f"Found an Xray executable at {engine_path}."
                    if engine_path
                    else "Xray is not detected. NovaPanel does not install or start it yet."
                ),
            ),
            "inbound_tcp_udp": Capability(
                status="unknown",
                detail="Network reachability must be verified with the hosting provider and an external test.",
            ),
        },
    )
