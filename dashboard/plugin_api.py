"""Read-only plugin namespace. Hermes supplies auth and profile scoping."""
import importlib.util
from pathlib import Path
import re
import sys
from fastapi import APIRouter, HTTPException

# Hermes loads API files as standalone modules. Give only our own bundled
# package a namespace; do not alter sys.path or import an installed namesake.
PACKAGE = '_exfilbar_dashboard_lib'
if PACKAGE not in sys.modules:
    root = Path(__file__).resolve().parents[1] / 'exfilbar'
    spec = importlib.util.spec_from_file_location(PACKAGE, root / '__init__.py', submodule_search_locations=[str(root)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE] = module
    spec.loader.exec_module(module)
from _exfilbar_dashboard_lib.ledger import Ledger

router = APIRouter()


@router.get('/feed')
def feed(session_id: str = '', key: str = ''):
    if len(session_id) > 4096 or (key and not re.fullmatch('[0-9a-f]{64}', key)) or (key and session_id):
        raise HTTPException(status_code=400, detail='Invalid session selector')
    try:
        return Ledger().read(key or session_id, hashed=bool(key))
    except Exception:
        raise HTTPException(status_code=503, detail='Feed temporarily unavailable. Retry shortly.') from None


@router.get('/routes')
def routes():
    try:
        return Ledger().routes()
    except Exception:
        raise HTTPException(status_code=503, detail='Routes temporarily unavailable. Retry shortly.') from None


@router.get('/sessions')
def sessions():
    try:
        return {'sessions': Ledger().sessions()}
    except Exception:
        raise HTTPException(status_code=503, detail='Feed temporarily unavailable. Retry shortly.') from None
