"""ML model routes: training endpoint."""

from fastapi import APIRouter, Depends
from ..models.db_models import User
from .auth import require_role

router = APIRouter(prefix="/model", tags=["model"])


@router.post("/train", status_code=202)
async def train_model(
    _admin: User = Depends(require_role("admin")),
):
    """Retrain the ML model on accumulated scan data."""
    from ..services.ml_predictor import retrain_model
    metrics = await retrain_model()
    return {"message": "Model retrained", "metrics": metrics}
