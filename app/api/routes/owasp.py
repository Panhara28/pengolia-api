from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.database import get_db
from app.core.exceptions import NotFoundError
from app.models.finding import Finding
from app.models.owasp import OWASPCategory
from app.models.user import User
from app.schemas.common import Page, PageParams, build_page, paginate
from app.schemas.finding import FindingRead
from app.schemas.owasp import OWASPCategoryRead, OWASPCoverageItem

router = APIRouter(prefix="/owasp", tags=["OWASP"])


@router.get("/categories", response_model=list[OWASPCategoryRead])
def list_categories(db: Session = Depends(get_db), _: User = Depends(get_current_active_user)):
    return db.execute(select(OWASPCategory).order_by(OWASPCategory.code)).scalars().all()


@router.get("/coverage", response_model=list[OWASPCoverageItem])
def get_coverage(db: Session = Depends(get_db), _: User = Depends(get_current_active_user)):
    categories = db.execute(select(OWASPCategory).order_by(OWASPCategory.code)).scalars().all()
    counts = dict(
        db.execute(
            select(Finding.owasp_category, func.count(Finding.id)).group_by(Finding.owasp_category)
        ).all()
    )
    return [
        OWASPCoverageItem(
            code=cat.code,
            name=cat.name,
            coverage_status=cat.coverage_status,
            finding_count=counts.get(cat.code, 0),
        )
        for cat in categories
    ]


@router.get("/categories/{code}/findings", response_model=Page[FindingRead])
def get_category_findings(
    code: str,
    params: PageParams = Depends(),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    category = db.execute(select(OWASPCategory).where(OWASPCategory.code == code)).scalar_one_or_none()
    if not category:
        raise NotFoundError("OWASP category")

    stmt = select(Finding).where(Finding.owasp_category == code).order_by(Finding.first_seen.desc())
    items, total = paginate(db, stmt, params)
    return build_page(items, total, params)
