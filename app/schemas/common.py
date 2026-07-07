import math
from typing import Annotated, Generic, Sequence, TypeVar

from fastapi import Query
from pydantic import BaseModel, StringConstraints
from sqlalchemy import Select
from sqlalchemy.orm import Session

T = TypeVar("T")

# A permissive email type: pydantic's EmailStr (via email-validator) rejects
# reserved/special-use TLDs like .local and .internal, which this platform
# uses deliberately for internal/staging/dev addresses and target domains.
AppEmailStr = Annotated[str, StringConstraints(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]


class PageParams:
    def __init__(
        self,
        page: int = Query(1, ge=1),
        page_size: int = Query(20, ge=1, le=200),
        search: str | None = Query(None),
        sort_by: str | None = Query(None),
        sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    ):
        self.page = page
        self.page_size = page_size
        self.search = search
        self.sort_by = sort_by
        self.sort_order = sort_order

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


class Page(BaseModel, Generic[T]):
    items: Sequence[T]
    total: int
    page: int
    page_size: int
    pages: int


def paginate(db: Session, stmt: Select, params: PageParams) -> tuple[list, int]:
    from sqlalchemy import func, select

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = db.execute(count_stmt).scalar_one()
    items = db.execute(stmt.offset(params.offset).limit(params.page_size)).scalars().all()
    return list(items), total


def build_page(items: list, total: int, params: PageParams) -> dict:
    pages = math.ceil(total / params.page_size) if params.page_size else 0
    return {
        "items": items,
        "total": total,
        "page": params.page,
        "page_size": params.page_size,
        "pages": pages,
    }
