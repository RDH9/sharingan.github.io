
from enum import Enum
from typing import List
from . import database
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

class Status(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    NONE = "none"

class Investigation(database.Base):
    __tablename__ = "investigation"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    target: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    inv: Mapped[List["Finding"]] = relationship(back_populates="find")


class Finding(database.Base):
    __tablename__ = "finding"
    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigation.id"))
    data: Mapped[str] = mapped_column(Text)
    confidence: Mapped[Status] = mapped_column(SQLEnum(Status), default=Status.NONE)
    module_source: Mapped[str] = mapped_column(String(100))
    data_type: Mapped[str] = mapped_column(String(50))
    source: Mapped[str] = mapped_column(String(500))
    find: Mapped["Investigation"] = relationship(back_populates="inv")



