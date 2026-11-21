# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
import typing
from datetime import datetime, timezone

from ..extensions import db, Base
from ..helpers.datetime_utils import ensure_utc_iso
from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, event, insert
from sqlalchemy.orm import Mapped, mapped_column, relationship

if typing.TYPE_CHECKING:
    from .variant import Variant

MOUNT_FILE_ID_PREFIX = "mount:"


class HostMount(Base):
    """A named host folder attached read-only to a variant through the host folder helper.

    The backend records attachments; the host-side helper verifies the host operator's
    approval for each folder before serving its content.
    """

    __tablename__ = "variant_host_mounts"
    __table_args__ = (UniqueConstraint("variant_id", "alias", name="uq_variant_host_mount_alias"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    variant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("variants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    alias: Mapped[str] = mapped_column(String(32), nullable=False)
    host_path: Mapped[str] = mapped_column(Text, nullable=False)
    approval_proof: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    variant: Mapped["Variant"] = relationship(back_populates="host_mounts")

    @property
    def file_id(self) -> str:
        return f"{MOUNT_FILE_ID_PREFIX}{self.alias}"

    def to_dict(self) -> dict:
        return {
            "attachment_id": str(self.id),
            "alias": self.alias,
            "file_id": self.file_id,
            "host_path": self.host_path,
            "created_at": ensure_utc_iso(self.created_at),
        }

    @staticmethod
    def get_by_variant(variant_id: uuid.UUID) -> list["HostMount"]:
        return list(db.session.execute(
            db.select(HostMount).where(HostMount.variant_id == variant_id).order_by(HostMount.alias)
        ).scalars().all())

    @staticmethod
    def get(variant_id: uuid.UUID, alias: str) -> "HostMount | None":
        return db.session.execute(
            db.select(HostMount).where(HostMount.variant_id == variant_id, HostMount.alias == alias)
        ).scalar_one_or_none()


class HostMountDetach(Base):
    """Helper cleanup survives both backend restarts and deletion of the parent variant."""

    __tablename__ = "host_mount_detach_outbox"

    attachment_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    variant_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    alias: Mapped[str] = mapped_column(String(32), nullable=False)


@event.listens_for(HostMount, "after_delete")
def _queue_detach(mapper, connection, mount: HostMount) -> None:
    connection.execute(insert(HostMountDetach).values(
        attachment_id=mount.id, variant_id=mount.variant_id, alias=mount.alias,
    ))
