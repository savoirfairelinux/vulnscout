"""NVD update helper — applies NVD API details to a Vulnerability record."""

import datetime

from ..models import Metrics


def apply_cvss_update(rec, details: dict, db) -> None:
    """Upsert the CVSS Metrics row for *rec* from NVD *details* (in-place, no commit).

    *db* must be the SQLAlchemy extension instance (passed in to keep this module
    free of Flask extension imports at load time).
    """
    base_score = details.get("base_score")
    cvss_version = details.get("cvss_version")
    cvss_vector = details.get("cvss_vector")
    if base_score is None or cvss_version is None:
        return
    existing = db.session.execute(
        db.select(Metrics).where(
            Metrics.vulnerability_id == rec.id,
            Metrics.version == cvss_version,
            Metrics.variant_id.is_(None),
        )
    ).scalars().first()
    if existing is not None:
        if float(existing.score or 0) != float(base_score) or existing.vector != cvss_vector:
            existing.score = base_score
            existing.vector = cvss_vector or existing.vector
    else:
        db.session.add(Metrics(
            vulnerability_id=rec.id,
            version=cvss_version,
            score=base_score,
            vector=cvss_vector or "",
            author="nvd",
        ))


def apply_nvd_update(vuln_record, details: dict, now: datetime.datetime) -> bool:
    """Compare NVD *details* against *vuln_record* and update in place if different.

    Returns True if any field changed, False if nothing differed.
    Always sets nvd_fetched_at regardless of whether any field changed.
    Sets nvd_data_updated_at only when at least one field changed.
    None values in *details* are treated as "no data" and never overwrite.
    """
    update_kwargs: dict = {}

    fields = [
        ("description", "description"),
        ("status", "status"),
        ("attack_vector", "attack_vector"),
        ("links", "links"),
        ("weaknesses", "weaknesses"),
        ("cpes", "cpes"),
        ("publish_date", "publish_date"),
        ("nvd_last_modified", "nvd_last_modified"),
    ]
    for detail_key, model_attr in fields:
        new_val = details.get(detail_key)
        if new_val is not None and new_val != getattr(vuln_record, model_attr):
            update_kwargs[model_attr] = new_val

    if not update_kwargs:
        vuln_record.update_record(nvd_fetched_at=now, commit=False)
        return False

    update_kwargs["nvd_fetched_at"] = now
    update_kwargs["nvd_data_updated_at"] = now
    update_kwargs["commit"] = False
    vuln_record.update_record(**update_kwargs)
    return True
