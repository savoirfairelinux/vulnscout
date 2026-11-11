# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import copy
import json
import os

import pytest

from src.helpers import context_draft as cd
from src.helpers.stride_model import StrideValidationError


def comp(cid, name, description=""):
    return {"id": cid, "name": name, "description": description, "trust_zone": ""}


def threat(tid, targets, description="t"):
    return {"id": tid, "category": "spoofing", "description": description, "target_ids": targets}


def model(components=(), threats=(), scope="Gateway", **texts):
    return {
        "variant_description": texts.get("variant_description"),
        "environment": texts.get("environment"),
        "other_info": texts.get("other_info"),
        "system": {"scope": scope, "actors": None, "entry_points": None, "trust_boundaries": None},
        "stride": {"components": list(components), "interactions": [], "threats": list(threats), "risks": []},
    }


BASE = model([comp("C1", "Web UI")], [threat("T1", ["C1"])], environment="Lab")


class TestNormalizeValues:

    def test_keeps_empty_text_distinct_from_null(self):
        values = cd.normalize_values({**BASE, "environment": "", "other_info": None})
        assert values["environment"] == "" and values["other_info"] is None
        assert values["system"]["actors"] is None
        assert values["stride"]["components"] == [comp("C1", "Web UI")]

    def test_rejects_non_string_text_and_invalid_rows(self):
        with pytest.raises(StrideValidationError) as exc:
            cd.normalize_values({**BASE, "environment": 3,
                                 "stride": {**BASE["stride"], "threats": [threat("T1", ["C9"])]}})
        assert exc.value.fields["environment"] == "must be a string"
        assert "threats[0].target_ids" in exc.value.fields

    def test_rejects_non_object(self):
        with pytest.raises(StrideValidationError):
            cd.normalize_values([])


class TestStorage:

    def test_write_read_delete_round_trip(self, tmp_path):
        directory = str(tmp_path / "ctx")
        cd.write_draft(directory, {"source": "a.pdf", "values": {}, "base_values": {}})
        assert cd.read_draft(directory)["source"] == "a.pdf"
        os.makedirs(os.path.join(directory, cd.IMPORT_DIR))
        with open(os.path.join(directory, cd.IMPORT_DIR, "a.pdf"), "wb") as handle:
            handle.write(b"x")
        assert cd.import_source_path(directory).endswith(os.path.join(cd.IMPORT_DIR, "a.pdf"))
        cd.delete_draft(directory)
        assert cd.read_draft(directory) is None and cd.import_source_path(directory) is None
        assert sorted(os.listdir(directory)) == []
        cd.delete_draft(directory)  # idempotent

    @pytest.mark.parametrize("content", ["{not json", json.dumps({"values": []}), json.dumps([1])])
    def test_corrupt_draft_is_removed(self, tmp_path, content):
        (tmp_path / cd.DRAFT_NAME).write_text(content)
        assert cd.read_draft(str(tmp_path)) is None
        assert not (tmp_path / cd.DRAFT_NAME).exists()

    def test_lock_is_per_variant(self):
        assert cd.lock_for("a") is cd.lock_for("a") and cd.lock_for("a") is not cd.lock_for("b")

    def test_saved_values_of_a_missing_context(self):
        values = cd.saved_values(None)
        assert values["environment"] is None and values["stride"]["components"] == []


class TestRebase:

    def test_saved_revision_without_model_change_keeps_the_draft(self):
        draft = model([comp("C1", "Web UI"), comp("C2", "Browser")], [threat("T1", ["C1", "C2"])])
        values, conflicts, renumbered = cd.rebase(BASE, copy.deepcopy(BASE), draft)
        assert conflicts == [] and renumbered == {}
        assert values["stride"] == cd.normalize_values(draft)["stride"]
        assert values["environment"] is None  # unchanged text stays "keep saved"

    def test_disjoint_edits_merge(self):
        saved = copy.deepcopy(BASE)
        saved["system"]["actors"] = "Admins"
        saved["stride"]["components"].append(comp("C2", "Cloud"))
        draft = copy.deepcopy(BASE)
        draft["environment"] = "Field"
        draft["stride"]["components"][0] = comp("C1", "Web UI", "lighttpd")
        values, conflicts, _ = cd.rebase(BASE, saved, draft)
        assert conflicts == []
        assert values["environment"] == "Field" and values["system"]["actors"] == "Admins"
        assert values["stride"]["components"] == [comp("C1", "Web UI", "lighttpd"), comp("C2", "Cloud")]

    def test_same_edit_on_both_sides_is_kept(self):
        edited = copy.deepcopy(BASE)
        edited["stride"]["components"][0] = comp("C1", "Web UI", "same")
        values, conflicts, _ = cd.rebase(BASE, edited, copy.deepcopy(edited))
        assert conflicts == [] and values["stride"]["components"] == [comp("C1", "Web UI", "same")]

    def test_changed_in_both_is_a_conflict(self):
        saved = copy.deepcopy(BASE)
        saved["stride"]["components"][0] = comp("C1", "Web UI", "mine")
        saved["system"]["scope"] = "Saved scope"
        draft = copy.deepcopy(BASE)
        draft["stride"]["components"][0] = comp("C1", "Web UI", "ai")
        draft["system"]["scope"] = "AI scope"
        values, conflicts, _ = cd.rebase(BASE, saved, draft)
        assert values is None
        assert {"path": "system.scope", "reason": "changed in both"} in conflicts
        assert {"path": "components[C1]", "reason": "changed in both"} in conflicts

    def test_changed_versus_deleted_is_a_conflict(self):
        saved = copy.deepcopy(BASE)
        saved["stride"]["threats"] = []
        draft = copy.deepcopy(BASE)
        draft["stride"]["threats"][0] = threat("T1", ["C1"], "ai")
        _, conflicts, _ = cd.rebase(BASE, saved, draft)
        assert conflicts == [{"path": "threats[T1]", "reason": "changed in draft, deleted since"}]

        saved = copy.deepcopy(BASE)
        saved["stride"]["threats"][0] = threat("T1", ["C1"], "mine")
        draft = copy.deepcopy(BASE)
        draft["stride"]["threats"] = []
        _, conflicts, _ = cd.rebase(BASE, saved, draft)
        assert conflicts == [{"path": "threats[T1]", "reason": "deleted in draft, changed since"}]

    def test_colliding_new_ids_are_renumbered_with_their_references(self):
        saved = copy.deepcopy(BASE)
        saved["stride"]["components"].append(comp("C2", "Cloud"))
        draft = copy.deepcopy(BASE)
        draft["stride"]["components"].append(comp("C2", "Updater"))
        draft["stride"]["threats"].append(threat("T2", ["C2"]))
        values, conflicts, renumbered = cd.rebase(BASE, saved, draft)
        assert conflicts == [] and renumbered == {"C2": "C3"}
        assert [c["name"] for c in values["stride"]["components"]] == ["Web UI", "Cloud", "Updater"]
        assert values["stride"]["threats"][1]["target_ids"] == ["C3"]

    def test_dangling_reference_is_a_conflict_with_a_row_path(self):
        base = model([comp("C1", "Web UI"), comp("C2", "Browser")], [threat("T1", ["C1"])])
        saved = copy.deepcopy(base)
        saved["stride"]["components"].pop()
        draft = copy.deepcopy(base)
        draft["stride"]["threats"].append(threat("T2", ["C2"]))
        values, conflicts, _ = cd.rebase(base, saved, draft)
        assert values is None
        assert conflicts == [{"path": "threats[T2].target_ids", "reason": "references an unknown id"}]

    def test_empty_text_clears_and_null_keeps(self):
        draft = {**copy.deepcopy(BASE), "environment": "", "other_info": None}
        saved = {**copy.deepcopy(BASE), "other_info": "Saved"}
        values, conflicts, _ = cd.rebase(BASE, saved, draft)
        assert conflicts == []
        assert values["environment"] == "" and values["other_info"] is None

    def test_text_changed_in_both_is_a_conflict(self):
        saved = {**copy.deepcopy(BASE), "environment": "Mine"}
        draft = {**copy.deepcopy(BASE), "environment": "AI"}
        _, conflicts, _ = cd.rebase(BASE, saved, draft)
        assert conflicts == [{"path": "environment", "reason": "changed in both"}]
