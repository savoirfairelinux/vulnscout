# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from html.parser import HTMLParser
from html import unescape as html_unescape
from jinja2 import sandbox, FileSystemLoader, ChoiceLoader
import subprocess
import os
import random
import re
import string
from datetime import datetime, timezone
from typing import Any, Callable, List, Optional
from ..models.iso8601_duration import Iso8601Duration
from ..models.sbom_package import SBOMPackage
from ..controllers import (
    ControllersCache,
    PackagesController,
    VulnerabilitiesController,
    AssessmentsController,
    ProjectController,
    VariantController,
    ScanController,
    SBOMDocumentController,
)


class Templates:
    def __init__(self, controllers: ControllersCache):
        self.packagesCtrl: PackagesController = controllers.packages
        self.vulnerabilitiesCtrl: VulnerabilitiesController = controllers.vulnerabilities
        self.assessmentsCtrl: AssessmentsController = controllers.assessments
        self.projectsCtrl: ProjectController | None = controllers.project
        self.variantsCtrl: VariantController | None = controllers.variant
        self.scansCtrl: ScanController | None = controllers.scan
        self.sbomDocumentsCtrl: SBOMDocumentController | None = controllers.sbom_document

        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.internal_loader = FileSystemLoader([
            template_dir,
            "views/templates"
        ])
        self.external_loader = FileSystemLoader([
            "/cache/vulnscout/templates",
            ".vulnscout/templates",
            "templates",
            "/scan/templates"
        ])

        self.env = sandbox.ImmutableSandboxedEnvironment(
            loader=ChoiceLoader([
                self.external_loader,
                self.internal_loader
            ]),
            autoescape=False
        )
        self.env.globals['env'] = TemplatesExtensions.get_env_var
        self.extensions = TemplatesExtensions(self.env)

    def render(self, template_name, **kwargs):
        template = self.env.get_template(template_name)
        kwargs["packages"] = self.packagesCtrl.to_dict()
        kwargs["unfiltered_vulnerabilities"] = self.vulnerabilitiesCtrl.to_dict()
        kwargs["vulnerabilities"] = {}
        # Exclude pending AI-generated assessments from reports — they are not
        # yet reviewed/approved. Their origin becomes "custom" once approved.
        kwargs["unfiltered_assessments"] = {
            aid: a for aid, a in self.assessmentsCtrl.to_dict().items()
            if a.get("origin") != "ai"
        }
        kwargs["assessments"] = {}

        if self.projectsCtrl is not None:
            kwargs["projects"] = {p["id"]: p for p in self.projectsCtrl.serialize_list(self.projectsCtrl.get_all())}
        else:
            kwargs["projects"] = {}
        if self.variantsCtrl is not None:
            kwargs["variants"] = {v["id"]: v for v in self.variantsCtrl.serialize_list(self.variantsCtrl.get_all())}
        else:
            kwargs["variants"] = {}
        if self.scansCtrl is not None:
            kwargs["scans"] = {s["id"]: s for s in self.scansCtrl.serialize_list(self.scansCtrl.get_all())}
        else:
            kwargs["scans"] = {}
        if self.sbomDocumentsCtrl is not None:
            all_docs = self.sbomDocumentsCtrl.serialize_list(self.sbomDocumentsCtrl.get_all())
            kwargs["sbom_documents"] = {d["id"]: d for d in all_docs}
        else:
            kwargs["sbom_documents"] = {}

        filter_date = None
        if "ignore_before" in kwargs and kwargs["ignore_before"] != "1970-01-01T00:00":
            filter_date = datetime.fromisoformat(kwargs["ignore_before"]).astimezone(timezone.utc)
        filter_epss = None
        if "only_epss_greater" in kwargs and kwargs["only_epss_greater"] >= 0.01:
            filter_epss = kwargs["only_epss_greater"] / 100

        if "scan_date" not in kwargs:
            kwargs["scan_date"] = "unknown date"  # don't use actual datetime by default.

        # Group every assessment by its vulnerability id once, up front. This
        # turns the per-vulnerability loop below into a pure in-memory lookup
        # instead of issuing one SELECT per vulnerability (the previous
        # gets_by_vuln() call), which made large reports extremely slow.
        assessments_by_vuln: dict[str, list] = {}
        for assessment in kwargs["unfiltered_assessments"].values():
            assessments_by_vuln.setdefault(assessment["vuln_id"], []).append(assessment)

        for vuln_obj in kwargs["unfiltered_vulnerabilities"].values():
            vuln_assessments = list(assessments_by_vuln.get(vuln_obj['id'], []))

            vuln_assessments = sorted(vuln_assessments, key=lambda x: x["timestamp"], reverse=True)  # type: ignore
            if len(vuln_assessments) >= 1:
                vuln_obj['unfiltered_assessments'] = vuln_assessments
                vuln_obj['assessments'] = []
                if filter_date is not None:
                    for assessment in vuln_assessments:
                        assess_date = datetime.fromisoformat(assessment["timestamp"]).astimezone(timezone.utc)
                        if assess_date >= filter_date:
                            vuln_obj['assessments'].append(assessment)
                else:
                    vuln_obj['assessments'] = vuln_assessments

                vuln_obj['last_assessment'] = vuln_assessments[0]
                vuln_obj['status'] = vuln_assessments[0]['status']

            if len(vuln_obj.get('assessments', [])) > 0:
                try:
                    epss_score = float((vuln_obj.get("epss", {}).get("score")) or 0.0)
                    if (filter_epss is None or epss_score >= filter_epss):
                        kwargs["vulnerabilities"][vuln_obj['id']] = vuln_obj
                except (ValueError, TypeError):
                    pass

        if filter_date is not None:
            for assessment in kwargs["unfiltered_assessments"].values():
                assess_date = datetime.fromisoformat(assessment["timestamp"]).astimezone(timezone.utc)
                if assess_date >= filter_date:
                    kwargs['assessments'][assessment["id"]] = assessment
        else:
            kwargs["assessments"] = kwargs["unfiltered_assessments"]

        scan_by_id = kwargs["scans"]
        doc_by_id = kwargs["sbom_documents"]
        variant_by_id = kwargs["variants"]

        for doc in kwargs["sbom_documents"].values():
            scan = scan_by_id.get(doc["scan_id"])
            doc["variant_id"] = scan["variant_id"] if scan else None

        for doc in kwargs["sbom_documents"].values():
            doc["packages"] = {}
            for sbom_pkg in SBOMPackage.get_by_document(doc["id"]):
                pkg_id = sbom_pkg.package.string_id
                if pkg_id in kwargs["packages"]:
                    doc["packages"][pkg_id] = kwargs["packages"][pkg_id]

        pkg_to_docs: dict = {}
        pkg_to_variants: dict = {}
        for doc in kwargs["sbom_documents"].values():
            for pkg_id in doc["packages"]:
                pkg_to_docs.setdefault(pkg_id, []).append(doc["id"])
                if doc["variant_id"]:
                    pkg_to_variants.setdefault(pkg_id, set()).add(doc["variant_id"])

        for pkg_id, pkg in kwargs["packages"].items():
            pkg["sbom_documents"] = {d: doc_by_id[d] for d in pkg_to_docs.get(pkg_id, []) if d in doc_by_id}
            pkg["variants"] = list(pkg_to_variants.get(pkg_id, set()))
            pkg["vulnerabilities"] = {}

        for vuln in kwargs["vulnerabilities"].values():
            by_variant: dict = {}
            for assessment in vuln.get("assessments", []):
                vid = assessment.get("variant_id")
                if vid:
                    by_variant.setdefault(vid, []).append(assessment)
            vuln["assessments_by_variant"] = by_variant
            vuln["variant_ids"] = list(by_variant.keys())

        vuln_by_pkg: dict = {}
        for vuln_id, vuln in kwargs["vulnerabilities"].items():
            for pkg_id in vuln.get("packages", []):
                vuln_by_pkg.setdefault(pkg_id, {})[vuln_id] = vuln

        for doc in kwargs["sbom_documents"].values():
            doc["vulnerabilities"] = {}
            for pkg_id in doc["packages"]:
                doc["vulnerabilities"].update(vuln_by_pkg.get(pkg_id, {}))

        for pkg_id, pkg in kwargs["packages"].items():
            pkg["vulnerabilities"] = vuln_by_pkg.get(pkg_id, {})

        for scan in kwargs["scans"].values():
            scan["variant"] = variant_by_id.get(scan["variant_id"])
            scan["sbom_documents"] = {
                d_id: d for d_id, d in kwargs["sbom_documents"].items()
                if d["scan_id"] == scan["id"]
            }
            scan["packages"] = {}
            for doc in scan["sbom_documents"].values():
                scan["packages"].update(doc["packages"])

        for variant in kwargs["variants"].values():
            vid = variant["id"]
            variant["scans"] = {s_id: s for s_id, s in kwargs["scans"].items() if s["variant_id"] == vid}
            variant["sbom_documents"] = {
                d_id: d for d_id, d in kwargs["sbom_documents"].items()
                if d.get("variant_id") == vid
            }
            variant["packages"] = {}
            for doc in variant["sbom_documents"].values():
                variant["packages"].update(doc["packages"])
            variant["assessments"] = [
                a for a in kwargs["assessments"].values() if a.get("variant_id") == vid
            ]
            variant["vulnerabilities"] = {
                vuln_id: v
                for vuln_id, v in kwargs["vulnerabilities"].items()
                if vid in v.get("variant_ids", [])
            }

        return template.render(**kwargs)

    def _run_asciidoctor(self, adoc: str, command: list[str], output_ext: str) -> bytes:
        """Run an asciidoctor command on *adoc* text and return the converted bytes."""
        random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
        adoc_path = f"{random_name}.adoc"
        output_path = f"{random_name}.{output_ext}"

        with open(adoc_path, "w+") as f:
            f.write(adoc)

        execution = subprocess.run(command + [adoc_path], capture_output=True)
        if execution.returncode != 0:
            print(execution.stdout)
            print(execution.stderr)
            try:
                if os.path.exists(adoc_path):
                    os.remove(adoc_path)
                if os.path.exists(output_path):
                    os.remove(output_path)
            finally:
                raise RuntimeError(f"Error converting adoc to {output_ext}: asciidoctor returned non-zero exit code")

        with open(output_path, "rb") as f:
            result = f.read()
        os.remove(adoc_path)
        os.remove(output_path)
        return result

    def adoc_to_pdf(self, adoc: str) -> bytes:
        return self._run_asciidoctor(adoc, ["asciidoctor-pdf"], "pdf")

    def adoc_to_html(self, adoc: str) -> bytes:
        return self._run_asciidoctor(adoc, ["asciidoctor"], "html")

    def list_documents(self):
        docs = []
        try:
            internal = self.internal_loader.list_templates()
            docs.extend([{"id": doc, "is_template": True, "category": ["built-in"]} for doc in internal])
            external = self.external_loader.list_templates()
            docs.extend([{"id": doc, "is_template": True, "category": ["custom"]} for doc in external])
        except Exception as e:
            print(e)
        return docs


class _HtmlStripper(HTMLParser):
    """Stdlib HTML tokenizer that strips tags and performs NO decoding.

    Block-level tags (``<p>``, ``<br>``, ``<li>``, ``<div>``, ``<tr>``, …)
    are replaced with a newline so that paragraph structure is preserved in
    the resulting plain text.  All other tags are silently dropped.

    ``convert_charrefs`` is deliberately disabled and entity/character
    references are re-emitted verbatim: entity decoding happens *before*
    this parser runs (see ``TemplatesExtensions._strip_html``). Keeping the
    tag-stripping pass decode-free guarantees that no decoding step remains
    after the last strip, so stripped output can never contain a tag that
    was hiding behind an entity reference.
    """

    _BLOCK_TAGS = frozenset({
        "p", "br", "div", "li", "tr", "th", "td",
        "h1", "h2", "h3", "h4", "h5", "h6",
        "blockquote", "pre", "hr",
    })

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:  # type: ignore[override]
        if tag.lower() in self._BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in self._BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        self._parts.append(data)

    def handle_entityref(self, name: str) -> None:
        # Anything still shaped like an entity reference at this point is
        # literal text: either an unknown name html.unescape left alone, or
        # a leftover from an input that exceeded the decode budget. Pass it
        # through verbatim -- it is inert and must not be interpreted.
        self._parts.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self._parts.append(f"&#{name};")

    def get_text(self) -> str:
        return "".join(self._parts)


class TemplatesExtensions:
    def __init__(self, jinjaEnv):
        jinjaEnv.filters["status"] = TemplatesExtensions.filter_status
        jinjaEnv.filters["status_pending"] = lambda value: TemplatesExtensions.filter_status(
            value,
            ["under_investigation", "in_triage"]
        )
        jinjaEnv.filters["status_fixed"] = lambda value: TemplatesExtensions.filter_status(
            value,
            ["fixed", "resolved", "resolved_with_pedigree"]
        )
        jinjaEnv.filters["status_ignored"] = lambda value: TemplatesExtensions.filter_status(
            value,
            ["not_affected", "false_positive"]
        )
        jinjaEnv.filters["status_affected"] = lambda value: TemplatesExtensions.filter_status(
            value,
            ["affected", "exploitable"]
        )

        jinjaEnv.filters["status_active"] = lambda value: TemplatesExtensions.filter_status(
            value,
            ["affected", "exploitable", "under_investigation", "in_triage"]
        )
        jinjaEnv.filters["status_inactive"] = lambda value: TemplatesExtensions.filter_status(
            value,
            ["not_affected", "false_positive", "fixed", "resolved", "resolved_with_pedigree"]
        )
        jinjaEnv.filters["severity"] = TemplatesExtensions.filter_severity
        jinjaEnv.filters["as_list"] = TemplatesExtensions.filter_as_list
        jinjaEnv.filters["limit"] = TemplatesExtensions.filter_limit
        jinjaEnv.filters["sort_by_epss"] = TemplatesExtensions.sort_by_epss
        jinjaEnv.filters["epss_score"] = TemplatesExtensions.filter_epss_score
        jinjaEnv.filters["sort_by_effort"] = TemplatesExtensions.sort_by_effort
        jinjaEnv.filters["print_iso8601"] = TemplatesExtensions.print_iso8601
        jinjaEnv.filters["sort_by_last_modified"] = TemplatesExtensions.sort_by_last_modified
        jinjaEnv.filters["last_assessment_date"] = TemplatesExtensions.filter_last_assessment_date
        jinjaEnv.filters["filter_by_publish_date"] = TemplatesExtensions.filter_publish_date
        jinjaEnv.filters["filter_by_variant"] = TemplatesExtensions.filter_by_variant
        jinjaEnv.filters["filter_by_project"] = TemplatesExtensions.filter_by_project
        jinjaEnv.filters["sort_by_scan_date"] = TemplatesExtensions.sort_by_scan_date
        jinjaEnv.filters["escape_adoc"] = TemplatesExtensions.escape_adoc

    @staticmethod
    def get_env_var(key: str, default: str = "") -> str:
        """Get an environment variable, looking up VULNSCOUT_TPL_<key> prefix first."""
        prefixed = os.getenv(f"VULNSCOUT_TPL_{key}")
        if prefixed is not None:
            return prefixed
        return default

    # A line made only of these runs is an AsciiDoc delimited-block fence
    # (example ``====``, listing ``----``, literal ``....``, sidebar ``****``,
    # quote ``____``, passthrough ``++++``, comment ``////``), an open block
    # ``--`` or a table fence (``|===``, ``,===``, ``:===``, ``!===``).
    _ADOC_BLOCK_FENCE = re.compile(r"^(?:[=\-.*_+/]{4,}|--|[|,:!]={3,})[ \t]*$")

    # A line that opens/closes a Markdown-style fenced code block (3+ backticks
    # or tildes, optionally followed by a language). Asciidoctor honours these
    # for Markdown compatibility, so a lone fence left by truncation would open
    # a code block that swallows everything after it.
    _ADOC_MD_FENCE = re.compile(r"^[`~]{3,}")

    # A line that starts with ``=`` (AsciiDoc section title) or ``#`` (Markdown
    # heading) followed by whitespace would create a spurious section/chapter
    # and corrupt the report's heading hierarchy.
    _ADOC_HEADING = re.compile(r"^(?:={1,6}|#{1,6})[ \t]")

    # Maximum number of entity-decoding passes performed by _strip_html
    # before stopping (see its docstring). Legitimate descriptions never
    # nest entity encoding more than a level or two; this bound only caps
    # CPU spent on adversarial, arbitrarily-nested inputs. Exceeding it is
    # safe: leftover entities stay encoded and inert.
    _MAX_ENTITY_DECODE_PASSES = 20

    @staticmethod
    def _strip_html(value: str) -> str:
        """Fully decode HTML entities, then strip tags in a single pass.

        Ordering is what makes this safe. Entity-encoded markup (e.g.
        ``&lt;b&gt;bold&lt;/b&gt;``, or deeper nestings like
        ``&amp;lt;b&amp;gt;``) only becomes a live tag when a decoding step
        runs *after* the last tag-stripping step. So:

        1. Decode entities to a fixed point with ``html.unescape`` (which
           never tokenizes tags), bounded by a pass budget. Legitimate
           descriptions converge in one or two passes; each extra pass means
           another deliberate layer of encoding. The budget exists purely to
           bound CPU on adversarial inputs (repeated whole-string unescape
           is O(passes * len)).
        2. Strip tags in a single pass with ``_HtmlStripper``, which
           performs *no* decoding and re-emits any remaining entity
           references verbatim.

        Because step 2 never decodes, there is no decoding step after the
        last strip: whatever entities survive an exhausted budget stay as
        inert literal text (``&lt;b&gt;`` renders as those characters) and
        can never re-materialise as raw HTML.
        """
        decoded = value
        for _ in range(TemplatesExtensions._MAX_ENTITY_DECODE_PASSES):
            next_decoded = html_unescape(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded

        stripper = _HtmlStripper()
        stripper.feed(decoded)
        stripper.close()
        return stripper.get_text()

    @staticmethod
    def escape_adoc(value: Optional[str]) -> str:
        """Neutralise AsciiDoc structural markup in arbitrary free-form text.

        Vulnerability descriptions are untrusted text (frequently kernel commit
        messages containing code, lockdep splats, separator lines, Markdown
        headings and fenced code blocks). When injected verbatim into an
        AsciiDoc template:

        * a line made of delimiter characters (``----``, ``====``, ``////`` ...)
          or a Markdown code fence (```` ``` ````) opens a delimited block that,
          if never closed, swallows the rest of the document. This is especially
          easy to trigger when truncation cuts a description between a fence and
          its matching closing delimiter;
        * a line starting with ``=`` or ``#`` becomes a section title and breaks
          the report's chapter hierarchy.

        We defuse such lines by prefixing them with a zero-width space so
        Asciidoctor no longer treats them as structural markup, while the
        visible text stays unchanged.

        HTML tags and entities are stripped first using Python's stdlib HTML
        tokenizer so that Asciidoctor never sees raw HTML syntax.
        """
        if not value:
            return ""
        # Fully decode HTML entities and strip any embedded tags (see
        # _strip_html) so Asciidoctor receives plain text instead of raw
        # HTML that would malform the rendered output.
        value = TemplatesExtensions._strip_html(value)
        lines = value.splitlines()
        for i, line in enumerate(lines):
            if (
                TemplatesExtensions._ADOC_BLOCK_FENCE.match(line)
                or TemplatesExtensions._ADOC_MD_FENCE.match(line)
                or TemplatesExtensions._ADOC_HEADING.match(line)
            ):
                lines[i] = "\u200b" + line
        return "\n".join(lines)

    @staticmethod
    def filter_status(value: list, status: str | list[str]) -> list:
        if type(status) is str:
            return [v for v in value if v["status"] == status]
        if type(status) is list:
            return [v for v in value if v["status"] in status]
        return []

    @staticmethod
    def filter_severity(value: list, severity: str | list[str]) -> list:
        if type(severity) is str:
            return [v for v in value if v["severity"]["severity"].lower() == severity.lower()]
        if type(severity) is list:
            return [v for v in value if v["severity"]["severity"].lower() in map(lambda x: x.lower(), severity)]
        return []

    @staticmethod
    def _to_list(value: dict | list) -> list:
        """Normalise *value* to a plain list (dict values or list copy)."""
        return list(value.values()) if isinstance(value, dict) else list(value)

    @staticmethod
    def filter_as_list(value: dict) -> list:
        return list(value.values())

    @staticmethod
    def filter_limit(value: list, limit: int) -> list:
        return value[:limit]

    @staticmethod
    def _generic_sort(value: dict | list, key_getter, reverse: bool = True) -> list[dict]:
        """Normalise *value* to a list and sort by *key_getter*."""
        return sorted(TemplatesExtensions._to_list(value), key=key_getter, reverse=reverse)

    @staticmethod
    def sort_by_epss(value: dict[str, dict[str, Any]] | list[dict[str, Any]]) -> list[dict[str, Any]]:
        return TemplatesExtensions._generic_sort(
            value, key_getter=lambda x: float(((x.get("epss") or {}).get("score")) or 0.0)
        )

    @staticmethod
    def filter_epss_score(value: dict[str, dict[str, Any]] | list[dict[str, Any]], minimum: float
                          ) -> list[dict[str, Any]]:
        vals = TemplatesExtensions._to_list(value)
        result: List[dict[str, Any]] = []
        for v in vals:
            score = 0.0
            try:
                epss_raw = (v.get("epss") or {}).get("score")
                score = float(epss_raw or 0.0) * 100
            except (ValueError, TypeError):
                score = 0.0
            if score >= minimum:
                result.append(v)
        return result

    @staticmethod
    def sort_by_effort(value: dict[str, dict] | list[dict]) -> list[dict]:
        return TemplatesExtensions._generic_sort(
            value, key_getter=lambda x: Iso8601Duration(x["effort"]["likely"] or "P0D").total_seconds
        )

    @staticmethod
    def print_iso8601(value: str) -> str:
        if type(value) is not str:
            return "N/A"
        if value.startswith("P"):
            return Iso8601Duration(value).human_readable()
        return datetime.fromisoformat(value).strftime("%Y %b %d - %H:%M")

    @staticmethod
    def sort_by_last_modified(value: dict[str, dict] | list[dict]) -> list[dict]:
        return TemplatesExtensions._generic_sort(
            value, key_getter=lambda x: x["last_assessment"]["timestamp"] or ""
        )

    @staticmethod
    def _filter_by_date(
        vals: List[dict],
        date_filter: str,
        get_date: Callable[[dict], Optional[str]],
        include_no_date: Callable[[dict], bool] = lambda _: False,
    ) -> List[dict]:
        """Filter *vals* by *date_filter*, extracting each item's date via *get_date*.

        *get_date* should return an ISO-8601 string or ``None``.
        *include_no_date* returns ``True`` for items that should be included when
        they have no date (used by filter_publish_date's ``include_unknown`` flag).
        Returns the original list unchanged when *date_filter* cannot be parsed.
        """

        def parse_item_date(v: dict) -> Optional[datetime]:
            raw = get_date(v)
            if not raw:
                return None
            try:
                d = datetime.fromisoformat(raw)
                return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
            except ValueError:
                return None

        result: List[dict] = []

        if ".." in date_filter:
            parts = date_filter.split("..")
            if len(parts) != 2:
                return vals
            try:
                start = datetime.fromisoformat(parts[0].strip()).replace(
                    hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
                end = datetime.fromisoformat(parts[1].strip()).replace(
                    hour=23, minute=59, second=59, microsecond=999999, tzinfo=timezone.utc)
            except ValueError:
                return vals
            for v in vals:
                d = parse_item_date(v)
                if d is not None:
                    if start <= d <= end:
                        result.append(v)
                elif include_no_date(v):
                    result.append(v)

        elif date_filter.startswith(">="):
            try:
                threshold = datetime.fromisoformat(date_filter[2:].strip()).replace(
                    hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
            except ValueError:
                return vals
            for v in vals:
                d = parse_item_date(v)
                if d is not None:
                    if d >= threshold:
                        result.append(v)
                elif include_no_date(v):
                    result.append(v)

        elif date_filter.startswith(">"):
            try:
                threshold = datetime.fromisoformat(date_filter[1:].strip()).replace(
                    hour=23, minute=59, second=59, microsecond=999999, tzinfo=timezone.utc)
            except ValueError:
                return vals
            for v in vals:
                d = parse_item_date(v)
                if d is not None:
                    if d > threshold:
                        result.append(v)
                elif include_no_date(v):
                    result.append(v)

        elif date_filter.startswith("<="):
            try:
                threshold = datetime.fromisoformat(date_filter[2:].strip()).replace(
                    hour=23, minute=59, second=59, microsecond=999999, tzinfo=timezone.utc)
            except ValueError:
                return vals
            for v in vals:
                d = parse_item_date(v)
                if d is not None:
                    if d <= threshold:
                        result.append(v)
                elif include_no_date(v):
                    result.append(v)

        elif date_filter.startswith("<"):
            try:
                threshold = datetime.fromisoformat(date_filter[1:].strip()).replace(
                    hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
            except ValueError:
                return vals
            for v in vals:
                d = parse_item_date(v)
                if d is not None:
                    if d < threshold:
                        result.append(v)
                elif include_no_date(v):
                    result.append(v)

        else:
            try:
                start = datetime.fromisoformat(date_filter.strip()).replace(
                    hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
                end = datetime.fromisoformat(date_filter.strip()).replace(
                    hour=23, minute=59, second=59, microsecond=999999, tzinfo=timezone.utc)
            except ValueError:
                return vals
            for v in vals:
                d = parse_item_date(v)
                if d is not None:
                    if start <= d <= end:
                        result.append(v)
                elif include_no_date(v):
                    result.append(v)

        return result

    @staticmethod
    def filter_last_assessment_date(value: dict[str, dict] | list[dict], date_filter: str) -> list[dict]:
        """
        Filter vulnerabilities based on their last assessment date.

        Supports the following formats:
        - '>2026-01-01': After this date (exclusive)
        - '>=2026-01-01': After or on this date (inclusive)
        - '<2026-01-01': Before this date (exclusive)
        - '<=2026-01-01': Before or on this date (inclusive)
        - '2026-01-01..2026-01-31': Between two dates (inclusive)
        - '2026-01-01': Exact date match

        Args:
            value: Dictionary or list of vulnerabilities
            date_filter: Date filter string in one of the supported formats

        Returns:
            List of filtered vulnerabilities
        """
        vals = TemplatesExtensions._to_list(value)

        def get_date(v: dict) -> Optional[str]:
            la = v.get("last_assessment")
            if la and isinstance(la, dict):
                return la.get("timestamp")
            return None

        return TemplatesExtensions._filter_by_date(vals, date_filter, get_date)

    @staticmethod
    def filter_publish_date(
        value: dict[str, dict] | list[dict],
        date_filter: str,
        include_unknown: bool = False
    ) -> list[dict]:
        """
        Filter vulnerabilities based on their publish date.

        Supports the following formats:
        - `>2026-01-01`: After this date (exclusive)
        - `>=2026-01-01`: After or on this date (inclusive)
        - `<2026-01-01`: Before this date (exclusive)
        - `<=2026-01-01`: Before or on this date (inclusive)
        - `2026-01-01..2026-01-31`: Between two dates (inclusive)
        - `2026-01-01`: Exact date match, but ignores time (hours, minutes, seconds)

        Args:
            `value`: Dictionary or list of vulnerabilities
            `date_filter`: Date filter string in one of the supported formats

        Returns:
            List of filtered vulnerabilities
        """
        vals = TemplatesExtensions._to_list(value)

        def get_date(v: dict) -> Optional[str]:
            return v.get("published") or None

        def include_no_date(v: dict) -> bool:
            return include_unknown and not v.get("published")

        return TemplatesExtensions._filter_by_date(vals, date_filter, get_date, include_no_date)

    @staticmethod
    def filter_by_variant(value: dict[str, dict] | list[dict], variant_id: str) -> list[dict]:
        vals = TemplatesExtensions._to_list(value)
        return [v for v in vals if v.get("variant_id") == variant_id or variant_id in v.get("variant_ids", [])]

    @staticmethod
    def filter_by_project(value: dict[str, dict] | list[dict], project_id: str) -> list[dict]:
        vals = TemplatesExtensions._to_list(value)
        return [v for v in vals if v.get("project_id") == project_id]

    @staticmethod
    def sort_by_scan_date(value: dict[str, dict] | list[dict]) -> list[dict]:
        return TemplatesExtensions._generic_sort(
            value, key_getter=lambda x: x.get("timestamp") or ""
        )
