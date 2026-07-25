"""PTT workflow and batch review handlers."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

from .. import findings, hypotheses, ptt, state
from ..history import history_contains
from ..phases import requires_hypothesis
from ..skill_receipts import (
    HermesSkillViewAdapter,
    bind_task,
    complete_delivery,
    prepare_delivery,
    prepare_review_readiness,
)
from .base import (
    _eng_path,
    _json,
    _running_background_command,
    _serialise_errors,
)


def _with_skill_token(note: str, skill: str, digest: str) -> str:
    """Keep exactly one replaceable selection token in a PTT note."""
    token = f"[skill:{skill}@{digest}]"
    stripped = re.sub(r"\s*\[skill:[^\]]+\]", "", note).strip()
    return f"{stripped} {token}".strip()


def _start_ptt_task(
    ptt_path: Path,
    tasks: list[ptt.PttTask],
    task_id: str,
    status: str,
    note: str,
    eng_dir: str | Path | None = None,
) -> str:
    """Arm one untouched, phase-bound task before the first target command."""

    if status != "[~]":
        raise ValueError("without a pending batch, only [~] may start a PTT task")
    active = ptt.find_active_task(tasks)
    if active and active.id != task_id:
        resolved_dir = ptt_path.parent.parent if eng_dir is None else Path(eng_dir)
        if state.has_pending_sync(resolved_dir):
            raise ValueError("an active PTT task already exists; review its pending batch first")
        superseded_note = f"{active.note} [superseded-by:{task_id}]".strip()
        ptt.update_task(ptt_path, active.id, "[x]", superseded_note)
        tasks = ptt.parse_ptt(ptt_path)
    selected = next((item for item in tasks if item.id == task_id), None)
    if selected is None:
        raise ValueError(f"PTT task {task_id!r} not found")
    if selected.status not in {"[ ]", "[~]"}:
        raise ValueError(f"PTT task {task_id!r} must be [ ] or [~] before it can be started")
    try:
        phase = ptt.normalize_phase(selected.phase)
    except ValueError as exc:
        raise ValueError(f"PTT task {task_id!r} must sit below a valid Phase heading") from exc
    ptt.update_task(ptt_path, task_id, status, note)
    return _json("ok", task_id=task_id, phase=phase.value, task_started=True)


def _task_row_contains(path: Path, task_id: str, marker: str) -> bool:
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\|\s*(PT-[\w-]+)\s*\|", line.strip())
        if match and match.group(1) == task_id:
            return marker in line
    return False


def _validate_review_batch(a: dict, pending: dict) -> dict:
    eng_dir = str(a.get("eng_dir") or "")
    task_id = str(a.get("id") or "").strip()
    note = str(a.get("note") or "").strip()
    status = str(a.get("status") or "").strip()
    if not task_id or not note:
        raise ValueError("active task id and non-empty review note are required")
    if status not in {"[~]", "[x]", "[!]", "[-]"}:
        raise ValueError("status must be one of [~], [x], [!], or [-]")

    batch_id = str(pending.get("batch_id") or "").strip()
    captured_task = str(pending.get("ptt_task_id") or "").strip()
    if not batch_id or not captured_task:
        raise ValueError("pending batch is missing its batch or PTT task identity")
    if task_id != captured_task:
        raise ValueError(f"reviewed task {task_id!r} does not match batch task {captured_task!r}")

    ptt_path = _eng_path(eng_dir) / "state" / "ptt.md"
    tasks = ptt.parse_ptt(ptt_path)
    selected = next((item for item in tasks if item.id == task_id), None)
    if selected is None:
        raise ValueError(f"batch task {task_id!r} is missing from the PTT")
    marker = f"[reviewed-batch:{batch_id}]"
    already_recorded = selected.status == status and _task_row_contains(ptt_path, task_id, marker)
    if not already_recorded:
        validation = ptt.validate_ptt(tasks)
        if validation.errors:
            raise ValueError("PTT must have exactly one valid active task before batch review")
        active = ptt.find_active_task(tasks)
        if not active or active.id != task_id:
            raise ValueError(f"batch task {task_id!r} must be the sole active [~] task")
        phases = {
            str(item.get("phase") or pending.get("phase") or "")
            for item in pending.get("commands") or []
        } - {""}
        incompatible = sorted(
            phase for phase in phases if not ptt.task_matches_phase(active, phase)
        )
        if incompatible:
            raise ValueError(
                f"batch task {task_id!r} is not phase-compatible with " + ", ".join(incompatible)
            )

    for item in pending.get("commands") or []:
        command = str(item.get("command") or "") if isinstance(item, dict) else str(item or "")
        if command and not history_contains(eng_dir, command):
            if _running_background_command(eng_dir, command):
                continue
            raise ValueError(
                f"pending command not yet in exact history: {command!r}; "
                "wait for execution completion before review"
            )

    finding = a.get("finding")
    if finding is not None:
        if not isinstance(finding, dict):
            raise ValueError("finding must be an object when supplied")
        findings._validate_from_pending_batch(
            eng_dir,
            pending,
            title=str(finding.get("title") or ""),
            severity=str(finding.get("severity") or ""),
            description=str(finding.get("description") or ""),
            impact=str(finding.get("impact") or ""),
            remediation=str(finding.get("remediation") or ""),
            finding_id=str(finding.get("finding_id") or ""),
            hypothesis_id=str(finding.get("hypothesis_id") or ""),
        )
    return {
        "batch_id": batch_id,
        "task_id": task_id,
        "status": status,
        "note": note,
        "marker": marker,
        "already_recorded": already_recorded,
        "ptt_path": ptt_path,
        "finding": finding,
    }


def _get_skill_view_adapter():
    for _name, mod in list(sys.modules.items()):
        if mod and hasattr(mod, "HermesSkillViewAdapter"):
            cls = mod.HermesSkillViewAdapter
            if getattr(cls, "__module__", "") not in (
                "plugins.violin_guard.skill_receipts",
                "vgpkg.skill_receipts",
            ):
                return cls
    return HermesSkillViewAdapter


@_serialise_errors
def handle_record_ptt(a, **kwargs):
    eng_dir = a["eng_dir"]
    doc = ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")
    pending = state.get_pending_sync(eng_dir)
    task = a.get("id")
    note = (a.get("note") or "").strip()
    status = a.get("status", "[~]")
    skill = str(a.get("skill") or "").strip()
    technique = str(a.get("technique") or "").strip()

    if not task or not note:
        raise ValueError("task id and non-empty lifecycle note required")
    if not skill or not technique:
        raise ValueError("skill and technique are required before a PTT update")
    if pending:
        raise ValueError(
            "a target batch is pending; use violin_review_batch instead of violin_record_ptt"
        )
    selected = next((item for item in doc if item.id == task), None)
    selected_phase = selected.phase if selected else str(a.get("phase") or "RECON")
    try:
        phase = ptt.normalize_phase(selected_phase)
    except ValueError as exc:
        raise ValueError(f"PTT task {task!r} must sit below a valid Phase heading") from exc
    hypothesis_id = str(a.get("hypothesis_id") or "").strip()
    if requires_hypothesis(phase) and not hypothesis_id:
        raise ValueError(f"hypothesis_id is required for {phase.value} PTT work")
    vulnerability_class = ""
    candidate_source = ""
    if hypothesis_id:
        normalized = hypothesis_id.removeprefix("H-").lstrip("0") or "0"
        matched = next(
            (
                h
                for h in hypotheses.parse_hypotheses(_eng_path(eng_dir) / "hypotheses.md")
                if h.id.lstrip("0") == normalized
            ),
            None,
        )
        vulnerability_class = matched.vuln_class if matched else ""
        candidate_source = matched.candidate_source if matched else ""
    digest = "sha256:" + hashlib.sha256(f"policy:{skill}".encode()).hexdigest()
    reservation = prepare_delivery(
        eng_dir,
        session_id=state.resolve_session_id(eng_dir) or "ptt",
        skill=skill,
        bundle_digest=digest,
        phase=phase.value,
        vulnerability_class=vulnerability_class or None,
        candidate_source=candidate_source or None,
    )
    if reservation.owner:
        adapter_cls = _get_skill_view_adapter()
        viewed = adapter_cls().view(skill, task_id=task)
        completed = complete_delivery(eng_dir, reservation, viewed)
        return _json(
            "skill_prepared" if completed.status == "delivered" else "skill_unavailable",
            transition_applied=False,
            skill={
                "name": skill,
                "digest": digest,
                "content": viewed.content,
                "error": viewed.error,
                "delivery_id": reservation.id,
            },
        )
    if reservation.status == "preparing":
        return _json(
            "skill_preparing", transition_applied=False, skill={"name": skill, "digest": digest}
        )
    binding = bind_task(
        eng_dir,
        task_id=task,
        delivery_id=reservation.id,
        hypothesis_id=hypothesis_id,
        technique=technique,
    )
    note = _with_skill_token(note, skill, digest)
    if not any(item.id == task for item in doc):
        created = ptt.create_task(
            _eng_path(eng_dir) / "state" / "ptt.md",
            task,
            a.get("title") or task,
            a.get("phase") or "RECON",
            note,
        )
        doc = ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")
        if status == "[ ]":
            return _json("ok", task_id=created.id, task_created=True)
    existing = next((item for item in doc if item.id == task), None)
    if existing and existing.status == "[~]" and status == "[~]":
        active = ptt.find_active_task(doc)
        if active and active.id != task:
            resolved_dir = _eng_path(eng_dir)
            if state.has_pending_sync(resolved_dir):
                raise ValueError(
                    "an active PTT task already exists; review its pending batch first"
                )
            superseded_note = f"{active.note} [superseded-by:{task}]".strip()
            ptt.update_task(
                _eng_path(eng_dir) / "state" / "ptt.md", active.id, "[x]", superseded_note
            )
        ptt.update_task(_eng_path(eng_dir) / "state" / "ptt.md", task, "[~]", note)
        return _json("ok", task_id=task, task_refreshed=True, binding=binding)
    if existing and status in {"[x]", "[-]"}:
        if existing.status != "[~]":
            raise ValueError("only the active [~] task may be closed outside a batch")
        ptt.update_task(_eng_path(eng_dir) / "state" / "ptt.md", task, status, note)
        return _json("ok", task_id=task, task_closed=True)
    return _start_ptt_task(
        _eng_path(eng_dir) / "state" / "ptt.md", doc, task, status, note, eng_dir=eng_dir
    )


@_serialise_errors
def handle_review_batch(a, **kwargs):
    """Review one completed batch, optionally record a finding, and release its lock."""

    eng_dir = str(a.get("eng_dir") or "").strip()
    if not eng_dir:
        raise ValueError("eng_dir is required")
    engagement = _eng_path(eng_dir)
    review_lock = engagement / "state" / "review-batch.json"
    try:
        with state.lock_file(review_lock):
            pending = state.get_pending_sync(engagement)
            if not pending:
                return _json(
                    "ok",
                    batch_id=None,
                    task_id=None,
                    task_status=None,
                    released=True,
                    finding=None,
                    finding_path=None,
                    message="nothing pending",
                )
            skill = str(a.get("skill") or "").strip()
            if skill:
                tasks = ptt.parse_ptt(engagement / "state" / "ptt.md")
                task_id = str(a.get("id") or "").strip()
                task = next((item for item in tasks if item.id == task_id), None)
                if task is None:
                    raise ValueError(f"batch task {task_id!r} is missing from the PTT")
                hypothesis_id = str(a.get("hypothesis_id") or "").strip()
                phase = ptt.normalize_phase(task.phase)
                if requires_hypothesis(phase) and not hypothesis_id:
                    raise ValueError(f"hypothesis_id is required for {phase.value} batch review")
                digest = "sha256:" + hashlib.sha256(f"policy:{skill}".encode()).hexdigest()
                reservation = prepare_delivery(
                    engagement,
                    session_id=state.resolve_session_id(engagement) or "review",
                    skill=skill,
                    bundle_digest=digest,
                    phase="RETROSPECTIVE" if skill == "fp-check" else phase.value,
                )
                if reservation.owner:
                    adapter_cls = _get_skill_view_adapter()
                    viewed = adapter_cls().view(skill, task_id=task_id)
                    completed = complete_delivery(engagement, reservation, viewed)
                    return _json(
                        "skill_prepared"
                        if completed.status == "delivered"
                        else "skill_unavailable",
                        transition_applied=False,
                        released=False,
                        skill={
                            "name": skill,
                            "digest": digest,
                            "content": viewed.content,
                            "error": viewed.error,
                            "delivery_id": reservation.id,
                        },
                    )
                if reservation.status == "preparing":
                    return _json("skill_preparing", transition_applied=False, released=False)
                if skill == "fp-check" and a.get("finding"):
                    finding_id = str((a.get("finding") or {}).get("finding_id") or "").upper()
                    evidence = findings._batch_evidence(engagement, pending)
                    evidence_digest = (
                        "sha256:" + hashlib.sha256("\n".join(sorted(evidence)).encode()).hexdigest()
                    )
                    prepare_review_readiness(
                        engagement,
                        finding_id=finding_id,
                        evidence_digest=evidence_digest,
                        delivery_id=reservation.id,
                    )
                    return _json(
                        "review_prepared",
                        transition_applied=False,
                        released=False,
                        finding_id=finding_id,
                    )
                a = {**a, "note": _with_skill_token(str(a.get("note") or ""), skill, digest)}
            context = _validate_review_batch(a, pending)
            finding_result = None
            finding = context["finding"]
            if finding is not None:
                finding_result = findings._create_from_pending_batch(
                    engagement,
                    pending=pending,
                    title=str(finding.get("title") or ""),
                    severity=str(finding.get("severity") or ""),
                    description=str(finding.get("description") or ""),
                    impact=str(finding.get("impact") or ""),
                    remediation=str(finding.get("remediation") or ""),
                    finding_id=str(finding.get("finding_id") or ""),
                    hypothesis_id=str(finding.get("hypothesis_id") or ""),
                )
            if not context["already_recorded"]:
                review_note = f"{context['note']} {context['marker']}"
                ptt.update_task(
                    context["ptt_path"], context["task_id"], context["status"], review_note
                )
            batch_evidence = findings._batch_evidence(engagement, pending)
            supplied_evidence = [str(item) for item in (a.get("evidence_paths") or [])]
            evidence_paths = sorted(set(supplied_evidence) | set(batch_evidence))
            semantic = state.record_semantic_review(
                engagement,
                task_id=context["task_id"],
                hypothesis_id=str(a.get("hypothesis_id") or ""),
                skill=skill or "review",
                technique=str(a.get("technique") or "batch-review"),
                outcome=str(a.get("outcome") or "progress"),
                evidence_paths=evidence_paths,
                next_action=str(a.get("next_action") or "review evidence"),
                next_technique=str(a.get("next_technique") or ""),
                research_attempted=bool(a.get("research_attempted")),
            )
            state.clear_pending_sync(engagement)
            return _json(
                "ok",
                batch_id=context["batch_id"],
                task_id=context["task_id"],
                task_status=context["status"],
                released=True,
                finding=finding_result,
                finding_path=finding_result.get("path") if finding_result else None,
                binding_task_id=None,
                semantic_progress=semantic,
            )
    except (OSError, ValueError) as exc:
        return _json(
            "blocked",
            released=False,
            error=str(exc),
            next_action="Resolve the reported batch, PTT, history, or finding issue and retry violin_review_batch",
        )


def _rebind_fields(a) -> tuple[str, str, str, str, str]:
    if a.get("confirm") is not True:
        raise ValueError("explicit confirm=true is required to rebind a pending batch")
    values = tuple(
        str(a.get(key) or "").strip()
        for key in ("eng_dir", "batch_id", "current_task_id", "replacement_task_id", "note")
    )
    if not all(values):
        raise ValueError(
            "eng_dir, batch_id, current_task_id, replacement_task_id, and note are required"
        )
    return values


def _validate_pending_identity(pending: dict, batch_id: str, current_task_id: str) -> None:
    actual_batch_id = str(pending.get("batch_id") or "")
    if actual_batch_id != batch_id:
        raise ValueError(
            f"stale batch id {batch_id!r}; current pending batch is {actual_batch_id!r}"
        )
    captured_task_id = str(pending.get("ptt_task_id") or "")
    if captured_task_id != current_task_id:
        raise ValueError(
            f"current task {current_task_id!r} does not match batch task {captured_task_id!r}"
        )


def _validate_pending_history(eng_dir: str, pending: dict) -> None:
    missing = next(
        (
            str(item.get("command") or "")
            for item in pending.get("commands") or []
            if item.get("command") and not history_contains(eng_dir, str(item.get("command")))
        ),
        "",
    )
    if missing:
        raise ValueError(
            f"pending command not yet in exact history: {missing!r}; "
            "wait for the batch to finish before rebinding"
        )


def _validated_replacement_task(
    eng_dir: str, pending: dict, current_task_id: str, replacement_task_id: str
):
    tasks = ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")
    if ptt.validate_ptt(tasks).errors:
        raise ValueError("PTT must have exactly one valid active task before rebinding")
    by_id = {task.id: task for task in tasks}
    if current_task_id not in by_id:
        raise ValueError(f"current batch task {current_task_id!r} is missing from the PTT")
    replacement = by_id.get(replacement_task_id)
    if replacement is None:
        raise ValueError(f"replacement task {replacement_task_id!r} is missing from the PTT")
    active = ptt.find_active_task(tasks)
    if active is None or active.id != replacement_task_id:
        raise ValueError(
            f"replacement task {replacement_task_id!r} must be the sole active [~] task"
        )
    phases = {
        str(item.get("phase") or pending.get("phase") or "")
        for item in pending.get("commands") or []
    } - {""}
    incompatible = sorted(
        phase for phase in phases if not ptt.task_matches_phase(replacement, phase)
    )
    if incompatible:
        raise ValueError(
            f"replacement task {replacement_task_id!r} is not phase-compatible with "
            + ", ".join(incompatible)
        )
    return replacement


@_serialise_errors
def handle_rebind_pending_batch(a, **kwargs):
    """Explicitly move a completed pending batch to another active PTT task."""

    try:
        eng_dir, batch_id, current_task_id, replacement_task_id, note = _rebind_fields(a)
        pending = state.get_pending_sync(eng_dir)
        if not pending:
            raise ValueError("no pending execution batch")
        _validate_pending_identity(pending, batch_id, current_task_id)
        _validate_pending_history(eng_dir, pending)
        _validated_replacement_task(eng_dir, pending, current_task_id, replacement_task_id)
        audit = state.rebind_pending_sync(
            eng_dir,
            expected_batch_id=batch_id,
            current_task_id=current_task_id,
            replacement_task_id=replacement_task_id,
            note=note,
        )
        return _json(
            "ok",
            batch_id=batch_id,
            ptt_task_id=replacement_task_id,
            ptt_reviewed=False,
            audit=audit,
        )
    except Exception as e:
        return _json("error", error=str(e))
