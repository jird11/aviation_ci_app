"""KIT-to-query guard rules shared with the existing Planner stage."""

import re

from aero_ews.collection.queries import get_program_engine_domain
from aero_ews.intelligence.query_repair import ADDITIVE_REASONS, append_missing, surface_terms
from ews_state import KIQPlan, logger
from ews_validation import (
    _detect_aircraft_families, _detect_engine_models,
    _detect_exact_variants, _detect_specific_variants,
)
from tasks import InformationRequirement, SearchPurpose

# Controlled Planner guard vocabularies and compiled scope patterns (preserved verbatim).
_PLANNER_UNREQUESTED_TOPICS = {
    "fuel": r"\bfuel\b",
    "engine": r"\b(?:engine|engines|gtf|pw1100|leap-?1|turbine)\b",
    "shortage": r"\b(?:shortag\w*|outage\w*)\b",
    "damage": r"\b(?:crack\w*|fracture\w*|corrosion|defect\w*)\b",
    "strike": r"\b(?:strike\w*|walkout\w*)\b",
    "accident": r"\b(?:accident\w*|crash\w*|runway\s+(?:overrun|excursion))\b",
    "production": r"\b(?:production|manufactur\w*|deliver\w*|capacity)\b",
    "orders": r"\b(?:orders?|purchas\w*|contract\w*|leas\w*)\b",
    "finance": r"\b(?:financial|loss\w*|profit\w*|earnings|revenue)\b",
    "logistics": r"\b(?:logistic\w*|freight|shipping|transport\w*|lead[ -]?time\w*|inventory)\b",
}
_BROAD_SCOPE = re.compile(r"\b(?:supply[ -]?chain|supplier\w*|procurement|sourcing|logistic\w*|market|industry|sector|strategic|competitive|business|risks?|production|operations?)\b", re.I)
_NARROW_SCOPE = re.compile(r"\b(?:inspect\w*|certif\w*|airworthiness|directive|compliance|approval|repair\w*|overhaul\w*|technical\s+requirement\w*)\b", re.I)
_SUPPLY_SCOPE = re.compile(r"\b(?:supply[ -]?chain|supplier\w*|procurement|sourcing|logistic\w*)\b", re.I)
_SUPPLY_CONTEXT = re.compile(
    r"\b(?:suppl\w*|procure\w*|sourc\w*|logistic\w*|freight|shipping|production|manufactur\w*|capacity|"
    r"deliver\w*|shortag\w*|bottleneck\w*|component\w*|parts?|inventory|lead[ -]?time\w*|contract\w*|orders?|export\w*|constraint\w*)\b", re.I,
)
_ENGINE_CODE = re.compile(r"\b(?:PW\d{3,5}[A-Z](?:-[A-Z0-9]+)?|LEAP[- ]?1[ABC]|GE9X|GE90|GENX|CFM56|TRENT\s+(?:XWB(?:-\d+)?|[A-Z0-9]+)|FJ\d{2}(?:-\d\w*)?)\b", re.I)
_COMPONENTS = {
    "gearbox": r"\b(?:gear[ -]?box|reduction\s+gear\w*)\b",
    "fan": r"\b(?:fan\s+(?:blade\w*|rotor\w*|case)|fan\s+module)\b",
    "turbine": r"\b(?:turbine\w*|turbín\w*|hpt)\b",
    "compressor": r"\b(?:compressor\w*|hpc)\b",
    "combustor": r"\b(?:combustor\w*|combustion\s+chamber)\b",
    "landing_gear": r"\blanding\s+gear\b",
    "avionics": r"\bavionic\w*\b",
    "fuselage": r"\bfuselage\b",
}
_ENGINE_SUBCOMPONENTS = frozenset({"gearbox", "fan", "turbine", "compressor", "combustor"})
_ENGINE_TOPIC_RE = re.compile(r"\b(?:engine|engines|propulsion|powerplant|turbine|gtf|leap)\b", re.I)
_GENERIC_NAMES = {
    "supply", "chain", "risk", "risks", "monitor", "current", "latest", "global", "industry", "market",
    "aviation", "aircraft", "aerospace", "technical", "strategic", "production", "financial", "supplier",
    "suppliers", "inspection", "requirements", "max", "neo", "xlr", "xwb", "gtf", "ad", "aog", "mro",
    "oem", "sec", "esef", "engine", "engines", "status", "certification", "durability", "grounding",
    "delivery", "deliveries", "shortage", "impact", "forging", "forgings", "casting", "castings",
    "titanium", "and", "the", "for", "airline", "airlines", "group", "holdings", "systems", "canada",
    "corp", "inc", "ltd", "international", "commercial", "door", "plug", "finding", "findings",
    "investigation", "delay", "delays", "defect", "defects", "acquisition", "airshow", "labor", "labour",
    "strike", "availability", "spare", "parts", "flight", "test", "thrust", "link", "occur", "manifold",
    "fuel", "fleet", "directive", "directives", "airworthiness", "issues", "issue", "quality",
    "manufacturing", "why", "what", "how",
}
_AUTHORITIES = re.compile(r"\b(?:FAA|EASA|NTSB|TCCA|CAAC|ANAC|UK\s+CAA|CAA)\b", re.I)
_EXCLUSION = re.compile(r"(?i:\b(?:excluding|exclude|without|except(?:\s+for)?|other\s+than|not\s+including))\s+([A-Za-z][\w-]*(?:\s+[A-Z][\w-]*)*)")
_COMPARISON = re.compile(r"\b([A-Z][\w-]*)\s+(?:vs\.?|versus|compared\s+(?:to|with))\s+([A-Z][\w-]*)\b")
_COMPARISON_ALT = re.compile(r"(?i:\b(?:compare|between))\s+([A-Z][\w-]*)\s+(?i:and|with)\s+([A-Z][\w-]*)\b")
_LIFECYCLE = re.compile(r"\b(?:current|latest|status|update\w*|since|after|follow[ -]?up|resolv\w*|resolution|recurr\w*|reopen\w*|improv\w*|worsen\w*)\b", re.I)
_CAUSE = re.compile(r"\b(?:why|caus\w*|because|due\s+to|led\s+to|leads\s+to|resulted\s+in)\b", re.I)
_INTENTS = {
    "inspection": re.compile(r"\binspect\w*\b", re.I), "certification": re.compile(r"\bcertif\w*\b", re.I),
    "airworthiness": re.compile(r"\b(?:airworthiness|directive)\b", re.I), "compliance": re.compile(r"\bcomplian\w*\b", re.I),
    "approval": re.compile(r"\bapprov\w*\b", re.I), "repair": re.compile(r"\b(?:repair\w*|overhaul\w*)\b", re.I),
}
_INSPECTION_REGULATION = re.compile(r"\b(?:airworthiness\s+directiv\w*|AD|service\s+bulletin\w*|maintenance|inspect\w*|compliance|interval\w*|deadline\w*|effective\s+date|mandatory\s+action\w*)\b", re.I)

# Precompiled auxiliary patterns used inside KIT constraint checks.
_YEAR_RE = re.compile(r"\b(?:19|20)\d{2}\b")
_AS_OF_RE = re.compile(r"\b(?:as\s+of|until|through|up\s+to|before|prior\s+to|between\s+(?:19|20)\d{2}\s+and|from\s+(?:19|20)\d{2}\s+to)\b", re.I)
_COMMERCIAL_RE = re.compile(r"\b(?:orders?|airshow|farnborough|paris\s+air\s+show|dubai\s+airshow|purchas\w*|contract\w*)\b", re.I)
_SAFETY_RE = re.compile(r"\b(?:defect\w*|crack\w*|ground\w*|incident\w*|accident\w*|investigation\w*|durabilit\w*)\b", re.I)
_SUPPLY_TOPICS = {"engine", "shortage", "damage", "strike", "production", "orders", "finance", "logistics"}
_BROAD_TOPICS = {"production", "orders", "finance"}


# Component, engine-code, authority, and multi-item coverage helpers.
def _components(text: str) -> set[str]: return {n for n, p in _COMPONENTS.items() if re.search(p, text or "", re.I)}
def _codes(text: str) -> set[str]: return {re.sub(r"[ -]", "", m.upper()) for m in _ENGINE_CODE.findall(text or "")}
def _code_is_allowed(code: str, allowed: set[str]) -> bool: return code in allowed or any(a.startswith(code) or code.startswith(a) for a in allowed)
def _authorities(text: str) -> set[str]: return {re.sub(r"\s+", " ", m.upper()) for m in _AUTHORITIES.findall(text or "")}
def _missing_any(required: set[str], matched: set[str]) -> set[str]: return set() if (len(required) > 1 and matched) else (required - matched)


def _sanitize_kiq_plan_for_kit(kit: str, plan: KIQPlan) -> KIQPlan:
    """Protect explicit KIT constraints without suppressing evidence-led decomposition."""
    kit = (kit or "").strip()
    exclusions = {m.group(1).strip() for m in _EXCLUSION.finditer(kit)}
    subject = _EXCLUSION.sub("", kit).strip(" ,;-") or kit

    kit_families, kit_variants, kit_exact = _detect_aircraft_families(subject), _detect_specific_variants(subject), _detect_exact_variants(subject)
    if re.search(r"\b777X\b", subject, re.I):
        kit_exact = set(kit_exact) | {"777:8", "777:9"}
        kit_variants = set(kit_variants) | _detect_specific_variants("Boeing 777-8 777-9")
    kit_engines, kit_codes, kit_components, kit_authorities = _detect_engine_models(subject), _codes(subject), _components(subject), _authorities(subject)

    # EXPLICIT_SCOPE: explicit engine/code in the KIT remains locked.
    # DOMAIN_EXPANSION: a generic engine KIT for a specific aircraft program may use engines from the domain map.
    domain_expansion = bool(_ENGINE_TOPIC_RE.search(subject) and (kit_families or kit_variants or kit_exact) and not (kit_engines or kit_codes))
    domain_info = get_program_engine_domain(subject) if domain_expansion else {"engine_models": (), "engine_manufacturers": ()}
    allowed_domain_engines = set().union(*(_detect_engine_models(m) for m in domain_info["engine_models"])) if domain_info["engine_models"] else set()
    allowed_domain_codes = _codes(" ".join(domain_info["engine_models"]))
    allowed_domain_oems = {oem.lower() for oem in domain_info["engine_manufacturers"]}
    allowed_engines, allowed_codes = kit_engines | allowed_domain_engines, kit_codes | allowed_domain_codes

    kit_years = set(_YEAR_RE.findall(subject))
    max_kit_year = max(map(int, kit_years), default=0)
    as_of, narrow_subject = bool(_AS_OF_RE.search(subject)), bool(_NARROW_SCOPE.search(subject))
    broad = bool(_BROAD_SCOPE.search(subject)) and not (narrow_subject or kit_components)
    supply_kit = bool(_SUPPLY_SCOPE.search(subject))
    allowed_topics = _SUPPLY_TOPICS if supply_kit else (_BROAD_TOPICS if broad else set())
    subject_topics = {n for n, p in _PLANNER_UNREQUESTED_TOPICS.items() if re.search(p, subject, re.I)}
    matching_intents = [n for n, p in _INTENTS.items() if p.search(subject)]
    is_commercial_only = bool(_COMMERCIAL_RE.search(subject) and not narrow_subject and not kit_authorities and not _SAFETY_RE.search(subject))

    comparison_pattern = _COMPARISON if _COMPARISON.search(subject) else _COMPARISON_ALT
    compared = tuple(m.groups()) if (m := comparison_pattern.search(subject)) else ()
    entities = {
        tok.lower() for tok in re.findall(r"\b[A-Z][a-z]{2,}\b|\b[A-Z]{2,}\b", subject)
        if tok.lower() not in _GENERIC_NAMES and tok.upper() not in kit_authorities and tok.upper() not in kit_codes
        and not any(tok.lower() in ex.lower().split() for ex in exclusions)
    }
    identities = list(dict.fromkeys([*sorted(entities), *sorted(kit_exact), *sorted(kit_codes), *sorted(kit_components), *sorted(kit_authorities)]))
    negative = " ".join(f'-"{n}"' if " " in n else f"-{n}" for n in sorted(exclusions))
    base_subject = " ".join(p for p in (subject, negative) if p).strip() or kit
    audit: list[dict[str, str]] = []
    additive_repairs: dict[str, str] = {}

    def record(field: str, original: str, replacement: str, reasons: list[str]) -> None:
        reason = ",".join(dict.fromkeys(reasons))
        audit.append({"field": field, "original": original, "corrected": replacement, "reason": reason})
        logger.warning("[PLANNER KIT GUARD] %s: %s | %r -> %r", field, reason, original, replacement)

    def violations(proposed: str, require_scope: bool = True, channel: str = "") -> list[str]:
        proposed = proposed or ""
        q_exact, q_codes, q_engines = _detect_exact_variants(proposed), _codes(proposed), _detect_engine_models(proposed)
        q_components, q_authorities = _components(proposed), _authorities(proposed)
        q_fams = _detect_aircraft_families(proposed)
        has_dom_eng = bool(domain_expansion and ((q_codes & allowed_domain_codes) or (q_engines & allowed_domain_engines)))
        has_dom_oem = bool(domain_expansion and any(re.search(rf"\b{re.escape(o)}\b", proposed, re.I) for o in allowed_domain_oems))
        has_allowed_code = bool(q_codes and allowed_codes and any(_code_is_allowed(c, allowed_codes) for c in q_codes))

        new_topics = {n for n, p in _PLANNER_UNREQUESTED_TOPICS.items() if n not in subject_topics and re.search(p, proposed, re.I)}
        if domain_expansion:
            new_topics.discard("damage")
        added_years = set(_YEAR_RE.findall(proposed)) - kit_years
        problems: list[str] = []

        if (q_fams - kit_families or _detect_specific_variants(proposed) - kit_variants or q_exact - kit_exact
                or q_engines - allowed_engines or any(not _code_is_allowed(c, allowed_codes) for c in q_codes)):
            problems.append("UNREQUESTED_MODEL")

        # For multi-model/multi-engine KITs, covering at least one requested model per query is sufficient.
        missing_exact = _missing_any(kit_exact, kit_exact & q_exact)
        matched_kit_codes = {c for c in kit_codes if any(_code_is_allowed(qc, {c}) for qc in q_codes)}
        missing_codes = _missing_any(kit_codes, matched_kit_codes)
        if (domain_expansion and (has_dom_eng or has_dom_oem) and channel in {"regulatory", "social", "media"}) or (
            kit_codes and matched_kit_codes and channel in {"regulatory", "social"}
        ):
            missing_exact = set()
        if require_scope and not compared and (missing_exact or missing_codes):
            problems.append("MISSING_MODEL")

        has_model_anchor = bool(matched_kit_codes or (kit_exact & q_exact) or has_dom_eng)
        reg_discovery = channel == "regulatory" and bool(_INSPECTION_REGULATION.search(proposed)) and (has_model_anchor or not (kit_codes or kit_exact))
        social_focused = channel == "social" and has_model_anchor
        if require_scope and not broad and _missing_any(kit_components, kit_components & q_components) and not (reg_discovery or social_focused):
            problems.append("MISSING_COMPONENT")
        if (q_components - kit_components - (_ENGINE_SUBCOMPONENTS if domain_expansion else set())) and not broad:
            problems.append("UNREQUESTED_COMPONENT")
        if kit_authorities and (q_authorities - kit_authorities):
            problems.append("UNREQUESTED_AUTHORITY")

        same_intent = any(_INTENTS[n].search(proposed) for n in matching_intents)
        supply_route = supply_kit and bool(_SUPPLY_CONTEXT.search(proposed))
        if require_scope and _missing_any(kit_authorities, kit_authorities & q_authorities) and not compared and channel != "social" and not supply_route:
            problems.append("MISSING_AUTHORITY")

        # If the query already carries an explicit aircraft model, family, or engine code from the KIT, do not force an extra entity.
        entity_covered = (
            any(re.search(rf"\b{re.escape(e)}\b", proposed, re.I) for e in entities)
            or has_dom_eng or has_dom_oem or bool((q_exact & kit_exact) or has_allowed_code or (q_fams & kit_families))
        )
        if require_scope and entities and not entity_covered:
            problems.append("MISSING_ENTITY")

        if (require_scope and not broad and narrow_subject and channel != "social"
                and not (same_intent or ("inspection" in matching_intents and reg_discovery) or supply_route or (not matching_intents and _NARROW_SCOPE.search(proposed)))):
            problems.append("ISSUE_SCOPE_MISMATCH")
        if require_scope and broad and supply_kit and not (_SUPPLY_CONTEXT.search(proposed) or same_intent):
            problems.append("ISSUE_SCOPE_MISMATCH")
        if any(re.search(rf"\b{re.escape(n)}\b", proposed, re.I) and not re.search(rf"(?:excluding|without|except|not\s+including|-)\s*\"?{re.escape(n)}\b", proposed, re.I) for n in exclusions):
            problems.append("EXCLUDED_ENTITY")
        if new_topics - allowed_topics:
            problems.append("ISSUE_SCOPE_MISMATCH")
        if added_years and ((as_of and any(int(y) > max_kit_year for y in added_years)) or (not broad and not _LIFECYCLE.search(proposed))):
            problems.append("TIME_SCOPE_MISMATCH")
        if require_scope and as_of and kit_years and not (kit_years & set(_YEAR_RE.findall(proposed))):
            problems.append("TIME_SCOPE_MISMATCH")
        return list(dict.fromkeys(problems))

    def fallback_query(proposed: str, channel: str) -> str:
        """Build a channel-appropriate compliant fallback query anchored on the KIT subject."""
        def _pick(*candidates: str) -> str:
            return next((c for c in candidates if not violations(c, channel=channel)), base_subject)

        if channel == "regulatory":
            cands = [" ".join(p for p in (domain_info["engine_models"][0], "airworthiness directive", negative) if p)] if (domain_expansion and domain_info["engine_models"]) else []
            cands.append(" ".join(p for p in (subject, "airworthiness directive", negative) if p))
            return _pick(*cands)
        if channel == "social":
            surf_models = surface_terms(subject, kit_exact, _detect_exact_variants) or (surface_terms(subject, kit_families, _detect_aircraft_families) if kit_families else [])
            cands = []
            if domain_expansion and domain_info["engine_models"]:
                base = f"{surf_models[0] if surf_models else ''} {domain_info['engine_models'][0]}".strip() or subject
                cands.append(" ".join(p for p in (base, negative) if p))
            parts = surf_models[:1] + surface_terms(subject, kit_codes, _codes)[:2] + surface_terms(subject, kit_components, _components)[:1]
            compact = " ".join(dict.fromkeys(parts)) if parts else " ".join(subject.split()[:4])
            cands.append(" ".join(p for p in (compact, negative) if p))
            return _pick(*cands)
        intent = "cause" if (_CAUSE.search(proposed) and _CAUSE.search(subject)) else ("status" if (_LIFECYCLE.search(proposed) and not as_of) else ("statement" if re.search(r"\bofficial\b", proposed, re.I) else ""))
        return _pick(" ".join(p for p in (subject, intent, negative) if p))

    def targeted_repair(proposed: str, reasons: list[str]) -> str:
        """Add only the missing KIT terms while preserving the planner's wording."""
        repairable = ADDITIVE_REASONS | ({"TIME_SCOPE_MISMATCH"} if as_of and kit_years else set())
        if not proposed or not set(reasons) <= repairable:
            return ""
        extra: list[str] = []
        if "MISSING_MODEL" in reasons:
            extra += surface_terms(subject, kit_exact - _detect_exact_variants(proposed), _detect_exact_variants)
            extra += surface_terms(subject, kit_codes - _codes(proposed), _codes)
        if "MISSING_COMPONENT" in reasons:
            extra += surface_terms(subject, kit_components - _components(proposed), _components)[:1]
        if "MISSING_AUTHORITY" in reasons:
            extra += sorted(kit_authorities - _authorities(proposed))[:1]
        if "MISSING_ENTITY" in reasons:
            if hit := next((m.group() for e in sorted(entities) if (m := re.search(rf"\b{re.escape(e)}\b", subject, re.I))), None):
                extra.append(hit)
        if "ISSUE_SCOPE_MISMATCH" in reasons:
            if hit := next((m.group() for p in _INTENTS.values() if (m := p.search(subject))), None):
                extra.append(hit)
        if "TIME_SCOPE_MISMATCH" in reasons and kit_years:
            extra += sorted(kit_years)
        cand = append_missing(proposed, extra)
        return cand if cand != proposed else ""

    def safe_query(proposed: str, channel: str, field: str) -> str:
        """Return proposed if valid, else try targeted additive repair before falling back."""
        proposed = proposed.strip() if isinstance(proposed, str) else ""
        if not (reasons := violations(proposed, channel=channel) if proposed else ["EMPTY_QUERY"]):
            return proposed
        if (repaired := targeted_repair(proposed, reasons)) and not violations(repaired, channel=channel):
            record(field, proposed, repaired, ["TARGETED_REPAIR", *reasons])
            additive_repairs[repaired] = proposed
            return repaired
        replacement = fallback_query(proposed, channel)
        if rem := violations(replacement, channel=channel):
            if (rep_fb := targeted_repair(replacement, rem)) and not violations(rep_fb, channel=channel):
                replacement = rep_fb
            else:
                record(field, proposed, replacement, [*reasons, "FALLBACK_BEST_EFFORT"])
                return replacement
        record(field, proposed, replacement, reasons)
        return replacement

    # Collect original planner queries and backfill missing objectives.
    raw_airshow = getattr(plan, "airshow_query", "") or ""
    originals = [
        q for f in ("media_and_pr_queries", "regulatory_and_ntsb_queries", "social_and_video_queries")
        for q in (getattr(plan, f, None) or []) if isinstance(q, str) and q.strip()
    ] + ([raw_airshow] if isinstance(raw_airshow, str) and raw_airshow.strip() else [])
    raw_obj = getattr(plan, "query_objectives", None)
    objectives: dict[str, str] = dict(raw_obj) if isinstance(raw_obj, dict) else {}

    def safe_objective(query: str) -> str:
        return f"Find dated source evidence addressing '{query}' and identify the facts, provenance and confirmations still missing."

    for orig_q in originals:
        if not isinstance(objectives.get(orig_q), str) or not objectives[orig_q].strip():
            objectives[orig_q] = safe_objective(orig_q)
            record("query_objectives", orig_q, orig_q, ["MISSING_OBJECTIVE_REPAIRED"])

    updated_objectives: dict[str, str] = {}

    def register(original: str, corrected: str, field: str, objective: str = "") -> bool:
        """Bind a sanitized query to its objective, rescoping or deduplicating collisions."""
        objective = objective or objectives.get(original, "")
        if not isinstance(objective, str) or not objective.strip():
            objective = safe_objective(corrected or original or subject)
            record(f"query_objectives.{field}", original or "", corrected, ["MISSING_OBJECTIVE_REPAIRED"])
        if corrected != original and additive_repairs.get(corrected) != original:
            record(f"query_objectives.{field}", objective, corrected, ["OBJECTIVE_RESCOPED_TO_REPAIRED_QUERY"])
            objective = safe_objective(corrected)

        if (previous := updated_objectives.get(corrected)) is not None:
            a, b = previous.strip().casefold(), objective.strip().casefold()
            if not (a == b or a in b or b in a):
                record(f"query_objectives.{field}", objective, corrected, ["OBJECTIVE_COLLISION_REPAIRED"])
                updated_objectives[corrected] = safe_objective(corrected)
            elif len(objective.strip()) > len(previous.strip()):
                updated_objectives[corrected] = objective
            if corrected != original:
                record(f"query_objectives.{field}", original, corrected, ["OBJECTIVE_REMAPPED"])
            record(field, original, corrected, ["QUERY_OBJECTIVE_REUSED" if field == "airshow_query" else "DUPLICATE_QUERY_COMPATIBLE_OBJECTIVE"])
            return False

        updated_objectives[corrected] = objective
        if corrected != original:
            record(f"query_objectives.{field}", original, corrected, ["OBJECTIVE_REMAPPED"])
        return True

    def sanitize_group(queries, channel: str, field: str) -> list[str]:
        results = []
        for i, orig_q in enumerate(queries or []):
            fname = f"{field}.{i}"
            corrected = safe_query(orig_q, channel, fname)
            register(orig_q if isinstance(orig_q, str) else "", corrected, fname)
            if corrected not in results:
                results.append(corrected)
        if not results and not (channel == "regulatory" and is_commercial_only):
            default_q = safe_query("", channel, f"{field}.0")
            register("", default_q, f"{field}.0")
            results.append(default_q)
        return results

    media = sanitize_group(plan.media_and_pr_queries, "media", "media_and_pr_queries")
    regulatory = sanitize_group(plan.regulatory_and_ntsb_queries, "regulatory", "regulatory_and_ntsb_queries")
    social = sanitize_group(plan.social_and_video_queries, "social", "social_and_video_queries")

    airshow = safe_query(raw_airshow, "airshow", "airshow_query")
    if len(airshow) > 120:
        terms = [*sorted(kit_codes), *sorted(kit_exact), *sorted(entities), *sorted(kit_components), *sorted(kit_authorities), *sorted(kit_years), *matching_intents]
        compact = " ".join(dict.fromkeys(terms))[:120].strip() or subject[:120].strip()
        if violations(compact, channel="airshow"):
            compact = airshow[:120].rsplit(" ", 1)[0].strip() or airshow[:120].strip()
            record("airshow_query", airshow, compact, ["QUERY_LENGTH_LIMIT_BEST_EFFORT"])
        else:
            record("airshow_query", airshow, compact, ["QUERY_LENGTH_LIMIT"])
        airshow = compact
    register(raw_airshow if isinstance(raw_airshow, str) else "", airshow, "airshow_query")

    unique_after = {q.casefold() for q in (*media, *regulatory, *social, airshow) if q}
    unique_before = {q.casefold() for q in originals if isinstance(q, str) and q}
    if len(unique_before) >= 4 and len(unique_after) < max(3, len(unique_before) // 2):
        record("plan", f"{len(unique_before)} distinct queries", f"{len(unique_after)} distinct queries", ["QUERY_DIVERSITY_LOW"])

    # Ensure each side of an explicit comparison KIT has dedicated media coverage when capacity allows.
    for entity in compared:
        if any(re.search(rf"\b{re.escape(entity)}\b", q, re.I) and not any(re.search(rf"\b{re.escape(o)}\b", q, re.I) for o in compared if o != entity) for q in media):
            continue
        focused = comparison_pattern.sub(entity, subject, count=1) + (" documented status" if as_of else " current status")
        if len(media) >= 4:
            record("media_and_pr_queries", focused, "", ["COMPARISON_CAPACITY_REACHED"])
            continue
        if f_viols := violations(focused, channel="media"):
            if (rep_f := targeted_repair(focused, f_viols)) and not violations(rep_f, channel="media"):
                focused = rep_f
            else:
                record(f"media_and_pr_queries.{len(media)}", focused, "", ["COMPARISON_QUERY_SKIPPED"])
                continue
        if register("", focused, f"media_and_pr_queries.{len(media)}", f"Find dated source evidence for {entity} within the requested KIT comparison."):
            media.append(focused)
            record(f"media_and_pr_queries.{len(media) - 1}", "", focused, ["COMPARISON_COVERAGE"])

    updates: dict = {
        "media_and_pr_queries": media, "regulatory_and_ntsb_queries": regulatory,
        "social_and_video_queries": social, "airshow_query": airshow, "query_objectives": updated_objectives,
    }

    # For causal KITs, ensure cause, impact, and causal-link information requirements are explicitly tracked.
    if _CAUSE.search(subject) and hasattr(plan, "information_requirements"):
        requirements = list(plan.information_requirements or [])
        core = re.sub(r"^(?:why|how|what)\s+(?:(?:did|does|do|has|have|is|are)\s+)?", "", subject, flags=re.I).rstrip(" ?")
        core = re.sub(r"\s+(?:occur|happen|arise|take\s+place)$", "", core, flags=re.I).strip()
        for label, purpose, question in (
            ("cause", SearchPurpose.CAUSE, f"What is the documented cause of {core}?"),
            ("impact", SearchPurpose.IMPACT, f"What was the documented impact of {core}?"),
            ("link", None, f"What evidence supports a causal link for {core}?"),
        ):
            if any((req.search_purposes == [purpose] if purpose else bool(re.search(r"\b(?:causal\s+link|causal\s+relation|causation)\b", req.question, re.I))) for req in requirements):
                continue
            requirements.append(InformationRequirement(
                question=question, search_purposes=[purpose] if purpose else [SearchPurpose.CAUSE, SearchPurpose.IMPACT], required_identity=identities,
            ))
            record(f"information_requirements.{len(requirements) - 1}", "", question, [f"MISSING_CAUSAL_{label.upper()}_REQUIREMENT"])
        updates["information_requirements"] = requirements

    # Guard strategy_rationale against unrequested models, excluded entities, or scope drift.
    rationale = plan.strategy_rationale or ""
    if rationale and (rat_viols := violations(rationale, require_scope=False)):
        trimmed = subject[:110].rsplit(" ", 1)[0] if len(subject) > 110 else subject
        replacement = f"Monitor {trimmed} with explicit KIT constraints and evidence-backed follow-up."
        record("strategy_rationale", rationale, replacement, rat_viols)
        rationale = replacement
    updates["strategy_rationale"] = rationale
    if "normalization_audit" in type(plan).model_fields:
        updates["normalization_audit"] = [*(plan.normalization_audit or []), *audit]
    return type(plan).model_validate(plan.model_copy(update=updates).model_dump())