"""KIT-to-query guard rules shared with the existing Planner stage."""

import re

from tasks import InformationRequirement, SearchPurpose
from ews_state import KIQPlan, logger
from aero_ews.intelligence.query_repair import ADDITIVE_REASONS, append_missing, surface_terms
from aero_ews.collection.queries import get_program_engine_domain
from ews_validation import (
    _detect_aircraft_families, _detect_engine_models,
    _detect_exact_variants, _detect_specific_variants,
)

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

_BROAD_SCOPE = re.compile(
    r"\b(?:supply[ -]?chain|supplier\w*|procurement|sourcing|logistic\w*|"
    r"market|industry|sector|strategic|competitive|business|risks?|production|operations?)\b", re.I,
)
_NARROW_SCOPE = re.compile(
    r"\b(?:inspect\w*|certif\w*|airworthiness|directive|compliance|"
    r"approval|repair\w*|overhaul\w*|technical\s+requirement\w*)\b", re.I,
)
_SUPPLY_SCOPE = re.compile(r"\b(?:supply[ -]?chain|supplier\w*|procurement|sourcing|logistic\w*)\b", re.I)
_SUPPLY_CONTEXT = re.compile(
    r"\b(?:suppl\w*|procure\w*|sourc\w*|logistic\w*|freight|shipping|"
    r"production|manufactur\w*|capacity|deliver\w*|shortag\w*|bottleneck\w*|"
    r"component\w*|parts?|inventory|lead[ -]?time\w*|contract\w*|orders?|export\w*|constraint\w*)\b", re.I,
)
_ENGINE_CODE = re.compile(
    r"\b(?:PW\d{3,5}[A-Z](?:-[A-Z0-9]+)?|LEAP[- ]?1[ABC]|GE9X|GE90|GENX|CFM56|"
    r"TRENT\s+(?:XWB(?:-\d+)?|[A-Z0-9]+)|FJ\d{2}(?:-\d\w*)?)\b", re.I,
)
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
    "supply", "chain", "risk", "risks", "monitor", "current", "latest", "global",
    "industry", "market", "aviation", "aircraft", "aerospace", "technical", "strategic",
    "production", "financial", "supplier", "suppliers", "inspection", "requirements",
    "max", "neo", "xlr", "xwb", "gtf", "ad", "aog", "mro", "oem", "sec", "esef",
    "engine", "engines", "status", "certification", "durability", "grounding",
    "delivery", "deliveries", "shortage", "impact", "forging", "forgings", "casting",
    "castings", "titanium", "and", "the", "for", "airline", "airlines", "group",
    "holdings", "systems", "canada", "corp", "inc", "ltd", "international", "commercial",
    "door", "plug", "finding", "findings", "investigation", "delay", "delays", "defect",
    "defects", "acquisition", "airshow", "labor", "labour", "strike", "availability",
    "spare", "parts", "flight", "test", "thrust", "link", "occur", "manifold", "fuel",
    "fleet", "directive", "directives", "airworthiness", "issues", "issue", "quality",
    "manufacturing", "why", "what", "how",
}
_AUTHORITIES = re.compile(r"\b(?:FAA|EASA|NTSB|TCCA|CAAC|ANAC|UK\s+CAA|CAA)\b", re.I)
_EXCLUSION = re.compile(
    r"(?i:\b(?:excluding|exclude|without|except(?:\s+for)?|other\s+than|not\s+including))\s+"
    r"([A-Za-z][\w-]*(?:\s+[A-Z][\w-]*)*)",
)
_COMPARISON = re.compile(
    r"\b([A-Z][\w-]*)\s+"
    r"(?:vs\.?|versus|compared\s+(?:to|with))\s+"
    r"([A-Z][\w-]*)\b"
)
_COMPARISON_ALT = re.compile(
    r"(?i:\b(?:compare|between))\s+([A-Z][\w-]*)\s+(?i:and|with)\s+([A-Z][\w-]*)\b"
)
_LIFECYCLE = re.compile(r"\b(?:current|latest|status|update\w*|since|after|follow[ -]?up|"
                        r"resolv\w*|resolution|recurr\w*|reopen\w*|improv\w*|worsen\w*)\b", re.I)
_CAUSE = re.compile(r"\b(?:why|caus\w*|because|due\s+to|led\s+to|leads\s+to|resulted\s+in)\b", re.I)
_INTENTS = {
    "inspection": re.compile(r"\binspect\w*\b", re.I),
    "certification": re.compile(r"\bcertif\w*\b", re.I),
    "airworthiness": re.compile(r"\b(?:airworthiness|directive)\b", re.I),
    "compliance": re.compile(r"\bcomplian\w*\b", re.I),
    "approval": re.compile(r"\bapprov\w*\b", re.I),
    "repair": re.compile(r"\b(?:repair\w*|overhaul\w*)\b", re.I),
}
_INSPECTION_REGULATION = re.compile(
    r"\b(?:airworthiness\s+directiv\w*|AD|service\s+bulletin\w*|"
    r"maintenance|inspect\w*|compliance|interval\w*|deadline\w*|"
    r"effective\s+date|mandatory\s+action\w*)\b", re.I,
)


def _components(text: str) -> set[str]:
    return {name for name, pattern in _COMPONENTS.items() if re.search(pattern, text or "", re.I)}


def _codes(text: str) -> set[str]:
    return {re.sub(r"[ -]", "", match.upper()) for match in _ENGINE_CODE.findall(text or "")}


def _code_is_allowed(code: str, allowed: set[str]) -> bool:
    return code in allowed or any(a.startswith(code) or code.startswith(a) for a in allowed)


def _authorities(text: str) -> set[str]:
    return {re.sub(r"\s+", " ", match.upper()) for match in _AUTHORITIES.findall(text or "")}


def _sanitize_kiq_plan_for_kit(kit: str, plan: KIQPlan) -> KIQPlan:
    """Protect explicit KIT constraints without suppressing evidence-led decomposition."""
    kit = (kit or "").strip()
    exclusions = {m.group(1).strip() for m in _EXCLUSION.finditer(kit)}
    subject = _EXCLUSION.sub("", kit).strip(" ,;-") or kit
    kit_families = _detect_aircraft_families(subject)
    kit_variants = _detect_specific_variants(subject)
    kit_exact = _detect_exact_variants(subject)
    if re.search(r"\b777X\b", subject, re.I):
        kit_exact = set(kit_exact) | {"777:8", "777:9"}
        kit_variants = set(kit_variants) | _detect_specific_variants("Boeing 777-8 777-9")
    kit_engines = _detect_engine_models(subject)
    kit_codes = _codes(subject)
    kit_components = _components(subject)
    kit_authorities = _authorities(subject)

    # EXPLICIT_SCOPE: konkrétní motor/kód v KIT zůstává zamčený.
    # DOMAIN_EXPANSION: obecný motorový KIT u konkrétního programu smí použít motory z doménové mapy.
    domain_expansion = bool(
        _ENGINE_TOPIC_RE.search(subject)
        and (kit_families or kit_variants or kit_exact)
        and not (kit_engines or kit_codes)
    )
    domain_info = (
        get_program_engine_domain(subject)
        if domain_expansion
        else {"engine_models": (), "engine_manufacturers": ()}
    )
    allowed_domain_engines = set().union(
        *(_detect_engine_models(m) for m in domain_info["engine_models"])
    ) if domain_info["engine_models"] else set()
    allowed_domain_codes = _codes(" ".join(domain_info["engine_models"]))
    allowed_domain_oems = {oem.lower() for oem in domain_info["engine_manufacturers"]}
    kit_years = set(re.findall(r"\b(?:19|20)\d{2}\b", subject))
    as_of = bool(re.search(r"\b(?:as\s+of|until|through|up\s+to|before|prior\s+to|"
                           r"between\s+(?:19|20)\d{2}\s+and|from\s+(?:19|20)\d{2}\s+to)\b", subject, re.I))
    broad = bool(_BROAD_SCOPE.search(subject)) and not (
        _NARROW_SCOPE.search(subject) or kit_components
    )
    supply_kit = bool(_SUPPLY_SCOPE.search(subject))
    allowed_topics = (
        {"engine", "shortage", "damage", "strike", "production", "orders", "finance", "logistics"}
        if supply_kit else {"production", "orders", "finance"} if broad else set()
    )
    comparison_pattern = _COMPARISON if _COMPARISON.search(subject) else _COMPARISON_ALT
    comparison = comparison_pattern.search(subject)
    compared = tuple(comparison.groups()) if comparison else ()
    entities = {
        token.lower() for token in re.findall(r"\b[A-Z][a-z]{2,}\b|\b[A-Z]{2,}\b", subject)
        if token.lower() not in _GENERIC_NAMES
        and token.upper() not in kit_authorities
        and token.upper() not in kit_codes
        and not any(token.lower() in excluded.lower().split() for excluded in exclusions)
    }
    identities = list(dict.fromkeys(
        [*sorted(entities), *sorted(kit_exact), *sorted(kit_codes),
         *sorted(kit_components), *sorted(kit_authorities)]
    ))
    audit: list[dict[str, str]] = []

    def record(field: str, original: str, replacement: str, reasons: list[str]) -> None:
        reason = ",".join(dict.fromkeys(reasons))
        audit.append({"field": field, "original": original,
                      "corrected": replacement, "reason": reason})
        logger.warning("[PLANNER KIT GUARD] %s: %s | %r -> %r", field, reason, original, replacement)

    def violations(proposed: str, require_scope: bool = True, channel: str = "") -> list[str]:
        proposed = proposed or ""
        q_exact = _detect_exact_variants(proposed)
        q_codes = _codes(proposed)
        q_engines = _detect_engine_models(proposed)
        q_components = _components(proposed)
        q_authorities = _authorities(proposed)
        allowed_engines = kit_engines | allowed_domain_engines
        allowed_codes = kit_codes | allowed_domain_codes
        has_domain_engine = bool(
            domain_expansion
            and ((q_codes & allowed_domain_codes) or (q_engines & allowed_domain_engines))
        )
        has_domain_oem = bool(
            domain_expansion
            and any(re.search(rf"\b{re.escape(oem)}\b", proposed, re.I) for oem in allowed_domain_oems)
        )
        has_allowed_code = bool(
            q_codes and allowed_codes and any(_code_is_allowed(c, allowed_codes) for c in q_codes)
        )
        new_topics = {
            name for name, pat in _PLANNER_UNREQUESTED_TOPICS.items()
            if re.search(pat, proposed, re.I) and not re.search(pat, subject, re.I)
        }
        if domain_expansion:
            new_topics.discard("damage")
        invalid_topics = new_topics - allowed_topics
        added_years = set(re.findall(r"\b(?:19|20)\d{2}\b", proposed)) - kit_years
        problems: list[str] = []

        unrequested_codes = {c for c in q_codes if not _code_is_allowed(c, allowed_codes)}
        if (_detect_aircraft_families(proposed) - kit_families
                or _detect_specific_variants(proposed) - kit_variants
                or q_exact - kit_exact
                or q_engines - allowed_engines
                or unrequested_codes):
            problems.append("UNREQUESTED_MODEL")

        # U multi-modelových/multi-motorových KITů stačí v jednom dotazu pokrýt alespoň jeden z požadovaných modelů.
        missing_exact = set() if (len(kit_exact) > 1 and (kit_exact & q_exact)) else (kit_exact - q_exact)
        matched_kit_codes = {c for c in kit_codes if any(_code_is_allowed(qc, {c}) for qc in q_codes)}
        missing_codes = set() if (len(kit_codes) > 1 and matched_kit_codes) else (kit_codes - matched_kit_codes)
        if domain_expansion and (has_domain_engine or has_domain_oem) and channel in {"regulatory", "social", "media"}:
            missing_exact = set()
        elif kit_codes and matched_kit_codes and channel in {"regulatory", "social"}:
            missing_exact = set()
        if require_scope and not compared and (missing_exact or missing_codes):
            problems.append("MISSING_MODEL")

        regulatory_discovery = (
            channel == "regulatory"
            and bool(_INSPECTION_REGULATION.search(proposed))
            and bool(matched_kit_codes or (kit_exact & q_exact) or has_domain_engine or not (kit_codes or kit_exact))
        )
        social_focused = (
            channel == "social"
            and bool(matched_kit_codes or (kit_exact & q_exact) or has_domain_engine)
        )
        missing_components = set() if (len(kit_components) > 1 and (kit_components & q_components)) else (
                    kit_components - q_components)
        if require_scope and not broad and missing_components and not (
                regulatory_discovery or social_focused
        ):
            problems.append("MISSING_COMPONENT")

        disallowed_components = (
                q_components - kit_components - (_ENGINE_SUBCOMPONENTS if domain_expansion else set())
        )
        if disallowed_components and not broad:
            problems.append("UNREQUESTED_COMPONENT")
        if q_authorities - kit_authorities and kit_authorities:
            problems.append("UNREQUESTED_AUTHORITY")

        matching_intents = [name for name, pattern in _INTENTS.items() if pattern.search(subject)]
        same_intent = any(_INTENTS[name].search(proposed) for name in matching_intents)
        inspection_route = ("inspection" in matching_intents and regulatory_discovery)
        supply_route = supply_kit and bool(_SUPPLY_CONTEXT.search(proposed))

        missing_authorities = set() if (len(kit_authorities) > 1 and (kit_authorities & q_authorities)) else (
                    kit_authorities - q_authorities)
        if (require_scope and missing_authorities
                and not compared and channel != "social" and not supply_route):
            problems.append("MISSING_AUTHORITY")

        # Pokud dotaz už jednoznačně nese model letadla, rodinu nebo kód motoru z KITu, nelep cizího výrobce.
        entity_covered = (
                any(re.search(rf"\b{re.escape(e)}\b", proposed, re.I) for e in entities)
                or has_domain_engine
                or has_domain_oem
                or bool(
            (q_exact & kit_exact) or has_allowed_code or (_detect_aircraft_families(proposed) & kit_families))
        )
        if require_scope and entities and not entity_covered:
            problems.append("MISSING_ENTITY")

        if (require_scope and not broad and _NARROW_SCOPE.search(subject)
                and channel != "social"
                and not (same_intent or inspection_route or supply_route
                         or (not matching_intents and _NARROW_SCOPE.search(proposed)))):
            problems.append("ISSUE_SCOPE_MISMATCH")
        if require_scope and broad and supply_kit and not (_SUPPLY_CONTEXT.search(proposed) or same_intent):
            problems.append("ISSUE_SCOPE_MISMATCH")
        if any(re.search(rf"\b{re.escape(name)}\b", proposed, re.I)
               and not re.search(rf"(?:excluding|without|except|not\s+including|-)\s*\"?{re.escape(name)}\b",
                                 proposed, re.I) for name in exclusions):
            problems.append("EXCLUDED_ENTITY")
        if invalid_topics:
            problems.append("ISSUE_SCOPE_MISMATCH")
        if added_years and (as_of and any(int(y) > max(map(int, kit_years), default=0)
                                    for y in added_years)
                            or not broad and not _LIFECYCLE.search(proposed)):
            problems.append("TIME_SCOPE_MISMATCH")
        if require_scope and as_of and kit_years and not kit_years.intersection(
            re.findall(r"\b(?:19|20)\d{2}\b", proposed)
        ):
            problems.append("TIME_SCOPE_MISMATCH")
        return list(dict.fromkeys(problems))

    def fallback_query(proposed: str, channel: str) -> str:
        negative = " ".join(f'-"{name}"' if " " in name else f"-{name}" for name in sorted(exclusions))
        base_subject = " ".join(part for part in (subject, negative) if part).strip() or kit
        if channel == "regulatory":
            if domain_expansion and domain_info["engine_models"]:
                core = domain_info["engine_models"][0]
                candidate = " ".join(part for part in (core, "airworthiness directive", negative) if part)
                if not violations(candidate, channel="regulatory"):
                    return candidate
            candidate = " ".join(part for part in (subject, "airworthiness directive", negative) if part)
            if not violations(candidate, channel="regulatory"):
                return candidate
            return base_subject
        if channel == "social":
            if domain_expansion and domain_info["engine_models"]:
                surface_models = surface_terms(subject, kit_exact, _detect_exact_variants)
                if not surface_models and kit_families:
                    surface_models = surface_terms(subject, kit_families, _detect_aircraft_families)
                model_hint = surface_models[0] if surface_models else ""
                base = f"{model_hint} {domain_info['engine_models'][0]}".strip() or subject
                candidate = " ".join(part for part in (base, negative) if part)
                if not violations(candidate, channel="social"):
                    return candidate
            model_parts = surface_terms(subject, kit_exact, _detect_exact_variants)[:1]
            if not model_parts and kit_families:
                model_parts = surface_terms(subject, kit_families, _detect_aircraft_families)[:1]
            parts = (
                model_parts
                + surface_terms(subject, kit_codes, _codes)[:2]
                + surface_terms(subject, kit_components, _components)[:1]
            )
            compact = " ".join(dict.fromkeys(parts)) if parts else " ".join(subject.split()[:4])
            candidate = " ".join(part for part in (compact, negative) if part)
            if not violations(candidate, channel="social"):
                return candidate
            return base_subject
        intent = (
            "cause" if _CAUSE.search(proposed) and _CAUSE.search(subject)
            else "status" if _LIFECYCLE.search(proposed) and not as_of
            else "statement" if re.search(r"\bofficial\b", proposed, re.I)
            else ""
        )
        candidate = " ".join(part for part in (subject, intent, negative) if part)
        if not violations(candidate, channel=channel):
            return candidate
        return base_subject

    additive_repairs: dict[str, str] = {}   # repaired query -> the planner's original

    def targeted_repair(proposed: str, reasons: list[str]) -> str:
        """Add only the missing KIT terms; keep the planner's distinctive wording."""
        repairable = ADDITIVE_REASONS | ({"TIME_SCOPE_MISMATCH"} if as_of and kit_years else set())
        if not proposed or not set(reasons) <= repairable:
            return ""
        extra: list[str] = []
        if "MISSING_MODEL" in reasons:
            extra += surface_terms(subject, kit_exact - _detect_exact_variants(proposed),
                                   _detect_exact_variants)
            extra += surface_terms(subject, kit_codes - _codes(proposed), _codes)
        if "MISSING_COMPONENT" in reasons:
            missing_comp = kit_components - _components(proposed)
            extra += surface_terms(subject, missing_comp, _components)[:1]
        if "MISSING_AUTHORITY" in reasons:
            extra += sorted(kit_authorities - _authorities(proposed))[:1]
        if "MISSING_ENTITY" in reasons:
            for entity in sorted(entities):
                found = re.search(rf"\b{re.escape(entity)}\b", subject, re.I)
                if found:
                    extra.append(found.group())
                    break
        if "ISSUE_SCOPE_MISMATCH" in reasons:
            for name, pattern in _INTENTS.items():
                found = pattern.search(subject)
                if found:
                    extra.append(found.group())
                    break
        if "TIME_SCOPE_MISMATCH" in reasons and kit_years:
            extra += sorted(kit_years)
        candidate = append_missing(proposed, extra)
        return candidate if candidate != proposed else ""

    def safe_query(proposed: str, channel: str, field: str) -> str:
        proposed = proposed.strip() if isinstance(proposed, str) else ""
        reasons = violations(proposed, channel=channel) if proposed else ["EMPTY_QUERY"]
        if reasons:
            repaired = targeted_repair(proposed, reasons)
            if repaired and not violations(repaired, channel=channel):
                record(field, proposed, repaired, ["TARGETED_REPAIR", *reasons])
                additive_repairs[repaired] = proposed
                return repaired
            replacement = fallback_query(proposed, channel)
            rem_reasons = violations(replacement, channel=channel)
            if rem_reasons:
                repaired_fallback = targeted_repair(replacement, rem_reasons)
                if repaired_fallback and not violations(repaired_fallback, channel=channel):
                    replacement = repaired_fallback
                else:
                    record(field, proposed, replacement, [*reasons, "FALLBACK_BEST_EFFORT"])
                    return replacement
            record(field, proposed, replacement, reasons)
            return replacement
        return proposed

    originals = [
        q for field in ("media_and_pr_queries", "regulatory_and_ntsb_queries", "social_and_video_queries")
        for q in (getattr(plan, field, None) or [])
        if isinstance(q, str) and q.strip()
    ]
    raw_airshow = getattr(plan, "airshow_query", "") or ""
    if isinstance(raw_airshow, str) and raw_airshow.strip():
        originals.append(raw_airshow)
    objectives = getattr(plan, "query_objectives", None)

    if not isinstance(objectives, dict):
        objectives = {}
    else:
        objectives = dict(objectives)

    def safe_objective(query: str) -> str:
        return (
            f"Find dated source evidence addressing '{query}' and identify "
            "the facts, provenance and confirmations still missing."
        )

    for original in originals:
        if (
            not isinstance(objectives.get(original), str)
            or not objectives[original].strip()
        ):
            objectives[original] = safe_objective(original)
            record("query_objectives", original, original, ["MISSING_OBJECTIVE_REPAIRED"])

    updated_objectives: dict[str, str] = {}

    def register(original: str, corrected: str, field: str, objective: str = "") -> bool:
        objective = objective or objectives.get(original, "")
        if not isinstance(objective, str) or not objective.strip():
            objective = safe_objective(corrected or original or subject)
            record(f"query_objectives.{field}", original or "", corrected, ["MISSING_OBJECTIVE_REPAIRED"])
        # An additive repair only adds missing KIT terms, so the planner's objective
        # still describes the query; a replacement does not and gets a safe objective.
        if corrected != original and additive_repairs.get(corrected) != original:
            record(
                f"query_objectives.{field}",
                objective,
                corrected,
                ["OBJECTIVE_RESCOPED_TO_REPAIRED_QUERY"],
            )
            objective = safe_objective(corrected)
        previous = updated_objectives.get(corrected)

        if previous is not None:
            a = previous.strip().casefold()
            b = objective.strip().casefold()

            if not (a == b or a in b or b in a):
                record(
                    f"query_objectives.{field}",
                    objective,
                    corrected,
                    ["OBJECTIVE_COLLISION_REPAIRED"],
                )
                updated_objectives[corrected] = safe_objective(corrected)
            elif len(objective.strip()) > len(previous.strip()):
                updated_objectives[corrected] = objective
            if corrected != original:
                record(f"query_objectives.{field}", original, corrected, ["OBJECTIVE_REMAPPED"])
            record(field, original, corrected, ["QUERY_OBJECTIVE_REUSED" if field == "airshow_query"
                                               else "DUPLICATE_QUERY_COMPATIBLE_OBJECTIVE"])
            return False
        updated_objectives[corrected] = objective
        if corrected != original:
            record(f"query_objectives.{field}", original, corrected, ["OBJECTIVE_REMAPPED"])
        return True

    def sanitize_group(queries, channel, field):
        results = []

        for i, original in enumerate(queries or []):
            field_name = f"{field}.{i}"
            corrected = safe_query(original, channel, field_name)
            register(original if isinstance(original, str) else "", corrected, field_name)
            if corrected not in results:
                results.append(corrected)

        is_commercial_only = bool(
            re.search(r"\b(?:orders?|airshow|farnborough|paris\s+air\s+show|dubai\s+airshow|purchas\w*|contract\w*)\b",
                      subject, re.I)
            and not _NARROW_SCOPE.search(subject)
            and not kit_authorities
            and not re.search(
                r"\b(?:defect\w*|crack\w*|ground\w*|incident\w*|accident\w*|investigation\w*|durabilit\w*)\b", subject,
                re.I)
        )
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
        terms = [*sorted(kit_codes), *sorted(kit_exact), *sorted(entities),
                 *sorted(kit_components), *sorted(kit_authorities), *sorted(kit_years)]
        terms += [name for name, pattern in _INTENTS.items() if pattern.search(subject)]
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
        record("plan", f"{len(unique_before)} distinct queries", f"{len(unique_after)} distinct queries",
               ["QUERY_DIVERSITY_LOW"])

    if compared:
        for entity in compared:
            if any(re.search(rf"\b{re.escape(entity)}\b", q, re.I) and not any(
                re.search(rf"\b{re.escape(other)}\b", q, re.I) for other in compared if other != entity
            ) for q in media):
                continue
            focused = comparison_pattern.sub(entity, subject, count=1) + (
                " documented status" if as_of else " current status"
            )
            if len(media) < 4:
                focused_violations = violations(focused, channel="media")
                if focused_violations:
                    repaired_focused = targeted_repair(focused, focused_violations)
                    if repaired_focused and not violations(repaired_focused, channel="media"):
                        focused = repaired_focused
                    else:
                        record(f"media_and_pr_queries.{len(media)}", focused, "", ["COMPARISON_QUERY_SKIPPED"])
                        continue
                objective = f"Find dated source evidence for {entity} within the requested KIT comparison."
                if register("", focused, f"media_and_pr_queries.{len(media)}", objective):
                    media.append(focused)
                    record(f"media_and_pr_queries.{len(media) - 1}", "", focused, ["COMPARISON_COVERAGE"])
            else:
                record("media_and_pr_queries", focused, "", ["COMPARISON_CAPACITY_REACHED"])

    updates = {
        "media_and_pr_queries": media,
        "regulatory_and_ntsb_queries": regulatory,
        "social_and_video_queries": social,
        "airshow_query": airshow,
        "query_objectives": updated_objectives,
    }

    if _CAUSE.search(subject) and hasattr(plan, "information_requirements"):
        requirements = list(plan.information_requirements or [])
        core = re.sub(r"^(?:why|how|what)\s+(?:(?:did|does|do|has|have|is|are)\s+)?",
                      "", subject, flags=re.I).rstrip(" ?")
        core = re.sub(r"\s+(?:occur|happen|arise|take\s+place)$", "", core, flags=re.I).strip()
        necessities = (
            ("cause", SearchPurpose.CAUSE, f"What is the documented cause of {core}?"),
            ("impact", SearchPurpose.IMPACT, f"What was the documented impact of {core}?"),
            ("link", None, f"What evidence supports a causal link for {core}?"),
        )
        for label, purpose, question in necessities:
            if any((req.search_purposes == [purpose] if purpose else
                    bool(re.search(r"\b(?:causal\s+link|causal\s+relation|causation)\b", req.question, re.I)))
                   for req in requirements):
                continue
            requirements.append(InformationRequirement(
                question=question, search_purposes=[purpose] if purpose else
                [SearchPurpose.CAUSE, SearchPurpose.IMPACT], required_identity=identities,
            ))
            record(f"information_requirements.{len(requirements) - 1}", "", question,
                   [f"MISSING_CAUSAL_{label.upper()}_REQUIREMENT"])
        updates["information_requirements"] = requirements

    rationale = plan.strategy_rationale or ""
    invalid_rationale = bool(violations(rationale, require_scope=False)) if rationale else False
    if invalid_rationale:
        trimmed_subject = subject[:110].rsplit(" ", 1)[0] if len(subject) > 110 else subject
        replacement = f"Monitor {trimmed_subject} with explicit KIT constraints and evidence-backed follow-up."
        record("strategy_rationale", rationale, replacement, violations(rationale, require_scope=False))
        rationale = replacement
    updates["strategy_rationale"] = rationale
    if "normalization_audit" in type(plan).model_fields:
        updates["normalization_audit"] = [*(plan.normalization_audit or []), *audit]
    return type(plan).model_validate(plan.model_copy(update=updates).model_dump())