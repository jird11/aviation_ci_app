"""Deterministic KIT search constraints; matching does not establish an event as fact."""

import re
from typing import Any, Iterable

# Compiled KIT parsing patterns and extensible data ontologies (preserved verbatim).
_REGULATORY = re.compile(
    r"(?<![A-Za-z0-9])(?:FAA[-\s]+20\d{2}[-\s]+\d{3,6}"
    r"|EASA(?:[-\s]+AD)?[-\s]+20\d{2}[-\s]+\d{3,5}(?:[-\s]*R\d+)?"
    r"|(?:FAA[-\s]+)?AD[-\s]+20\d{2}[-\s]+\d{2}[-\s]+\d{2}"
    r"|20\d{2}-\d{5})(?![A-Za-z0-9])", re.I,
)
_MODELS = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z]{1,5}[- ]?\d{2,5}(?:[A-Za-z]{1,3}|MAX\d{1,2})?"
    r"(?:-[A-Za-z0-9]{1,7}){0,2}(?:\s+(?:MAX\s*\d{1,2}|XLR|NEO|CEO|NG|ER|LR|E2))?"
    r"|[A-Za-z]{1,5}[- ]?\d[A-Za-z](?:-[A-Za-z0-9]{1,7})?"
    r"|\d{3}(?:[- ]?(?:\d{1,4}[A-Za-z]?|MAX[- ]?\d{1,2}|XLR|NEO|CEO|NG|ER|LR|E2|X|F))?"
    r"(?:[- ]?(?:MAX[- ]?\d{0,2}|XLR|NEO|CEO|NG|ER|LR|E2|X|F))?)"
    r"(?![A-Za-z0-9])", re.I,
)
_EXCLUDE = re.compile(r"\b(?:exclude|excluding|except|but\s+not|not\s+about|rather\s+than|ignore)\b", re.I)
_OPTIONAL = re.compile(r"\b(?:including|such\s+as|for\s+example|e\.g\.|optionally)\b", re.I)
_CONSEQUENCE = re.compile(r"\b(?:impacts?\s+on|effects?\s+on|consequences?\s+for|leads?\s+to|leading\s+to|results?\s+in|affects?)\b", re.I)

_COMPONENTS = (
    ("hpt", r"\b(?:hpt|high[- ]pressure\s+turbine)\b", '(HPT OR "high pressure turbine")'),
    ("hpc", r"\b(?:hpc|high[- ]pressure\s+compressor)\b", '(HPC OR "high pressure compressor")'),
    ("fan blade", r"\b(?:fan\s+blades?|fanblade\w*)\b", '("fan blade" OR "fan blades")'),
    ("landing gear", r"\blanding[- ]gear\b", '"landing gear"'),
    ("flight control", r"\bflight[- ]control(?:\s+systems?)?\b", '"flight control"'),
    ("aerostructure", r"\baerostructures?\b", '(aerostructure OR aerostructures)'),
    ("fuselage", r"\bfuselages?\b", '(fuselage OR fuselages)'),
    ("avionics", r"\bavionics\b", 'avionics'),
    ("nacelle", r"\bnacelles?\b", '(nacelle OR nacelles)'),
    ("combustor", r"\b(?:combustors?|combustion\s+chambers?)\b", '(combustor OR "combustion chamber")'),
    ("gearbox", r"\b(?:gearboxes|gearbox)\b", '(gearbox OR gearboxes)'),
    ("bearing", r"\bbearings?\b", '(bearing OR bearings)'),
    ("casting", r"\bcastings?\b", '(casting OR castings)'),
    ("forging", r"\bforgings?\b", '(forging OR forgings)'),
    ("brake", r"\bbrakes?\b", '(brake OR brakes)'),
    ("turbine", r"\bturbines?\b", '(turbine OR turbines)'),
    ("compressor", r"\bcompressors?\b", '(compressor OR compressors)'),
    ("engine", r"\bengines?\b", '(engine OR engines)'),
    ("blade", r"\bblades?\b", '(blade OR blades)'),
    ("wing", r"\bwings?\b", '(wing OR wings)'),
)
_ASPECTS = (
    ("quality", r"\b(?:quality|defect\w*|nonconform\w*|rework|inspect\w*)\b", '(quality OR defect OR inspection)'),
    ("supply", r"\b(?:supply|supplies|supplier|shortag\w*|constraint\w*|bottleneck\w*)\b", '(supply OR shortage OR constraint)'),
    ("delivery", r"\b(?:deliver\w*|disrupt\w*|delay\w*|schedule\w*)\b", '(delivery OR disruption OR delay)'),
    ("production", r"\b(?:production|manufactur\w*|ramp\w*|capacity|assembly)\b", '(production OR manufacturing OR capacity)'),
    ("regulatory", r"\b(?:airworthiness|directiv\w*|regulat\w*|certif\w*|compliance)\b", '(airworthiness OR directive OR certification)'),
    ("commercial", r"\b(?:orders?|purchas\w*|contracts?|leas\w*)\b", '(order OR contract OR purchase)'),
    ("cause", r"\b(?:root\s+cause|causes?|failure\s+mechanism|technical\s+origin)\b", '(cause OR "failure mechanism")'),
)
_EVENTS = (
    ("supersession", r"\bsupersed\w*\b", '(superseded OR superseding)'),
    ("withdrawal", r"\bwithdraw\w*\b", '(withdrawn OR withdrawal)'),
    ("amendment", r"\bamend\w*\b", '(amended OR amendment)'),
    ("certification", r"\bcertif\w*\b", '(certification OR certified)'),
    ("shortage", r"\b(?:shortag\w*|bottleneck\w*|supply\s+constraint\w*)\b", '(shortage OR bottleneck)'),
    ("failure", r"\b(?:fail\w*|defect\w*|fractur\w*)\b", '(failure OR defect)'),
    ("delay", r"\bdelay\w*\b", '(delay OR delayed)'),
    ("inspection", r"\binspect\w*\b", '(inspection OR inspected)'),
    ("grounding", r"\bground\w*\b", '(grounding OR grounded)'),
    ("production", r"\b(?:production|manufactur\w*|ramp[- ]?up)\b", '(production OR manufacturing)'),
    ("delivery", r"\bdeliver\w*\b", '(delivery OR deliveries)'),
    ("order", r"\borders?\b", '(order OR orders)'),
    ("strike", r"\bstrikes?\b", '(strike OR strikes)'),
)
_FALLBACK_ENTITIES = (
    "Spirit AeroSystems", "GE Aerospace", "Pratt Whitney", "Rolls-Royce",
    "CFM International", "Safran", "Airbus", "Boeing", "Embraer", "COMAC", "RTX",
)
_NAMED_COMPANY = re.compile(
    r"\b[A-Z][\w&.-]*(?:\s+[A-Z][\w&.-]*){0,3}\s+"
    r"(?:Aerospace|AeroSystems|Aviation|Airlines|Airways|Engines|Aerostructures|Technologies|"
    r"Industries|Systems|Corporation|Limited|Ltd|PLC|Inc)\b"
)
_EVENT_QUERY = {name: q for name, _, q in _EVENTS}
_IGNORED_MODEL_PREFIXES = {"FAA", "EASA", "NTSB", "ISO", "FY", "DOC"}
_AMBIGUOUS_ENTITY_NAMES = {"spirit", "general", "air", "ge"}


# Scope-slicing, quoting, deduplication, and identifier normalization helpers.
def _unique(values: Iterable[str]) -> list[str]: return list(dict.fromkeys(values))
def _positive(text: str) -> str: return _EXCLUDE.split(text or "", maxsplit=1)[0]
def _required(text: str) -> str: return _OPTIONAL.split(_positive(text), maxsplit=1)[0]
def _quote(value: str) -> str: return f'"{value}"' if (" " in value or "-" in value) else value
def _or_group(items: list[str]) -> str: return items[0] if len(items) == 1 else f"({' OR '.join(items)})"
def _model_key(value: str) -> str: return re.sub(r"^(\d{3})(\d{1,2})max$", r"\1max\2", re.sub(r"[\s-]+", "", value.lower()))
def _reg_matches(text: str, *, positive_only: bool = True) -> list[tuple[str, str]]: return [(m.group(), _reg_key(m.group())) for m in _REGULATORY.finditer(_positive(text) if positive_only else text)]
def kit_regulatory_ids(text: str) -> list[str]: return _unique(re.sub(r"\s+", "-", v.upper()) for v, _ in _reg_matches(text))
def kit_models(text: str) -> list[str]: return _unique(k for _, k in _model_matches(text))
def kit_components(text: str) -> list[str]: return [name for name, _ in _components(text)]
def kit_aspects(text: str) -> list[str]: return [n for n, p, _ in _ASPECTS if re.search(p, _positive(text), re.I)]
def kit_events(text: str) -> list[str]: return [n for n, p, _ in _EVENTS if re.search(p, _CONSEQUENCE.split(_required(text), maxsplit=1)[0], re.I)]


def _has_term(text: str, term: str) -> bool:
    """Match term tokens on alphanumeric boundaries across separators."""
    pat = r"[\s&./-]+".join(map(re.escape, re.findall(r"[a-z0-9]+", term.lower())))
    return bool(pat and re.search(rf"(?<![a-z0-9]){pat}(?![a-z0-9])", text.lower()))


def _reg_key(value: str) -> str:
    """Normalize regulatory IDs so FAA/EASA AD formatting variants compare equal."""
    key = re.sub(r"[\s-]", "", value.upper())
    return key.replace("EASAAD", "EASA", 1) if key.startswith("EASAAD") else (key[3:] if key.startswith("FAAAD") else key)


def _model_matches(text: str, *, positive_only: bool = True) -> list[tuple[str, str]]:
    """Return (raw_model, canonical_key) pairs while excluding agency and year codes."""
    clean = _REGULATORY.sub(" ", _positive(text) if positive_only else text)
    return [
        (v, _model_key(v)) for m in _MODELS.finditer(clean)
        if not ((p := re.match(r"[A-Za-z]+", v := m.group())) and (
            p.group().upper() in _IGNORED_MODEL_PREFIXES or re.fullmatch(r"[A-Za-z]{2,5}[- ](?:19|20)\d{2}", v)
        ))
    ]


def kit_entities(text: str, registry: Iterable[dict[str, Any]] = ()) -> list[str]:
    """Identify explicitly named companies without deriving them from aircraft models."""
    positive, entities = _positive(text), []
    for sup in registry:
        names = sorted((n for n in (sup.get("official_name"), sup.get("name"), *(sup.get("aliases") or []))
                        if isinstance(n, str) and len(n) >= 3 and not any(c.isdigit() for c in n)), key=len, reverse=True)
        if (hit := next((n for n in names if _has_term(positive, n)), None)) and hit.lower() not in _AMBIGUOUS_ENTITY_NAMES:
            entities.append(hit)
    entities.extend(n for n in _FALLBACK_ENTITIES if _has_term(positive, n))
    entities.extend(m.group() for m in _NAMED_COMPANY.finditer(positive))
    return _unique(entities)


def _components(text: str) -> list[tuple[str, str]]:
    """Extract non-overlapping component (name, query_clause) pairs in specificity order."""
    rem, found = _positive(text), []
    for name, pat, q in _COMPONENTS:
        if re.search(pat, rem, re.I):
            found.append((name, q))
            rem = re.sub(pat, " ", rem, flags=re.I)
    return found


def kit_exclusions(text: str) -> list[str]:
    """Extract explicitly excluded terms following an exclusion marker."""
    if not (m := _EXCLUDE.search(text or "")):
        return []
    return _unique(t for p in re.split(r",|;|\b(?:and|or)\b", text[m.end():], flags=re.I) if (t := p.strip(' .:;"\'')))


def newsapi_constraints(text: str, registry: Iterable[dict[str, Any]] = ()) -> list[str]:
    """AND identity anchors; OR related aspects to avoid coupling cause and effect."""
    core, pos = _required(text), _positive(text)
    parts = [
        *(_quote(n) for n in kit_entities(core, registry)),
        *(_quote(v) for v in kit_regulatory_ids(core)),
        *(_quote(v) for v, _ in _model_matches(core)),
        *(q for _, q in _components(core)),
    ]
    if aspects := [q for _, pat, q in _ASPECTS if re.search(pat, pos, re.I)]:
        parts.append(_or_group(aspects))
    if not _CONSEQUENCE.search(core) and (events := [q for _, pat, q in _EVENTS if re.search(pat, core, re.I)]):
        parts.append(_or_group(events))
    parts.extend(f"NOT {_quote(t)}" for t in kit_exclusions(text))
    return _unique(parts)


def preserve_kit_constraints(kit: str, proposed: str, registry: Iterable[dict[str, Any]] = ()) -> str:
    """Restore mandatory identities without forcing every cause/effect into one query."""
    query, core, exclusions = (proposed or "").strip(), _required(kit), kit_exclusions(kit)
    for term in exclusions:
        if not re.search(rf'\bNOT\s+"?{re.escape(term)}', query, re.I):
            query = re.sub(rf"(?<!\w){re.escape(term)}(?!\w)", " ", query, flags=re.I)

    required_ids = {k for _, k in _reg_matches(kit)}
    query = _REGULATORY.sub(lambda m: m.group() if _reg_key(m.group()) in required_ids else " ", query)
    req_models = {k: v for v, k in _model_matches(core)}
    if req_models:
        protected = list(_REGULATORY.finditer(query))
        for m in reversed(list(_MODELS.finditer(query))):
            if not any(m.start() < r.end() and m.end() > r.start() for r in protected) and _model_key(m.group()) not in req_models:
                query = f"{query[:m.start()]} {query[m.end():]}"

    q_reg_keys, q_models, q_comps = {k for _, k in _reg_matches(query)}, set(kit_models(query)), set(kit_components(query))
    q_aspects, q_events = kit_aspects(query), kit_events(query)
    extra = [
        *(_quote(n) for n in kit_entities(core, registry) if not _has_term(query, n)),
        *(_quote(v) for v, k in _reg_matches(core) if k not in q_reg_keys),
        *(_quote(v) for k, v in req_models.items() if k not in q_models),
        *(_quote(n) for n in kit_components(core) if n not in q_comps),
    ]
    if re.search(r"\b(?:only|solely|specifically|strictly)\b", core, re.I):
        extra.extend(n for n in set(kit_aspects(core)) if n not in q_aspects)

    k_events, k_aspects = kit_events(kit), kit_aspects(kit)
    if not _CONSEQUENCE.search(core) and k_events and not (set(k_events) & set(q_events)):
        extra.append(_EVENT_QUERY[k_events[0]])
    elif not q_aspects and not q_events and k_aspects:
        extra.append(k_aspects[0])

    extra.extend(f"NOT {_quote(t)}" for t in exclusions if not re.search(rf"\bNOT\s+{re.escape(_quote(t))}", query, re.I))
    return " ".join(_unique([query, *extra])).strip()


def has_verified_subject_link(kit: str, document: str, registry: Iterable[dict[str, Any]] = ()) -> bool:
    """Check source identity without inferring specific applicability from generic industry terms."""
    req_ids = {_reg_key(v) for v in kit_regulatory_ids(kit)}
    doc_ids = {k for _, k in _reg_matches(document, positive_only=False)}
    if req_ids and not req_ids.issubset(doc_ids):
        return False
    models, doc_models = set(kit_models(kit)), {k for _, k in _model_matches(document, positive_only=False)}
    if models and doc_models and not (models & doc_models):
        return False
    matched_company = any(_has_term(document, n) for n in kit_entities(kit, registry))
    if matched_company and re.search(r"\b(?:film|movie|actor|actress|cinema|hollywood)\b", document, re.I):
        if not re.search(r"\b(?:aerospace|aviation|aircraft|engine|turbine|industrial|flight)\b", document, re.I):
            return False
    return bool(req_ids or (models & doc_models) or matched_company)