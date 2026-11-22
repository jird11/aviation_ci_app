"""Deterministic KIT search constraints; matching does not establish an event as fact."""

import re
from typing import Any, Iterable


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
_CONSEQUENCE = re.compile(r"\b(?:impacts?\s+on|effects?\s+on|consequences?\s+for|"
                          r"leads?\s+to|leading\s+to|results?\s+in|affects?)\b", re.I)

# Extend these ontologies as data, never as company- or aircraft-specific branches.
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


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _positive(text: str) -> str:
    return _EXCLUDE.split(text or "", maxsplit=1)[0]


def _required(text: str) -> str:
    return _OPTIONAL.split(_positive(text), maxsplit=1)[0]


def _has_term(text: str, term: str) -> bool:
    tokens = re.findall(r"[a-z0-9]+", term.lower())
    pattern = r"[\s&./-]+".join(map(re.escape, tokens))
    return bool(pattern and re.search(rf"(?<![a-z0-9]){pattern}(?![a-z0-9])", text.lower()))


def _reg_key(value: str) -> str:
    key = re.sub(r"[\s-]", "", value.upper())
    if key.startswith("EASAAD"):
        return key.replace("EASAAD", "EASA", 1)
    return key[3:] if key.startswith("FAAAD") else key


def _model_key(value: str) -> str:
    key = re.sub(r"[\s-]+", "", value.lower())
    return re.sub(r"^(\d{3})(\d{1,2})max$", r"\1max\2", key)


def _reg_matches(text: str, *, positive_only: bool = True) -> list[tuple[str, str]]:
    source = _positive(text) if positive_only else text
    return [(m.group(), _reg_key(m.group())) for m in _REGULATORY.finditer(source)]


def kit_regulatory_ids(text: str) -> list[str]:
    """Exact, positive-scope docket, directive and Federal Register identifiers."""
    return _unique(re.sub(r"\s+", "-", value.upper()) for value, _ in _reg_matches(text))


def _model_matches(text: str, *, positive_only: bool = True) -> list[tuple[str, str]]:
    clean = _REGULATORY.sub(" ", _positive(text) if positive_only else text)
    matches = []
    for m in _MODELS.finditer(clean):
        value = m.group()
        prefix = re.match(r"[A-Za-z]+", value)
        if prefix and (prefix.group().upper() in {"FAA", "EASA", "NTSB", "ISO", "FY", "DOC"}
                       or re.fullmatch(r"[A-Za-z]{2,5}[- ](?:19|20)\d{2}", value)):
            continue
        matches.append((value, _model_key(value)))
    return matches


def kit_models(text: str) -> list[str]:
    return _unique(key for _, key in _model_matches(text))


def kit_entities(text: str, registry: Iterable[dict[str, Any]] = ()) -> list[str]:
    """Identify explicitly named companies without deriving them from models."""
    positive = _positive(text)
    entities = []
    for supplier in registry:
        names = [supplier.get("official_name"), supplier.get("name"), *(supplier.get("aliases") or [])]
        names = sorted((n for n in names if isinstance(n, str) and len(n) >= 3
                        and not any(c.isdigit() for c in n)), key=len, reverse=True)
        match = next((n for n in names if _has_term(positive, n)), None)
        if match and match.lower() not in {"spirit", "general", "air", "ge"}:
            entities.append(match)
    entities.extend(n for n in _FALLBACK_ENTITIES if _has_term(positive, n))
    entities.extend(m.group() for m in _NAMED_COMPANY.finditer(positive))
    return _unique(entities)


def _components(text: str) -> list[tuple[str, str]]:
    remaining, found = _positive(text), []
    for name, pattern, query in _COMPONENTS:
        if re.search(pattern, remaining, re.I):
            found.append((name, query))
            remaining = re.sub(pattern, " ", remaining, flags=re.I)
    return found


def kit_components(text: str) -> list[str]:
    return [name for name, _ in _components(text)]


def kit_aspects(text: str) -> list[str]:
    positive = _positive(text)
    return [name for name, pattern, _ in _ASPECTS if re.search(pattern, positive, re.I)]


def kit_events(text: str) -> list[str]:
    primary = _CONSEQUENCE.split(_required(text), maxsplit=1)[0]
    return [name for name, pattern, _ in _EVENTS if re.search(pattern, primary, re.I)]


def kit_exclusions(text: str) -> list[str]:
    match = _EXCLUDE.search(text or "")
    if not match:
        return []
    return _unique(part.strip(' .:;\"\'') for part in re.split(r",|;|\b(?:and|or)\b", text[match.end():], flags=re.I)
                   if part.strip(' .:;\"\''))


def _quote(value: str) -> str:
    return f'"{value}"' if " " in value or "-" in value else value


def newsapi_constraints(text: str, registry: Iterable[dict[str, Any]] = ()) -> list[str]:
    """AND identity anchors; OR related aspects to avoid coupling cause and effect."""
    core = _required(text)
    parts = [_quote(name) for name in kit_entities(core, registry)]
    parts.extend(_quote(value) for value in kit_regulatory_ids(core))
    parts.extend(_quote(value) for value, _ in _model_matches(core))
    parts.extend(query for _, query in _components(core))
    aspects = [query for name, pattern, query in _ASPECTS if re.search(pattern, _positive(text), re.I)]
    if aspects:
        parts.append(aspects[0] if len(aspects) == 1 else f"({' OR '.join(aspects)})")
    if not _CONSEQUENCE.search(core):
        events = [query for name, pattern, query in _EVENTS if re.search(pattern, core, re.I)]
        if events:
            parts.append(events[0] if len(events) == 1 else f"({' OR '.join(events)})")
    parts.extend(f"NOT {_quote(term)}" for term in kit_exclusions(text))
    return _unique(parts)


def preserve_kit_constraints(kit: str, proposed: str, registry: Iterable[dict[str, Any]] = ()) -> str:
    """Restore mandatory identities without forcing every cause/effect into one query."""
    query = (proposed or "").strip()
    for term in kit_exclusions(kit):
        if not re.search(rf'\bNOT\s+"?{re.escape(term)}', query, re.I):
            query = re.sub(rf'(?<!\w){re.escape(term)}(?!\w)', " ", query, flags=re.I)
    required_ids = {key for _, key in _reg_matches(kit)}
    query = _REGULATORY.sub(lambda m: m.group() if _reg_key(m.group()) in required_ids else " ", query)
    required_models = dict((key, value) for value, key in _model_matches(_required(kit)))
    if required_models:
        protected = list(_REGULATORY.finditer(query))
        for match in reversed(list(_MODELS.finditer(query))):
            if any(match.start() < r.end() and match.end() > r.start() for r in protected):
                continue
            if _model_key(match.group()) not in required_models:
                query = query[:match.start()] + " " + query[match.end():]
    extra = [_quote(name) for name in kit_entities(_required(kit), registry)
             if not _has_term(query, name)]
    extra.extend(_quote(value) for value, key in _reg_matches(_required(kit)) if key not in {
        item_key for _, item_key in _reg_matches(query)
    })
    present_models = set(kit_models(query))
    extra.extend(_quote(value) for key, value in required_models.items() if key not in present_models)
    present_components = set(kit_components(query))
    extra.extend(_quote(name) for name in kit_components(_required(kit)) if name not in present_components)
    required_aspects = set(kit_aspects(_required(kit))) if re.search(
        r"\b(?:only|solely|specifically|strictly)\b", _required(kit), re.I
    ) else set()
    extra.extend(name for name in required_aspects if name not in kit_aspects(query))
    if not _CONSEQUENCE.search(_required(kit)) and kit_events(kit) and not set(kit_events(kit)) & set(kit_events(query)):
        extra.append(next(value for name, _, value in _EVENTS if name == kit_events(kit)[0]))
    elif not kit_aspects(query) and not kit_events(query) and kit_aspects(kit):
        extra.append(kit_aspects(kit)[0])
    extra.extend(f"NOT {_quote(term)}" for term in kit_exclusions(kit)
                 if not re.search(rf"\bNOT\s+{re.escape(_quote(term))}", query, re.I))
    return " ".join(_unique([query, *extra])).strip()


def has_verified_subject_link(kit: str, document: str, registry: Iterable[dict[str, Any]] = ()) -> bool:
    """Check source identity, never infer specific applicability from industry terms."""
    requested_ids = {_reg_key(v) for v in kit_regulatory_ids(kit)}
    document_ids = {key for _, key in _reg_matches(document, positive_only=False)}
    if requested_ids and not requested_ids.issubset(document_ids):
        return False
    models = set(kit_models(kit))
    document_models = {key for _, key in _model_matches(document, positive_only=False)}
    if models and document_models and not models & document_models:
        return False
    requested = kit_entities(kit, registry)
    matched_company = any(_has_term(document, name) for name in requested)
    if matched_company and re.search(r"\b(?:film|movie|actor|actress|cinema|hollywood)\b", document, re.I):
        if not re.search(r"\b(?:aerospace|aviation|aircraft|engine|turbine|industrial|flight)\b", document, re.I):
            return False
    return bool(requested_ids or (models & document_models) or matched_company)
