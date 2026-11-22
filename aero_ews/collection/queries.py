"""NewsAPI query planning with stable regulatory and technical identities."""

import re
from collections.abc import Iterable
from typing import Literal


MAX_QUERY_LENGTH = 500  # NewsAPI /v2/everything q limit.

REGULATORY_RE = re.compile(
    r"(?<!\w)(?:FAA[-\s]+20\d{2}[-\s]+\d{3,7}"
    r"|(?:FAA|EASA|(?-i:[A-Z]{2,10}))[-\s]+(?:AD|EAD|PAD|SB|NPRM|AC|SAIB|DOCKET|RIN)[-\s]+20\d{2}[-/]\d{1,6}(?:[-/]\d{1,6})?"
    r"|(?:FAA|EASA|CAA|TCCA|CAAC|ANAC|CASA|DGAC|ICAO|EU|NPRM|RIN)"
    r"(?:[-\s]+(?:AD|DOCKET|RIN))[-\s]+[A-Z0-9]{2,8}(?:[-/][A-Z0-9]{1,8}){1,3}"
    r"|(?:AD|DOCKET|RIN)[-\s]+[A-Z0-9]{2,8}(?:[-/][A-Z0-9]{1,8}){1,3}"
    r"|20\d{2}-\d{4,6}"
    r"|(?:(?:ICAO|(?-i:[A-Z]{2,10}))[-\s]+)?(?:DOC|DOCUMENT)[-\s]+(?!20\d{2}-)\d{3,6})(?!\w)",
    re.I,
)
AIRCRAFT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"(?:ATR|DASH|GLOBAL|CHALLENGER|FALCON|SUPERJET|PHENOM|PRAETOR|CITATION|KING\s+AIR)[-\s]+\d{1,4}[A-Z0-9-]*"
    r"|[A-Z]{1,8}[-]?\d{1,5}[A-Z0-9]*"
    r"(?:[-/][A-Z0-9]{1,7}|[ -](?:MAX(?:\s*\d{1,2})?|NEO|CEO|XLR|E2|\d{1,4})){0,2}"
    r"|[1-9]\d{2}(?:[-\s]*MAX(?:[-\s]*\d{1,2})?|[- ](?:\d{1,3}|NG|ER|LR|XLR|F))?"
    r")(?![A-Za-z0-9])",
    re.I,
)
ENGINE_RE = re.compile(
    r"(?<!\w)(?:"
    r"TRENT[- ]+(?:XWB(?:[- ]?\d{2})?|\d{2,4})"
    r"|PEARL[- ]+(?:700|10X|15)"
    r"|PASSPORT(?:[- ]?20)?"
    r"|GENX(?:[- ]?[12]B)?"
    r"|SAM[- ]?146"
    r"|TV7[- ]?117[A-Z0-9-]*"
    r"|(?-i:[A-Z]{2,4})[- ]+(?!20\d{2}\b)\d{1,4}[A-Z0-9-]*"
    r")(?!\w)",
    re.I,
)
MODEL_TOKEN_RE = re.compile(f"(?:{AIRCRAFT_RE.pattern}|{ENGINE_RE.pattern})", re.I)

# Company and product discovery is open-ended; aliases only normalize spelling.
ENTITY_SUFFIX_RE = re.compile(
    r"\b([a-z][\w&'-]{1,})\s+"
    r"(aerospace|aerostructures|aerosystems|aviation|airlines|systems|"
    r"technologies|industries|group|corporation|corp|inc|ltd)\b", re.I,
)
PROPER_NAME_RE = re.compile(r"\b(?:[A-Z][A-Za-z]{1,}|(?=[A-Z0-9]*[A-Z])[A-Z0-9]{2,6})\b")
AGENCIES = frozenset({"faa", "easa", "ntsb", "icao", "caa", "tcca", "caac", "anac", "casa", "dgac"})
COMPONENTS = (
    (r"\bhpt\b|\bhigh[- ]pressure\s+turbine\b", ("HPT", "high pressure turbine")),
    (r"\bhpc\b|\bhigh[- ]pressure\s+compressor\b", ("HPC", "high pressure compressor")),
    (r"\bfan\s+blades?\b", ("fan blade", "fan blades")),
    (r"\blanding\s+gear\b", ("landing gear",)),
    (r"\bgearbox\b", ("gearbox",)),
    (r"\bturbine\b", ("turbine",)),
    (r"\bcompressor\b", ("compressor",)),
    (r"\bbearing\b", ("bearing",)),
    (r"\bbrakes?\b", ("brake", "brakes")),
    (r"\bengines?\b", ("engine", "engines")),
)
EVENTS = (
    (r"\bsupersed\w*\b", ("superseded", "superseding")),
    (r"\bamend\w*\b", ("amended", "amendment")),
    (r"\bwithdraw\w*\b", ("withdrawn", "withdrawal")),
    (r"\b(?:directiv\w*|airworth\w*|AD)\b", ("directive", "airworthiness directive")),
    (r"\b(?:shortag\w*|bottleneck\w*|supply\s+constraint\w*)\b", ("shortage", "bottleneck", "supply constraints")),
    (r"\bdelay\w*\b", ("delay", "delayed", "delays")),
    (r"\b(?:certif\w*|approv\w*|type\s+certificate)\b",
     ("certification", "certified", "approved", "cleared", "granted", "type certificate")),
    (r"\binspect\w*\b", ("inspection", "inspected")),
    (r"\b(?:fail\w*|defect\w*)\b", ("failure", "defect")),
    (r"\bground\w*\b", ("grounded", "grounding")),
    (r"\bcancel\w*\b", ("cancelled", "cancellations")),
    (r"\b(?:produc\w*|manufactur\w*)\b", ("production", "manufacturing")),
    (r"\bdeliver\w*\b", ("deliveries", "delivery")),
    (r"\border\w*\b", ("orders", "order")),
    (r"\bcontract\w*\b", ("contract", "contracts")),
    (r"\b(?:sourc\w*|procur\w*)\b", ("sourcing", "procurement")),
    (r"\binvestigat\w*\b", ("investigation", "investigating", "findings")),
    (r"\binvest(?:ment|ing|ed|ors?|s)?\b", ("investment", "investing")),
    (r"\bexpan\w*\b", ("expansion", "expanding")),
    (r"\bmaintenan\w*\b", ("maintenance", "maintaining")),
    (r"\bregulat\w*\b", ("regulatory", "regulation")),
    (r"\b(?:disrupt\w*|interrupt\w*)\b", ("disruption", "interruption")),
)
INDUSTRY_CONTEXT = ("aerospace", "aviation", "aircraft", "engine", "airline", "turbine", "maintenance")
STATUS_TERMS = (
    (r"\b(?:certif\w*|approv\w*|type\s+certificate)\b",
     ("certification decision", "type certificate status")),
    (r"\b(?:delay\w*|postpon\w*|disrupt\w*)\b",
     ("current delay status", "revised delivery schedule")),
    (r"\b(?:shortag\w*|bottleneck\w*|constraint\w*)\b",
     ("current shortage status", "supply constraint update")),
    (r"\b(?:ground\w*|airworth\w*)\b",
     ("airworthiness status", "operational restriction update")),
    (r"\binspect\w*\b", ("inspection requirements", "inspection compliance interval")),
    (r"\bsupersed\w*\b", ("superseded", "replaced")),
    (r"\bamend\w*\b", ("amended", "revised")),
    (r"\bwithdraw\w*\b", ("withdrawn", "rescinded")),
)

# Information needs describe what must be established, not an assumed outcome.
# Multiple needs can coexist in one KIT; no aircraft or engine catalogue is used.
NEED_SEARCH_TERMS = {
    "INSPECTION_OBLIGATION": ("mandatory inspection airworthiness directive", "inspection applicability requirements"),
    "INSPECTION_DEADLINE": ("inspection compliance interval", "inspection deadline effective date"),
    "INSPECTION_COMPLETION": ("inspection completion records", "inspection sign-off evidence"),
    "RETURN_TO_SERVICE": ("return to service records", "operational service restoration"),
    "REGULATORY_REVISION": ("amended superseding directive", "regulatory revision effective date"),
    "TECHNICAL_DEFECT": ("technical defect findings", "affected component defect scope"),
    "REPAIR_COMPLETION": ("completed corrective action verification", "repair closure evidence"),
    "CERTIFICATION_STATUS": ("certification decision status", "issued type certificate decision"),
    "SUPPLY_DISRUPTION": ("supply disruption status", "production delivery constraints"),
    "GENERAL_STATUS": ("current documented status", "latest official update"),
}


def classify_information_needs(query: str) -> tuple[str, ...]:
    """Identify independent evidence needs without inferring an event's outcome."""
    text = re.sub(r"\s+", " ", query or "").casefold()
    inspection = bool(re.search(r"\binspect\w*\b", text))
    completion = bool(re.search(
        r"\b(?:inspect\w*\s+(?:complet\w*|finish\w*|perform\w*|sign(?:ed)?[ -]off)"
        r"|(?:complet\w*|finish\w*|perform\w*)\s+(?:the\s+)?inspect\w*"
        r"|inspection\s+(?:completion|sign[ -]off))\b", text))
    needs = []

    def add(name: str, condition: bool) -> None:
        if condition:
            needs.append(name)

    add("INSPECTION_OBLIGATION", inspection and bool(re.search(
        r"\b(?:requirement\w*|mandat\w*|obligat\w*|directive\w*|compliance)\b", text)))
    add("INSPECTION_DEADLINE", inspection and bool(re.search(
        r"\b(?:deadline\w*|interval\w*|due\s+date|compliance\s+time|time\s+limit)\b", text)))
    add("INSPECTION_COMPLETION", inspection and completion)
    add("RETURN_TO_SERVICE", bool(re.search(
        r"\b(?:return(?:ed|ing)?\s+to\s+service|back\s+in\s+service|"
        r"resum(?:ed|ing|ption)\s+(?:of\s+)?operations?)\b", text)))
    add("REGULATORY_REVISION", bool(re.search(r"\b(?:amend\w*|supersed\w*|withdraw\w*|rescinded|revis\w*)\b", text)
                                     and re.search(r"\b(?:regulat\w*|directive\w*|rule\w*|ad|docket|faa|easa)\b", text)))
    add("TECHNICAL_DEFECT", bool(re.search(r"\b(?:defect\w*|failur\w*|crack\w*|fractur\w*|fault\w*|malfunction\w*)\b", text)))
    add("REPAIR_COMPLETION", bool(re.search(
        r"\b(?:repair\w*|corrective\s+action)\b.*\b(?:complet\w*|verif\w*|closed|resolved)\b"
        r"|\b(?:complet\w*|verif\w*)\b.*\brepair\w*\b", text)))
    add("CERTIFICATION_STATUS", bool(re.search(r"\b(?:certif\w*|type\s+approv\w*|type\s+certificate)\b", text)))
    add("SUPPLY_DISRUPTION", bool(re.search(
        r"\b(?:supply\s+chain|shortag\w*|bottleneck\w*|production\s+delay\w*|delivery\s+delay\w*|disrupt\w*)\b", text)))
    if not needs and re.search(r"\b(?:status|latest|current|progress|update\w*)\b", text):
        needs.append("GENERAL_STATUS")
    return tuple(needs)
STOPWORDS = frozenset({
    "which", "about", "latest", "news", "what", "does", "from", "with", "when",
    "this", "that", "issues", "report", "reports", "official", "and", "the",
    "for", "or", "not", "versus", "between", "after", "before", "under",
    "status", "update", "updates", "plans", "plan", "current", "there",
    "why", "how", "where", "who", "whose", "are", "was", "were", "has",
    "have", "had", "is", "its", "been", "being", "will", "would", "could",
    "should", "can", "may", "might", "any", "all", "some", "many", "much",
    "more", "most", "into", "onto", "over", "also", "their", "them", "they",
    "these", "those", "such", "then", "than", "through", "during", "since",
    "regarding", "concerning", "happening", "recent", "new", "information",
    "find", "show", "tell", "please", "effects", "impact", "affect", "affects",
    "company", "companies", "industry", "sector", "situation", "developments",
})


PROGRAM_ENGINE_DOMAIN_MAP: dict[str, dict[str, tuple[str, ...]]] = {
    # --- AIRBUS ---
    "A220": {
        "engine_models": ("PW1500G", "PW1519G", "PW1521G", "PW1524G", "PW1525G", "GTF"),
        "engine_manufacturers": ("Pratt & Whitney",),
    },
    "A220-100": {
        "engine_models": ("PW1500G", "PW1519G", "PW1521G", "PW1524G", "GTF"),
        "engine_manufacturers": ("Pratt & Whitney",),
    },
    "A220-300": {
        "engine_models": ("PW1500G", "PW1519G", "PW1521G", "PW1524G", "PW1525G", "GTF"),
        "engine_manufacturers": ("Pratt & Whitney",),
    },
    "A318": {
        "engine_models": ("PW6000", "CFM56-5"),
        "engine_manufacturers": ("Pratt & Whitney", "CFM International"),
    },
    "A319": {
        "engine_models": ("CFM56-5B", "V2500", "CFM56"),
        "engine_manufacturers": ("CFM International", "International Aero Engines"),
    },
    "A319CEO": {
        "engine_models": ("CFM56-5B", "V2500", "CFM56"),
        "engine_manufacturers": ("CFM International", "International Aero Engines"),
    },
    "A319NEO": {
        "engine_models": ("PW1100G", "LEAP-1A", "GTF"),
        "engine_manufacturers": ("Pratt & Whitney", "CFM International", "International Aero Engines"),
    },
    "A320": {
        "engine_models": ("CFM56-5A", "CFM56-5B", "V2500", "PW1100G", "LEAP-1A", "CFM56", "GTF"),
        "engine_manufacturers": ("CFM International", "International Aero Engines", "Pratt & Whitney"),
    },
    "A320CEO": {
        "engine_models": ("CFM56-5A", "CFM56-5B", "V2500", "CFM56"),
        "engine_manufacturers": ("CFM International", "International Aero Engines"),
    },
    "A320NEO": {
        "engine_models": ("PW1100G", "PW1100G-JM", "LEAP-1A", "GTF"),
        "engine_manufacturers": ("Pratt & Whitney", "CFM International", "International Aero Engines"),
    },
    "A321": {
        "engine_models": ("CFM56-5B", "V2500", "PW1100G", "LEAP-1A", "CFM56", "GTF"),
        "engine_manufacturers": ("CFM International", "International Aero Engines", "Pratt & Whitney"),
    },
    "A321CEO": {
        "engine_models": ("CFM56-5B", "V2500", "CFM56"),
        "engine_manufacturers": ("CFM International", "International Aero Engines"),
    },
    "A321NEO": {
        "engine_models": ("PW1100G", "PW1100G-JM", "LEAP-1A", "GTF"),
        "engine_manufacturers": ("Pratt & Whitney", "CFM International", "International Aero Engines"),
    },
    "A321XLR": {
        "engine_models": ("PW1100G", "PW1100G-JM", "LEAP-1A", "GTF"),
        "engine_manufacturers": ("Pratt & Whitney", "CFM International", "International Aero Engines"),
    },
    "A330": {
        "engine_models": ("Trent 700", "CF6-80E1", "PW4000"),
        "engine_manufacturers": ("Rolls-Royce", "GE Aerospace", "Pratt & Whitney"),
    },
    "A330CEO": {
        "engine_models": ("Trent 700", "CF6-80E1", "PW4000"),
        "engine_manufacturers": ("Rolls-Royce", "GE Aerospace", "Pratt & Whitney"),
    },
    "A330NEO": {
        "engine_models": ("Trent 7000",),
        "engine_manufacturers": ("Rolls-Royce",),
    },
    "A330-800": {
        "engine_models": ("Trent 7000",),
        "engine_manufacturers": ("Rolls-Royce",),
    },
    "A330-900": {
        "engine_models": ("Trent 7000",),
        "engine_manufacturers": ("Rolls-Royce",),
    },
    "A340": {
        "engine_models": ("CFM56-5C", "Trent 500"),
        "engine_manufacturers": ("CFM International", "Rolls-Royce"),
    },
    "A350": {
        "engine_models": ("Trent XWB", "Trent XWB-84", "Trent XWB-97"),
        "engine_manufacturers": ("Rolls-Royce",),
    },
    "A350-900": {
        "engine_models": ("Trent XWB", "Trent XWB-84"),
        "engine_manufacturers": ("Rolls-Royce",),
    },
    "A350-1000": {
        "engine_models": ("Trent XWB", "Trent XWB-97"),
        "engine_manufacturers": ("Rolls-Royce",),
    },
    "A350F": {
        "engine_models": ("Trent XWB", "Trent XWB-97"),
        "engine_manufacturers": ("Rolls-Royce",),
    },
    "A380": {
        "engine_models": ("Trent 900", "GP7200"),
        "engine_manufacturers": ("Rolls-Royce", "Engine Alliance", "GE Aerospace", "Pratt & Whitney"),
    },
    "A400M": {
        "engine_models": ("TP400", "TP400-D6"),
        "engine_manufacturers": ("Europrop International", "Safran", "Rolls-Royce", "MTU Aero Engines", "ITP Aero"),
    },

    # --- BOEING ---
    "737": {
        "engine_models": ("CFM56-3", "CFM56-7B", "LEAP-1B", "CFM56"),
        "engine_manufacturers": ("CFM International",),
    },
    "737NG": {
        "engine_models": ("CFM56-7B", "CFM56"),
        "engine_manufacturers": ("CFM International",),
    },
    "737 MAX": {
        "engine_models": ("LEAP-1B",),
        "engine_manufacturers": ("CFM International",),
    },
    "747": {
        "engine_models": ("CF6", "PW4000", "RB211", "GEnx", "GEnx-2B"),
        "engine_manufacturers": ("GE Aerospace", "Pratt & Whitney", "Rolls-Royce"),
    },
    "747-8": {
        "engine_models": ("GEnx", "GEnx-2B"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "757": {
        "engine_models": ("PW2000", "RB211"),
        "engine_manufacturers": ("Pratt & Whitney", "Rolls-Royce"),
    },
    "767": {
        "engine_models": ("CF6", "PW4000"),
        "engine_manufacturers": ("GE Aerospace", "Pratt & Whitney"),
    },
    "777": {
        "engine_models": ("GE90", "Trent 800", "PW4000"),
        "engine_manufacturers": ("GE Aerospace", "Rolls-Royce", "Pratt & Whitney"),
    },
    "777X": {
        "engine_models": ("GE9X",),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "777-9": {
        "engine_models": ("GE9X",),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "777-8": {
        "engine_models": ("GE9X",),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "787": {
        "engine_models": ("GEnx", "GEnx-1B", "Trent 1000"),
        "engine_manufacturers": ("GE Aerospace", "Rolls-Royce"),
    },
    "787-8": {
        "engine_models": ("GEnx-1B", "Trent 1000", "GEnx"),
        "engine_manufacturers": ("GE Aerospace", "Rolls-Royce"),
    },
    "787-9": {
        "engine_models": ("GEnx-1B", "Trent 1000", "GEnx"),
        "engine_manufacturers": ("GE Aerospace", "Rolls-Royce"),
    },
    "787-10": {
        "engine_models": ("GEnx-1B", "Trent 1000", "GEnx"),
        "engine_manufacturers": ("GE Aerospace", "Rolls-Royce"),
    },
    "KC-46": {
        "engine_models": ("PW4000", "PW4062"),
        "engine_manufacturers": ("Pratt & Whitney",),
    },
    "P-8": {
        "engine_models": ("CFM56-7B", "CFM56"),
        "engine_manufacturers": ("CFM International",),
    },

    # --- COMAC (CHINA) ---
    "C919": {
        "engine_models": ("LEAP-1C", "CJ-1000A", "CJ1000A"),
        "engine_manufacturers": ("CFM International", "AECC"),
    },
    "C929": {
        "engine_models": ("CJ-2000", "CJ2000"),
        "engine_manufacturers": ("AECC",),
    },
    "C909": {
        "engine_models": ("CF34-10A", "CF34"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "ARJ21": {
        "engine_models": ("CF34-10A", "CF34"),
        "engine_manufacturers": ("GE Aerospace",),
    },

    # --- ILYUSHIN, SUKHOI / IRKUT, ANTONOV, TUPOLEV ---
    "IL-76": {
        "engine_models": ("D-30KP", "PS-90A", "PS-90A-76"),
        "engine_manufacturers": ("Aviadvigatel", "UEC"),
    },
    "IL-96": {
        "engine_models": ("PS-90A", "PD-35"),
        "engine_manufacturers": ("Aviadvigatel", "UEC"),
    },
    "IL-114": {
        "engine_models": ("TV7-117SM", "TV7-117"),
        "engine_manufacturers": ("UEC-Klimov", "UEC"),
    },
    "MC-21": {
        "engine_models": ("PW1400G", "PD-14", "GTF"),
        "engine_manufacturers": ("Pratt & Whitney", "Aviadvigatel", "UEC"),
    },
    "MS-21": {
        "engine_models": ("PW1400G", "PD-14", "GTF"),
        "engine_manufacturers": ("Pratt & Whitney", "Aviadvigatel", "UEC"),
    },
    "SSJ100": {
        "engine_models": ("SaM146", "PD-8"),
        "engine_manufacturers": ("PowerJet", "Safran", "UEC"),
    },
    "SUPERJET 100": {
        "engine_models": ("SaM146", "PD-8"),
        "engine_manufacturers": ("PowerJet", "Safran", "UEC"),
    },
    "SJ-100": {
        "engine_models": ("PD-8", "SaM146"),
        "engine_manufacturers": ("UEC", "PowerJet"),
    },
    "AN-124": {
        "engine_models": ("D-18T",),
        "engine_manufacturers": ("Ivchenko-Progress", "Motor Sich"),
    },
    "AN-148": {
        "engine_models": ("D-436", "D-436-148"),
        "engine_manufacturers": ("Ivchenko-Progress", "Motor Sich"),
    },
    "AN-158": {
        "engine_models": ("D-436", "D-436-148"),
        "engine_manufacturers": ("Ivchenko-Progress", "Motor Sich"),
    },
    "TU-204": {
        "engine_models": ("PS-90A", "RB211"),
        "engine_manufacturers": ("Aviadvigatel", "Rolls-Royce"),
    },
    "TU-214": {
        "engine_models": ("PS-90A",),
        "engine_manufacturers": ("Aviadvigatel", "UEC"),
    },

    # --- EMBRAER, ATR, DE HAVILLAND, BOMBARDIER, GULFSTREAM ---
    "E170": {
        "engine_models": ("CF34-8E", "CF34"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "E175": {
        "engine_models": ("CF34-8E", "CF34"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "E190": {
        "engine_models": ("CF34-10E", "CF34"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "E195": {
        "engine_models": ("CF34-10E", "CF34"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "E190-E2": {
        "engine_models": ("PW1900G", "PW1919G", "PW1921G", "PW1922G", "GTF"),
        "engine_manufacturers": ("Pratt & Whitney",),
    },
    "E195-E2": {
        "engine_models": ("PW1900G", "PW1923G", "GTF"),
        "engine_manufacturers": ("Pratt & Whitney",),
    },
    "C-390": {
        "engine_models": ("V2500", "V2500-E5"),
        "engine_manufacturers": ("International Aero Engines",),
    },
    "ATR 42": {
        "engine_models": ("PW120", "PW127", "PW127XT"),
        "engine_manufacturers": ("Pratt & Whitney Canada", "RTX"),
    },
    "ATR 72": {
        "engine_models": ("PW124B", "PW127", "PW127M", "PW127XT"),
        "engine_manufacturers": ("Pratt & Whitney Canada", "RTX"),
    },
    "Q400": {
        "engine_models": ("PW150", "PW150A"),
        "engine_manufacturers": ("Pratt & Whitney Canada", "RTX"),
    },
    "DASH 8": {
        "engine_models": ("PW100", "PW120", "PW150A"),
        "engine_manufacturers": ("Pratt & Whitney Canada", "RTX"),
    },
    "CRJ700": {
        "engine_models": ("CF34-8C", "CF34-8C5"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "CRJ900": {
        "engine_models": ("CF34-8C", "CF34-8C5"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "CRJ1000": {
        "engine_models": ("CF34-8C", "CF34-8C5"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "GLOBAL 7500": {
        "engine_models": ("Passport", "Passport 20"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "GLOBAL 8000": {
        "engine_models": ("Passport", "Passport 20"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "G500": {
        "engine_models": ("PW800", "PW814GA"),
        "engine_manufacturers": ("Pratt & Whitney Canada", "RTX"),
    },
    "G600": {
        "engine_models": ("PW800", "PW815GA"),
        "engine_manufacturers": ("Pratt & Whitney Canada", "RTX"),
    },
    "G700": {
        "engine_models": ("Pearl 700",),
        "engine_manufacturers": ("Rolls-Royce",),
    },
    "G800": {
        "engine_models": ("Pearl 700",),
        "engine_manufacturers": ("Rolls-Royce",),
    },

    # --- DEFENSE AND ROTORCRAFT PROGRAMS ---
    "F-35": {
        "engine_models": ("F135",),
        "engine_manufacturers": ("Pratt & Whitney", "RTX"),
    },
    "F-16": {
        "engine_models": ("F110", "F100"),
        "engine_manufacturers": ("GE Aerospace", "Pratt & Whitney"),
    },
    "F/A-18": {
        "engine_models": ("F404", "F414"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "B-21": {
        "engine_models": ("F135",),
        "engine_manufacturers": ("Pratt & Whitney", "RTX"),
    },
    "CH-53K": {
        "engine_models": ("T408", "GE38"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "V-22": {
        "engine_models": ("AE1107C",),
        "engine_manufacturers": ("Rolls-Royce",),
    },

    # --- ADDITIONAL BUSINESS, REGIONAL, LEGACY & ROTORCRAFT PROGRAMS ---
    "FALCON 6X": {
        "engine_models": ("PW812D", "PW800"),
        "engine_manufacturers": ("Pratt & Whitney Canada", "RTX"),
    },
    "FALCON 8X": {
        "engine_models": ("PW307D",),
        "engine_manufacturers": ("Pratt & Whitney Canada", "RTX"),
    },
    "FALCON 10X": {
        "engine_models": ("Pearl 10X",),
        "engine_manufacturers": ("Rolls-Royce",),
    },
    "PC-12": {
        "engine_models": ("PT6A", "PT6E", "PT6"),
        "engine_manufacturers": ("Pratt & Whitney Canada", "RTX"),
    },
    "PC-24": {
        "engine_models": ("FJ44-4A", "FJ44"),
        "engine_manufacturers": ("Williams International",),
    },
    "CHALLENGER 3500": {
        "engine_models": ("HTF7350", "HTF7000"),
        "engine_manufacturers": ("Honeywell",),
    },
    "CHALLENGER 650": {
        "engine_models": ("CF34-3B", "CF34"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "CITATION LONGITUDE": {
        "engine_models": ("HTF7700L", "HTF7000"),
        "engine_manufacturers": ("Honeywell",),
    },
    "KING AIR": {
        "engine_models": ("PT6A", "PT6"),
        "engine_manufacturers": ("Pratt & Whitney Canada", "RTX"),
    },
    "A300": {
        "engine_models": ("CF6", "PW4000"),
        "engine_manufacturers": ("GE Aerospace", "Pratt & Whitney"),
    },
    "A310": {
        "engine_models": ("CF6", "PW4000"),
        "engine_manufacturers": ("GE Aerospace", "Pratt & Whitney"),
    },
    "CRJ200": {
        "engine_models": ("CF34-3B1", "CF34"),
        "engine_manufacturers": ("GE Aerospace",),
    },
    "MD-11": {
        "engine_models": ("CF6", "PW4000"),
        "engine_manufacturers": ("GE Aerospace", "Pratt & Whitney"),
    },
    "H145": {
        "engine_models": ("Arriel 2E", "Arriel"),
        "engine_manufacturers": ("Safran",),
    },
    "H160": {
        "engine_models": ("Arrano",),
        "engine_manufacturers": ("Safran",),
    },
    "AW139": {
        "engine_models": ("PT6C-67C", "PT6"),
        "engine_manufacturers": ("Pratt & Whitney Canada", "RTX"),
    },
    "S-92": {
        "engine_models": ("CT7-8A", "CT7"),
        "engine_manufacturers": ("GE Aerospace",),
    },
}


_EXPLICIT_ENGINE_OEM_MAP: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    # CFM & LEAP
    (r"\bLEAP[- ]?1A\b", ("LEAP-1A",), ("CFM International",)),
    (r"\bLEAP[- ]?1B\b", ("LEAP-1B",), ("CFM International",)),
    (r"\bLEAP[- ]?1C\b", ("LEAP-1C",), ("CFM International",)),
    (r"\bLEAP(?![- ]?1[ABC]\b)\b", ("LEAP-1A", "LEAP-1B", "LEAP-1C"), ("CFM International",)),
    (r"\bCFM56[- ]?5[AB]?\b", ("CFM56-5B", "CFM56"), ("CFM International",)),
    (r"\bCFM56[- ]?7B\b", ("CFM56-7B", "CFM56"), ("CFM International",)),
    (r"\bCFM56(?![- ]?[357][A-Z]?\b)\b", ("CFM56",), ("CFM International",)),
    (r"\bV2500\b", ("V2500",), ("International Aero Engines",)),

    # Pratt & Whitney / RTX GTF & legacy/regional
    (r"\bPW11\d{2}G(?:[- ]?JM)?\b", ("PW1100G", "PW1100G-JM", "GTF"),
     ("Pratt & Whitney", "International Aero Engines")),
    (r"\bPW15\d{2}G(?:[- ]?[A-Z0-9]+)?\b", ("PW1500G", "GTF"), ("Pratt & Whitney",)),
    (r"\bPW19\d{2}G(?:[- ]?[A-Z0-9]+)?\b", ("PW1900G", "GTF"), ("Pratt & Whitney",)),
    (r"\bPW14\d{2}G\b", ("PW1400G", "GTF"), ("Pratt & Whitney",)),
    (r"\bPW1000G\b", ("GTF", "PW1100G", "PW1500G", "PW1900G"), ("Pratt & Whitney",)),
    (r"\bPW4000\b", ("PW4000",), ("Pratt & Whitney",)),
    (r"\bPW2000\b", ("PW2000",), ("Pratt & Whitney",)),
    (r"\bPW800\b", ("PW800",), ("Pratt & Whitney Canada",)),
    (r"\bPW127(?:XT|M|F|G|E)?\b", ("PW127XT", "PW127"), ("Pratt & Whitney Canada",)),
    (r"\bPW150A?\b", ("PW150A", "PW150"), ("Pratt & Whitney Canada",)),

    # Rolls-Royce
    (r"\bTRENT[- ]?XWB[- ]?84\b", ("Trent XWB-84", "Trent XWB"), ("Rolls-Royce",)),
    (r"\bTRENT[- ]?XWB[- ]?97\b", ("Trent XWB-97", "Trent XWB"), ("Rolls-Royce",)),
    (r"\bTRENT[- ]?XWB\b", ("Trent XWB",), ("Rolls-Royce",)),
    (r"\bTRENT[- ]?7000\b", ("Trent 7000",), ("Rolls-Royce",)),
    (r"\bTRENT[- ]?700\b", ("Trent 700",), ("Rolls-Royce",)),
    (r"\bTRENT[- ]?800\b", ("Trent 800",), ("Rolls-Royce",)),
    (r"\bTRENT[- ]?900\b", ("Trent 900",), ("Rolls-Royce",)),
    (r"\bTRENT[- ]?1000\b", ("Trent 1000",), ("Rolls-Royce",)),
    (r"\bPEARL[- ]?700\b", ("Pearl 700",), ("Rolls-Royce",)),
    (r"\bRB211\b", ("RB211",), ("Rolls-Royce",)),

    # GE Aerospace / Engine Alliance
    (r"\bGE9X\b", ("GE9X",), ("GE Aerospace",)),
    (r"\bGE90\b", ("GE90",), ("GE Aerospace",)),
    (r"\bGENX(?:[- ]?1B|[- ]?2B)?\b", ("GEnx",), ("GE Aerospace",)),
    (r"\bCF6(?:[- ]?80[A-Z0-9-]*)?\b", ("CF6",), ("GE Aerospace",)),
    (r"\bCF34(?:[- ]?[18]0[A-Z0-9-]*)?\b", ("CF34",), ("GE Aerospace",)),
    (r"\bGP7200\b", ("GP7200",), ("Engine Alliance", "GE Aerospace", "Pratt & Whitney")),
    (r"\bPASSPORT\b", ("Passport",), ("GE Aerospace",)),

    # COMAC (AECC) & Russian / Ukrainian engines (Aviadvigatel / UEC / PowerJet / Motor Sich)
    (r"\bCJ[- ]?1000A?\b", ("CJ-1000A",), ("AECC",)),
    (r"\bCJ[- ]?2000\b", ("CJ-2000",), ("AECC",)),
    (r"\bPD[- ]?14\b", ("PD-14",), ("Aviadvigatel", "UEC")),
    (r"\bPD[- ]?8\b", ("PD-8",), ("UEC",)),
    (r"\bPD[- ]?35\b", ("PD-35",), ("Aviadvigatel", "UEC")),
    (r"\bPS[- ]?90A?(?:[- ]?76)?\b", ("PS-90A",), ("Aviadvigatel", "UEC")),
    (r"\bSAM146\b", ("SaM146",), ("PowerJet", "Safran", "UEC")),
    (r"\bTV7[- ]?117(?:SM)?\b", ("TV7-117",), ("UEC-Klimov", "UEC")),
    (r"\bD[- ]?30KP\b", ("D-30KP",), ("Aviadvigatel", "UEC")),
    (r"\bD[- ]?18T\b", ("D-18T",), ("Ivchenko-Progress", "Motor Sich")),
    (r"\bD[- ]?436(?:[- ]?148)?\b", ("D-436",), ("Ivchenko-Progress", "Motor Sich")),

    # Defense / turboprop engines
    (r"\bF135\b", ("F135",), ("Pratt & Whitney",)),
    (r"\bF110\b", ("F110",), ("GE Aerospace",)),
    (r"\bF404\b|\bF414\b", ("F404", "F414"), ("GE Aerospace",)),
    (r"\bTP400(?:-D6)?\b", ("TP400",), ("Europrop International", "Safran", "Rolls-Royce")),

    # Business jet & rotorcraft engines
    (r"\bPEARL[- ]?10X\b", ("Pearl 10X",), ("Rolls-Royce",)),
    (r"\bPW812D\b|\bPW307D\b", ("PW812D", "PW307D"), ("Pratt & Whitney Canada",)),
    (r"\bPT6[ACE]?(?:-\d+[A-Z]?)?\b", ("PT6",), ("Pratt & Whitney Canada",)),
    (r"\bFJ44(?:-\d+[A-Z]?)?\b", ("FJ44",), ("Williams International",)),
    (r"\bHTF7(?:000|350|700L)\b", ("HTF7000",), ("Honeywell",)),
    (r"\bARRIEL(?:\s*2E)?\b", ("Arriel",), ("Safran",)),
    (r"\bARRANO\b", ("Arrano",), ("Safran",)),
    (r"\bCT7(?:-\d+[A-Z]?)?\b", ("CT7",), ("GE Aerospace",)),
)


def _normalize_domain_program_key(model: str) -> str:
    raw = re.sub(r"\s+", " ", (model or "").strip().upper())
    compact = re.sub(r"[-\s]+", "", raw)
    exact_map = {
        "777X": "777X",
        "B777X": "777X",
        "7779": "777-9",
        "777-9": "777-9",
        "7778": "777-8",
        "777-8": "777-8",
        "777": "777",
        "737MAX": "737 MAX",
        "737 MAX": "737 MAX",
        "737NG": "737NG",
        "737": "737",
        "7478": "747-8",
        "747-8": "747-8",
        "747": "747",
        "7878": "787-8",
        "787-8": "787-8",
        "7879": "787-9",
        "787-9": "787-9",
        "78710": "787-10",
        "787-10": "787-10",
        "787": "787",
        "A320NEO": "A320NEO",
        "A320CEO": "A320CEO",
        "A320": "A320",
        "A321NEO": "A321NEO",
        "A321CEO": "A321CEO",
        "A321XLR": "A321XLR",
        "A321": "A321",
        "A319NEO": "A319NEO",
        "A319CEO": "A319CEO",
        "A319": "A319",
        "A330NEO": "A330NEO",
        "A330CEO": "A330CEO",
        "A330800": "A330-800",
        "A330-800": "A330-800",
        "A330900": "A330-900",
        "A330-900": "A330-900",
        "A330": "A330",
        "A350900": "A350-900",
        "A350-900": "A350-900",
        "A3501000": "A350-1000",
        "A350-1000": "A350-1000",
        "A350F": "A350F",
        "A350": "A350",
        "A220100": "A220-100",
        "A220-100": "A220-100",
        "A220300": "A220-300",
        "A220-300": "A220-300",
        "A220": "A220",
        "ATR42": "ATR 42",
        "ATR 42": "ATR 42",
        "ATR72": "ATR 72",
        "ATR 72": "ATR 72",
        "IL76": "IL-76",
        "IL-76": "IL-76",
        "IL96": "IL-96",
        "IL-96": "IL-96",
        "IL114": "IL-114",
        "IL-114": "IL-114",
        "AN124": "AN-124",
        "AN-124": "AN-124",
        "AN148": "AN-148",
        "AN-148": "AN-148",
        "AN158": "AN-158",
        "AN-158": "AN-158",
        "TU204": "TU-204",
        "TU-204": "TU-204",
        "TU214": "TU-214",
        "TU-214": "TU-214",
        "MC21": "MC-21",
        "MC-21": "MC-21",
        "MS21": "MS-21",
        "MS-21": "MS-21",
        "SUPERJET100": "SUPERJET 100",
        "SUPERJET 100": "SUPERJET 100",
        "SJ100": "SJ-100",
        "SJ-100": "SJ-100",
        "C390": "C-390",
        "C-390": "C-390",
        "FALCON6X": "FALCON 6X",
        "FALCON 6X": "FALCON 6X",
        "FALCON8X": "FALCON 8X",
        "FALCON 8X": "FALCON 8X",
        "FALCON10X": "FALCON 10X",
        "FALCON 10X": "FALCON 10X",
        "PC12": "PC-12",
        "PC-12": "PC-12",
        "PC24": "PC-24",
        "PC-24": "PC-24",
        "CHALLENGER3500": "CHALLENGER 3500",
        "CHALLENGER 3500": "CHALLENGER 3500",
        "CHALLENGER650": "CHALLENGER 650",
        "CHALLENGER 650": "CHALLENGER 650",
        "MD11": "MD-11",
        "MD-11": "MD-11",
        "S92": "S-92",
        "S-92": "S-92",
    }
    if raw in exact_map:
        return exact_map[raw]
    if compact in exact_map:
        return exact_map[compact]
    if raw.startswith("737 MAX"):
        return "737 MAX"
    return raw


_EXCLUSION_SPLIT_RE = re.compile(
    r"\b(?:excluding|exclude|except(?:\s+for)?|without|not\s+including|kromě|vyjma)\b", re.I
)
_MINUS_TERM_RE = re.compile(r'(?<!\w)-"([^"]+)"|(?<!\w)-([A-Za-z0-9][A-Za-z0-9._-]*)')


def _strip_exclusions(query: str) -> tuple[str, list[str]]:
    """Separate negative exclusions from positive search terms."""
    raw = str(query or "")
    excluded: list[str] = []
    for m in _MINUS_TERM_RE.finditer(raw):
        term = (m.group(1) or m.group(2) or "").strip()
        if term:
            excluded.append(term)
    raw = _MINUS_TERM_RE.sub(" ", raw)
    parts = _EXCLUSION_SPLIT_RE.split(raw, maxsplit=1)
    positive = parts[0].strip(" ,;-")
    if len(parts) > 1 and parts[1].strip():
        for chunk in re.split(r",|\band\b", parts[1], flags=re.I):
            cleaned_chunk = chunk.strip(" .;-")
            if cleaned_chunk:
                excluded.append(cleaned_chunk)
    return positive, _unique(excluded)


def get_program_engine_domain(query: str) -> dict[str, tuple[str, ...]]:
    """Return engine models/OEMs; if an exact engine is already named, do NOT expand to rival engines."""
    positive, _ = _strip_exclusions(query)
    explicit_models: list[str] = []
    explicit_oems: list[str] = []
    for pattern, e_models, e_oems in _EXPLICIT_ENGINE_OEM_MAP:
        if re.search(pattern, positive, re.I):
            explicit_models.extend(e_models)
            explicit_oems.extend(e_oems)
    if explicit_models:
        return {
            "engine_models": tuple(dict.fromkeys(explicit_models)),
            "engine_manufacturers": tuple(dict.fromkeys(explicit_oems)),
        }

    models = [token.upper() for token in _model_tokens(positive)]
    engine_models: list[str] = []
    engine_oems: list[str] = []
    for model in models:
        key = _normalize_domain_program_key(model)
        entry = PROGRAM_ENGINE_DOMAIN_MAP.get(key)
        if not entry:
            continue
        engine_models.extend(entry["engine_models"])
        engine_oems.extend(entry["engine_manufacturers"])
    return {
        "engine_models": tuple(dict.fromkeys(engine_models)),
        "engine_manufacturers": tuple(dict.fromkeys(engine_oems)),
    }


def _unique(values):
    return list(dict.fromkeys(values))


def _model_tokens(query: str) -> list[str]:
    """Extract structural model codes without treating regulations as aircraft."""
    without_names = ENTITY_SUFFIX_RE.sub(" ", REGULATORY_RE.sub(" ", query or ""))
    return _unique(_canonical_model(match.group(0)).lower()
                   for match in MODEL_TOKEN_RE.finditer(without_names))


def _clause(terms) -> str:
    normalized = (re.sub(r'["()]', "", str(term)).strip() for term in terms if str(term).strip())
    terms = _unique(term for term in normalized if term)
    quoted = [term if term.isalnum() and term.upper() not in {"AND", "OR", "NOT"}
              else f'"{term}"' for term in terms]
    return "(" + " OR ".join(quoted) + ")" if len(quoted) > 1 else quoted[0] if quoted else ""


def _regulatory_identifier(value: str) -> str:
    value = value.upper()
    return re.sub(r"[-\s]+", "-", value) if re.match(r"FAA[-\s]+20\d{2}", value) else value


def _canonical_model(model: str) -> str:
    value = re.sub(r"\s+", " ", model.strip().upper())
    variant = re.fullmatch(r"737[-\s]*MAX[-\s]*(\d{1,2})|737[-\s]+(\d{1,2})", value)
    if variant:
        return f"737 MAX {int(variant[1] or variant[2])}"
    suffix = re.fullmatch(r"([A-Z]{1,5}\d{2,5})[-\s]*(NEO|CEO|XLR|E2)", value)
    if suffix:
        return f"{suffix[1]}-E2" if suffix[2] == "E2" else f"{suffix[1]}{suffix[2]}"
    return value


def _model_aliases(model: str) -> list[str]:
    """Search format variants without changing an aircraft or engine identity."""
    model = _canonical_model(model)
    forms = [model]
    max_variant = re.fullmatch(r"737 MAX (\d{1,2})", model)
    if max_variant:
        variant = max_variant[1]
        forms.extend((f"737-{variant}", f"737 MAX {variant}", f"737 MAX-{variant}"))
    elif model.endswith("-E2"):
        forms.extend((model.replace("-", " "), model.replace("-", "")))
    elif "-" in model:
        forms.append(model.replace("-", " "))
    elif " " in model:
        forms.append(model.replace(" ", "-"))
    else:
        suffix = re.fullmatch(r"([A-Z]+\d+)(NEO|CEO|XLR|E2)", model, re.I)
        if suffix:
            forms.extend((f"{suffix[1]} {suffix[2]}", f"{suffix[1]}-{suffix[2]}"))
    return _unique(forms)


def _bounded_query(groups: list[list[str]], optional: Iterable[str] = ()) -> str:
    """Trim redundant OR alternatives, never the last term of a required group."""
    groups = [_unique(group) for group in groups if group]
    build = lambda: " AND ".join(_clause(group) for group in groups)
    result = build()
    while len(result) > MAX_QUERY_LENGTH:
        removable = [i for i, group in enumerate(groups) if len(group) > 1]
        if not removable:
            raise ValueError("Required KIT identities and topics exceed the NewsAPI query limit")
        index = max(removable, key=lambda i: len(_clause(groups[i])) - len(_clause(groups[i][:-1])))
        groups[index].pop()
        result = build()
    for addition in filter(None, optional):
        candidate = " AND ".join(filter(None, (result, addition)))
        if len(candidate) <= MAX_QUERY_LENGTH:
            result = candidate
    depth, quoted = 0, False
    for char in result:
        if char == '"':
            quoted = not quoted
        elif not quoted:
            depth += (char == "(") - (char == ")")
            if depth < 0:
                break
    if depth or quoted:
        raise ValueError("Unbalanced NewsAPI boolean query")
    return result


def news_api_search_key(
    query: str, *, mode: Literal["exact", "expanded", "alternative", "resolution", "recall"] = "exact",
    entities: Iterable[str] = (),
) -> str:
    """Build a bounded query with verified regulatory and model identities.

    Alternative can relax a manufacturer; recall retains identities while
    dropping optional issue wording; resolution targets status changes.
    """
    if mode not in {"exact", "expanded", "alternative", "resolution", "recall"}:
        raise ValueError("Unsupported NewsAPI search mode")
    positive_raw, excluded_terms = _strip_exclusions(query or "")
    cleaned = re.sub(r"\s+", " ", positive_raw.replace(",", " ")).strip()
    cleaned = re.sub(r"\bP\s*(?:&|and)\s*W\b", "Pratt & Whitney", cleaned, flags=re.I)
    cleaned = re.sub(r"\bPratt[\s&-]+(?:and\s+)?Whitney\b", "Pratt & Whitney", cleaned, flags=re.I)
    if not cleaned:
        return ""

    regulations = _unique(_regulatory_identifier(m.group()) for m in REGULATORY_RE.finditer(cleaned))
    if isinstance(entities, str):
        entities = (entities,)
    explicit = _unique(entity.strip() for entity in entities if isinstance(entity, str) and entity.strip())
    companies = list(explicit)
    company_groups: list[list[str]] = []
    remainder = REGULATORY_RE.sub(" ", cleaned)
    if re.search(r"\bPratt\s*&\s*Whitney\b", remainder, re.I):
        company_groups.append(["Pratt & Whitney", "Pratt Whitney"])
        remainder = re.sub(r"\bPratt\s*&\s*Whitney\b", " ", remainder, flags=re.I)
    for pat, variants in (
            (r"\bRolls[- ]Royce\b", ["Rolls-Royce", "Rolls Royce"]),
            (r"\bDe\s+Havilland\b", ["De Havilland"]),
            (r"\bParker[- ]Hannifin\b", ["Parker-Hannifin", "Parker Hannifin"]),
            (r"\bCurtiss[- ]Wright\b", ["Curtiss-Wright", "Curtiss Wright"]),
            (r"\bIvchenko[- ]Progress\b", ["Ivchenko-Progress", "Ivchenko Progress"]),
            (r"\bLiebherr[- ]Aerospace\b", ["Liebherr-Aerospace", "Liebherr Aerospace"]),
    ):
        if re.search(pat, remainder, re.I):
            company_groups.append(variants)
            remainder = re.sub(pat, " ", remainder, flags=re.I)
    for match in ENTITY_SUFFIX_RE.finditer(remainder):
        companies.append(match.group())
    remainder = ENTITY_SUFFIX_RE.sub(" ", remainder)
    for name in explicit:
        remainder = re.sub(re.escape(name), " ", remainder, flags=re.I)
    models = _unique(token.upper() for token in _model_tokens(remainder))
    remainder = MODEL_TOKEN_RE.sub(" ", remainder)

    components = []
    for pattern, terms in COMPONENTS:
        if re.search(pattern, remainder, re.I):
            components.append(terms)
            remainder = re.sub(pattern, " ", remainder, flags=re.I)
    events = []
    for pattern, terms in EVENTS:
        if re.search(pattern, remainder, re.I):
            events.append(terms)
            remainder = re.sub(pattern, " ", remainder, flags=re.I)

    agencies = [word.upper() for word in re.findall(r"\b[A-Za-z]{2,5}\b", remainder)
                if word.lower() in AGENCIES]
    remainder = re.sub(r"\b(?:" + "|".join(AGENCIES) + r")\b", " ", remainder, flags=re.I)
    generic_proper = STOPWORDS | {"aerospace", "aviation", "aircraft", "airline", "airlines", "supplier", "suppliers"}
    proper = [m.group() for m in PROPER_NAME_RE.finditer(remainder)
              if m.group().lower() not in generic_proper]
    for name in proper:
        remainder = re.sub(rf"\b{re.escape(name)}\b", " ", remainder, count=1)
    companies.extend(proper)
    companies = _unique(companies)

    residual = _unique(word for word in re.findall(r"(?u)\b[^\W\d_][\w'-]{2,}\b", remainder.lower())
                       if word not in STOPWORDS)
    context = (*INDUSTRY_CONTEXT, *(term for group in components for term in group))
    needs = classify_information_needs(cleaned)
    status_terms = _unique(term for need in needs for term in NEED_SEARCH_TERMS[need])
    if mode == "resolution" and not status_terms:
        return ""
    event_terms = _unique(term for group in events for term in group)
    required = [[term] for term in regulations]
    required.extend(_model_aliases(model) for model in models)
    required.extend([term] for term in agencies)
    all_company_groups = [*company_groups, *([term] for term in companies)]
    if mode != "alternative" or not models:
        if len(all_company_groups) > 1 and mode in {"alternative", "recall"}:
            required.append(_unique(t for grp in all_company_groups for t in grp))
        else:
            required.extend(all_company_groups)
    if len(components) > 1 and mode in {"alternative", "recall"}:
        required.append(_unique(t for grp in components for t in grp))
    else:
        required.extend(list(group) for group in components)
    if mode == "recall":
        if event_terms and not regulations:
            required.append(event_terms)
    elif mode == "exact" and len(events) > 1 and len(needs) <= 1 and len(required) <= 3:
        required.extend(list(group) for group in events)
    else:
        topic = status_terms if mode == "resolution" else event_terms
        if topic:
            required.append(topic)
    if residual and mode != "recall":
        required.append(residual[:4])
    optional = ([_clause(context)] if mode == "exact" and all_company_groups
                                      and not models and not regulations else [])
    for ex in excluded_terms[:2]:
        ex_clean = re.sub(r'["()]', "", ex).strip()
        if ex_clean:
            neg = f'NOT "{ex_clean}"' if " " in ex_clean or "-" in ex_clean else f"NOT {ex_clean}"
            optional.append(neg)
    return _bounded_query(required, optional)


def news_api_precision_key(query: str, *, entities: Iterable[str] = ()) -> str:
    """Legacy precision API using the canonical identity-preserving compiler."""
    result = news_api_search_key(query, mode="exact", entities=entities)
    if not result or _model_tokens(query) or REGULATORY_RE.search(query):
        return result
    context = _clause(INDUSTRY_CONTEXT)
    if context not in result and not any(term in query.lower() for term in INDUSTRY_CONTEXT):
        precise = f"{result} AND {context}"
        if len(precise) <= MAX_QUERY_LENGTH:
            return precise
    return result


def news_api_query_variants(query: str, *, entities: Iterable[str] = ()) -> dict[str, str]:
    """Prepare distinct bounded queries; callers decide which requests their quota allows."""
    entities = (entities,) if isinstance(entities, str) else tuple(entities)
    result: dict[str, str] = {}
    for name in ("exact", "alternative", "recall", "resolution"):
        value = news_api_search_key(query, mode=name, entities=entities)
        if value and value not in result.values():
            result[name] = value
    return result


_REGULATORY_FILLER_RE = re.compile(
    r"\b(?:official\s+decisions?\s+and\s+notices?|latest\s+developments?|"
    r"current\s+status\s+and\s+subsequent\s+changes?|technical\s+updates?|"
    r"media\s+reports?|easa)\b",
    re.I,
)


def build_federal_register_queries(query: str) -> list[str]:
    """Build concise FAA Federal Register queries using engine/model/docket IDs."""
    positive_raw, _ = _strip_exclusions(query or "")
    cleaned = re.sub(r"\s+", " ", _REGULATORY_FILLER_RE.sub(" ", positive_raw)).strip()
    regs = _unique(_regulatory_identifier(m.group()) for m in REGULATORY_RE.finditer(cleaned))
    if regs:
        return regs[:4]

    queries: list[str] = []
    engine_topic = bool(
        re.search(r"\b(?:engine|engines|turbine|hpt|hpc|propulsion|gearbox|fan\s+blade)\b", cleaned, re.I))
    component_terms = [
        terms[-1] for pattern, terms in COMPONENTS
        if pattern != r"\bengines?\b" and re.search(pattern, cleaned, re.I)
    ]
    domain = get_program_engine_domain(cleaned)
    if engine_topic and domain["engine_models"]:
        for eng in domain["engine_models"][:3]:
            queries.append(f"{eng} {component_terms[0]}" if component_terms else eng)
        for oem in domain["engine_manufacturers"][:3]:
            queries.append(oem)
        return _unique(queries)[:6]

    models = _unique(token.upper() for token in _model_tokens(cleaned))
    if models:
        suffix = f" {component_terms[0]}" if component_terms else ""
        return _unique(f"{m}{suffix}" for m in models)[:4]
    return [cleaned] if cleaned else []


def build_social_video_queries(query: str) -> list[str]:
    """Build short 2-4 token queries suitable for Bluesky and YouTube search."""
    positive_raw, _ = _strip_exclusions(query or "")
    cleaned = re.sub(r"\s+", " ", _REGULATORY_FILLER_RE.sub(" ", positive_raw)).strip()
    models = _unique(token.upper() for token in _model_tokens(cleaned))
    engine_topic = bool(re.search(
        r"\b(?:engine|engines|turbine|hpt|hpc|propulsion|gtf|leap|pw1\d{3}g|"
        r"trent|genx|ge9x|ge90|cfm56|v2500|pd-14|pd-8|cj-1000|pt6|f135|pearl|sam146)\b",
        cleaned, re.I,
    ))
    domain = get_program_engine_domain(cleaned)
    out: list[str] = []
    if models and engine_topic and domain["engine_models"]:
        aircraft_only = [m for m in models if not any(e.upper() == m.upper() for e in domain["engine_models"])]
        primary_aircraft = aircraft_only[0] if aircraft_only else ""
        for eng in domain["engine_models"][:3]:
            out.append(f"{primary_aircraft} {eng}".strip() if primary_aircraft else f"{eng} engine")
        if primary_aircraft:
            out.append(f"{primary_aircraft} engine")
        return _unique(out)[:4]

    words = [
        w for w in re.findall(r"[A-Za-z0-9-]+", cleaned)
        if w.lower() not in STOPWORDS and len(w) >= 2
    ]
    compact = " ".join(_unique(words)[:4])
    return [compact] if compact else []
