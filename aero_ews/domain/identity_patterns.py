"""Technical identity lookup tables and compiled evidence patterns."""

import re
from typing import Dict

from tasks import SCMTier


def _compile_map(raw: Dict[str, str], flags: int = re.I) -> Dict[str, re.Pattern]:
    """Compile a key -> regex string mapping with consistent flags."""
    return {k: re.compile(pat, flags) for k, pat in raw.items()}


# Engine model lexical hints (family labels remain distinct from variant identities).
ENGINE_MODEL_PATTERNS: Dict[str, re.Pattern] = _compile_map({
    # CFM International
    "CFM56": r"\bcfm[\s-]?56\b", "LEAP-1A": r"\bleap[\s-]*1a(?:[0-9][a-z0-9]*)?\b",
    "LEAP-1B": r"\bleap[\s-]*1b(?:[0-9][a-z0-9]*)?\b", "LEAP-1C": r"\bleap[\s-]*1c(?:[0-9][a-z0-9]*)?\b",
    "LEAP": r"\bleap\b",
    # Pratt & Whitney (GTF is a broad family term, not synonymous with PW1100G)
    "PW1100G_GTF": r"\bpw[\s-]*1100g(?:[\s-]*jm)?\b|\bpw11\d{2}g[a0-9]?(?:-\s*jm)?\b",
    "PW1500G_GTF": r"\bpw[\s-]*1500g\b|\bpw15\d{2}g(?:a|-\s*\d)?\b",
    "PW1900G_GTF": r"\bpw[\s-]*1900g\b|\bpw19\d{2}g(?:-\s*(?:rc|a))?\b",
    "GTF": r"\b(?:gtf|geared[\s-]*turbo[\s-]*fan)\b",
    "PW4000": r"\bpw[\s-]*4000\b", "PW2000": r"\bpw[\s-]*2000\b",
    # GE Aerospace & Engine Alliance
    "GE90": r"\bge[\s-]?90\b", "GE9X": r"\bge[\s-]?9x\b", "GENX": r"\bge[\s-]?nx\b",
    "CF34": r"\bcf[\s-]?34\b", "CF6": r"\bcf[\s-]?6\b", "GP7000": r"\bgp[\s-]?7000\b",
    # Rolls-Royce
    "TRENT_1000": r"\btrent[\s-]*1000\b", "TRENT_7000": r"\btrent[\s-]*7000\b",
    "TRENT_700": r"\btrent[\s-]*700\b", "TRENT_900": r"\btrent[\s-]*900\b",
    "TRENT_XWB": r"\btrent[\s-]*xwb(?:[\s-]*\d+)?\b", "RB211": r"\brb[\s-]*211\b",
    # IAE, COMAC (AECC), Russian/Ukrainian, and turboprop/military engines
    "V2500": r"\bv[\s-]?2500\b", "AE3007": r"\bae[\s-]*3007\b",
    "CJ1000A": r"\bcj[\s-]*1000a?\b", "CJ2000": r"\bcj[\s-]*2000\b",
    "PD14": r"\bpd[\s-]*14\b", "PD8": r"\bpd[\s-]*8\b", "PD35": r"\bpd[\s-]*35\b",
    "PS90": r"\bps[\s-]*90a?(?:[\s-]*76)?\b", "SAM146": r"\bsam[\s-]*146\b",
    "PW127": r"\bpw[\s-]*127(?:[\s-]*(?:xt|m|b))?\b", "PT6": r"\bpt[\s-]*6a?\b",
    "F135": r"\bf[\s-]*135\b", "F110": r"\bf[\s-]*110\b",
})

# Specific aircraft variant lexical hints.
SPECIFIC_AIRCRAFT_VARIANT_PATTERNS: Dict[str, re.Pattern] = _compile_map({
    "777X": r"\b(?:777xs?|777-8|777-9|b777x)\b", "777F": r"\b(?:777f|777\s+freighter|b777f)\b",
    "777_LEGACY": r"\b(?:777-200|777-300(?:er)?)\b",
    "737_MAX": r"\b(?:737[\s_-]*max|737-7|737-8|737-9|737-10|max\s*[789]|max\s*10)\b",
    "737_NG": r"\b(?:737\s*ng|737-700|737-800|737-900)\b",
    "787": r"\b(?:787|787-8|787-9|787-10|dreamliner)\b", "767": r"\b(?:767|767-300f?)\b",
    "A321XLR": r"\ba321\s*xlr\b",
    "A320NEO_FAMILY": r"\b(?:a3(?:19|20|21)[\s-]*neo|a3(?:19|20|21)-\d{3}n[a-z]?|a320neo_family)\b",
    "A320CEO_FAMILY": r"\ba3(?:18|19|20|21)\s*ceo\b",
    "A350F": r"\ba350f\b", "A350": r"\ba350(?:-\d{3})?\b",
    "A330NEO": r"\ba330\s*neo|a330-900\b", "A220": r"\ba220(?:-[13]00)?\b",
    "C919": r"\bc919\b", "C909": r"\b(?:c909|arj[\s-]?21)\b", "EJET_E2": r"\be(?:175|190|195)[\s-]?e2\b",
    "C929": r"\bc929\b", "EJET_E1": r"\be(?:170|175|190|195)(?:[\s-]?(?:lr|ar))?\b",
    "ATR": r"\batr[\s-]?(?:42|72)(?:[\s-]*(?:500|600))?\b",
    "IL_76_96": r"\bil[\s-]?(?:76|96|114)(?:[\s-]*(?:md|td|90|400))?\b",
    "MC_21": r"\b(?:mc|ms)[\s-]?21(?:[\s-]*300)?\b",
    "SUPERJET": r"\b(?:ssj[\s-]?100|sj[\s-]?100|superjet[\s-]?100)\b",
    "KC_46": r"\bkc[\s-]?46a?\b", "F_35": r"\bf[\s-]?35[abc]?\b",
})

# Broad aircraft family lexical hints across OEMs.
AIRCRAFT_FAMILY_PATTERNS: Dict[str, re.Pattern] = _compile_map({
    "A220": r"\ba220(?:-\d{3})?\b", "A320_FAMILY": r"\ba3(?:18|19|20|21)(?:[\s-]?(?:neo|ceo|xlr|lr)|-\d{3}[a-z]{0,2})?\b",
    "A330": r"\ba330(?:[\s-]?neo|-\d{3}[a-z]?)?\b", "A350": r"\ba350(?:-\d{3}|f)?\b",
    "A380": r"\ba380(?:-\d{3})?\b", "A400M": r"\ba400m\b",
    "B737": r"\b(?:b\s*)?737(?:[\s-]?(?:max|ng|\d{1,4}))?\b", "B747": r"\b(?:b\s*)?747(?:-\d{3}[a-z]?)?\b",
    "B757": r"\b(?:b\s*)?757(?:-\d{3})?\b", "B767": r"\b(?:b\s*)?767(?:-\d{3}[a-z]?)?\b",
    "B777": r"\b(?:b\s*)?777(?:x|-[0-9]{1,3}[a-z]?)?\b", "B787": r"\b(?:b\s*)?787(?:-\d{1,2})?\b|\bdreamliner\b",
    "C919": r"\bc919\b", "C909": r"\b(?:c909|arj[\s-]?21)\b",
    "E_JETS": r"\b(?:e[\s-]?(?:170|175|190|195)(?:[\s-]?e2)?|erj[\s-]?(?:170|175|190|195))\b",
    "ATR": r"\batr[\s-]?(?:42|72)(?:-\d{3})?\b", "CRJ": r"\bcrj[\s-]?(?:200|700|900|1000)\b",
    "Q400": r"\b(?:dash[\s-]?8[\s-]?q400|q400)\b", "C929": r"\bc929\b",
    "MC_21": r"\b(?:mc|ms)[\s-]?21(?:[\s-]*300)?\b",
    "SUPERJET": r"\b(?:ssj[\s-]?100|sj[\s-]?100|superjet[\s-]?100)\b",
    "ILYUSHIN_ANTONOV": r"\b(?:il[\s-]?(?:76|96|114)|an[\s-]?(?:124|148|158)|tu[\s-]?(?:204|214))\b",
    "GULFSTREAM": r"\bg(?:280|500|600|650|700|800)(?:er)?\b",
    "GLOBAL_JET": r"\bglobal[\s-]?(?:5500|6500|7500|8000)\b",
})

# Aerospace component keyword -> canonical label vocabulary (preserved verbatim).
COMPONENT_KEYWORDS_MAP: Dict[str, str] = {
    "fire switch": "Engine Fire Switch / Cockpit Fire Panel",
    "powder metal": "High-Pressure Turbine Discs (Powder Metal)", "powdered metal": "High-Pressure Turbine Discs (Powder Metal)",
    "fan blade": "Engine Fan Blades", "fan blades": "Engine Fan Blades",
    "turbine blade": "Engine Turbine Blades", "turbine blades": "Engine Turbine Blades",
    "compressor blade": "Engine Compressor Blades", "compressor blades": "Engine Compressor Blades",
    "combustor": "Engine Combustion System", "combustion chamber": "Engine Combustion System",
    "hydraulic pump": "Hydraulic Pump", "hydraulic pumps": "Hydraulic Pump",
    "fuel pump": "Fuel Pump", "fuel pumps": "Fuel Pump",
    "fuel tank": "Aircraft Fuel Tank", "fuel tanks": "Aircraft Fuel Tank",
    "avionics": "Flight Deck Avionics System",
    "wiring harness": "Electrical Wiring Harness", "wiring harnesses": "Electrical Wiring Harness",
    "flight management system": "Flight Management System", "flight management computer": "Flight Management System",
    "fuselage": "Aircraft Fuselage Structure",
    "door plug": "Fuselage Door Plug", "door plugs": "Fuselage Door Plug",
    "wing spar": "Wing Spar", "wing spars": "Wing Spar",
    "engine pylon": "Engine Pylon", "engine pylons": "Engine Pylon",
    "slotted nut": "Wing Thrust Spigot Slotted Nuts", "trailing-edge rib kit": "Wing Trailing-Edge Rib Kit",
    "flight control actuator": "Flight Control Actuator", "flight control actuators": "Flight Control Actuator",
    "hydraulic actuator": "Hydraulic Actuator", "hydraulic actuators": "Hydraulic Actuator",
    "landing gear": "Landing Gear System",
    "brake assembly": "Aircraft Brake Assembly", "brake assemblies": "Aircraft Brake Assembly",
    "evacuation slide": "Door Emergency Evacuation Slide System",
    "titanium": "Aerospace Titanium Forgings / Raw Material", "casting": "Precision Turbine Castings",
    "nacelle": "Engine Nacelle / Thrust Reverser", "nacelles": "Engine Nacelle / Thrust Reverser",
    "thrust reverser": "Engine Nacelle / Thrust Reverser",
    "gearbox": "Accessory / Transfer Gearbox", "accessory gearbox": "Accessory / Transfer Gearbox",
    "rotor": "Rotor / Rotating Assembly", "stator": "Stator Vane Assembly",
    "borescope": "Borescope Inspection / Internal Hardware", "apu": "Auxiliary Power Unit (APU)",
    "flight control": "Flight Control System", "rudder": "Flight Control System",
    "elevator": "Flight Control System", "aileron": "Flight Control System",
    "composite": "Composite Airframe / Structures", "composites": "Composite Airframe / Structures",
    "superalloy": "High-Temperature Superalloys", "superalloys": "High-Temperature Superalloys",
}

# Linguistic, geographic, wire-service, and temporal evidence patterns (preserved verbatim).
HYPOTHETICAL_IN_FACTS_REGEX = re.compile(r"\b(?:could|might|would|potentially|hypothetical\w*|speculat\w*|if\s+this|may\s+lead\s+to|threatens\s+to)\b", re.I)
CAUSAL_CLAIM_REGEX = re.compile(r"\b(?:caus(?:es|ed|ing)|lead(?:s|ing)\s+to|result(?:s|ed|ing)\s+in|forc(?:es|ed|ing)|trigger(?:s|ed|ing)|due\s+to|because\s+of|prompted\s+by|delays?\s+delivery)\b", re.I)

EVENT_LOCATION_EVIDENCE_MAP: Dict[str, re.Pattern] = _compile_map({
    "North America (USA / Canada)": r"\b(?:united\s+states|u\.s\.|usa|faa|ntsb|federal\s+register|renton|everett|charleston|wichita|seattle|connecticut|east\s+hartford|clayville|goodyear|arizona|dallas|detroit|mobile,\s+alabama|canada|mirabel|montreal|toronto)\b",
    "Europe (EU / UK / France / Germany)": r"\b(?:europe\w*|easa|toulouse|hamburg|farnborough|paris|france|germany|united\s+kingdom|u\.k\.|britain|london|derby|filton|bremen|madrid|spain|italy|dublin|hungary|warsaw|istanbul|turkish)\b",
    "Asia-Pacific (China / Singapore / Japan / India)": r"\b(?:china|shanghai|beijing|tianjin|singapore|india|new\s+delhi|mumbai|japan|tokyo|south\s+korea|seoul|taiwan|taipei|australia|sydney|melbourne)\b",
    "Middle East (UAE / Qatar / Saudi Arabia)": r"\b(?:dubai|uae|united\s+arab\s+emirates|abu\s+dhabi|qatar|doha|saudi\s+arabia|riyadh|jeddah)\b",
})
_EVENT_LOCATION_PATTERN = re.compile(
    r"\b(?:production|assembly|manufacturing|factory|plant|facility|incident|disruption|strike|accident|ground test|stoppage|production halt)\b.{0,90}?\b(?:in|at|near)\s+"
    r"(Everett|Seattle|Renton|Wichita|Florida|Washington|Charleston|Toulouse|Hamburg|Bremen|Derby|Farnborough|Shanghai|Tianjin|Singapore|Montreal|Mirabel|Dubai|Doha)\b",
    re.I | re.S,
)
_LOCATION_TO_REGION = {
    **{k: "North America (USA / Canada)" for k in ("everett", "seattle", "renton", "wichita", "florida", "washington", "charleston", "montreal", "mirabel")},
    **{k: "Europe (EU / UK / France / Germany)" for k in ("toulouse", "hamburg", "bremen", "derby", "farnborough")},
    **{k: "Asia-Pacific (China / Singapore / Japan / India)" for k in ("shanghai", "tianjin", "singapore")},
    **{k: "Middle East (UAE / Qatar / Saudi Arabia)" for k in ("dubai", "doha")},
}
_WIRE_PATTERNS = _compile_map({
    "REUTERS": r"\breuters\b",
    "ASSOCIATED_PRESS": r"\b(?:associated press|ap news)\b",
    "AGENCE_FRANCE_PRESSE": r"\b(?:agence france.presse|afp)\b",
})
_PRIOR_PERIOD_CAUSE_RE = re.compile(r"\b(?:year[- ]ago|prior[- ]year|previous[- ]year)\b.{0,100}\b(?:mostly|mainly|primarily|largely)\s+(?:from|due to|because of)\b", re.I | re.S)
_CURRENT_PERIOD_RE = re.compile(r"\b(?:q[1-4]\s*20\d{2}|20\d{2}\s+q[1-4])\b", re.I)
_CLAIM_CAUSE_RE = re.compile(r"\b(?:primary\s+cause\s*:|(?:mainly|primarily|mostly|largely)\s+(?:due\s+to|from|because\s+of))", re.I)
_EXACT_VARIANT_RE = re.compile(r"(?<!\w)(?:[AB]\s*)?(\d{3})(?:[\s_-]*(max|neo|ceo|xlr|lr|er)(?:[\s_-]*(\d{1,3}))?|[\s_-]+(\d{1,3}))?(?!\w)", re.I)
AIRLINE_AND_REGULATOR_PATTERN = re.compile(
    r"\b(?:airlines?|airways|air\s+lines?|air\s+transport|air\s+cargo|aircraft\s+leas\w*|aviation\s+capital|"
    r"air\s+canada|qantas|indigo|wizz(?:\s*air)?|lufthansa|ryanair|delta\s+air|"
    r"united\s+airlines|american\s+airlines|jetblue|easyjet|emirates|etihad|qatar|flydubai|starlux|aegean|"
    r"iberia|klm|air\s+france|turkish\s+airlines|spirit\s+airlines|aer\s+lingus|korean\s+air|"
    r"faa|easa|ntsb|caa|tcca|tsb|caac|anac|casa|bea|icao|iata|"
    r"european\s+commission|civil\s+aviation|aviation\s+authority|transport\s+safety|"
    r"federal\s+aviation|safety\s+agency|ministry|regulator\w*)\b", re.I,
)
REGISTRY_TIER_MAP: Dict[str, SCMTier] = {
    "OEM (Final Assembler)": SCMTier.OEM, "Tier 1 (Systems/Engines)": SCMTier.TIER_1,
    "Tier 2 (Subcomponents)": SCMTier.TIER_2, "Tier 3 (Raw Materials)": SCMTier.TIER_3,
    "Regulator / Airline": SCMTier.REGULATOR_AIRLINE,
}
ONGOING_OR_RECONFIRMED_PATTERNS = re.compile(
    r"\b(?:reaffirm\w*|reconfirm\w*|reiterat\w*|previously\s+(?:announced|delayed|pushed)|"
    r"contin(?:ues|ued)\s+to\s+(?:expect|anticipate|target)|still\s+expects?|"
    r"maintains?\s+(?:its\s+)?(?:20\d{2}|schedule|target)|on\s+track\s+for\s+20\d{2}|remains?\s+scheduled)\b", re.I,
)
HISTORICAL_RECAP_PATTERNS = re.compile(r"\b(?:in\s+20\d{2}|years\s+ago|history\s+of|documentary)\b", re.I)

# Explicit engine family sets, canonical labels, and known aliases (preserved verbatim).
_GTF_SPECIFIC_MODELS = frozenset({"PW1100G_GTF", "PW1500G_GTF", "PW1900G_GTF"})
_LEAP_SPECIFIC_MODELS = frozenset({"LEAP-1A", "LEAP-1B", "LEAP-1C"})
_PD_SPECIFIC_MODELS = frozenset({"PD14", "PD8", "PD35"})
_CJ_SPECIFIC_MODELS = frozenset({"CJ1000A", "CJ2000"})

ENGINE_CANONICAL_IDENTITIES = {
    **{key: key for key in ENGINE_MODEL_PATTERNS},
    "PW1100G_GTF": "PW1100G", "PW1500G_GTF": "PW1500G", "PW1900G_GTF": "PW1900G",
    "TRENT_1000": "Trent 1000", "TRENT_7000": "Trent 7000", "TRENT_700": "Trent 700",
    "TRENT_900": "Trent 900", "TRENT_XWB": "Trent XWB",
    "CJ1000A": "CJ-1000A", "CJ2000": "CJ-2000", "PD14": "PD-14", "PD8": "PD-8",
    "PD35": "PD-35", "PS90": "PS-90A", "SAM146": "SaM146", "PW127": "PW127",
    "PT6": "PT6", "F135": "F135", "F110": "F110",
}
ENGINE_KNOWN_ALIASES = {
    "PW1100G_GTF": ("PW1100G", "PW1100G-JM"), "PW1500G_GTF": ("PW1500G",), "PW1900G_GTF": ("PW1900G",),
    "LEAP-1A": ("LEAP-1A", "LEAP 1A"), "LEAP-1B": ("LEAP-1B", "LEAP 1B"), "LEAP-1C": ("LEAP-1C", "LEAP 1C"),
    "CJ1000A": ("CJ-1000A", "CJ1000A", "CJ-1000"), "CJ2000": ("CJ-2000", "CJ2000"),
    "PD14": ("PD-14", "PD14"), "PD8": ("PD-8", "PD8"), "PS90": ("PS-90A", "PS-90", "PS90"),
    "PW127": ("PW127", "PW127M", "PW127XT"), "PT6": ("PT6", "PT6A"),
}
ENGINE_FAMILY_MEMBERS = {
    "GTF": _GTF_SPECIFIC_MODELS, "LEAP": _LEAP_SPECIFIC_MODELS,
    "PD": _PD_SPECIFIC_MODELS, "CJ": _CJ_SPECIFIC_MODELS,
}
SYNTACTIC_MODEL_TOKEN_RE = re.compile(r"\b[A-Z]{1,5}-?\d{2,5}[A-Z0-9-]*\b", re.I)