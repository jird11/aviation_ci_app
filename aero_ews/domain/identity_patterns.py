"""Technical identity lookup tables and compiled evidence patterns."""

import re
from typing import Dict

from tasks import SCMTier

# Technical identity dictionaries are lexical hints; they are not installation or applicability proof.
ENGINE_MODEL_PATTERNS: Dict[str, re.Pattern] = {
    # ============================================================
    # CFM International engine names (family labels remain distinct from variant identities).
    # ============================================================
    "CFM56": re.compile(
        r"\bcfm[\s-]?56\b", re.I
    ),
    "LEAP-1A": re.compile(
        r"\bleap[\s-]*1a(?:[0-9][a-z0-9]*)?\b", re.I
    ),
    "LEAP-1B": re.compile(
        r"\bleap[\s-]*1b(?:[0-9][a-z0-9]*)?\b", re.I
    ),
    "LEAP-1C": re.compile(
        r"\bleap[\s-]*1c(?:[0-9][a-z0-9]*)?\b", re.I
    ),
    "LEAP": re.compile(
        r"\bleap\b", re.I
    ),
    # ============================================================
    # Pratt & Whitney models; GTF is a broad family term, not synonymous with PW1100G.
    # ============================================================
    "PW1100G_GTF": re.compile(
        r"\bpw[\s-]*1100g(?:[\s-]*jm)?\b|\bpw11\d{2}g[a0-9]?(?:-\s*jm)?\b", re.I
    ),
    "PW1500G_GTF": re.compile(
        r"\bpw[\s-]*1500g\b|\bpw15\d{2}g(?:a|-\s*\d)?\b", re.I
    ),
    "PW1900G_GTF": re.compile(
        r"\bpw[\s-]*1900g\b|\bpw19\d{2}g(?:-\s*(?:rc|a))?\b", re.I
    ),
    "GTF": re.compile(
        r"\b(?:gtf|geared[\s-]*turbo[\s-]*fan)\b", re.I
    ),
    "PW4000": re.compile(
        r"\bpw[\s-]*4000\b", re.I
    ),
    "PW2000": re.compile(
        r"\bpw[\s-]*2000\b", re.I
    ),
    # ============================================================
    # GE Aerospace and Engine Alliance model identifiers.
    # ============================================================
    "GE90": re.compile(
        r"\bge[\s-]?90\b", re.I
    ),
    "GE9X": re.compile(
        r"\bge[\s-]?9x\b", re.I
    ),
    "GENX": re.compile(
        r"\bge[\s-]?nx\b", re.I
    ),
    "CF34": re.compile(
        r"\bcf[\s-]?34\b", re.I
    ),
    "CF6": re.compile(
        r"\bcf[\s-]?6\b", re.I
    ),
    "GP7000": re.compile(
        r"\bgp[\s-]?7000\b", re.I
    ),
    # ============================================================
    # Rolls-Royce engine families and named variants.
    # ============================================================
    "TRENT_1000": re.compile(
        r"\btrent[\s-]*1000\b", re.I
    ),
    "TRENT_7000": re.compile(
        r"\btrent[\s-]*7000\b", re.I
    ),
    "TRENT_700": re.compile(
        r"\btrent[\s-]*700\b", re.I
    ),
    "TRENT_900": re.compile(
        r"\btrent[\s-]*900\b", re.I
    ),
    "TRENT_XWB": re.compile(
        r"\btrent[\s-]*xwb(?:[\s-]*\d+)?\b", re.I
    ),
    "RB211": re.compile(
        r"\brb[\s-]*211\b", re.I
    ),
    # ============================================================
    # International Aero Engines and other historically monitored engine models.
    # ============================================================
    "V2500": re.compile(
        r"\bv[\s-]?2500\b", re.I
    ),
    "AE3007": re.compile(
        r"\bae[\s-]*3007\b", re.I
    ),
# ============================================================
    # COMAC (AECC), Russian/Ukrainian, and turboprop/military engines.
    # ============================================================
    "CJ1000A": re.compile(
        r"\bcj[\s-]*1000a?\b", re.I
    ),
    "CJ2000": re.compile(
        r"\bcj[\s-]*2000\b", re.I
    ),
    "PD14": re.compile(
        r"\bpd[\s-]*14\b", re.I
    ),
    "PD8": re.compile(
        r"\bpd[\s-]*8\b", re.I
    ),
    "PD35": re.compile(
        r"\bpd[\s-]*35\b", re.I
    ),
    "PS90": re.compile(
        r"\bps[\s-]*90a?(?:[\s-]*76)?\b", re.I
    ),
    "SAM146": re.compile(
        r"\bsam[\s-]*146\b", re.I
    ),
    "PW127": re.compile(
        r"\bpw[\s-]*127(?:[\s-]*(?:xt|m|b))?\b", re.I
    ),
    "PT6": re.compile(
        r"\bpt[\s-]*6a?\b", re.I
    ),
    "F135": re.compile(
        r"\bf[\s-]*135\b", re.I
    ),
    "F110": re.compile(
        r"\bf[\s-]*110\b", re.I
    ),
}

SPECIFIC_AIRCRAFT_VARIANT_PATTERNS: Dict[str, re.Pattern] = {
    "777X": re.compile(r"\b(?:777xs?|777-8|777-9|b777x)\b", re.I),
    "777F": re.compile(r"\b(?:777f|777\s+freighter|b777f)\b", re.I),
    "777_LEGACY": re.compile(r"\b(?:777-200|777-300(?:er)?)\b", re.I),
    "737_MAX": re.compile(r"\b(?:737[\s_-]*max|737-7|737-8|737-9|737-10|max\s*[789]|max\s*10)\b", re.I),
    "737_NG": re.compile(r"\b(?:737\s*ng|737-700|737-800|737-900)\b", re.I),
    "787": re.compile(r"\b(?:787|787-8|787-9|787-10|dreamliner)\b", re.I),
    "767": re.compile(r"\b(?:767|767-300f?)\b", re.I),
    "A321XLR": re.compile(r"\ba321\s*xlr\b", re.I),
    "A320NEO_FAMILY": re.compile(
        r"\b(?:"
        r"a3(?:19|20|21)[\s-]*neo"
        r"|a3(?:19|20|21)-\d{3}n[a-z]?"
        r"|a320neo_family"
        r")\b",
        re.I,
    ),
    "A320CEO_FAMILY": re.compile(r"\ba3(?:18|19|20|21)\s*ceo\b", re.I),
    "A350F": re.compile(r"\ba350f\b", re.I),
    "A350": re.compile(r"\ba350(?:-\d{3})?\b", re.I),
    "A330NEO": re.compile(r"\ba330\s*neo|a330-900\b", re.I),
    "A220": re.compile(r"\ba220(?:-[13]00)?\b", re.I),
    "C919": re.compile(r"\bc919\b", re.I),
    "C909": re.compile(
        r"\b(?:c909|arj[\s-]?21)\b",
        re.I,
    ),
    "EJET_E2": re.compile(
        r"\be(?:175|190|195)[\s-]?e2\b",
        re.I,
    ),
    "C929": re.compile(
        r"\bc929\b", re.I
    ),
    "EJET_E1": re.compile(
        r"\be(?:170|175|190|195)(?:[\s-]?(?:lr|ar))?\b", re.I
    ),
    "ATR": re.compile(
        r"\batr[\s-]?(?:42|72)(?:[\s-]*(?:500|600))?\b", re.I
    ),
    "IL_76_96": re.compile(
        r"\bil[\s-]?(?:76|96|114)(?:[\s-]*(?:md|td|90|400))?\b", re.I
    ),
    "MC_21": re.compile(
        r"\b(?:mc|ms)[\s-]?21(?:[\s-]*300)?\b", re.I
    ),
    "SUPERJET": re.compile(
        r"\b(?:ssj[\s-]?100|sj[\s-]?100|superjet[\s-]?100)\b", re.I
    ),
    "KC_46": re.compile(
        r"\bkc[\s-]?46a?\b", re.I
    ),
    "F_35": re.compile(
        r"\bf[\s-]?35[abc]?\b", re.I
    ),
}

AIRCRAFT_FAMILY_PATTERNS: Dict[str, re.Pattern] = {
    # Airbus aircraft-family aliases for lexical program identification.
    "A220": re.compile(
        r"\ba220(?:-\d{3})?\b", re.I
    ),
    "A320_FAMILY": re.compile(
        r"\ba3(?:18|19|20|21)"
        r"(?:[\s-]?(?:neo|ceo|xlr|lr)|-\d{3}[a-z]{0,2})?\b",
        re.I,
    ),
    "A330": re.compile(
        r"\ba330(?:[\s-]?neo|-\d{3}[a-z]?)?\b", re.I
    ),
    "A350": re.compile(
        r"\ba350(?:-\d{3}|f)?\b", re.I
    ),
    "A380": re.compile(
        r"\ba380(?:-\d{3})?\b", re.I
    ),
    "A400M": re.compile(
        r"\ba400m\b", re.I
    ),
    # Boeing aircraft-family aliases for lexical program identification.
    "B737": re.compile(
        r"\b(?:b\s*)?737(?:[\s-]?(?:max|ng|\d{1,4}))?\b",
        re.I,
    ),
    "B747": re.compile(
        r"\b(?:b\s*)?747(?:-\d{3}[a-z]?)?\b",
        re.I,
    ),
    "B757": re.compile(
        r"\b(?:b\s*)?757(?:-\d{3})?\b",
        re.I,
    ),
    "B767": re.compile(
        r"\b(?:b\s*)?767(?:-\d{3}[a-z]?)?\b",
        re.I,
    ),
    "B777": re.compile(
        r"\b(?:b\s*)?777(?:x|-[0-9]{1,3}[a-z]?)?\b",
        re.I,
    ),
    "B787": re.compile(
        r"\b(?:b\s*)?787(?:-\d{1,2})?\b|\bdreamliner\b",
        re.I,
    ),
    # COMAC: C919 and C909/ARJ21 remain distinct programs.
    "C919": re.compile(
        r"\bc919\b", re.I
    ),
    "C909": re.compile(
        r"\b(?:c909|arj[\s-]?21)\b", re.I
    ),
    # Embraer regional-jet family aliases.
    "E_JETS": re.compile(
        r"\b(?:e[\s-]?(?:170|175|190|195)"
        r"(?:[\s-]?e2)?|"
        r"erj[\s-]?(?:170|175|190|195))\b",
        re.I,
    ),
    # Other regional aircraft families.
    "ATR": re.compile(
        r"\batr[\s-]?(?:42|72)(?:-\d{3})?\b",
        re.I,
    ),
    "CRJ": re.compile(
        r"\bcrj[\s-]?(?:200|700|900|1000)\b",
        re.I,
    ),
    "Q400": re.compile(
        r"\b(?:dash[\s-]?8[\s-]?q400|q400)\b",
        re.I,
    ),
# Additional regional, cargo, business, and non-Western families.
    "C929": re.compile(
        r"\bc929\b", re.I
    ),
    "MC_21": re.compile(
        r"\b(?:mc|ms)[\s-]?21(?:[\s-]*300)?\b", re.I
    ),
    "SUPERJET": re.compile(
        r"\b(?:ssj[\s-]?100|sj[\s-]?100|superjet[\s-]?100)\b", re.I
    ),
    "ILYUSHIN_ANTONOV": re.compile(
        r"\b(?:il[\s-]?(?:76|96|114)|an[\s-]?(?:124|148|158)|tu[\s-]?(?:204|214))\b", re.I
    ),
    "GULFSTREAM": re.compile(
        r"\bg(?:280|500|600|650|700|800)(?:er)?\b", re.I
    ),
    "GLOBAL_JET": re.compile(
        r"\bglobal[\s-]?(?:5500|6500|7500|8000)\b", re.I
    ),
}

# Central aerospace component vocabulary used in deterministic evidence checks.
# Aliases share a canonical label; a text match does not independently verify a defect.

COMPONENT_KEYWORDS_MAP: Dict[str, str] = {
    # ============================================================
    # ENGINE & PROPULSION SYSTEMS
    # ============================================================
    "fire switch": "Engine Fire Switch / Cockpit Fire Panel",
    "powder metal": "High-Pressure Turbine Discs (Powder Metal)",
    "powdered metal": "High-Pressure Turbine Discs (Powder Metal)",
    "fan blade": "Engine Fan Blades",
    "fan blades": "Engine Fan Blades",
    "turbine blade": "Engine Turbine Blades",
    "turbine blades": "Engine Turbine Blades",
    "compressor blade": "Engine Compressor Blades",
    "compressor blades": "Engine Compressor Blades",
    "combustor": "Engine Combustion System",
    "combustion chamber": "Engine Combustion System",
    # ============================================================
    # FUEL & HYDRAULIC SYSTEMS
    # ============================================================
    "hydraulic pump": "Hydraulic Pump",
    "hydraulic pumps": "Hydraulic Pump",
    "fuel pump": "Fuel Pump",
    "fuel pumps": "Fuel Pump",
    "fuel tank": "Aircraft Fuel Tank",
    "fuel tanks": "Aircraft Fuel Tank",
    # ============================================================
    # AVIONICS & ELECTRICAL SYSTEMS
    # ============================================================
    "avionics": "Flight Deck Avionics System",
    "wiring harness": "Electrical Wiring Harness",
    "wiring harnesses": "Electrical Wiring Harness",
    "flight management system": "Flight Management System",
    "flight management computer": "Flight Management System",
    # ============================================================
    # AIRCRAFT STRUCTURES
    # ============================================================
    "fuselage": "Aircraft Fuselage Structure",
    "door plug": "Fuselage Door Plug",
    "door plugs": "Fuselage Door Plug",
    "wing spar": "Wing Spar",
    "wing spars": "Wing Spar",
    "engine pylon": "Engine Pylon",
    "engine pylons": "Engine Pylon",
    "slotted nut": "Wing Thrust Spigot Slotted Nuts",
    "trailing-edge rib kit": "Wing Trailing-Edge Rib Kit",
    # ============================================================
    # FLIGHT CONTROL SYSTEMS
    # ============================================================
    "flight control actuator": "Flight Control Actuator",
    "flight control actuators": "Flight Control Actuator",
    "hydraulic actuator": "Hydraulic Actuator",
    "hydraulic actuators": "Hydraulic Actuator",
    # ============================================================
    # LANDING GEAR & BRAKING
    # ============================================================
    "landing gear": "Landing Gear System",
    "brake assembly": "Aircraft Brake Assembly",
    "brake assemblies": "Aircraft Brake Assembly",
    # ============================================================
    # SAFETY & EMERGENCY SYSTEMS
    # ============================================================
    "evacuation slide": "Door Emergency Evacuation Slide System",
    # ============================================================
    # MATERIALS & MANUFACTURING
    # ============================================================
    "titanium": "Aerospace Titanium Forgings / Raw Material",
    "casting": "Precision Turbine Castings",
# ============================================================
    # ADDITIONAL ENGINE, NACELLE & STRUCTURAL SUBSYSTEMS
    # ============================================================
    "nacelle": "Engine Nacelle / Thrust Reverser",
    "nacelles": "Engine Nacelle / Thrust Reverser",
    "thrust reverser": "Engine Nacelle / Thrust Reverser",
    "gearbox": "Accessory / Transfer Gearbox",
    "accessory gearbox": "Accessory / Transfer Gearbox",
    "rotor": "Rotor / Rotating Assembly",
    "stator": "Stator Vane Assembly",
    "borescope": "Borescope Inspection / Internal Hardware",
    "apu": "Auxiliary Power Unit (APU)",
    "flight control": "Flight Control System",
    "rudder": "Flight Control System",
    "elevator": "Flight Control System",
    "aileron": "Flight Control System",
    "composite": "Composite Airframe / Structures",
    "composites": "Composite Airframe / Structures",
    "superalloy": "High-Temperature Superalloys",
    "superalloys": "High-Temperature Superalloys",
}

HYPOTHETICAL_IN_FACTS_REGEX = re.compile(
    r"\b(?:could|might|would|potentially|hypothetical\w*|speculat\w*|if\s+this|may\s+lead\s+to|threatens\s+to)\b", re.I
)
CAUSAL_CLAIM_REGEX = re.compile(
    r"\b(?:caus(?:es|ed|ing)|lead(?:s|ing)\s+to|result(?:s|ed|ing)\s+in|forc(?:es|ed|ing)|trigger(?:s|ed|ing)|due\s+to|because\s+of|prompted\s+by|delays?\s+delivery)\b",
    re.I,
)

EVENT_LOCATION_EVIDENCE_MAP: Dict[str, re.Pattern] = {
    "North America (USA / Canada)": re.compile(
        r"\b(?:united\s+states|u\.s\.|usa|faa|ntsb|federal\s+register|renton|everett|charleston|wichita|"
        r"seattle|connecticut|east\s+hartford|clayville|goodyear|arizona|dallas|detroit|mobile,\s+alabama|"
        r"canada|mirabel|montreal|toronto)\b", re.I
    ),
    "Europe (EU / UK / France / Germany)": re.compile(
        r"\b(?:europe\w*|easa|toulouse|hamburg|farnborough|paris|france|germany|united\s+kingdom|u\.k\.|"
        r"britain|london|derby|filton|bremen|madrid|spain|italy|dublin|hungary|warsaw|istanbul|turkish)\b", re.I
    ),
    "Asia-Pacific (China / Singapore / Japan / India)": re.compile(
        r"\b(?:china|shanghai|beijing|tianjin|singapore|india|new\s+delhi|mumbai|japan|tokyo|south\s+korea|"
        r"seoul|taiwan|taipei|australia|sydney|melbourne)\b", re.I
    ),
    "Middle East (UAE / Qatar / Saudi Arabia)": re.compile(
        r"\b(?:dubai|uae|united\s+arab\s+emirates|abu\s+dhabi|qatar|doha|saudi\s+arabia|riyadh|jeddah)\b", re.I
    ),
}

_EVENT_LOCATION_PATTERN = re.compile(
    r"\b(?:production|assembly|manufacturing|factory|plant|facility|incident|disruption|"
    r"strike|accident|ground test|stoppage|production halt)\b.{0,90}?\b(?:in|at|near)\s+"
    r"(Everett|Seattle|Renton|Wichita|Florida|Washington|Charleston|Toulouse|Hamburg|Bremen|"
    r"Derby|Farnborough|Shanghai|Tianjin|Singapore|Montreal|Mirabel|Dubai|Doha)\b",
    re.I | re.S,
)

_LOCATION_TO_REGION = {
    **{k: "North America (USA / Canada)" for k in
       ("everett", "seattle", "renton", "wichita", "florida", "washington", "charleston", "montreal", "mirabel")},
    **{k: "Europe (EU / UK / France / Germany)" for k in ("toulouse", "hamburg", "bremen", "derby", "farnborough")},
    **{k: "Asia-Pacific (China / Singapore / Japan / India)" for k in ("shanghai", "tianjin", "singapore")},
    **{k: "Middle East (UAE / Qatar / Saudi Arabia)" for k in ("dubai", "doha")},
}

_WIRE_PATTERNS = {
    "REUTERS": re.compile(r"\breuters\b", re.I),
    "ASSOCIATED_PRESS": re.compile(r"\b(?:associated press|ap news)\b", re.I),
    "AGENCE_FRANCE_PRESSE": re.compile(r"\b(?:agence france.presse|afp)\b", re.I),
}

_PRIOR_PERIOD_CAUSE_RE = re.compile(
    r"\b(?:year[- ]ago|prior[- ]year|previous[- ]year)\b.{0,100}\b(?:mostly|mainly|primarily|largely)\s+(?:from|due to|because of)\b",
    re.I | re.S,
)
_CURRENT_PERIOD_RE = re.compile(r"\b(?:q[1-4]\s*20\d{2}|20\d{2}\s+q[1-4])\b", re.I)
_CLAIM_CAUSE_RE = re.compile(
    r"\b(?:primary\s+cause\s*:|(?:mainly|primarily|mostly|largely)\s+(?:due\s+to|from|because\s+of))", re.I)

_EXACT_VARIANT_RE = re.compile(
    r"(?<!\w)(?:[AB]\s*)?(\d{3})(?:[\s_-]*(max|neo|ceo|xlr|lr|er)(?:[\s_-]*(\d{1,3}))?|[\s_-]+(\d{1,3}))?(?!\w)",
    re.I,
)

AIRLINE_AND_REGULATOR_PATTERN = re.compile(
    r"\b(?:airlines?|airways|air\s+canada|qantas|indigo|wizz(?:\s*air)?|lufthansa|ryanair|delta|"
    r"united|american\s+airlines|jetblue|easyjet|emirates|etihad|qatar|flydubai|starlux|aegean|"
    r"iberia|klm|air\s+france|turkish|spirit\s+airlines|cyprus|aircastle|aer\s+lingus|korean\s+air|"
    r"asiana|jeju\s+air|jin\s+air|hainan|volotea|condor|norwegian|swiss|austrian|flyone|ajet|"
    r"faa|easa|ntsb|caa|icao|iata|federal\s+aviation|safety\s+agency|ministry|regulator\w*)\b",
    re.I,
)

REGISTRY_TIER_MAP: Dict[str, SCMTier] = {
    "OEM (Final Assembler)": SCMTier.OEM,
    "Tier 1 (Systems/Engines)": SCMTier.TIER_1,
    "Tier 2 (Subcomponents)": SCMTier.TIER_2,
    "Tier 3 (Raw Materials)": SCMTier.TIER_3,
    "Regulator / Airline": SCMTier.REGULATOR_AIRLINE,
}

ONGOING_OR_RECONFIRMED_PATTERNS = re.compile(
    r"\b(?:reaffirm\w*|reconfirm\w*|reiterat\w*|previously\s+(?:announced|delayed|pushed)|"
    r"contin(?:ues|ued)\s+to\s+(?:expect|anticipate|target)|still\s+expects?|"
    r"maintains?\s+(?:its\s+)?(?:20\d{2}|schedule|target)|on\s+track\s+for\s+20\d{2}|remains?\s+scheduled)\b",
    re.I,
)

HISTORICAL_RECAP_PATTERNS = re.compile(r"\b(?:in\s+20\d{2}|years\s+ago|history\s+of|documentary)\b", re.I)

# Identify explicit engine names; generic family labels must not override specific variants.
_GTF_SPECIFIC_MODELS = frozenset({'PW1100G_GTF', 'PW1500G_GTF', 'PW1900G_GTF'})

_LEAP_SPECIFIC_MODELS = frozenset({'LEAP-1A', 'LEAP-1B', 'LEAP-1C'})

# Catalog entries are explicit identity labels; a generic code-looking token is not one.
ENGINE_CANONICAL_IDENTITIES = {
    **{key: key for key in ENGINE_MODEL_PATTERNS},
    "PW1100G_GTF": "PW1100G",
    "PW1500G_GTF": "PW1500G",
    "PW1900G_GTF": "PW1900G",
    "TRENT_1000": "Trent 1000",
    "TRENT_7000": "Trent 7000",
    "TRENT_700": "Trent 700",
    "TRENT_900": "Trent 900",
    "TRENT_XWB": "Trent XWB",
}
ENGINE_KNOWN_ALIASES = {
    "PW1100G_GTF": ("PW1100G", "PW1100G-JM"),
    "PW1500G_GTF": ("PW1500G",),
    "PW1900G_GTF": ("PW1900G",),
    "LEAP-1A": ("LEAP-1A", "LEAP 1A"),
    "LEAP-1B": ("LEAP-1B", "LEAP 1B"),
    "LEAP-1C": ("LEAP-1C", "LEAP 1C"),
}
ENGINE_FAMILY_MEMBERS = {"GTF": _GTF_SPECIFIC_MODELS, "LEAP": _LEAP_SPECIFIC_MODELS}
SYNTACTIC_MODEL_TOKEN_RE = re.compile(r"\b[A-Z]{1,5}-?\d{2,5}[A-Z0-9-]*\b", re.I)

ENGINE_CANONICAL_IDENTITIES.update({
    "CJ1000A": "CJ-1000A",
    "CJ2000": "CJ-2000",
    "PD14": "PD-14",
    "PD8": "PD-8",
    "PD35": "PD-35",
    "PS90": "PS-90A",
    "SAM146": "SaM146",
    "PW127": "PW127",
    "PT6": "PT6",
    "F135": "F135",
    "F110": "F110",
})

ENGINE_KNOWN_ALIASES.update({
    "CJ1000A": ("CJ-1000A", "CJ1000A", "CJ-1000"),
    "CJ2000": ("CJ-2000", "CJ2000"),
    "PD14": ("PD-14", "PD14"),
    "PD8": ("PD-8", "PD8"),
    "PS90": ("PS-90A", "PS-90", "PS90"),
    "PW127": ("PW127", "PW127M", "PW127XT"),
    "PT6": ("PT6", "PT6A"),
})

_PD_SPECIFIC_MODELS = frozenset({"PD14", "PD8", "PD35"})
_CJ_SPECIFIC_MODELS = frozenset({"CJ1000A", "CJ2000"})
ENGINE_FAMILY_MEMBERS.update({
    "PD": _PD_SPECIFIC_MODELS,
    "CJ": _CJ_SPECIFIC_MODELS,
})