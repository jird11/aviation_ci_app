"""Governed source and aerospace supplier registry definitions."""

import os
from enum import Enum
from typing import Any, Dict, List


class SourceLegalStatus(str, Enum):
    """Configured access and collection policy statuses for governed sources."""
    ALLOWED = "ALLOWED"
    RESTRICTED = "RESTRICTED"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    DISABLED = "DISABLED"


# Default operational telemetry fields merged into every registered source.
_SRC_DEFAULTS = {
    "last_legal_review_date": "2026-10-15",
    "tdm_opt_out": False,
    "last_success_at": None,
    "success_count": 0,
    "failure_count": 0,
}

# Core source definitions (all metadata, ToS URLs, legal bases, and rate limits preserved verbatim).
_BASE_SOURCES: Dict[str, Dict[str, Any]] = {
    "SRC_001": {
        "name": "FAA Federal Register", "domain": "federalregister.gov",
        "source_type": "REGULATORY", "origin": "PRIMARY", "access_method": "API",
        "allowed_access_method": "API (Official REST Endpoint)",
        "tos_url": "https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/developer-resources",
        "usage_restrictions": "Public domain (17 U.S.C. 105); unrestricted retention, processing, and internal/external redistribution.",
        "tdm_copyright_basis": "Public Domain (No copyright / TDM restrictions)",
        "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (official regulatory records; minimal personal data)",
        "verified_domain": True, "legal_status": SourceLegalStatus.ALLOWED.value,
        "license_notes": "US Government Public Domain / Federal Register API",
        "rate_limit_rpm": 30, "min_interval_sec": 1.0,
    },
    "SRC_002": {
        "name": "EASA Safety & Regulatory Monitor (via RSS Proxy)", "domain": "easa.europa.eu",
        "technical_host": "news.google.com", "source_type": "REGULATORY",
        "origin": "PRIMARY_VIA_AGGREGATOR", "access_method": "RSS",
        "allowed_access_method": "RSS (Metadata & Short Snippets Only)",
        "tos_url": "https://www.easa.europa.eu/en/legal-notice",
        "usage_restrictions": "Store metadata, headlines, and short excerpts only; attribute EASA; no commercial redistribution of full texts.",
        "tdm_copyright_basis": "EU Directive 2019/790 Art. 3/4 TDM & EASA Legal Notice",
        "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (institutional safety notices)",
        "verified_domain": True, "legal_status": SourceLegalStatus.ALLOWED.value,
        "license_notes": "Metadata & public safety notices via RSS search index",
        "rate_limit_rpm": 20, "min_interval_sec": 1.5,
    },
    "SRC_003": {
        "name": "NTSB Aviation Investigation Monitor (via RSS Proxy)", "domain": "ntsb.gov",
        "technical_host": "news.google.com", "source_type": "REGULATORY",
        "origin": "PRIMARY_VIA_AGGREGATOR", "access_method": "RSS",
        "allowed_access_method": "RSS (Metadata & Short Snippets Only)",
        "tos_url": "https://www.ntsb.gov/Pages/policies.aspx",
        "usage_restrictions": "US Government public safety notices; retain metadata and short summaries; cite original NTSB link.",
        "tdm_copyright_basis": "Public Domain (US Federal Agency) / RSS Aggregation",
        "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (exclude victim/crew private PII)",
        "verified_domain": True, "legal_status": SourceLegalStatus.ALLOWED.value,
        "license_notes": "Public safety investigation notices",
        "rate_limit_rpm": 20, "min_interval_sec": 1.5,
    },
    "SRC_004": {
        "name": "News API Global Media", "domain": "newsapi.org",
        "source_type": "MEDIA_AGGREGATOR", "origin": "SECONDARY", "access_method": "API",
        "allowed_access_method": "API + Approved robots.txt/TDM-compliant Snippet Extraction",
        "tos_url": "https://newsapi.org/terms",
        "usage_restrictions": "Internal academic/CI analysis only; store short verbatim quotes (<450 chars) & URLs; no full-article republication.",
        "tdm_copyright_basis": "NewsAPI ToS + EU Directive 2019/790 Art. 4 (subject to publisher TDM-Reservation opt-out)",
        "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (redact reporter/contact PII)",
        "verified_domain": True, "legal_status": SourceLegalStatus.ALLOWED.value,
        "license_notes": "NewsAPI Developer/Academic Terms - snippet & link indexing",
        "rate_limit_rpm": 20, "min_interval_sec": 1.5,
    },
    "SRC_005": {
        "name": "Official Industry PR (Aircraft OEMs & Suppliers)",
        "domain": "airbus.com,boeing.mediaroom.com,comac.cc", "technical_host": "news.google.com",
        "source_type": "OEM_PR", "origin": "PRIMARY_VIA_AGGREGATOR", "access_method": "RSS",
        "allowed_access_method": "RSS (Public Corporate Press Releases)",
        "tos_url": "https://www.airbus.com/en/terms-of-use",
        "usage_restrictions": "Public investor/media releases; retain title, link, and short summary for internal CI monitoring.",
        "tdm_copyright_basis": "Corporate PR Public Press License / EU Directive 2019/790 Art. 4",
        "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (corporate spokespersons only; contact PII redacted)",
        "verified_domain": True, "legal_status": SourceLegalStatus.ALLOWED.value,
        "license_notes": "Public corporate press releases",
        "rate_limit_rpm": 20, "min_interval_sec": 1.5,
    },
    "SRC_006": {
        "name": "International Airshow Newsrooms",
        "domain": "farnboroughairshow.com,siae.fr,dubaiairshow.aero,singaporeairshow.com",
        "source_type": "INDUSTRY_EVENT", "origin": "PRIMARY", "access_method": "PLAYWRIGHT_CRAWLER",
        "allowed_access_method": "Approved Scraping (Strict robots.txt & TDM-Reservation check mandatory)",
        "tos_url": "https://www.farnboroughairshow.com/terms-and-conditions/",
        "usage_restrictions": "RESTRICTED: Suspend immediately if robots.txt is unreachable or disallows crawling; retain short excerpts only; no redistribution.",
        "tdm_copyright_basis": "EU Directive 2019/790 Art. 4 TDM (Strictly conditional on absence of machine-readable opt-out)",
        "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (B2B event press releases; personal career/HR posts filtered out)",
        "verified_domain": True, "legal_status": SourceLegalStatus.RESTRICTED.value,
        "license_notes": "Respect robots.txt and rate limits; short excerpts only",
        "rate_limit_rpm": 12, "min_interval_sec": 2.5,
    },
    "SRC_007": {
        "name": "Bluesky AT Protocol Aviation Feed", "domain": "bsky.app",
        "source_type": "COMMUNITY_SOCIAL", "origin": "SECONDARY_UNVERIFIED", "access_method": "API",
        "allowed_access_method": "API (Official AT Protocol Public Search)",
        "tos_url": "https://bsky.social/about/support/tos",
        "usage_restrictions": "Exclude private/personal posts unrelated to aerospace; anonymize author handles; internal weak-signal verification only.",
        "tdm_copyright_basis": "AT Protocol Developer Terms",
        "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest with strict Data Minimization (personal non-aerospace posts dropped; handles pseudonymized)",
        "verified_domain": False, "legal_status": SourceLegalStatus.RESTRICTED.value,
        "license_notes": "AT Protocol public search API",
        "rate_limit_rpm": 20, "min_interval_sec": 1.5,
    },
    "SRC_008": {
        "name": "YouTube Data API v3 & Transcripts", "domain": "youtube.com",
        "source_type": "VIDEO_MEDIA", "origin": "SECONDARY_UNVERIFIED", "access_method": "API",
        "allowed_access_method": "API (YouTube Data API v3)",
        "tos_url": "https://developers.google.com/youtube/terms/api-services-terms-of-service",
        "usage_restrictions": "Temporary analytical processing of spoken B2B/aviation news transcripts; no redistribution of full transcripts; exclude personal vlogs.",
        "tdm_copyright_basis": "YouTube API Services Terms of Service",
        "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (public B2B media channels only; personal hobbyist vlogs rejected)",
        "verified_domain": False, "legal_status": SourceLegalStatus.RESTRICTED.value,
        "license_notes": "YouTube Data API v3 Terms of Service",
        "rate_limit_rpm": 30, "min_interval_sec": 2.0,
    },
    **{
        sid: {
            "name": f"{company} RSS", "domain": domain, "source_type": "SUPPLIER_PR",
            "origin": "PRIMARY", "access_method": "RSS", "tos_url": tos,
            "last_legal_review_date": os.getenv(f"{env_key}_REVIEW_DATE", ""),
            "legal_status": "RESTRICTED" if (os.getenv(f"{env_key}_APPROVED") == "1" and os.getenv(f"{env_key}_REVIEW_DATE")) else "REQUIRES_REVIEW",
            "verified_domain": True, "tdm_copyright_basis": "Review required",
            "usage_restrictions": "Metadata only; permission required",
            "rate_limit_rpm": 6, "min_interval_sec": 10.0,
        }
        for sid, company, domain, tos, env_key in (
            ("SRC_010", "GE Aerospace", "geaerospace.com", "https://www.geaerospace.com/pl/node/5536", "EWS_GE_RSS"),
            ("SRC_011", "RTX", "rtx.com", "https://www.rtx.com/Terms-of-Use", "EWS_RTX_RSS"),
        )
    },
}

# Build SOURCE_REGISTRY, merge supplementary sources, and apply post-merge policy overrides.
SOURCE_REGISTRY: Dict[str, Dict[str, Any]] = {k: {**_SRC_DEFAULTS, "source_id": k, **v} for k, v in _BASE_SOURCES.items()}

from ews_sources_extra import registry_additions

SOURCE_REGISTRY.update({sid: {**_SRC_DEFAULTS, **cfg} for sid, cfg in registry_additions().items()})

for _sid, _patch in (
    ("SRC_002", {"name": "EASA Official AD Index", "technical_host": "easa.europa.eu", "origin": "PRIMARY", "legal_status": "REQUIRES_REVIEW", "policy_status": "REQUIRES_REVIEW"}),
    ("SRC_003", {"name": "NTSB Public Aviation API", "domain": "api.ntsb.gov", "source_type": "REGULATORY", "origin": "PRIMARY", "technical_host": "api.ntsb.gov", "access_method": "AUTHENTICATED_API", "legal_status": "REQUIRES_REVIEW", "policy_status": "REQUIRES_REVIEW"}),
    ("SRC_004", {"policy_status": "DEV_ONLY"}),
    ("SRC_005", {"name": "Airbus Press Releases RSS", "legal_status": "REQUIRES_REVIEW", "policy_status": "REQUIRES_REVIEW", "domain": "airbus.com", "technical_host": "airbus.com", "origin": "PRIMARY"}),
    ("SRC_006", {"policy_status": "REQUIRES_REVIEW"}),
):
    SOURCE_REGISTRY[_sid].update(_patch)

SOURCE_REGISTRY.pop("SRC_009", None)
SOURCE_REGISTRY["SRC_030"] = {
    **SOURCE_REGISTRY["SRC_005"], "source_id": "SRC_030", "name": "Boeing Newsroom RSS",
    "domain": "boeing.mediaroom.com", "technical_host": "boeing.mediaroom.com",
    "origin": "PRIMARY", "access_method": "RSS", "tos_url": "https://boeing.mediaroom.com/rss-feeds",
    "legal_status": "ALLOWED", "policy_status": "ENABLED",
}

# Aerospace OEM and multi-tier supplier registry (all entities, aliases, programs, and tiers preserved verbatim).
_SUPPLIER_FIELDS = ("entity_id", "official_name", "aliases", "default_tier", "components", "programs", "downstream_oems", "geography", "source_ref")
_OEM = "OEM (Final Assembler)"
_T1 = "Tier 1 (Systems/Engines)"
_T2 = "Tier 2 (Subcomponents)"
_T3 = "Tier 3 (Raw Materials)"

_SUPPLIER_ROWS = (
    # Aircraft OEMs (Final Assemblers)
    ("ENT_AIRBUS", "Airbus SE", ["airbus", "airbus se", "airbus sas", "airbus commercial", "airbus commercial aircraft", "airbus canada", "airbus helicopters", "airbus defence and space"], _OEM, ["Final Aircraft Assembly", "Wing Design", "Rotorcraft & Defense Airframes"], ["A320neo", "A321neo", "A321XLR", "A350", "A350F", "A220", "A330neo", "A380", "A400M", "H145", "H160"], ["Airbus SE"], "Europe (EU)", "Airbus Annual Report / Official Registry"),
    ("ENT_BOEING", "The Boeing Company", ["boeing", "the boeing company", "boeing commercial airplanes", "boeing defense", "mcdonnell douglas"], _OEM, ["Final Aircraft Assembly", "Commercial & Defense Airframes"], ["737 MAX", "737 NG", "777X", "777", "787", "787 Dreamliner", "767", "747-8", "KC-46", "P-8"], ["The Boeing Company"], "North America (USA)", "Boeing SEC Form 10-K"),
    ("ENT_COMAC", "COMAC", ["comac", "commercial aircraft corporation of china"], _OEM, ["Final Aircraft Assembly"], ["C919", "C929", "C909", "ARJ21"], ["COMAC"], "Asia-Pacific (China)", "COMAC Official Directory"),
    ("ENT_EMBRAER", "Embraer S.A.", ["embraer", "embraer sa", "embraer commercial aviation", "embraer executive jets"], _OEM, ["Final Aircraft Assembly", "Regional & Executive Airframes"], ["E175", "E190-E2", "E195-E2", "C-390", "Phenom 300", "Praetor 600"], ["Embraer S.A."], "South America (Brazil)", "Embraer SEC Form 20-F"),
    ("ENT_ATR", "ATR", ["atr", "avions de transport regional"], _OEM, ["Regional Turboprop Airframes"], ["ATR 42", "ATR 72"], ["ATR"], "Europe (EU)", "ATR Official Disclosures"),
    ("ENT_DE_HAVILLAND", "De Havilland Aircraft of Canada", ["de havilland", "de havilland canada", "de havilland aircraft of canada"], _OEM, ["Regional Turboprop Airframes"], ["Dash 8", "Q400"], ["De Havilland Aircraft of Canada"], "North America (Canada)", "De Havilland Canada Official Registry"),
    ("ENT_BOMBARDIER", "Bombardier Inc.", ["bombardier", "bombardier aviation", "bombardier aerospace"], _OEM, ["Business Jet Airframes"], ["Global 7500", "Global 8000", "Challenger 3500", "Challenger 650"], ["Bombardier Inc."], "North America (Canada)", "Bombardier Annual Report"),
    ("ENT_GULFSTREAM", "Gulfstream Aerospace", ["gulfstream", "gulfstream aerospace", "general dynamics"], _OEM, ["Business Jet Airframes"], ["G280", "G500", "G600", "G650", "G700", "G800"], ["Gulfstream Aerospace"], "North America (USA)", "General Dynamics SEC Form 10-K"),
    ("ENT_TEXTRON", "Textron Aviation", ["textron", "textron aviation", "cessna", "beechcraft", "bell textron", "bell helicopter"], _OEM, ["Business Jets", "Turboprops", "Rotorcraft"], ["Citation Longitude", "King Air", "Bell V-280"], ["Textron Aviation"], "North America (USA)", "Textron SEC Form 10-K"),
    ("ENT_DASSAULT", "Dassault Aviation", ["dassault", "dassault aviation"], _OEM, ["Business & Defense Airframes"], ["Falcon 6X", "Falcon 8X", "Falcon 10X"], ["Dassault Aviation"], "Europe (EU)", "Dassault Aviation Annual Report"),
    ("ENT_PILATUS", "Pilatus Aircraft", ["pilatus", "pilatus aircraft"], _OEM, ["Single-Engine Turboprops & Light Jets"], ["PC-12", "PC-24"], ["Pilatus Aircraft"], "Europe (Switzerland)", "Pilatus Aircraft Official Registry"),
    ("ENT_LOCKHEED", "Lockheed Martin", ["lockheed martin", "lockheed", "sikorsky", "sikorsky aircraft"], _OEM, ["Defense Airframes", "Rotorcraft"], ["F-35", "F-16", "C-130J", "CH-53K", "S-92"], ["Lockheed Martin"], "North America (USA)", "Lockheed Martin SEC Form 10-K"),
    ("ENT_NORTHROP", "Northrop Grumman", ["northrop grumman", "northrop"], _OEM, ["Defense Airframes & Aerospace Systems"], ["B-21", "F-35"], ["Northrop Grumman", "Lockheed Martin"], "North America (USA)", "Northrop Grumman SEC Form 10-K"),
    ("ENT_LEONARDO", "Leonardo S.p.A.", ["leonardo", "leonardo helicopters", "agustawestland", "leonardo aerostructures"], _OEM, ["Rotorcraft", "Aerostructures", "Defense Electronics"], ["AW139", "AW189", "787", "ATR 72"], ["Leonardo S.p.A.", "The Boeing Company", "ATR"], "Europe (EU)", "Leonardo Annual Financial Report"),
    ("ENT_BAE", "BAE Systems", ["bae systems", "bae"], _OEM, ["Defense Airframes", "Avionics & Electronic Warfare"], ["F-35", "Eurofighter Typhoon"], ["BAE Systems", "Lockheed Martin"], "Europe (UK)", "BAE Systems Annual Report"),
    ("ENT_UAC", "United Aircraft Corporation (UAC)", ["uac", "united aircraft corporation", "ilyushin", "sukhoi", "yakovlev", "irkut", "tupolev"], _OEM, ["Commercial & Transport Airframes"], ["MC-21", "SJ-100", "SSJ100", "IL-76", "IL-96", "IL-114", "TU-204", "TU-214"], ["United Aircraft Corporation (UAC)"], "Eurasia (Russia)", "UAC Corporate Disclosures"),
    ("ENT_ANTONOV", "Antonov", ["antonov", "antonov company"], _OEM, ["Heavy Transport & Regional Airframes"], ["AN-124", "AN-148", "AN-158"], ["Antonov"], "Europe (Ukraine)", "Antonov Official Directory"),
    # Tier 1 (Engines, Systems, Aerostructures & Major MRO)
    ("ENT_PW", "Pratt & Whitney (RTX)", ["pratt & whitney", "pratt and whitney", "pratt whitney", "p&w", "pratt & whitney canada", "pratt whitney canada", "pratt & whitney rtx", "rtx", "rtx corp", "rtx corporation", "raytheon", "raytheon technologies", "international aero engines", "international aero engines, llc", "international aero engines ag", "iae", "iae llc", "iae ag", "gtf", "pw1100g", "pw1100g-jm", "pw1127g", "pw1133g", "pw1500g", "pw1900g", "pw127", "pw150", "pw800", "pt6", "v2500", "f135"], _T1, ["PW1100G-JM GTF Turbofan Engine", "PW1500G Engine", "PW1900G Engine", "Turboprop & Regional Engines"], ["A320neo", "A321neo", "A321XLR", "A220", "E190-E2", "E195-E2", "ATR 42", "ATR 72", "Q400", "F-35"], ["Airbus SE", "Embraer S.A.", "ATR", "De Havilland Aircraft of Canada", "Lockheed Martin"], "North America (USA / Canada)", "RTX SEC Form 10-K / Supplier Registry"),
    ("ENT_CFM", "CFM International (GE / Safran)", ["cfm", "cfm international", "cfm56", "leap", "leap-1a", "leap-1b", "leap-1c"], _T1, ["LEAP-1A Engine", "LEAP-1B Engine", "LEAP-1C Engine", "CFM56 Engine"], ["A320neo", "A321neo", "A321XLR", "737 MAX", "737 NG", "C919"], ["Airbus SE", "The Boeing Company", "COMAC"], "North America (USA) / Europe (EU)", "CFM International Joint Venture Registry"),
    ("ENT_SAFRAN", "Safran S.A.", ["safran", "safran aircraft engines", "safran landing systems", "safran nacelles", "safran seats", "safran helicopter engines"], _T1, ["LEAP Engine Modules", "Landing Gear", "Nacelles", "Cabin Interiors", "Helicopter Engines"], ["A320neo", "A321XLR", "A350", "737 MAX", "787", "H145", "H160"], ["Airbus SE", "The Boeing Company"], "Europe (EU)", "Safran Universal Registration Document"),
    ("ENT_GE", "GE Aerospace", ["ge aerospace", "ge aviation", "general electric", "ge9x", "ge90", "genx", "cf6", "cf34"], _T1, ["GE9X Engine", "GEnx Engine", "GE90 Engine", "CF34 Engine", "LEAP Core"], ["777X", "777", "787", "747-8", "A320neo", "737 MAX", "E175", "CRJ900", "Global 7500"], ["The Boeing Company", "Airbus SE", "Embraer S.A.", "Bombardier Inc."], "North America (USA)", "GE Aerospace SEC Form 10-K"),
    ("ENT_RR", "Rolls-Royce Holdings", ["rolls-royce", "rolls royce", "rolls royce civil aerospace", "trent 1000", "trent xwb", "trent 7000", "trent 700", "trent 900", "pearl 700", "pearl 10x"], _T1, ["Trent XWB-84/97 Engine", "Trent 7000 Engine", "Trent 1000 Engine", "Pearl Business Jet Engines"], ["A350", "A350F", "A330neo", "787", "A380", "G700", "G800", "Falcon 10X"], ["Airbus SE", "The Boeing Company", "Gulfstream Aerospace", "Dassault Aviation"], "Europe (UK)", "Rolls-Royce Civil Aerospace Disclosures"),
    ("ENT_SPIRIT", "Spirit AeroSystems", ["spirit aerosystems", "spirit aero"], _T1, ["737 Fuselage", "A350 Center Fuselage Section", "A220 Pylons/Wings"], ["737 MAX", "787", "A350", "A220"], ["The Boeing Company", "Airbus SE"], "North America (USA)", "Spirit AeroSystems 10-K"),
    ("ENT_COLLINS", "Collins Aerospace", ["collins aerospace", "rockwell collins", "goodrich"], _T1, ["Avionics", "Nacelles", "Actuation Systems"], ["A320neo", "A321XLR", "737 MAX", "787", "A350", "A220"], ["Airbus SE", "The Boeing Company"], "North America (USA)", "RTX / Collins Aerospace Product Catalog"),
    ("ENT_HONEYWELL", "Honeywell Aerospace", ["honeywell", "honeywell aerospace", "htf7000", "htf7350", "htf7700l"], _T1, ["APUs", "Avionics", "Flight Controls", "Business Jet Engines"], ["737 MAX", "787", "777X", "A320neo", "A350", "Challenger 3500", "Citation Longitude"], ["The Boeing Company", "Airbus SE", "Bombardier Inc.", "Textron Aviation"], "North America (USA)", "Honeywell SEC Form 10-K"),
    ("ENT_PARKER", "Parker-Hannifin", ["parker-hannifin", "parker hannifin", "parker aerospace", "meggitt"], _T1, ["Hydraulic & Fuel Systems", "Flight Control Actuation", "Braking Systems"], ["737 MAX", "787", "777X", "A320neo", "A350", "A220", "E190-E2"], ["The Boeing Company", "Airbus SE", "Embraer S.A."], "North America (USA) / Europe", "Parker-Hannifin SEC Form 10-K"),
    ("ENT_EATON", "Eaton Aerospace", ["eaton", "eaton aerospace", "eaton corporation"], _T1, ["Hydraulic Systems", "Fuel & Pneumatic Systems", "Electrical Power Distribution"], ["A320neo", "A350", "737 MAX", "787", "F-35"], ["Airbus SE", "The Boeing Company", "Lockheed Martin"], "North America (USA) / Europe (EU)", "Eaton SEC Form 10-K"),
    ("ENT_LIEBHERR", "Liebherr-Aerospace", ["liebherr", "liebherr-aerospace", "liebherr aerospace"], _T1, ["Flight Control Actuators", "Landing Gear", "Air Management Systems"], ["A320neo", "A350", "A220", "E190-E2", "E195-E2", "C919"], ["Airbus SE", "Embraer S.A.", "COMAC"], "Europe (EU)", "Liebherr-Aerospace Official Directory"),
    ("ENT_MTU", "MTU Aero Engines", ["mtu", "mtu aero engines"], _T1, ["Low-Pressure Turbines", "High-Pressure Compressors", "Engine MRO"], ["A320neo", "A220", "E190-E2", "787", "A350"], ["Pratt & Whitney (RTX)", "GE Aerospace", "Airbus SE"], "Europe (EU)", "MTU Aero Engines Annual Report"),
    ("ENT_ITP", "ITP Aero", ["itp aero"], _T1, ["Low-Pressure Turbines", "Engine Structures & Externals"], ["A350", "A330neo", "787", "A400M"], ["Rolls-Royce Holdings", "Pratt & Whitney (RTX)", "Airbus SE"], "Europe (EU)", "ITP Aero Official Disclosures"),
    ("ENT_GKN", "GKN Aerospace / Melrose", ["gkn", "gkn aerospace", "melrose", "melrose industries"], _T1, ["Engine Structures & Fan Cases", "Aerostructures", "Wiring Systems"], ["A320neo", "A350", "737 MAX", "787", "777X", "A220"], ["Airbus SE", "The Boeing Company", "Pratt & Whitney (RTX)", "Rolls-Royce Holdings"], "Europe (UK / EU)", "Melrose Industries Annual Report"),
    ("ENT_THALES", "Thales", ["thales", "thales group", "thales avionics"], _T1, ["Flight Deck Avionics", "Flight Control Computers", "In-Flight Entertainment"], ["A320neo", "A350", "A330neo", "787", "ATR 72", "SSJ100"], ["Airbus SE", "The Boeing Company", "ATR"], "Europe (EU)", "Thales Universal Registration Document"),
    ("ENT_L3HARRIS", "L3Harris Technologies", ["l3harris", "l3 harris", "l3-harris", "aerojet rocketdyne"], _T1, ["Avionics", "Mission Systems", "Propulsion"], ["F-35", "F-16", "KC-46", "787", "A350"], ["Lockheed Martin", "The Boeing Company", "Airbus SE"], "North America (USA)", "L3Harris SEC Form 10-K"),
    ("ENT_GARMIN", "Garmin Aviation", ["garmin", "garmin aviation"], _T1, ["Integrated Flight Decks", "Avionics"], ["Citation Longitude", "King Air", "Phenom 300", "PC-12"], ["Textron Aviation", "Embraer S.A.", "Pilatus Aircraft"], "North America (USA)", "Garmin SEC Form 10-K"),
    ("ENT_AECC", "AECC (Aero Engine Corporation of China)", ["aecc", "aero engine corporation of china", "cj-1000a", "cj1000a", "cj-2000"], _T1, ["CJ-1000A Turbofan Engine", "CJ-2000 Engine"], ["C919", "C929"], ["COMAC"], "Asia-Pacific (China)", "AECC Official Disclosures"),
    ("ENT_UEC", "UEC / Aviadvigatel", ["uec", "united engine corporation", "aviadvigatel", "uec-klimov", "klimov", "pd-14", "pd-8", "pd-35", "ps-90a", "sam146"], _T1, ["PD-14 Engine", "PD-8 Engine", "PS-90A Engine", "TV7-117 Turboprop"], ["MC-21", "SJ-100", "SSJ100", "IL-76", "IL-96", "IL-114", "TU-214"], ["United Aircraft Corporation (UAC)"], "Eurasia (Russia)", "UEC Corporate Disclosures"),
    ("ENT_MOTOR_SICH", "Ivchenko-Progress / Motor Sich", ["ivchenko-progress", "ivchenko progress", "motor sich", "d-18t", "d-436"], _T1, ["D-18T Turbofan Engine", "D-436 Turbofan Engine"], ["AN-124", "AN-148", "AN-158"], ["Antonov"], "Europe (Ukraine)", "Ivchenko-Progress / Motor Sich Registry"),
    ("ENT_WILLIAMS", "Williams International", ["williams international", "fj44", "fj44-4a"], _T1, ["FJ44 Turbofan Engines"], ["PC-24", "Citation CJ4"], ["Pilatus Aircraft", "Textron Aviation"], "North America (USA)", "Williams International Official Directory"),
    ("ENT_FTAI", "FTAI Aviation", ["ftai", "ftai aviation"], _T1, ["CFM56 & V2500 Engine MRO Modules"], ["737 NG", "A320ceo"], ["CFM International (GE / Safran)"], "North America (USA)", "FTAI Aviation SEC Form 10-K"),
    ("ENT_STANDARDAERO", "StandardAero", ["standardaero", "standard aero"], _T1, ["Engine MRO Services (LEAP, CFM56, CF34, HTF7000, PT6)"], ["A320neo", "737 MAX", "E175", "ATR 72"], ["CFM International (GE / Safran)", "GE Aerospace", "Pratt & Whitney (RTX)"], "North America (USA) / Global", "StandardAero SEC Form 10-K"),
    ("ENT_LHT", "Lufthansa Technik", ["lufthansa technik"], _T1, ["Airframe, Component & Engine MRO"], ["A320neo", "A350", "787", "737 MAX"], ["Airbus SE", "The Boeing Company"], "Europe (EU)", "Lufthansa Group Annual Report"),
    # Tier 2 & Tier 3 (Subcomponents, Castings, Composites, Raw Materials)
    ("ENT_HOWMET", "Howmet Aerospace", ["howmet", "howmet aerospace", "arconic"], _T2, ["Turbine Airfoils & Castings", "Titanium Structural Parts", "Aerospace Fasteners"], ["A320neo", "A321XLR", "737 MAX", "787", "777X", "A350", "F-35"], ["GE Aerospace", "Pratt & Whitney (RTX)", "Rolls-Royce Holdings", "Airbus SE", "The Boeing Company"], "North America (USA) / Europe", "Howmet Aerospace SEC Form 10-K"),
    ("ENT_HEXCEL", "Hexcel Corporation", ["hexcel", "hexcel corporation", "hexcel composites"], _T2, ["Carbon Fiber Prepregs", "Honeycomb Cores", "Composite Structures"], ["A350", "A320neo", "A220", "787", "777X", "CH-53K"], ["Airbus SE", "The Boeing Company", "Spirit AeroSystems"], "North America (USA) / Europe (EU)", "Hexcel SEC Form 10-K"),
    ("ENT_TORAY", "Toray Industries", ["toray", "toray industries", "toray composite materials"], _T3, ["Aerospace Carbon Fiber & Prepreg Materials"], ["787", "777X", "A350"], ["The Boeing Company", "Airbus SE"], "Asia-Pacific (Japan)", "Toray Industries Annual Report"),
    ("ENT_ATI", "ATI Inc.", ["ati", "ati inc", "allegheny technologies"], _T3, ["Nickel Superalloys", "Titanium Forgings & Mill Products"], ["A320neo", "737 MAX", "787", "A350", "777X"], ["GE Aerospace", "Pratt & Whitney (RTX)", "Rolls-Royce Holdings", "The Boeing Company"], "North America (USA)", "ATI Inc. SEC Form 10-K"),
    ("ENT_CARPENTER", "Carpenter Technology", ["carpenter technology", "carpenter tech"], _T3, ["Specialty Alloys", "Powder Metallurgy Materials"], ["A320neo", "737 MAX", "787", "A350"], ["GE Aerospace", "Pratt & Whitney (RTX)", "Safran S.A."], "North America (USA)", "Carpenter Technology SEC Form 10-K"),
    ("ENT_ALBANY", "Albany Engineered Composites", ["albany engineered composites", "albany international"], _T2, ["3D Woven Composite Fan Blades & Cases (LEAP)"], ["A320neo", "737 MAX", "C919"], ["Safran S.A.", "CFM International (GE / Safran)"], "North America (USA)", "Albany International SEC Form 10-K"),
    ("ENT_KHI", "Kawasaki Heavy Industries", ["kawasaki heavy industries", "khi aerospace"], _T1, ["787 Forward Fuselage Sections", "Engine Components (Trent, PW1100G)"], ["787", "777X", "A320neo", "A350"], ["The Boeing Company", "Rolls-Royce Holdings", "Pratt & Whitney (RTX)"], "Asia-Pacific (Japan)", "Kawasaki Heavy Industries Annual Report"),
    ("ENT_MHI", "Mitsubishi Heavy Industries", ["mitsubishi heavy industries", "mhi aerospace"], _T1, ["787 Composite Wing Boxes", "777X Rear Fuselage Panels", "Engine Components"], ["787", "777X", "A320neo"], ["The Boeing Company", "Pratt & Whitney (RTX)", "Rolls-Royce Holdings"], "Asia-Pacific (Japan)", "Mitsubishi Heavy Industries Annual Report"),
    ("ENT_SUBARU", "Subaru Aerospace", ["subaru aerospace", "subaru corporation aerospace"], _T1, ["787 & 777X Center Wing Box"], ["787", "777X"], ["The Boeing Company"], "Asia-Pacific (Japan)", "Subaru Corporation Annual Report"),
    ("ENT_VSMPO", "VSMPO-AVISMA / Titanium Suppliers", ["vsmpo", "vsmpo-avisma"], _T3, ["Aerospace-grade Titanium Forgings", "Superalloys"], ["A350", "787", "A320neo", "737 MAX", "777X"], ["Airbus SE", "The Boeing Company", "Safran S.A.", "Spirit AeroSystems"], "Global", "Aerospace Raw Material Supply Chain Registry"),
)
AEROSPACE_SUPPLIER_REGISTRY: List[Dict[str, Any]] = [dict(zip(_SUPPLIER_FIELDS, row)) for row in _SUPPLIER_ROWS]

# Preserve legacy enum qualification for serialized Python references.
SourceLegalStatus.__module__ = "tools"