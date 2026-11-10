"""Additional official sources for Aero_EWS."""

import csv
import json
import os
import re
import unicodedata
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlparse, urljoin

import feedparser
import requests
from bs4 import BeautifulSoup

# ID: name, group, status, method, endpoint
SOURCES = {
    "SRC_012": ("Eurostat API", "news", "ENABLED", "API",
                "https://ec.europa.eu/eurostat/api/dissemination/statistics/1.0/data/avia_paoc"),
    "SRC_013": ("Eurostat Statistics RSS", "news", "ENABLED", "RSS",
                "https://ec.europa.eu/eurostat/api/dissemination/catalogue/rss/en/statistics-update.rss"),
    "SRC_014": ("BTS TranStats", "news", "ENABLED", "CSV_IMPORT", "https://www.transtats.bts.gov/"),
    "SRC_015": ("BTS Schedule B-43", "news", "ENABLED", "CSV_IMPORT", "https://www.transtats.bts.gov/"),
    "SRC_019": ("EASA News RSS", "regulatory", "ENABLED", "RSS",
                "https://www.easa.europa.eu/newsroom-and-events/news/feed.xml"),
    "SRC_020": ("EASA Press Releases RSS", "regulatory", "ENABLED", "RSS",
                "https://www.easa.europa.eu/newsroom-and-events/press-releases/feed.xml"),
    "SRC_021": ("EASA Suspected Unapproved Parts RSS", "regulatory", "ENABLED", "RSS",
                "https://www.easa.europa.eu/en/domains/aircraft-products/suspected-unapproved-parts/feed.xml"),
    "SRC_022": ("EASA Type Certificates RSS", "regulatory", "ENABLED", "RSS",
                "https://www.easa.europa.eu/en/document-library/type-certificates/feed.xml"),
    "SRC_023": ("EASA Easy Access Rules XML", "regulatory", "ENABLED", "XML_IMPORT",
                "https://www.easa.europa.eu/en/document-library/easy-access-rules"),
    "SRC_024": ("EASA Airworthiness Directives", "regulatory", "REQUIRES_REVIEW", "MANUAL",
                "https://ad.easa.europa.eu/"),
    "SRC_025": ("EASA Safety Publications", "regulatory", "REQUIRES_REVIEW", "MANUAL", "https://ad.easa.europa.eu/"),
    "SRC_026": (
        "NTSB CAROL Historical Export", "regulatory",
        "REQUIRES_REVIEW", "CSV_IMPORT",
        "https://data.ntsb.gov/carol-main-public/basic-search"
    ),
    "SRC_027": (
        "SEC EDGAR", "pr", "ENABLED", "API",
        "https://data.sec.gov/"
    ),
    "SRC_028": ("TED Search API", "airshow", "ENABLED", "API", "https://api.ted.europa.eu/v3/notices/search"),
    "SRC_029": ("USAspending API", "airshow", "ENABLED", "API",
                "https://api.usaspending.gov/api/v2/search/spending_by_award/"),
    "SRC_031": (
        "XBRL International ESEF Filing Index",
        "pr",
        "ENABLED",
        "API",
        "https://filings.xbrl.org/api/filings",
    ),
}


# SEC EDGAR monitored entities.
# Tickers are candidates resolved against the live SEC ticker/CIK
# directory. Missing or retired tickers must never be guessed.
SEC_WATCHLIST = {
    "AIRCRAFT_OEM_AND_PRIMES": {
        "Boeing": "BA",
        "Embraer": "ERJ",
        "Textron": "TXT",
        "General Dynamics": "GD",
        "Lockheed Martin": "LMT",
        "Northrop Grumman": "NOC",
        "Huntington Ingalls": "HII",
    },

    "ENGINES_AND_SYSTEMS": {
        "GE Aerospace": "GE",
        "RTX": "RTX",
        "Honeywell": "HON",
        "TransDigm": "TDG",
        "Woodward": "WWD",
        "HEICO": "HEI",
        "Parker-Hannifin": "PH",
        "Eaton": "ETN",
        "Crane Company": "CR",
        "Curtiss-Wright": "CW",
        "Moog": "MOG.A",
        "Teledyne": "TDY",
        "Amphenol": "APH",
        "TE Connectivity": "TEL",
    },

    "AEROSTRUCTURES_AND_MATERIALS": {
        "Howmet Aerospace": "HWM",
        "Hexcel": "HXL",
        "ATI": "ATI",
        "Carpenter Technology": "CRS",
        "RBC Bearings": "RBC",
        "Albany International": "AIN",
        "Ducommun": "DCO",
        "Kaiser Aluminum": "KALU",
        "Materion": "MTRN",
        "Loar Holdings": "LOAR",
        "Karman Holdings": "KRMN",
    },

    "MRO_AND_AFTERMARKET": {
        "AAR": "AIR",
        "StandardAero": "SARO",
        "VSE Corporation": "VSEC",
        "FTAI Aviation": "FTAI",
    },

    "DEFENSE_AND_AVIONICS": {
        "L3Harris": "LHX",
        "Leonardo DRS": "DRS",
        "Elbit Systems": "ESLT",
        "Mercury Systems": "MRCY",
        "Astronics": "ATRO",
        "AeroVironment": "AVAV",
        "Kratos Defense": "KTOS",
        "Leidos": "LDOS",
        "SAIC": "SAIC",
        "CACI": "CACI",
        "BWX Technologies": "BWXT",
        "OSI Systems": "OSIS",
        "Viasat": "VSAT",
        "KBR": "KBR",
    },

    "SPACE_AND_NEW_AIRCRAFT": {
        "Rocket Lab": "RKLB",
        "Redwire": "RDW",
        "Intuitive Machines": "LUNR",
        "Planet Labs": "PL",
        "BlackSky": "BKSY",
        "Iridium": "IRDM",
        "AST SpaceMobile": "ASTS",
        "Joby Aviation": "JOBY",
        "Archer Aviation": "ACHR",
        "Vertical Aerospace": "EVTL",
    },

    "AIRLINES_AND_LESSORS": {
        "Delta Air Lines": "DAL",
        "United Airlines": "UAL",
        "American Airlines": "AAL",
        "Southwest Airlines": "LUV",
        "Alaska Air Group": "ALK",
        "JetBlue": "JBLU",
        "SkyWest": "SKYW",
        "Ryanair": "RYAAY",
        "Copa Holdings": "CPA",
        "Volaris": "VLRS",
        "AerCap": "AER",
        "Sumisho Air Lease": "AL",
        "Willis Lease Finance": "WLFC",
    },
}

# Some valid foreign SEC filers may be missing from the
# SEC company_tickers.json search directory.
# These CIKs are sourced from actual SEC filings.
SEC_CIK_OVERRIDES = {
    "Embraer": 1355444,
    "Elbit Systems": 1027664,
    "Sumisho Air Lease": 1487712,
}


# Resolve brand names and subsidiaries to their reporting parent.
SEC_ALIASES = {
    "Boeing": (
        "boeing", "737 max", "787 dreamliner", "777x",
    ),
    "Embraer": (
        "embraer", "e190-e2", "e195-e2",
    ),
    "Textron": (
        "textron", "cessna", "beechcraft", "bell textron",
    ),
    "General Dynamics": (
        "general dynamics", "gulfstream",
    ),
    "GE Aerospace": (
        "ge aerospace", "ge aviation", "general electric",
        "ge9x", "genx",
    ),
    "RTX": (
        "rtx", "raytheon", "pratt & whitney",
        "pratt and whitney", "collins aerospace",
        "pw1100g", "pw1500g", "pw1900g",
    ),
    "Honeywell": (
        "honeywell", "honeywell aerospace",
    ),
    "Crane Company": (
        "crane company", "crane aerospace",
    ),
    "Parker-Hannifin": (
        "parker-hannifin", "parker hannifin",
        "parker aerospace",
    ),
    "AAR": ("aar corp", "aar corporation", "aar"),
    "L3Harris": ("l3harris", "l3 harris"),
    "Leonardo DRS": ("leonardo drs",),
    "Sumisho Air Lease": (
    "sumisho air lease",
    "air lease",
    "air lease corporation",
    ),
    "Ryanair": ("ryanair",),
}


# Additional issuer names, historical brands, divisions and product identifiers.
# These are discovery aliases, NOT proof of a reporting relationship.
# Keep SEC_WATCHLIST tickers and SEC_CIK_OVERRIDES unchanged.

SEC_MORE_ALIASES = {
    "Boeing": (
        "the boeing company", "boeing commercial airplanes",
        "b737 max", "737-8", "737-9", "737-10",
        "787 dreamliner", "b777x",
    ),
    "Embraer": (
        "embraer sa", "e-jet e2", "e190 e2", "e195 e2",
    ),
    "Textron": (
        "textron aviation", "cessna aircraft", "beechcraft",
        "bell textron", "bell helicopter",
    ),
    "General Dynamics": (
        "gulfstream aerospace", "gulfstream aircraft",
        "gulfstream",
    ),
    "Lockheed Martin": (
        "lockheed martin corporation", "lockheed",
    ),
    "Northrop Grumman": (
        "northrop grumman corporation", "northrop",
    ),
    "Huntington Ingalls": (
        "huntington ingalls industries", "hii inc",
    ),
    "GE Aerospace": (
        "general electric aerospace", "ge aviation",
        "ge 9x", "ge9x", "genx", "ge nx",
    ),
    "RTX": (
        "rtx corporation", "raytheon technologies",
        "pratt whitney", "p&w", "pratt whitney canada",
        "pw1127g", "pw1133g", "pw1100g jm",
        "gtf engine",
    ),
    "Honeywell": (
        "honeywell international", "honeywell aerospace",
    ),
    "TransDigm": (
        "transdigm group", "transdigm group inc",
    ),
    "Woodward": (
        "woodward inc", "woodward l orange",
    ),
    "HEICO": (
        "heico corporation", "heico aerospace",
    ),
    "Parker-Hannifin": (
        "parker hannifin", "parker hannifin corporation",
        "parker aerospace",
    ),
    "Eaton": (
        "eaton corporation", "eaton aerospace",
    ),
    "Crane Company": (
        "crane aerospace",
        "crane aerospace and electronics", "crane co",
    ),
    "Curtiss-Wright": (
        "curtiss wright", "curtiss wright corporation",
    ),
    "Moog": (
        "moog inc", "moog aircraft group", "moog aerospace",
    ),
    "Teledyne": (
        "teledyne technologies", "teledyne flir",
        "flir systems",
    ),
    "Amphenol": (
        "amphenol corporation", "amphenol aerospace",
    ),
    "TE Connectivity": (
        "te connectivity ltd", "te connectivity limited",
        "tyco electronics",
    ),
    "Howmet Aerospace": (
        "howmet", "howmet aerospace inc",
    ),
    "Hexcel": (
        "hexcel corporation", "hexcel composites",
    ),
    "ATI": (
        "ati inc", "allegheny technologies",
        "allegheny technologies incorporated",
    ),
    "Carpenter Technology": (
        "carpenter technology corporation",
        "carpenter technology corp",
    ),
    "RBC Bearings": (
        "rbc bearings inc",
    ),
    "Albany International": (
        "albany engineered composites",
        "albany international corp",
    ),
    "Ducommun": (
        "ducommun inc",
    ),
    "Kaiser Aluminum": (
        "kaiser aluminium", "kaiser aluminum corporation",
    ),
    "Materion": (
        "materion corporation", "brush wellman",
    ),
    "Loar Holdings": (
        "loar holdings inc", "loar group",
    ),
    "Karman Holdings": (
        "karman space and defense", "karman space & defense",
        "karman holdings inc",
    ),
    "AAR": (
        "aar corp", "aar corporation", "aar aircraft services",
    ),
    "StandardAero": (
        "standard aero", "standardaero inc",
    ),
    "VSE Corporation": (
        "vse corp", "vse aviation",
    ),
    "FTAI Aviation": (
        "ftai aviation ltd",
    ),
    "L3Harris": (
        "l3 harris", "l3-harris", "l3harris technologies",
    ),
    "Leonardo DRS": (
        "leonardo drs inc", "drs technologies",
    ),
    "Elbit Systems": (
        "elbit systems ltd", "elbit systems limited",
    ),
    "Mercury Systems": (
        "mercury systems inc",
    ),
    "Astronics": (
        "astronics corporation", "astronics advanced electronics",
    ),
    "AeroVironment": (
        "aero vironment", "aerovironment inc",
    ),
    "Kratos Defense": (
        "kratos defense and security solutions",
        "kratos defense & security solutions",
    ),
    "Leidos": (
        "leidos holdings", "leidos inc",
    ),
    "SAIC": (
        "science applications international corporation",
        "saic inc",
    ),
    "CACI": (
        "caci international", "caci inc",
    ),
    "BWX Technologies": (
        "bwx technologies inc",
    ),
    "OSI Systems": (
        "osi systems inc",
    ),
    "Viasat": (
        "viasat inc",
    ),
    "KBR": (
        "kbr inc",
    ),
    "Rocket Lab": (
        "rocketlab", "rocket lab usa",
    ),
    "Redwire": (
        "redwire space", "redwire corporation",
    ),
    "Intuitive Machines": (
        "intuitive machines inc",
    ),
    "Planet Labs": (
        "planet labs pbc", "planet labs inc",
    ),
    "BlackSky": (
        "blacksky technology",
    ),
    "Iridium": (
        "iridium communications",
    ),
    "AST SpaceMobile": (
        "ast space mobile", "ast spacemobile inc",
    ),
    "Joby Aviation": (
        "joby aviation inc",
    ),
    "Archer Aviation": (
        "archer aviation inc",
    ),
    "Vertical Aerospace": (
        "vertical aerospace ltd", "vx4 evtol",
    ),
    "Delta Air Lines": (
        "delta airlines", "delta air lines inc",
    ),
    "United Airlines": (
        "united airlines holdings", "united air lines",
        "united airlines inc",
    ),
    "American Airlines": (
        "american airlines group", "american air lines",
    ),
    "Southwest Airlines": (
        "southwest airlines co",
    ),
    "Alaska Air Group": (
        "alaska airlines", "alaska air group inc",
    ),
    "JetBlue": (
        "jetblue airways", "jet blue",
        "jetblue airways corporation",
    ),
    "SkyWest": (
        "skywest airlines", "skywest inc",
    ),
    "Ryanair": (
        "ryanair holdings", "ryanair dac", "ryanair group",
    ),
    "Copa Holdings": (
        "copa airlines", "copa holdings sa",
    ),
    "Volaris": (
        "volaris airlines",
        "controladora vuela compania de aviacion",
    ),
    "AerCap": (
        "aercap holdings", "aercap holdings nv",
    ),
    "Sumisho Air Lease": (
        "air lease corp", "air lease corporation",
        "sumisho air lease",
    ),
    "Willis Lease Finance": (
        "willis lease finance corporation",
        "willis lease finance corp", "willis lease",
    ),
}

# Merge without losing the existing, tested aliases.
for _company, _extra_aliases in SEC_MORE_ALIASES.items():
    SEC_ALIASES[_company] = tuple(dict.fromkeys(
        (*SEC_ALIASES.get(_company, ()), *_extra_aliases)
    ))


# Ambiguous words can identify unrelated organizations or concepts.
# Accept them alone as explicit, exact queries, not as weak substrings.
SEC_WEAK_AUTO_ALIASES = {
    "aar",
    "ati",
    "saic",
    "moog",
    "iridium",
    "air lease",
}


def _sec_norm(value):
    """Normalize accents, symbols, hyphens and whitespace consistently."""
    text = unicodedata.normalize(
        "NFKD", str(value or "").casefold()
    ).replace("&", " and ")

    text = "".join(
        char for char in text
        if not unicodedata.combining(char)
    )

    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def select_sec_targets(query, limit):
    """Resolve relevant SEC filers, or rotate a broad watchlist.

    Returns (group, company_name, ticker) tuples.
    """
    universe = [
        (group, name, ticker)
        for group, companies in SEC_WATCHLIST.items()
        for name, ticker in companies.items()
    ]

    normalized_query = _sec_norm(query)
    matched = []

    for group, name, ticker in universe:

        # Always include the canonical name, even when aliases exist.
        aliases = (
            name,
            *SEC_ALIASES.get(name, ()),
        )

        for alias in aliases:
            normalized_alias = _sec_norm(alias)

            if not normalized_alias:
                continue

            # Prevent ambiguous short names from matching unrelated KITs.
            if (
                    normalized_alias in SEC_WEAK_AUTO_ALIASES
                    and normalized_query != normalized_alias
            ):
                continue

            # General Electric has separately named businesses;
            # do not infer GE Aerospace from a Vernova/HealthCare query.
            if (
                    name == "GE Aerospace"
                    and normalized_alias == "general electric"
                    and re.search(
                r"\b(?:healthcare|health care|vernova)\b",
                normalized_query,
            )
            ):
                continue

            pattern = (
                    r"(?<![a-z0-9])"
                    + re.escape(normalized_alias)
                    + r"(?![a-z0-9])"
            )

            if re.search(pattern, normalized_query):
                matched.append((group, name, ticker))
                break

    if matched:
        return matched[:limit]

    mode = os.getenv(
        "EWS_SEC_SCAN_MODE", "targeted"
    ).strip().lower()

    if mode != "rotating":
        return []

    # Cover successive portions of the universe on successive
    # days, without contacting every SEC filer in one run.
    batch_size = max(
        1,
        min(
            30,
            limit,
            int(os.getenv("EWS_SEC_COMPANIES_PER_RUN", "5")),
        ),
    )

    from datetime import timezone

    batches = (len(universe) + batch_size - 1) // batch_size

    configured_batch = os.getenv("EWS_SEC_BATCH_INDEX")

    if configured_batch is not None:
        batch = int(configured_batch) % batches
    else:
        batch = (
            datetime.now(timezone.utc).date().toordinal()
            % batches
        )

    start = batch * batch_size
    return universe[start:start + batch_size]


# ESEF/XBRL – curated discovery list, not guaranteed issuer coverage.
# (API search term, legal issuer terms, KIT search aliases)
ESEF_WATCHLIST = {
    "Airbus": ("Airbus", ("Airbus",), ("Airbus", "A320neo", "A321neo", "A350", "A220")),
    "Safran": ("Safran", ("Safran",), ("Safran", "CFM International", "LEAP-1A")),
    "Thales": ("Thales", ("Thales",), ("Thales", "Thales avionics")),
    "Dassault Aviation": ("Dassault", ("Dassault",), ("Dassault Aviation", "Rafale", "Falcon 6X")),
    "Rolls-Royce": ("Rolls", ("Rolls-Royce", "Rolls Royce"), ("Rolls-Royce", "Rolls Royce", "Trent XWB", "Trent 1000")),
    "BAE Systems": ("BAE Systems", ("BAE Systems",), ("BAE Systems",)),
    "Leonardo": ("Leonardo", ("Leonardo",), ("Leonardo", "Leonardo S.p.A.")),
    "Saab": ("Saab", ("Saab",), ("Saab", "Gripen E")),
    "Kongsberg": ("Kongsberg", ("Kongsberg",), ("Kongsberg",)),
    "QinetiQ": ("QinetiQ", ("QinetiQ",), ("QinetiQ",)),
    "Chemring": ("Chemring", ("Chemring",), ("Chemring",)),
    "Babcock": ("Babcock", ("Babcock",), ("Babcock",)),
    "Melrose": ("Melrose", ("Melrose",), ("Melrose", "GKN Aerospace")),
    "Senior": ("Senior", ("Senior plc",), ("Senior plc", "Senior Aerospace")),
    "Avio": ("Avio", ("Avio S.p.A.", "Avio SpA"), ("Avio S.p.A.", "Vega C")),
    "FACC": ("FACC", ("FACC",), ("FACC",)),
    "MTU Aero Engines": ("MTU Aero", ("MTU Aero",), ("MTU Aero Engines",)),
    "Rheinmetall": ("Rheinmetall", ("Rheinmetall",), ("Rheinmetall",)),
}


def _esef_match(text, phrase):
    needle = _sec_norm(phrase)
    haystack = _sec_norm(text)

    if not needle:
        return False

    return bool(re.search(
        r"(?<![a-z0-9])"
        + re.escape(needle)
        + r"(?![a-z0-9])",
        haystack,
    ))


def _esef_date(raw):
    raw = str(raw or "")[:10]
    try:
        return datetime.strptime(
            raw, "%Y-%m-%d"
        ).date().isoformat()
    except ValueError:
        return "DATE_UNKNOWN"


def _esef_safe_url(raw):
    if not isinstance(raw, str) or not raw.strip():
        return ""

    try:
        candidate = urljoin(
            "https://filings.xbrl.org/",
            raw.strip(),
        )
        parsed = urlparse(candidate)

        if (
            parsed.scheme == "https"
            and parsed.hostname == "filings.xbrl.org"
            and not parsed.username
            and not parsed.password
            and parsed.port in (None, 443)
        ):
            return candidate
    except ValueError:
        pass

    return ""

ESEF_VERIFIED_LEIS = {
    "Airbus": {
        "MINO79WLOO247M1IL051",
    },
    "Safran": {
        "969500UIC89GT3UL7L24",
    },
    "Rolls-Royce": {
        "213800EC7997ZBLZJH69",
        "X57JK1U580XATGR67572",
    },
}

def collect_esef_metadata(query, limit, fetch, within_scope):
    """
    Metadata-only ESEF collector.
    Maximum 3 targeted API requests; one page per issuer.
    """

    chosen = [
        (name, search, issuer_terms)
        for name, (search, issuer_terms, aliases)
        in ESEF_WATCHLIST.items()
        if any(
            _esef_match(query, alias)
            for alias in aliases
        )
    ][:3]

    results = []
    seen = set()

    for target, search, issuer_terms in chosen:

        params = {
            "include": "entity",
            "sort": "-processed",
            "page[size]": 40,
            "page[number]": 1,
            "filter": json.dumps([{
                "name": "entity.name",
                "op": "ilike",
                "val": f"%{search}%",
            }], separators=(",", ":")),
        }

        response = fetch(params)

        if response is None or response.status_code != 200:
            raise ValueError(
                f"ESEF API unavailable for {target}"
            )

        payload = response.json()

        if (
            not isinstance(payload, dict)
            or not isinstance(payload.get("data"), list)
        ):
            raise ValueError(
                "Invalid ESEF JSON:API payload"
            )

        # Build issuer identity lookup from JSON:API included entities.
        entities = {}

        for item in payload.get("included", []):
            if (
                not isinstance(item, dict)
                or item.get("type") != "entity"
            ):
                continue

            attrs = item.get("attributes") or {}

            if isinstance(attrs, dict):
                for key in (
                    str(item.get("id") or ""),
                    str(attrs.get("identifier") or ""),
                ):
                    if key:
                        entities[key] = attrs

        for item in payload["data"]:

            if (
                not isinstance(item, dict)
                or item.get("type") != "filing"
            ):
                continue

            attrs = item.get("attributes") or {}

            if not isinstance(attrs, dict):
                continue

            rel = (
                (item.get("relationships") or {})
                .get("entity") or {}
            )

            rel_data = rel.get("data") or {}

            lei_from_filing = str(
                attrs.get("fxo_id") or ""
            ).split("-", 1)[0]

            verified_leis = ESEF_VERIFIED_LEIS.get(target)

            if (
                verified_leis
                and lei_from_filing not in verified_leis
            ):
                # Similar company names are not enough
                # to establish issuer identity.
                continue

            rel_id = (
                str(rel_data.get("id") or "")
                if isinstance(rel_data, dict)
                else ""
            )

            entity = (
                entities.get(rel_id)
                or entities.get(lei_from_filing)
                or {}
            )

            issuer = str(
                entity.get("name") or ""
            ).strip()

            # Never assign another company's filing to the KIT target.
            if not issuer or not any(
                _esef_match(issuer, term)
                for term in issuer_terms
            ):
                continue

            # Published is the original publication date.
            # Processed and period_end must NOT substitute for it.
            published = _esef_date(
                attrs.get("published")
            )

            if not within_scope(published):
                continue

            period_end = _esef_date(
                attrs.get("period_end")
            )

            filing_id = str(
                item.get("id") or ""
            )

            sha = str(
                attrs.get("sha256") or ""
            )

            unique_key = sha or filing_id

            if not unique_key or unique_key in seen:
                continue

            safe_url = next(
                (
                    u for u in (
                        _esef_safe_url(
                            attrs.get("viewer_url")
                        ),
                        _esef_safe_url(
                            attrs.get("report_url")
                        ),
                        _esef_safe_url(
                            (item.get("links") or {})
                            .get("self")
                        ),
                    )
                    if u
                ),
                "",
            )

            if not safe_url:
                continue

            seen.add(unique_key)

            lei = str(
                entity.get("identifier")
                or lei_from_filing
            )

            body = (
                f"[ESEF_FILING_METADATA_ONLY] "
                f"{issuer}; LEI {lei}; "
                f"country {attrs.get('country')}; "
                f"accounting period end {period_end}; "
                f"published {published}; "
                f"index processed {attrs.get('processed')}; "
                f"filing ID {filing_id}. "
                "This is XBRL International repository "
                "index metadata only: underlying financial "
                "results, operational events, supply-chain "
                "disruptions and causality are NOT verified."
            )

            results.append({
                "title": (
                    f"{issuer} ESEF/UKSEF filing "
                    f"({period_end})"
                ),
                "url": safe_url,
                "body": body,
                "date": published,
                "metadata": {
                    "document_type":
                        "ESEF_FILING_METADATA_ONLY",
                    "full_text_available": False,
                    "evidence_scope":
                        "FILING_EXISTENCE_ONLY",
                    "issuer_name": issuer,
                    "issuer_lei": lei,
                    "filing_id": filing_id,
                    "filing_sha256": sha,
                    "reported_period_end": period_end,
                    "index_processed_at": str(
                        attrs.get("processed") or ""
                    ),
                    "original_published_at": published,
                    "filing_country": str(
                        attrs.get("country") or ""
                    ),
                    "aggregation_provider":
                        "XBRL International "
                        "(filings.xbrl.org)",
                    "validation_error_count":
                        attrs.get("error_count"),
                },
            })

            if len(results) >= max(
                1, min(int(limit), 10)
            ):
                return results

    return results


def registry_additions():
    result = {}
    for sid, (name, group, status, method, url) in SOURCES.items():
        kind = {
            "news": "MARKET_DATA",
            "regulatory": "REGULATORY",
            "pr": "OEM_PR",
            "airshow": "INDUSTRY_EVENT",
        }[group]
        result[sid] = {
            "source_id": sid,
            "name": name,
            "category": group,
            "policy_status": status,
            "legal_status": "ALLOWED" if status == "ENABLED" else status,
            "source_type": kind,
            "origin": "PRIMARY",
            "domain": urlparse(url).hostname,
            "access_method": method,
            "tos_url": url,
            "last_legal_review_date": "2026-11-09",
            "verified_domain": True,
            "rate_limit_rpm": 8,
            "min_interval_sec": 2,
            "usage_restrictions": "Official API/RSS or manual export; provider terms apply",
        }

        if sid == "SRC_031":
            result[sid].update(
        origin = "SECONDARY",
        source_type = "CORPORATE_FILING_METADATA",
        tos_url = "https://filings.xbrl.org/docs/about",
        last_legal_review_date = "2026-11-10",
        rate_limit_rpm = 6,
        min_interval_sec = 10,
        usage_restrictions = (
            "Public XBRL API; metadata only. "
            "Provider terms and rate limits may change."
        ),
    )

    return result


def official_api_post(source_id, url, payload):
    """POST only to registered official APIs with rate limiting."""
    from tools import RATE_LIMITER, is_source_allowed

    allowed = {
        "SRC_028": {
            "https://api.ted.europa.eu/v3/notices/search",
        },
        "SRC_029": {
            "https://api.usaspending.gov/api/v2/search/spending_by_award/",
            "https://api.usaspending.gov/api/v2/transactions/",
        },
    }

    if url not in allowed.get(source_id, set()):
        raise ValueError("Unapproved API endpoint")

    if not is_source_allowed(source_id):
        return None

    RATE_LIMITER.wait_for_slot(source_id)

    response = requests.post(
        url,
        json=payload,
        timeout=25,
        allow_redirects=False,
        headers={
            "User-Agent": "AeroEWS Academic Research/2.0",
            "Accept": "application/json",
        },
    )

    RATE_LIMITER.record_outcome(
        source_id,
        response.status_code == 200,
    )

    if response.status_code != 200:
        return None

    if len(response.content) > 2_000_000:
        return None

    try:
        return response.json()
    except ValueError:
        return None


def collect_extra(query, platforms, limit):
    from tools import (
        safe_http_get,
        register_collected_document,
        is_date_within_scope,
    )

    selected = " ".join(platforms).lower()
    if any(w in selected for w in ("ntsb", "faa", "easa")):
        selected += " regulatory"

    words = [
        w for w in re.findall(r"[a-z0-9]{4,}", query.lower())
        if w not in {"airbus", "boeing", "aircraft", "aviation", "aerospace"}
    ]
    output = []
    limit = min(limit, 10)

    def add(
            sid, title, url, body,
            date="DATE_UNKNOWN",
            force=False,
            **metadata
    ):
        if len(output) - group_start >= limit:
            return
        if not force and words and not any(
                w in (title + " " + body).lower() for w in words
        ):
            return
        if date != "DATE_UNKNOWN" and not is_date_within_scope(date):
            return
        doc = register_collected_document(
            sid,
            SOURCES[sid][0],
            url,
            title,
            str(body)[:2500],
            str(date),
            query,
        )
        doc.update(metadata)
        output.append(
            f"DOC_ID: {doc['doc_id']} | SOURCE_ID: {sid}\n"
            f"DATE: {doc['published_at']}\n"
            f"Title: {doc['title']}\n"
            f"Link: {url}\nSummary: {doc['text']}\n---"
        )

    def get(sid, url=None, **kwargs):
        return safe_http_get(
            url or SOURCES[sid][4],
            source_id=sid, timeout=15, **kwargs
        )

    for sid, (name, group, status, method, url) in SOURCES.items():
        review_test = (
                os.getenv("EWS_TEST_REVIEW_SOURCES") == "1"
                and os.getenv("EWS_ENV", "development").lower()
                in {"dev", "development", "test"}
        )

        if group not in selected or (
                status != "ENABLED"
                and not (review_test and status == "REQUIRES_REVIEW")
        ):
            continue

        group_start = len(output)

        try:

            if method == "RSS":
                response = get(sid)

                if response is None or response.status_code != 200:
                    continue

                entries = feedparser.parse(response.content).entries

                for entry in entries:
                    title = str(entry.get("title") or "")

                    summary = BeautifulSoup(
                        str(entry.get("summary") or ""),
                        "html.parser"
                    ).get_text(" ", strip=True)

                    raw_date = str(
                        entry.get("published")
                        or entry.get("updated")
                        or ""
                    )

                    # Standard ISO date or Airbus-style numeric date.
                    numeric = re.search(
                        r"\b(\d{1,2})/(\d{1,2})/(20\d{2})\b",
                        raw_date,
                    )

                    if numeric:
                        month, day, year = map(int, numeric.groups())
                        try:
                            pub_date = datetime(
                                year, month, day
                            ).date().isoformat()
                        except ValueError:
                            pub_date = "DATE_UNKNOWN"
                    else:
                        from tools import normalize_date_str
                        pub_date = normalize_date_str(raw_date) or "DATE_UNKNOWN"

                    link = entry.get("link") or url

                    if sid == "SRC_013":
                        dataset_code = title.split(" - ", 1)[0].strip().upper()

                        if not dataset_code.startswith(("AVIA_", "AIRP_")):
                            continue

                        category = str(entry.get("category") or "")

                        body = (
                            f"EUROSTAT DATASET METADATA UPDATE. "
                            f"Dataset: {dataset_code}. "
                            f"Update category: {category}. "
                            f"Description: {summary}. "
                            "This is not a confirmed aviation safety incident."
                        )

                        add(
                            sid,
                            title,
                            link,
                            body,
                            pub_date,
                            force=True,
                            document_type="STATISTICAL_METADATA_UPDATE",
                            dataset_code=dataset_code,
                            update_category=category,
                        )
                    else:
                        add(
                            sid,
                            title,
                            link,
                            summary or title,
                            pub_date,
                        )

                    if len(output) - group_start >= limit:
                        break



            elif sid == "SRC_012":

                response = get(sid, params={

                    "geo": "EU27_2020",

                    "freq": "M",

                    "lastTimePeriod": 3,

                })

                if response is None or response.status_code != 200:
                    continue

                data = response.json()

                values = data.get("value") or {}

                if not values:
                    continue

                time_dimension = (

                    data.get("dimension", {})

                    .get("time", {})

                    .get("category", {})

                    .get("index", {})

                )

                periods = (

                    list(time_dimension.keys())

                    if isinstance(time_dimension, dict)

                    else []

                )

                from tools import normalize_date_str

                updated_at = (

                        normalize_date_str(str(data.get("updated") or ""))

                        or "DATE_UNKNOWN"

                )

                sample = list(values.items())[-8:]

                body = (

                    "EUROSTAT MONTHLY AVIATION STATISTICAL SERIES. "

                    "Dataset: avia_paoc. "

                    f"Number of returned statistical values: {len(values)}. "

                    f"Recent periods: {periods[-3:]}. "

                    f"Sample JSON-stat indices and values: {sample}. "

                    f"Dataset updated: {updated_at}. "

                    "Dataset update time is not an aircraft incident date. "

                    "A period-over-period comparison is required before "

                    "concluding that traffic increased or decreased."

                )

                add(

                    sid,

                    "Eurostat monthly aviation statistics – avia_paoc",

                    response.url,

                    body,

                    updated_at,

                    force=True,

                    document_type="STATISTICAL_SERIES",

                    dataset_code="avia_paoc",

                    sample_values=sample,

                    reference_periods=periods[-3:],

                )


            elif method in {"CSV_IMPORT", "XML_IMPORT"}:
                root = Path(os.getenv(
                    "EWS_OFFICIAL_EXPORT_DIR",
                    "data/official_exports"
                ))

                if method == "CSV_IMPORT":
                    for path in sorted(root.glob(f"{sid}_*.csv"))[-2:]:
                        with path.open(
                                encoding="utf-8-sig",
                                errors="replace", newline=""
                        ) as file:
                            for i, row in enumerate(csv.DictReader(file)):
                                if i >= 3000:
                                    break
                                body = " | ".join(
                                    f"{k}: {v}"
                                    for k, v in row.items() if v
                                )[:900]
                                add(
                                    sid, f"{name} – {path.stem} / {i + 1}",
                                    url + f"#row-{path.stem}-{i + 1}",
                                    f"Official historical export {path.name}: " + body,
                                )

                else:
                    from defusedxml import ElementTree as ET

                    for path in sorted(root.glob(f"{sid}_*.xml"))[-2:]:
                        if path.stat().st_size > 15_000_000:
                            continue
                        for i, (_, elem) in enumerate(
                                ET.iterparse(path, events=("end",))
                        ):
                            if i > 5000:
                                break
                            body = " ".join(elem.itertext())[:900]
                            if body.strip():
                                add(
                                    sid,
                                    f"EASA Rules – {path.stem} / {i}",
                                    url + f"#xml-{path.stem}-{i}",
                                    body,
                                )
                            elem.clear()


            elif sid == "SRC_031":

                contact = os.getenv(
                    "EWS_CONTACT_EMAIL", ""
                ).strip().removeprefix("mailto:")

                if "@" not in contact:
                    output.append(
                        "ESEF: EWS_CONTACT_EMAIL missing"
                    )
                    continue

                headers = {
                    "User-Agent":
                        f"AeroEWS Academic Research {contact}",
                    "Accept":
                        "application/vnd.api+json, application/json",
                }

                records = collect_esef_metadata(
                    query,
                    limit,
                    fetch=lambda params: get(
                        sid,
                        params=params,
                        headers=headers,
                        max_bytes=2_000_000,
                    ),
                    within_scope=is_date_within_scope,
                )

                for item in records:
                    add(
                        sid,
                        item["title"],
                        item["url"],
                        item["body"],
                        item["date"],
                        force=True,
                        **item["metadata"],
                    )

            elif sid == "SRC_027":

                contact = os.getenv(

                    "EWS_CONTACT_EMAIL", ""

                ).strip().removeprefix("mailto:")

                if "@" not in contact:
                    output.append(

                        "SEC EDGAR: EWS_CONTACT_EMAIL is missing."

                    )

                    continue

                selected_companies = select_sec_targets(
                    query,
                    limit,
                )

                if not selected_companies:
                    continue

                headers = {

                    "User-Agent": f"AeroEWS Academic Research {contact}",

                    "Accept": "application/json, text/html",

                }

                mapping_response = get(

                    sid,

                    "https://www.sec.gov/files/company_tickers.json",

                    headers=headers,

                )

                if (

                        mapping_response is None

                        or mapping_response.status_code != 200

                ):
                    continue

                cik_map = {

                    str(value["ticker"]).upper(): int(value["cik_str"])

                    for value in mapping_response.json().values()

                    if isinstance(value, dict)

                       and value.get("ticker")

                       and value.get("cik_str")

                }

                for sec_group, company_name, ticker in selected_companies:

                    cik = SEC_CIK_OVERRIDES.get(company_name)

                    if cik is None:
                        ticker_variants = (
                            ticker.upper(),
                            ticker.upper().replace(".", "-"),
                            ticker.upper().replace("-", "."),
                        )

                        cik = next(
                            (
                                cik_map[variant]
                                for variant in ticker_variants
                                if variant in cik_map
                            ),
                            None,
                        )

                    if cik is None:
                        print(
                            f"[SEC] UNRESOLVED_ENTITY: "
                            f"{company_name} ({ticker})"
                        )
                        continue

                    cik = int(cik)

                    company_filing_count = 0

                    per_company_limit = (
                        limit if len(selected_companies) == 1 else 1
                    )

                    submissions = get(
                        sid,
                        f"https://data.sec.gov/submissions/CIK{cik:010d}.json",
                        headers=headers,
                    )

                    if submissions is None or submissions.status_code != 200:
                        continue

                    submissions_payload = submissions.json()

                    if not isinstance(submissions_payload, dict):
                        continue

                    # The CIK must agree with the requested issuer.
                    if (
                            str(submissions_payload.get("cik") or "")
                                    .lstrip("0")
                            != str(cik)
                    ):
                        print(
                            f"[SEC] CIK_MISMATCH: "
                            f"{company_name} expected={cik}"
                        )
                        continue

                    filings = (
                        submissions_payload
                        .get("filings", {})
                        .get("recent", {})
                    )

                    for i, form in enumerate(filings.get("form", [])[:120]):

                        if (
                                len(output) - group_start >= limit
                                or company_filing_count >= per_company_limit
                        ):
                            break

                        if form not in {
                            "8-K", "8-K/A",
                            "10-Q", "10-Q/A",
                            "10-K", "10-K/A",
                            "6-K",
                            "20-F", "20-F/A",
                            "40-F",
                        }:
                            continue

                        filing_date = filings["filingDate"][i]

                        if not is_date_within_scope(filing_date):
                            continue

                        accession = filings["accessionNumber"][i]

                        primary_document = filings["primaryDocument"][i]

                        if not accession or not primary_document:
                            continue

                        document_url = (

                            f"https://www.sec.gov/Archives/edgar/data/"

                            f"{cik}/{accession.replace('-', '')}/"

                            f"{quote(primary_document)}"

                        )

                        acceptance_times = filings.get(

                            "acceptanceDateTime", []

                        )

                        accepted_at = (

                            acceptance_times[i]

                            if i < len(acceptance_times)

                            else ""

                        )

                        body = (

                            f"SEC EDGAR OFFICIAL FILING. "

                            f"Company ticker: {ticker}. "

                            f"Form: {form}. "

                            f"Filing date: {filing_date}. "

                            f"Acceptance time: {accepted_at}. "

                            f"Accession number: {accession}. "

                        )

                        full_text_available = False

                        filing_page = None

                        if os.getenv("EWS_SEC_FETCH_FULL_TEXT", "0") == "1":
                            filing_page = get(
                                sid,
                                document_url,
                                headers=headers,
                                check_robots=True,
                                max_bytes=3_000_000,
                            )

                        if (
                                filing_page is not None
                                and filing_page.status_code == 200
                                and "html" in filing_page.headers.get(
                            "Content-Type", ""
                        ).lower()
                        ):
                            soup = BeautifulSoup(
                                filing_page.text,
                                "html.parser"
                            )

                            for element in soup(
                                    ["script", "style", "nav", "footer"]
                            ):
                                element.decompose()

                            full_text = soup.get_text(" ", strip=True)

                            if len(full_text) >= 120:
                                body += "FILING EXCERPT: " + full_text[:1800]
                                full_text_available = True

                        if not full_text_available:
                            body += (
                                "FULL_TEXT_UNAVAILABLE: "
                                "Only official SEC filing metadata were obtained. "
                                "The underlying filing contents were not verified."
                            )

                        add(

                            sid,

                            f"{ticker} SEC {form} {accession}",

                            document_url,

                            body,

                            filing_date,

                            force=True,

                            document_type=(
                                "SEC_FILING_FULL_TEXT"
                                if full_text_available
                                else "SEC_FILING_METADATA_ONLY"
                            ),
                            full_text_available=full_text_available,
                            accession_number=accession,
                            filing_form=form,
                            accepted_at=accepted_at,
                            sec_company=company_name,
                            sec_group=sec_group,
                            sec_ticker=ticker,
                            sec_cik=cik,
                        )
                        company_filing_count += 1




            elif sid == "SRC_028":

                from tools import get_time_window_utc

                scope_start, scope_end = get_time_window_utc()

                date_filter = (

                    f" AND PD>={scope_start:%Y%m%d}"

                    if scope_start

                    else ""

                )

                search_term = query[:75].replace('"', " ").strip()

                if not search_term:
                    search_term = "aircraft"

                payload = {

                    "query": (

                        f'FT~"{search_term}"'

                        f"{date_filter} "

                        "SORT BY publication-date DESC"

                    ),

                    "fields": [

                        "publication-number",

                        "publication-date",

                        "notice-title",

                    ],

                    "page": 1,

                    "limit": max(10, limit),

                    "scope": "ALL",

                }

                data = official_api_post(sid, url, payload) or {}

                for item in data.get("notices", []):

                    if len(output) - group_start >= limit:
                        break

                    number = str(

                        item.get("publication-number") or ""

                    )

                    publication_date = str(

                        item.get("publication-date")

                        or "DATE_UNKNOWN"

                    )

                    if not number:
                        continue

                    if not is_date_within_scope(publication_date):
                        continue

                    titles = item.get("notice-title") or {}

                    if isinstance(titles, dict):

                        title = (

                                titles.get("eng")

                                or next(iter(titles.values()), "")

                        )

                    else:

                        title = str(titles)

                    document_url = (

                            "https://ted.europa.eu/en/notice/"

                            + quote(number)

                    )

                    body = (

                        f"TED PROCUREMENT NOTICE. "

                        f"Number: {number}. "

                        f"Publication date: {publication_date}. "

                        f"Title: {title}. "

                        "This is a procurement signal, not a safety incident."

                    )

                    add(

                        sid,

                        f"TED {number} – {str(title)[:150]}",

                        document_url,

                        body,

                        publication_date,

                        force=True,

                        document_type="PROCUREMENT_NOTICE",

                        notice_number=number,

                    )


            elif sid == "SRC_029":

                from tools import get_time_window_utc

                scope_start, scope_end = get_time_window_utc()

                date_start = (

                    scope_start.date().isoformat()

                    if scope_start

                    else "2000-01-01"

                )

                payload = {

                    "filters": {

                        "keywords": [query[:160]],

                        "award_type_codes": ["A", "B", "C", "D"],

                        "time_period": [{

                            "start_date": date_start,

                            "end_date": scope_end.date().isoformat(),

                            "date_type": "action_date",

                        }],

                    },

                    "fields": [

                        "Award ID",

                        "Recipient Name",

                        "Start Date",

                        "End Date",

                        "Award Amount",

                        "Description",

                    ],

                    "page": 1,

                    "limit": max(5, limit),

                    "sort": "Award Amount",

                    "order": "desc",

                }

                awards = official_api_post(

                    sid, url, payload

                ) or {}

                for award in awards.get("results", []):

                    if len(output) - group_start >= limit:
                        break

                    award_id = str(award.get("Award ID") or "")

                    internal_id = (

                            award.get("generated_internal_id")

                            or award.get("internal_id")

                    )

                    if not award_id or not internal_id:
                        continue

                    transactions = official_api_post(

                        sid,

                        "https://api.usaspending.gov/api/v2/transactions/",

                        {

                            "award_id": internal_id,

                            "page": 1,

                            "limit": 100,

                        },

                    ) or {}

                    recent = [

                        transaction

                        for transaction in transactions.get("results", [])

                        if transaction.get("action_date")

                           and is_date_within_scope(

                            str(transaction["action_date"])

                        )

                    ]

                    recent.sort(

                        key=lambda x: str(x["action_date"]),

                        reverse=True,

                    )

                    for transaction in recent[:2]:

                        if len(output) - group_start >= limit:
                            break

                        action_date = str(

                            transaction.get("action_date") or ""

                        )

                        modification = str(

                            transaction.get("modification_number")

                            or "UNKNOWN"

                        )

                        obligation = transaction.get(

                            "federal_action_obligation"

                        )

                        action_type = str(

                            transaction.get("action_type_description")

                            or ""

                        )

                        if modification in ("", "UNKNOWN", "0"):

                            document_type = "CONTRACT_TRANSACTION"

                        else:

                            document_type = "CONTRACT_MODIFICATION"

                        body = (

                            f"USASPENDING OFFICIAL TRANSACTION. "

                            f"Award: {award_id}. "

                            f"Recipient: {award.get('Recipient Name')}. "

                            f"Original award start: {award.get('Start Date')}. "

                            f"Transaction date: {action_date}. "

                            f"Modification: {modification}. "

                            f"Action type: {action_type}. "

                            f"Incremental obligation: {obligation}. "

                            f"Total award: {award.get('Award Amount')}. "

                            f"Description: {str(award.get('Description') or '')[:450]}. "

                            "This transaction is not necessarily a new contract."

                        )

                        document_url = (

                                "https://www.usaspending.gov/award/"

                                + quote(str(internal_id))

                                + "#"

                                + quote(action_date + "-" + modification)

                        )

                        add(

                            sid,

                            f"USAspending {award_id} {modification}",

                            document_url,

                            body,

                            action_date,

                            force=True,

                            document_type=document_type,

                            award_id=award_id,

                            modification_number=modification,

                            action_date=action_date,

                            incremental_obligation=obligation,

                        )


        except (
                OSError, ValueError, KeyError, IndexError,
                requests.RequestException, ImportError
        ) as exc:
            output.append(f"{name}: unavailable ({type(exc).__name__}: {exc})")

    return "\n".join(output)
