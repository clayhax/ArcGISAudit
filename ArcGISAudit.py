#!/usr/bin/python3
"""
ArcGISAudit.py

Very Basic ArcGIS Server / ArcGIS Enterprise reconnaissance and misconfiguration audit tool.
Use only during authorized security testing.

"""
from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import random
import re
import socket
import ssl
import string
import textwrap
import time
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse
from datetime import date, datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_TIMEOUT = 15
DEFAULT_THREADS = 12
USER_AGENT = "arcgis-audit/4.0 (+authorized security assessment)"

KNOWN_ENDPOINTS = [
    "/server/rest/services",
    "/server/rest/info",
    "/arcgis/rest/services",
    "/arcgis/rest/info",
    "/rest/services",
    "/rest/info",
    "/portal/sharing/",
    "/portal/sharing/rest",
    "/portal/sharing/generateToken",
    "/portal/sharing/rest/generateToken",
    "/portal/sharing/oauth2/authorize",
    "/portal/sharing/community",
    "/portal/sharing/community/users",
    "/portaladmin",
    "/portaladmin/login",
    "/arcgis/admin",
    "/arcgis/admin/login",
    "/arcgis/manager",
    "/arcgis/manager/",
    "/arcgis/login",
    "/arcgis/tokens",
    "/webgis/rest/login",
    "/webgis/rest/services",
    "/webgis/manager/",
    "/webgis/admin/login",
    "/webgis/tokens/",
    "/gcswebportal/Login.aspx",
    "/arcgispublic/",
    "/Link/Admin/Account/LogOn",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/Proxy/proxy.ashx",
    "/proxy/proxy.ashx",
]

COMMON_ARCGIS_BASES = [
    "",
    "/arcgis",
    "/server",
    "/gis",
    "/portal",
    "/webgis",
]

SERVICE_CHILD_SUFFIXES = [
    "/layers",
    "/legend",
    "/iteminfo",
    "/queryDomains",
    "/replicas",
    "/allLayersAndTables",
    "/uploads",
    "/uploads/info",
]

ARC_GIS_ENTERPRISE_LIFECYCLE = {
    "12.0": {"release_date": "2025-11-18", "mature_start": None},
    "11.5": {"release_date": "2025-05-22", "mature_start": "2029-06-01"},
    "11.4": {"release_date": "2024-11-07", "mature_start": "2026-05-01"},
    "11.3": {"release_date": "2024-05-23", "mature_start": "2028-06-01"},
    "11.2": {"release_date": "2023-11-09", "mature_start": "2025-06-01"},
    "11.1": {"release_date": "2023-04-20", "mature_start": "2027-05-01"},
    "11.0": {"release_date": "2022-07-22", "mature_start": "2024-02-01"},
    "10.9.1": {"release_date": "2021-11-18", "mature_start": "2025-12-01"},
    "10.9": {"release_date": "2021-05-06", "mature_start": "2022-11-01"},
    "10.8.1": {"release_date": "2020-07-28", "mature_start": "2024-08-01"},
    "10.8": {"release_date": "2020-02-20", "mature_start": "2021-09-01"},
    "10.7.1": {"release_date": "2019-06-27", "mature_start": "2023-06-01"},
    "10.7": {"release_date": "2019-03-21", "mature_start": "2020-10-01"},
    "10.6.1": {"release_date": "2018-07-17", "mature_start": "2022-01-01"},
    "10.6": {"release_date": "2018-01-17", "mature_start": "2022-01-01"},
    "10.5.1": {"release_date": "2017-06-29", "mature_start": "2020-12-01"},
    "10.5": {"release_date": "2016-12-15", "mature_start": "2020-12-01"},
    "10.4.1": {"release_date": "2016-05-31", "mature_start": "2020-02-01"},
    "10.4": {"release_date": "2016-02-18", "mature_start": "2020-02-01"},
    "10.3.1": {"release_date": "2015-05-13", "mature_start": "2018-12-01"},
    "10.3": {"release_date": "2014-12-10", "mature_start": "2018-12-01"},
    "10.2.2": {"release_date": "2014-04-15", "mature_start": "2017-07-01"},
    "10.2.1": {"release_date": "2014-01-07", "mature_start": "2017-07-01"},
    "10.2": {"release_date": "2013-07-30", "mature_start": "2017-07-01"},
    "10.1": {"release_date": "2012-06-11", "mature_start": "2016-01-01"},
    "10.0": {"release_date": "2010-06-30", "mature_start": "2014-01-01"},
}

VERSION_CVE_LINKS = {
    "arcgis_server": {
        "11.4": "https://www.cvedetails.com/version/1905831/Esri-Arcgis-Server-11.4.html",
        "11.3": "https://www.cvedetails.com/version/1905819/Esri-Arcgis-Server-11.3.html",
        "11.2": "https://www.cvedetails.com/version/1905793/Esri-Arcgis-Server-11.2.html",
        "11.1": "https://www.cvedetails.com/version/1709044/Esri-Arcgis-Server-11.1.html",
        "11.0": "https://www.cvedetails.com/version/1571054/Esri-Arcgis-Server-11.0.html",
        "10.9.1": "https://www.cvedetails.com/version/1414562/Esri-Arcgis-Server-10.9.1.html",
        "10.9": "https://www.cvedetails.com/version/1307644/Esri-Arcgis-Server-10.9.html",
        "10.8.1": "https://www.cvedetails.com/version/1196946/Esri-Arcgis-Server-10.8.1.html",
        "10.8": "https://www.cvedetails.com/version/1057130/Esri-Arcgis-Server-10.8.html",
    },
    "portal_for_arcgis": {
        "11.4": "https://www.cvedetails.com/version/1905825/Esri-Portal-For-Arcgis-11.4.html",
        "11.3": "https://www.cvedetails.com/version/1905816/Esri-Portal-For-Arcgis-11.3.html",
        "11.2": "https://www.cvedetails.com/version/1781121/Esri-Portal-For-Arcgis-11.2.html",
        "11.1": "https://www.cvedetails.com/version/1709041/Esri-Portal-For-Arcgis-11.1.html",
        "11.0": "https://www.cvedetails.com/version/1571045/Esri-Portal-For-Arcgis-11.0.html",
        "10.9.1": "https://www.cvedetails.com/version/1414547/Esri-Portal-For-Arcgis-10.9.1.html",
        "10.9": "https://www.cvedetails.com/version/1307641/Esri-Portal-For-Arcgis-10.9.html",
        "10.8.1": "https://www.cvedetails.com/version/1196943/Esri-Portal-For-Arcgis-10.8.1.html",
        "10.8": "https://www.cvedetails.com/version/1057127/Esri-Portal-For-Arcgis-10.8.html",
    },
}

FALLBACK_PRODUCT_SEARCH = {
    "arcgis_server": "https://www.cvedetails.com/product-search.php?vendor_id=11958&search=ArcGIS+Server",
    "portal_for_arcgis": "https://www.cvedetails.com/product-search.php?vendor_id=11958&search=Portal+for+ArcGIS",
}

LIKELY_PORTAL_USERNAMES = [
    "admin",
    "administrator",
    "portaladmin",
    "arcgis",
    "siteadmin",
]

XSS_TEST_PARAMETERS = [
    "q",
    "query",
    "search",
    "keyword",
    "returnUrl",
    "redirect",
    "redirect_uri",
    "next",
    "url",
    "message",
    "error",
    "username",
]

XSS_TEST_PATH_MARKERS = [
    "login",
    "manager",
    "oauth2",
    "logon",
    "tokens",
    "signin",
    "home",
    "apps",
    "webappviewer",
    "dashboards",
    "experience",
]

XSS_SINK_FIELD_KEYWORDS = [
    "name",
    "title",
    "label",
    "description",
    "comment",
    "comments",
    "notes",
    "note",
    "popup",
    "html",
    "alias",
    "display",
    "message",
]

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}

@dataclass
class HTTPObservation:
    url: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    title: Optional[str] = None
    content_length: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    redirect_chain: List[str] = field(default_factory=list)
    body_preview: Optional[str] = None
    json_body: Optional[Any] = None
    error: Optional[str] = None


class ArcGISAuditor:
    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
        threads: int = DEFAULT_THREADS,
        max_services: Optional[int] = None,
        max_layers_per_service: Optional[int] = None,
        admin_mode: bool = False,
        active_checks: bool = False,
        ssrf_test_url: Optional[str] = None,
        xss_checks: bool = False,
        query_injection_checks: bool = False,
    ) -> None:
        self.base_url = self._normalize_base_url(base_url)
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.threads = threads
        self.max_services = max_services
        self.max_layers_per_service = max_layers_per_service
        self.admin_mode = admin_mode
        self.active_checks = active_checks
        self.ssrf_test_url = ssrf_test_url or "https://example.com/"
        self.xss_checks = xss_checks
        self.query_injection_checks = query_injection_checks
        self.session = self._build_session()
        self.base_url = self._discover_base_url()
        self.platform = self._detect_arcgis_platform()
        self.findings: Dict[str, Any] = {
            "target": self.base_url,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "discovery": {
                "platform": self.platform
            },
            "http": {},
            "tls": {},
            "rest": {},
            "portal": {},
            "admin": {},
            "misconfigurations": {"issues": []},
            "version_risk": {},
            "report_ready_findings": [],
            "summary": {},
            "errors": [],
        }
        self.token_cache: Dict[str, str] = {}
        
    @staticmethod
    def _rand_marker(prefix: str = "arcgis") -> str:
        return f"{prefix}-" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))

    @staticmethod
    def _normalize_base_url(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return url.rstrip("/")

    @staticmethod
    def _origin_from(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def _join(origin: str, path: str) -> str:
        return origin.rstrip("/") + "/" + path.lstrip("/")
    
    def _discover_base_url(self) -> str:
        parsed = urlparse(self.base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        supplied_path = parsed.path.rstrip("/")

        candidates: List[str] = []

        # First try exactly what the user supplied
        if supplied_path:
            candidates.append(origin + supplied_path)

        # Then try common ArcGIS base paths
        for base in COMMON_ARCGIS_BASES:
            candidate = origin + base
            if candidate not in candidates:
                candidates.append(candidate)

        for candidate in candidates:
            for suffix in ["/rest/services", "/server/rest/services", "/sharing/rest"]:
                test_url = candidate.rstrip("/") + suffix
                obs = self.request("GET", test_url, params={"f": "json"}, expect_json=True, allow_redirects=True)
                body = obs.json_body if isinstance(obs.json_body, dict) else {}

                if body and (
                    "currentVersion" in body
                    or "services" in body
                    or "folders" in body
                    or "authInfo" in body
                ):
                    return candidate.rstrip("/")

        return self.base_url
        
    def _detect_arcgis_platform(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "server": False,
            "portal": False,
            "version": None,
            "web_adaptor": None,
        }

        try:
            # Test REST services root
            obs = self.request(
                "GET",
                f"{self.base_url}/rest/services",
                params={"f": "json"},
                expect_json=True,
                allow_redirects=True,
            )

            body = obs.json_body if isinstance(obs.json_body, dict) else {}

            if body:
                if "currentVersion" in body:
                    info["server"] = True
                    info["version"] = body.get("currentVersion")

                if "folders" in body or "services" in body:
                    info["server"] = True

            # Detect Portal
            portal_obs = self.request(
                "GET",
                f"{self.base_url}/sharing/rest",
                params={"f": "json"},
                expect_json=True,
                allow_redirects=True,
            )

            portal_body = portal_obs.json_body if isinstance(portal_obs.json_body, dict) else {}

            if portal_body and ("authInfo" in portal_body or "portalHostname" in portal_body):
                info["portal"] = True

            # Web adaptor detection
            parsed = urlparse(self.base_url)
            if parsed.path:
                info["web_adaptor"] = parsed.path.strip("/")

        except Exception:
            pass

        return info

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST", "HEAD", "OPTIONS"),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def log_error(self, message: str) -> None:
        self.findings["errors"].append(message)
        
    def log_stage(self, message: str) -> None:
        print(f"[ArcGISAudit] {message}", flush=True)

    def add_issue(self, title: str, severity: str, description: str, evidence: Optional[Dict[str, Any]] = None, remediation: Optional[str] = None, category: str = "misconfiguration") -> None:
        severity = self._normalize_severity(severity)
        issue = {
            "title": title,
            "severity": severity.lower(),
            "category": category,
            "description": description,
            "evidence": evidence or {},
        }
        if remediation:
            issue["remediation"] = remediation
        self.findings.setdefault("misconfigurations", {}).setdefault("issues", []).append(issue)

    def _normalize_severity(self, severity: str) -> str:
        s = (severity or "").lower()

        if s in ["info", "informational"]:
            return "informational"
        if s in ["low"]:
            return "low"
        if s in ["medium", "med"]:
            return "medium"
        if s in ["high"]:
            return "high"

        return "informational"

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        expect_json: bool = False,
    ) -> HTTPObservation:
        obs = HTTPObservation(url=url)
        try:
            resp = self.session.request(
                method,
                url,
                params=params,
                data=data,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects,
            )
            obs.status_code = resp.status_code
            obs.content_type = resp.headers.get("Content-Type")
            obs.server = resp.headers.get("Server")
            obs.powered_by = resp.headers.get("X-Powered-By")
            obs.content_length = len(resp.content)
            obs.headers = dict(resp.headers)
            obs.redirect_chain = [r.url for r in resp.history] + [resp.url]
            text = resp.text or ""
            obs.body_preview = text[:8000]
            m = re.search(r"<title>\s*(.*?)\s*</title>", text, re.I | re.S)
            if m:
                obs.title = re.sub(r"\s+", " ", m.group(1)).strip()
            if expect_json or (obs.content_type and "json" in obs.content_type.lower()):
                try:
                    obs.json_body = resp.json()
                except Exception:
                    pass
            return obs
        except requests.RequestException as exc:
            obs.error = str(exc)
            return obs

    def get_json(self, url: str, token: Optional[str] = None, extra_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = {"f": "json"}
        if extra_params:
            params.update(extra_params)
        if token:
            params["token"] = token
        obs = self.request("GET", url, params=params, expect_json=True)
        if obs.error:
            raise RuntimeError(obs.error)
        if not isinstance(obs.json_body, dict):
            raise RuntimeError(f"Non-JSON response from {url} (status={obs.status_code})")
        return obs.json_body

    @staticmethod
    def _best_candidate(results: Dict[str, Any], required_keys: Set[str], preferred_suffixes: List[str]) -> Optional[str]:
        good = []
        for url, info in results.items():
            keys = set(info.get("keys", []))
            if info.get("has_json") and required_keys.issubset(keys):
                good.append(url)
        if not good:
            return None
        for suffix in preferred_suffixes:
            for url in good:
                if url.endswith(suffix):
                    return url
        return good[0]
        
    @staticmethod
    def _normalize_version_key(version: Any) -> Optional[str]:
        if version is None:
            return None
        s = str(version).strip()
        if not s:
            return None
        parts = s.split(".")
        if len(parts) >= 3 and parts[2] == "0":
            parts = parts[:2]
        if len(parts) > 3:
            parts = parts[:3]
        return ".".join(parts)

    @staticmethod
    def _parse_date(value: Optional[str]) -> Optional[date]:
        if not value:
            return None
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except Exception:
            return None
            
    def _collect_version_detection_urls(self) -> Dict[str, List[str]]:
        resolved = self.findings.get("discovery", {}).get("resolved", {})
        out: Dict[str, List[str]] = defaultdict(list)

        candidates = []
        for key in ["catalog", "rest_info", "sharing_root", "portaladmin_root"]:
            url = resolved.get(key)
            if url:
                candidates.append(url)

        for url in candidates:
            try:
                body = self.get_json(url)
            except Exception:
                continue

            version = body.get("currentVersion") or body.get("fullVersion")
            normalized = self._normalize_version_key(version)
            if normalized:
                out[normalized].append(url)

        for version, urls in out.items():
            out[version] = sorted(list(dict.fromkeys(urls)))

        return dict(out)
        
    def _add_arcgis_version_findings(self) -> None:
        detected_versions = self._collect_version_detection_urls()
        if not detected_versions:
            return

        today = date.today()

        for version, urls in detected_versions.items():
            lifecycle = ARC_GIS_ENTERPRISE_LIFECYCLE.get(version, {})
            release_date = lifecycle.get("release_date")
            mature_start = lifecycle.get("mature_start")

            self.add_issue(
                title="ArcGIS Version Information Disclosure",
                severity="informational",
                description="ArcGIS version information was disclosed through publicly accessible REST endpoints. This information may help attackers identify version-specific vulnerabilities, exploits, or misconfigurations.",
                evidence={
                    "version": version,
                    "detected_at_urls": urls,
                    "release_date": release_date,
                    "mature_start": mature_start,
                },
                remediation="Restrict unauthenticated access to version-disclosing endpoints where possible and continue applying vendor updates and security fixes.",
                category="version_risk",
            )

            mature_start_date = self._parse_date(mature_start)
            if mature_start_date and today >= mature_start_date:
                self.add_issue(
                    title="Unpatched and Unsupported Software Version Detection",
                    severity="high",
                    description="The detected ArcGIS Enterprise version has entered the vendor Mature lifecycle phase. In this phase, no further patches or hot fixes are applied, increasing the risk that known vulnerabilities will remain unaddressed.",
                    evidence={
                        "version": version,
                        "detected_at_urls": urls,
                        "release_date": release_date,
                        "mature_start": mature_start,
                        "reasons": [f"Version entered Mature phase on {mature_start}."],
                    },
                    remediation="Upgrade ArcGIS Enterprise to a currently supported version that remains eligible for vendor patches and hot fixes.",
                    category="misconfiguration",
                )

    def probe_common_paths(self) -> Dict[str, Any]:
        parsed = urlparse(self.base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        seed_path = parsed.path.rstrip("/")

        candidates = []
        if seed_path:
            candidates.extend(
                [
                    origin + seed_path,
                    origin + seed_path + "/rest/services",
                    origin + seed_path + "/server/rest/services",
                    origin + seed_path + "/admin",
                    origin + seed_path + "/admin/login",
                    origin + seed_path + "/manager",
                    origin + seed_path + "/rest/info",
                    origin + seed_path + "/sharing/rest",
                    origin + seed_path + "/sharing/",
                    origin + seed_path + "/portaladmin",
                    origin + seed_path + "/tokens",
                    origin + seed_path + "/Proxy/proxy.ashx",
                ]
            )

        candidates.append(origin)
        candidates.extend([self._join(origin, p) for p in KNOWN_ENDPOINTS])

        uniq: List[str] = []
        seen = set()
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                uniq.append(candidate)

        def probe_url(url: str) -> Tuple[str, Dict[str, Any]]:
            as_json = self.request("GET", url, params={"f": "json"}, allow_redirects=True, expect_json=True)
            normal = self.request("GET", url, allow_redirects=True)
            headers_subset = {
                k: v
                for k, v in normal.headers.items()
                if k.lower()
                in {
                    "server",
                    "x-powered-by",
                    "location",
                    "set-cookie",
                    "access-control-allow-origin",
                    "access-control-allow-credentials",
                    "access-control-allow-methods",
                    "content-security-policy",
                    "x-frame-options",
                }
            }
            return (
                url,
                {
                    "status_code": normal.status_code,
                    "content_type": normal.content_type,
                    "title": normal.title,
                    "redirect_chain": normal.redirect_chain,
                    "error": normal.error,
                    "headers": headers_subset,
                    "has_json": as_json.json_body is not None,
                    "keys": sorted(list(as_json.json_body.keys()))[:80] if isinstance(as_json.json_body, dict) else [],
                    "body_preview": normal.body_preview[:800] if normal.body_preview else None,
                },
            )

        results: Dict[str, Any] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(probe_url, url) for url in uniq]
            for fut in concurrent.futures.as_completed(futures):
                url, data = fut.result()
                results[url] = data

        self.findings["discovery"]["probes"] = results

        login_portals = []
        seen_login_urls = set()
        for url, info in sorted(results.items()):
            if self._is_real_login_surface(url, info):
                redirect_chain = info.get("redirect_chain") or []
                final_url = redirect_chain[-1] if redirect_chain else url
                canonical_url = final_url
                if final_url.lower().rstrip("/").endswith(("/arcgis/manager", "/arcgis/tokens", "/webgis/manager", "/webgis/tokens")):
                    canonical_url = final_url.rstrip("/") + "/"
                if canonical_url in seen_login_urls:
                    continue
                seen_login_urls.add(canonical_url)
                login_portals.append(
                    {
                        "url": canonical_url,
                        "requested_url": url,
                        "status_code": info.get("status_code"),
                        "title": info.get("title"),
                        "content_type": info.get("content_type"),
                        "redirect_chain": redirect_chain,
                    }
                )

        discovered = {
            "origin": origin,
            "catalog": self._best_candidate(results, required_keys={"currentVersion"}, preferred_suffixes=["/arcgis/rest/services", "/server/rest/services", "/rest/services", "/webgis/rest/services"]),
            "rest_info": self._best_candidate(results, required_keys={"currentVersion", "authInfo"}, preferred_suffixes=["/arcgis/rest/info", "/rest/info"]),
            "admin_root": self._best_candidate(results, required_keys={"resources"}, preferred_suffixes=["/arcgis/admin", "/admin"]),
            "sharing_root": self._best_candidate(results, required_keys={"currentVersion"}, preferred_suffixes=["/portal/sharing/rest", "/arcgis/sharing/rest", "/sharing/rest"]),
            "portaladmin_root": self._best_candidate(results, required_keys={"currentVersion"}, preferred_suffixes=["/portaladmin"]),
            "login_portals": login_portals,
            "exposed_policy_files": [
                url for url, info in results.items() if urlparse(url).path.lower() in {"/crossdomain.xml", "/clientaccesspolicy.xml"} and self._is_exposed_policy_file(url, info)
            ],
            "possible_proxy_endpoints": [
                url for url, info in results.items() if "proxy.ashx" in url.lower() and info.get("status_code") not in (None, 404)
            ],
        }
        self.findings["discovery"]["resolved"] = discovered
        return discovered

    def _is_real_login_surface(self, url: str, info: Dict[str, Any]) -> bool:
        status = info.get("status_code")
        if status in (404, 410, None):
            return False

        headers = info.get("headers") or {}
        title = (info.get("title") or "").lower()
        preview = (info.get("body_preview") or "").lower()
        content_type = (info.get("content_type") or "").lower()
        location = (headers.get("Location") or headers.get("location") or "").lower()

        redirect_chain = info.get("redirect_chain") or []
        final_url = redirect_chain[-1] if redirect_chain else url

        requested_path = urlparse(url).path.rstrip("/").lower()
        final_path = urlparse(final_url).path.rstrip("/").lower()
        location_path = urlparse(location).path.rstrip("/").lower() if location else ""

        known_login_paths = {
            "/arcgis/manager",
            "/arcgis/admin/login",
            "/arcgis/login",
            "/arcgis/tokens",
            "/portal/sharing/generatetoken",
            "/portal/sharing/rest/generatetoken",
            "/portal/sharing/oauth2/authorize",
            "/portaladmin/login",
            "/webgis/manager",
            "/webgis/admin/login",
            "/webgis/tokens",
            "/webgis/rest/login",
            "/gcswebportal/login.aspx",
            "/link/admin/account/logon",
        }

        path_markers = ["login", "manager", "tokens", "oauth2", "generatetoken", "logon"]
        body_markers = ["sign in", "login", "log in", "username", "password", "oauth", "token", "arcgis manager"]

        if (
            requested_path in known_login_paths
            or final_path in known_login_paths
            or location_path in known_login_paths
        ):
            return status in (200, 301, 302, 303, 307, 308, 401, 403)

        if status in (301, 302, 303, 307, 308):
            return any(
                m in requested_path or m in final_path or m in location_path
                for m in path_markers
            )

        if status in (401, 403):
            return any(m in requested_path or m in final_path for m in path_markers)

        if status == 200:
            path_looks_login_like = any(
                m in requested_path or m in final_path
                for m in path_markers
            )
            body_looks_login_like = (
                any(m in title for m in body_markers)
                or any(m in preview for m in body_markers)
                or "application/json" in content_type
            )
            return path_looks_login_like and (
                body_looks_login_like or final_path != requested_path or final_path in known_login_paths
            )

        return False

    def _is_exposed_policy_file(self, url: str, info: Dict[str, Any]) -> bool:
        if info.get("status_code") != 200:
            return False
        body = (info.get("body_preview") or "").lower()
        return any(marker in body for marker in [
            "<cross-domain-policy",
            "<allow-access-from",
            "<site-control",
            "<access-policy>",
            "<cross-domain-access>",
            "<policy>",
        ])

    def capture_http_fingerprint(self, discovered: Dict[str, Any]) -> None:
        targets = [self.base_url, discovered.get("catalog"), discovered.get("rest_info"), discovered.get("admin_root"), discovered.get("sharing_root")]
        targets = [t for t in targets if t]
        report = {}
        for url in targets:
            obs = self.request("GET", url, allow_redirects=True)
            report[url] = {
                "status_code": obs.status_code,
                "server": obs.server,
                "powered_by": obs.powered_by,
                "content_type": obs.content_type,
                "title": obs.title,
                "headers": {
                    k: v
                    for k, v in obs.headers.items()
                    if k.lower()
                    in {
                        "server",
                        "x-powered-by",
                        "x-frame-options",
                        "content-security-policy",
                        "strict-transport-security",
                        "x-content-type-options",
                        "referrer-policy",
                        "access-control-allow-origin",
                        "access-control-allow-credentials",
                        "set-cookie",
                        "location",
                    }
                },
                "redirect_chain": obs.redirect_chain,
                "error": obs.error,
            }
        self.findings["http"] = report

    def capture_tls_fingerprint(self, discovered: Dict[str, Any]) -> None:
        url = discovered.get("catalog") or self.base_url
        parsed = urlparse(url)
        if parsed.scheme != "https":
            self.findings["tls"] = {"enabled": False, "reason": "Target is not HTTPS"}
            return
        host = parsed.hostname
        port = parsed.port or 443
        result: Dict[str, Any] = {"enabled": True, "host": host, "port": port}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    result["protocol"] = ssock.version()
                    result["cipher"] = ssock.cipher()
                    result["peer_certificate"] = {
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                        "serialNumber": cert.get("serialNumber"),
                        "subjectAltName": cert.get("subjectAltName"),
                    }
        except Exception as exc:
            result["error"] = str(exc)
        self.findings["tls"] = result

    def try_generate_server_token(self, rest_info_url: str) -> Optional[str]:
        if not self.username or not self.password:
            return None
        if rest_info_url in self.token_cache:
            return self.token_cache[rest_info_url]
        try:
            info = self.get_json(rest_info_url)
        except Exception as exc:
            self.log_error(f"Could not read REST info for token discovery: {exc}")
            return None
        auth = info.get("authInfo") or {}
        token_url = auth.get("tokenServicesUrl")
        if not token_url:
            return None
        referer = self.base_url
        forms = [
            {"username": self.username, "password": self.password, "client": "referer", "referer": referer, "f": "json", "expiration": 60},
            {"username": self.username, "password": self.password, "client": "requestip", "f": "json", "expiration": 60},
        ]
        for form in forms:
            obs = self.request("POST", token_url, data=form, expect_json=True)
            body = obs.json_body or {}
            token = body.get("token")
            if token:
                self.token_cache[rest_info_url] = token
                return token
        self.log_error(f"Failed to obtain server token from {token_url}")
        return None

    def try_generate_portal_token(self, sharing_root: str) -> Optional[str]:
        if not self.username or not self.password:
            return None
        cache_key = sharing_root.rstrip("/")
        if cache_key in self.token_cache:
            return self.token_cache[cache_key]
        token_candidates = [sharing_root.rstrip("/") + "/generateToken", sharing_root.rstrip("/") + "/rest/generateToken"]
        for token_url in token_candidates:
            forms = [
                {"username": self.username, "password": self.password, "client": "referer", "referer": self.base_url, "f": "json", "expiration": 60},
                {"username": self.username, "password": self.password, "client": "requestip", "f": "json", "expiration": 60},
            ]
            for form in forms:
                obs = self.request("POST", token_url, data=form, expect_json=True)
                body = obs.json_body or {}
                token = body.get("token")
                if token:
                    self.token_cache[cache_key] = token
                    return token
        return None

    def enumerate_rest(self, discovered: Dict[str, Any]) -> None:
        catalog_url = discovered.get("catalog")
        if not catalog_url:
            self.log_error("No ArcGIS REST services catalog discovered")
            return

        rest: Dict[str, Any] = {}
        token = None
        if discovered.get("rest_info"):
            try:
                rest_info = self.get_json(discovered["rest_info"])
                rest["info"] = rest_info
                token = self.try_generate_server_token(discovered["rest_info"])
            except Exception as exc:
                self.log_error(f"Failed to retrieve REST info: {exc}")

        root = self.get_json(catalog_url, token=token)
        rest["catalog_root"] = {
            "currentVersion": root.get("currentVersion"),
            "folders": root.get("folders", []),
            "services": root.get("services", []),
            "url": catalog_url,
        }

        folder_records = []
        services: List[Dict[str, Any]] = list(root.get("services", []))
        for folder in [f for f in root.get("folders", []) if f and f != "/"]:
            folder_url = catalog_url.rstrip("/") + "/" + quote(folder)
            folder_record = {"name": folder, "url": folder_url, "services": [], "error": None}
            try:
                folder_json = self.get_json(folder_url, token=token)
                folder_record["services"] = folder_json.get("services", [])
                services.extend(folder_json.get("services", []))
            except Exception as exc:
                folder_record["error"] = str(exc)
                self.log_error(f"Failed folder enumeration for {folder_url}: {exc}")
            folder_records.append(folder_record)
        rest["folders"] = folder_records

        if self.max_services is not None:
            services = services[: self.max_services]

        rest["services"] = self._enrich_services(catalog_url, services, token)
        self.findings["rest"] = rest

    def _service_url(self, catalog_url: str, svc: Dict[str, Any]) -> str:
        name = svc.get("name", "")
        svc_type = svc.get("type", "")
        return f"{catalog_url.rstrip('/')}/{quote(name)}/{quote(svc_type)}"

    def _enrich_services(self, catalog_url: str, services: List[Dict[str, Any]], token: Optional[str]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []

        def worker(svc: Dict[str, Any]) -> Dict[str, Any]:
            url = self._service_url(catalog_url, svc)
            result: Dict[str, Any] = {"name": svc.get("name"), "type": svc.get("type"), "url": url}
            try:
                meta = self.get_json(url, token=token)
                result["metadata"] = self._extract_service_metadata(meta)
                result["layers"] = self._enumerate_layers(url, meta, token)
                result["relationships"] = self._derive_service_relationships(meta)
                result["child_resources"] = self._enumerate_service_children(url, token)
                result["uploads"] = self._check_service_uploads(url, svc.get("type"), meta, token)
            except Exception as exc:
                result["error"] = str(exc)
            return result

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {executor.submit(worker, svc): svc for svc in services}
            for future in concurrent.futures.as_completed(future_map):
                out.append(future.result())

        out.sort(key=lambda x: (x.get("type") or "", x.get("name") or ""))
        return out

    @staticmethod
    def _extract_service_metadata(meta: Dict[str, Any]) -> Dict[str, Any]:
        interesting = [
            "currentVersion",
            "serviceDescription",
            "description",
            "copyrightText",
            "capabilities",
            "supportedQueryFormats",
            "supportsDynamicLayers",
            "hasVersionedData",
            "hasStaticData",
            "maxRecordCount",
            "maxImageHeight",
            "maxImageWidth",
            "singleFusedMapCache",
            "initialExtent",
            "fullExtent",
            "spatialReference",
            "units",
            "documentInfo",
            "minScale",
            "maxScale",
            "exportTilesAllowed",
            "syncEnabled",
            "allowGeometryUpdates",
            "editorTrackingInfo",
            "enableZDefaults",
            "zDefault",
            "schemaLastEditDate",
            "dateFieldsTimeReference",
        ]
        return {k: meta.get(k) for k in interesting if k in meta}

    @staticmethod
    def _derive_service_relationships(meta: Dict[str, Any]) -> Dict[str, Any]:
        caps = str(meta.get("capabilities", ""))
        return {
            "has_layers": bool(meta.get("layers")),
            "has_tables": bool(meta.get("tables")),
            "supports_query": "Query" in caps,
            "supports_editing": any(word in caps for word in ["Create", "Update", "Delete", "Editing", "Uploads", "Sync"]),
            "child_resource_counts": {"layers": len(meta.get("layers", []) or []), "tables": len(meta.get("tables", []) or [])},
        }

    def _enumerate_service_children(self, service_url: str, token: Optional[str]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for suffix in SERVICE_CHILD_SUFFIXES:
            url = service_url.rstrip("/") + suffix
            try:
                j = self.get_json(url, token=token)
                out[suffix] = {
                    "url": url,
                    "keys": sorted(j.keys())[:60],
                    "status": "ok",
                }
            except Exception as exc:
                out[suffix] = {"url": url, "status": "error", "error": str(exc)}
        return out

    def _check_service_uploads(self, service_url: str, service_type: str, meta: Dict[str, Any], token: Optional[str]) -> Dict[str, Any]:
        result = {
            "checked": False,
            "suspected": False,
            "reachable": False,
            "url": None,
            "confidence": "none",
            "reason": None,
            "capabilities": None,
            "upload_probe": None,
        }

        if service_type != "FeatureServer":
            return result

        caps = str(meta.get("capabilities", ""))
        caps_lower = caps.lower()
        result["capabilities"] = caps
        result["checked"] = True
        result["suspected"] = any(word in caps_lower for word in ["uploads", "create", "update", "editing", "sync"])

        uploads_url = service_url.rstrip("/") + "/uploads"
        result["url"] = uploads_url

        params = {"f": "json"}
        if token:
            params["token"] = token

        obs = self.request("GET", uploads_url, params=params, expect_json=True)
        result["status_code"] = obs.status_code

        body = obs.json_body if isinstance(obs.json_body, dict) else None
        if body is not None:
            result["keys"] = sorted(body.keys())[:30]
            err = body.get("error") if isinstance(body.get("error"), dict) else {}
            msg = str(err.get("message") or "")
            details = " ".join(str(x) for x in (err.get("details") or []))
            combined = (msg + " " + details).lower()

            result["response"] = {
                k: body.get(k)
                for k in ["itemID", "items", "success", "status", "error", "uploadId"]
                if k in body
            }

            if any(k in body for k in ["itemID", "items", "uploadId"]):
                result["reachable"] = True
                result["confidence"] = "confirmed"
                result["reason"] = "Uploads endpoint returned upload-specific JSON content."

            elif err.get("code") in (401, 403, 498, 499) or any(
                x in combined
                for x in ["token", "permission", "not authorized", "not authenticated", "insufficient", "access denied"]
            ):
                result["confidence"] = "likely"
                result["reason"] = "Uploads endpoint appears to exist and returned an authentication or authorization response."

            elif "service not started" in combined:
                result["confidence"] = "weak"
                result["reason"] = "Request reached ArcGIS service logic, but a service-not-started error is not sufficient to confirm uploads are enabled."

            elif obs.status_code == 200 and not err:
                result["confidence"] = "likely"
                result["reason"] = "Uploads endpoint returned structured JSON, but without upload-specific markers."

            else:
                result["confidence"] = "weak"
                result["reason"] = "Response was inconclusive for confirming upload capability."

        else:
            result["body_preview"] = (obs.body_preview or "")[:300]
            if obs.status_code in (401, 403):
                result["confidence"] = "likely"
                result["reason"] = "Uploads endpoint returned an authorization response."
            else:
                result["confidence"] = "none"
                result["reason"] = "No upload-specific response was observed."

        # Probe the actual upload operation endpoint
        upload_endpoint = service_url.rstrip("/") + "/uploads/upload"

        upload_params = {"f": "json"}
        if token:
            upload_params["token"] = token

        upload_obs = self.request(
            "POST",
            upload_endpoint,
            data=upload_params,
            expect_json=True,
            allow_redirects=True,
        )

        result["upload_probe"] = {
            "endpoint": upload_endpoint,
            "status_code": upload_obs.status_code,
            "reachable": False,
            "probe_command": f'curl -sk -X POST "{upload_endpoint}" --data-urlencode "f=json"',
            "manual_upload_test_command": (
                f'curl -sk -X POST "{upload_endpoint}" '
                f'-F "f=json" '
                f'-F "file=@./proof.txt;type=text/plain"'
            ),
        }

        upload_body = upload_obs.json_body if isinstance(upload_obs.json_body, dict) else None

        if upload_body is not None:
            upload_err = upload_body.get("error") if isinstance(upload_body.get("error"), dict) else {}
            upload_msg = str(upload_err.get("message") or "")
            upload_details = " ".join(str(x) for x in (upload_err.get("details") or []))
            upload_combined = (upload_msg + " " + upload_details).lower()

            result["upload_probe"]["response"] = {
                k: upload_body.get(k)
                for k in ["success", "item", "itemID", "uploadId", "status", "error"]
                if k in upload_body
            }
            result["upload_probe"]["error_code"] = upload_err.get("code")
            result["upload_probe"]["error_message"] = upload_err.get("message")

            # Strongest confirmation: successful upload response
            if upload_body.get("success") is True or any(k in upload_body for k in ["item", "itemID", "uploadId"]):
                result["upload_probe"]["reachable"] = True
                result["upload_probe"]["note"] = "Upload endpoint accepted the request and returned upload-specific JSON."
                result["reachable"] = True
                result["confidence"] = "confirmed"
                result["reason"] = "Upload operation endpoint accepted requests and returned upload-specific JSON."

            # Auth-required responses still confirm the handler exists
            elif upload_err.get("code") in (401, 403, 498, 499) or any(
                x in upload_combined
                for x in ["token", "permission", "not authorized", "not authenticated", "access denied"]
            ):
                result["upload_probe"]["reachable"] = True
                result["upload_probe"]["note"] = "Upload endpoint requires authentication."
                if result["confidence"] == "none":
                    result["confidence"] = "likely"
                    result["reason"] = "Upload endpoint appears to exist and returned an authentication or authorization response."

            # Missing-file / upload-processing errors are still strong evidence the handler executed
            elif (
                ("missing" in upload_combined and "file" in upload_combined)
                or ("upload" in upload_combined)
                or ("performing upload operation" in upload_combined)
                or (upload_err.get("code") == 500 and "upload" in upload_combined)
                or (upload_err.get("code") == 400 and any(x in upload_combined for x in ["file", "attachment", "upload"]))
            ):
                result["upload_probe"]["reachable"] = True
                result["upload_probe"]["note"] = "Upload endpoint processed the request and returned an upload-related ArcGIS error."
                if result["confidence"] != "confirmed":
                    result["confidence"] = "confirmed"
                    result["reason"] = "Upload operation endpoint executed server-side upload logic."

            else:
                result["upload_probe"]["note"] = "Upload endpoint response was inconclusive."

        else:
            result["upload_probe"]["body_preview"] = (upload_obs.body_preview or "")[:300]

            if upload_obs.status_code in (401, 403):
                result["upload_probe"]["reachable"] = True
                result["upload_probe"]["note"] = "Upload endpoint requires authentication."
                if result["confidence"] == "none":
                    result["confidence"] = "likely"
                    result["reason"] = "Upload endpoint appears to exist and returned an authentication or authorization response."

            elif upload_obs.status_code == 200:
                result["upload_probe"]["note"] = "Upload endpoint returned a non-JSON HTTP 200 response."
            else:
                result["upload_probe"]["note"] = "Upload endpoint response was inconclusive."

        return result

    def _enumerate_layers(self, service_url: str, meta: Dict[str, Any], token: Optional[str]) -> Dict[str, Any]:
        result: Dict[str, Any] = {"layers": [], "tables": []}
        items: List[Tuple[str, Dict[str, Any]]] = []
        for layer in meta.get("layers", []) or []:
            items.append(("layer", layer))
        for table in meta.get("tables", []) or []:
            items.append(("table", table))

        if not items:
            for suffix in ["/layers", "/allLayersAndTables"]:
                try:
                    layers_json = self.get_json(service_url + suffix, token=token)
                    for layer in layers_json.get("layers", []) or []:
                        items.append(("layer", layer))
                    for table in layers_json.get("tables", []) or []:
                        items.append(("table", table))
                    if items:
                        break
                except Exception:
                    pass

        if self.max_layers_per_service is not None:
            items = items[: self.max_layers_per_service]
            
        total_layers = len(items)
        progress = 0
        progress_lock = threading.Lock()
        service_name = service_url.split("/services/")[-1]
        
        def layer_worker(kind: str, layer_stub: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
            nonlocal progress, total_layers, progress_lock
            with progress_lock:
                progress += 1
                if progress < total_layers:
                    print(f"\r[ArcGISAudit] Enumerating layers for {service_name}... ({progress}/{total_layers})", end="", flush=True)
            
            layer_id = layer_stub.get("id")
            layer_url = f"{service_url}/{layer_id}"
            record: Dict[str, Any] = {"id": layer_id, "name": layer_stub.get("name"), "url": layer_url, "kind": kind}
            try:
                meta = self.get_json(layer_url, token=token)
                fields = meta.get("fields") or []
                record["metadata"] = {
                    "type": meta.get("type"),
                    "displayField": meta.get("displayField"),
                    "geometryType": meta.get("geometryType"),
                    "hasAttachments": meta.get("hasAttachments"),
                    "htmlPopupType": meta.get("htmlPopupType"),
                    "objectIdField": meta.get("objectIdField"),
                    "globalIdField": meta.get("globalIdField"),
                    "typeIdField": meta.get("typeIdField"),
                    "subtypeField": meta.get("subtypeField"),
                    "defaultVisibility": meta.get("defaultVisibility"),
                    "minScale": meta.get("minScale"),
                    "maxScale": meta.get("maxScale"),
                    "supportsAdvancedQueries": (meta.get("advancedQueryCapabilities") or {}).get("supportsAdvancedQueries"),
                    "supportsStatistics": (meta.get("advancedQueryCapabilities") or {}).get("supportsStatistics"),
                    "supportedQueryFormats": meta.get("supportedQueryFormats"),
                    "capabilities": meta.get("capabilities"),
                    "extent": meta.get("extent"),
                }
                
                self._check_feature_attachments(layer_url, meta)
                self._check_add_attachment_endpoint(layer_url, meta)
                
                capabilities = str(meta.get("capabilities") or "")
                supports_query = (
                    "Query" in capabilities
                    or bool((meta.get("advancedQueryCapabilities") or {}).get("supportsAdvancedQueries"))
                )

                if supports_query:
                    self._check_query_injection(layer_url, meta)
                
                record["fields"] = [
                    {
                        "name": f.get("name"),
                        "type": f.get("type"),
                        "alias": f.get("alias"),
                        "length": f.get("length"),
                        "nullable": f.get("nullable"),
                        "editable": f.get("editable"),
                        "domain": (f.get("domain") or {}).get("type") if isinstance(f.get("domain"), dict) else None,
                    }
                    for f in fields
                ]
                
                # Stored XSS sink discovery
                if self.xss_checks:
                    self._check_possible_stored_xss_sink(layer_url, meta, record["fields"])
                
                record["relationships"] = meta.get("relationships", [])
                record["templates_count"] = len(meta.get("templates", []) or [])
                record["types_count"] = len(meta.get("types", []) or [])
            except Exception as exc:
                record["error"] = str(exc)
            return kind, record

        if items:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.threads, max(1, len(items)))) as executor:
                futures = [executor.submit(layer_worker, kind, stub) for kind, stub in items]
                for future in concurrent.futures.as_completed(futures):
                    kind, record = future.result()
                    bucket = "layers" if kind == "layer" else "tables"
                    result[bucket].append(record)
                    
            if total_layers > 0:
                print("\r" + " " * 140 + "\r", end="", flush=True)
                print(f"\r[ArcGISAudit] Enumerating layers for {service_name}... ({total_layers}/{total_layers})", flush=True)

        result["layers"].sort(key=lambda x: x.get("id", -1))
        result["tables"].sort(key=lambda x: x.get("id", -1))
        return result

    def enumerate_portal(self, discovered: Dict[str, Any]) -> None:
        sharing_root = discovered.get("sharing_root")
        if not sharing_root:
            return
        portal: Dict[str, Any] = {}
        try:
            root = self.get_json(sharing_root)
            portal["sharing_root"] = root
        except Exception as exc:
            self.log_error(f"Failed to enumerate sharing root: {exc}")

        self_url = sharing_root.rstrip("/") + "/portals/self"
        try:
            me = self.get_json(self_url)
            portal["self"] = {
                k: me.get(k)
                for k in [
                    "id",
                    "name",
                    "isPortal",
                    "portalMode",
                    "customBaseUrl",
                    "allSSL",
                    "urlKey",
                    "currentVersion",
                    "portalHostname",
                    "useStandardizedQueries",
                    "supportsHostedServices",
                    "supportsOAuth",
                ]
                if k in me
            }
        except Exception as exc:
            self.log_error(f"Failed to enumerate portals/self: {exc}")

        self.findings["portal"] = portal

    def enumerate_admin(self, discovered: Dict[str, Any]) -> None:
        admin_root = discovered.get("admin_root")
        if not admin_root or not self.admin_mode:
            return
        token = None
        rest_info = discovered.get("rest_info")
        if rest_info:
            token = self.try_generate_server_token(rest_info)
        if not token:
            self.log_error("Admin mode requested, but no admin-capable token could be obtained")
            return

        admin: Dict[str, Any] = {}
        try:
            root = self.get_json(admin_root, token=token)
            admin["root"] = root
        except Exception as exc:
            self.log_error(f"Failed admin root enumeration: {exc}")
            self.findings["admin"] = admin
            return

        subpaths = {
            "info": "/info",
            "machines": "/machines",
            "clusters": "/clusters",
            "data": "/data",
            "services": "/services",
            "security": "/security",
            "system": "/system",
            "logs": "/logs",
            "uploads": "/uploads",
            "mode": "/mode",
            "usagereports": "/usagereports",
            "webadaptors": "/system/webadaptors",
            "directories": "/system/directories",
            "properties": "/system/properties",
            "handlers": "/system/handlers",
            "platformservices": "/system/platformservices",
        }
        for key, suffix in subpaths.items():
            url = admin_root.rstrip("/") + suffix
            try:
                admin[key] = self.get_json(url, token=token)
            except Exception as exc:
                admin[key] = {"error": str(exc), "url": url}

        self.findings["admin"] = admin

    def assess_misconfigurations(self, discovered: Dict[str, Any]) -> None:
        candidate_urls = []
        for key in ["catalog", "rest_info", "sharing_root", "admin_root"]:
            if discovered.get(key):
                candidate_urls.append(discovered[key])
        candidate_urls.extend([p.get("url") for p in discovered.get("login_portals", []) if p.get("url")])
        candidate_urls.extend(discovered.get("possible_proxy_endpoints", []))
        candidate_urls = list(dict.fromkeys([u for u in candidate_urls if u]))

        self._check_cross_domain_policy_files(discovered)
        self._check_unauthenticated_admin_exposure(discovered)
        self._check_cors(candidate_urls)
        self._check_host_header(candidate_urls)
        self._check_portal_user_enumeration(discovered)
        self._check_feature_upload_exposure()
        self._check_public_query_data_exposure()
        self._check_services_directory_exposure(discovered)
        self._check_sensitive_field_exposure()
        self._check_public_portal_content_enumeration(discovered)
        self._check_token_generation_misconfigurations(discovered)
        self._check_feature_editing_without_auth()
        self._check_upload_directory_exposure(discovered)
        self._check_proxy_ssrf(discovered)
        self._check_open_redirect(candidate_urls)
        if self.xss_checks:
            self._check_reflected_xss(candidate_urls)

    def _check_cross_domain_policy_files(self, discovered: Dict[str, Any]) -> None:
        for url in discovered.get("exposed_policy_files", []):
            obs = self.request("GET", url)
            body = obs.body_preview or ""
            lowered = body.lower()
            permissive = False
            if "*" in body or "domain=\"*\"" in lowered or "uri=\"*\"" in lowered:
                permissive = True
            sev = "medium" if permissive else "low"
            desc = "Cross-domain policy file is exposed."
            if permissive:
                desc = "Permissive cross-domain policy file is exposed and appears to trust all origins or domains."
            self.add_issue(
                title="Exposed cross-domain policy file",
                severity=sev,
                description=desc,
                evidence={"url": url, "status_code": obs.status_code, "body_preview": body[:500]},
                remediation="Remove legacy policy files if not required, or restrict trusted domains to the minimum necessary set.",
            )
            
    def _check_unauthenticated_admin_exposure(self, discovered: Dict[str, Any]) -> None:
        parsed = urlparse(self.base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        candidates = [
            self._join(origin, "/arcgis/admin"),
            self._join(origin, "/arcgis/admin/services"),
            self._join(origin, "/arcgis/admin/system"),
            self._join(origin, "/arcgis/admin/machines"),
        ]

        # If discovery already identified an admin root, probe relative to it too.
        admin_root = discovered.get("admin_root")
        if admin_root:
            admin_root = admin_root.rstrip("/")
            candidates.extend(
                [
                    admin_root,
                    admin_root + "/services",
                    admin_root + "/system",
                    admin_root + "/machines",
                ]
            )

        candidates = list(dict.fromkeys(candidates))

        for url in candidates:
            obs = self.request("GET", url, params={"f": "json"}, expect_json=True, allow_redirects=True)
            if obs.error or not isinstance(obs.json_body, dict):
                continue

            body = obs.json_body
            keys = set(body.keys())

            # Common signs of actual ArcGIS admin JSON rather than an HTML/login page.
            admin_indicators = any(
                k in body for k in [
                    "resources",
                    "machines",
                    "services",
                    "folders",
                    "sites",
                    "platformServices",
                    "directories",
                    "currentVersion",
                    "fullVersion"
                ]
            )

            # Detect authentication enforcement more reliably
            auth_error = False

            msg_parts = []

            # Case 1: {"error": {...}} structure
            err = body.get("error")
            if isinstance(err, dict):
                msg_parts.append(str(err.get("message") or ""))
                msg_parts.extend(str(x) for x in (err.get("details") or []))

            # Case 2: ArcGIS admin top-level error structure
                msg_parts.append(str(body.get("status") or ""))
                msg_parts.append(str(body.get("code") or ""))
                msg_parts.extend(str(x) for x in (body.get("messages") or []))

            combined = " ".join(msg_parts).lower()

            if (
                body.get("code") in (498, 499)  # ArcGIS token required codes
                or body.get("status") == "error"
                or any(
                    x in combined
                    for x in [
                        "token",
                        "not authorized",
                        "unauthorized",
                        "permission",
                        "access denied",
                        "login",
                    ]
                )
            ):
                auth_error = True


            if admin_indicators and not auth_error and body.get("status") != "error":
                self.add_issue(
                    title="Unauthenticated ArcGIS Admin API exposure",
                    severity="critical",
                    description="An ArcGIS administrative endpoint returned structured admin JSON without requiring authentication.",
                    evidence={
                        "url": url,
                        "status_code": obs.status_code,
                        "keys": sorted(list(keys))[:40],
                        "response": {
                            k: body.get(k)
                            for k in ["resources", "machines", "services", "status", "currentVersion", "fullVersion"]
                            if k in body
                        },
                        "body_preview": (obs.body_preview or "")[:500],
                    },
                    remediation="Restrict access to ArcGIS administrative endpoints through the Web Adaptor, reverse proxy, and network controls, and require authentication for all admin resources.",
                )

    def _check_cors(self, urls: List[str]) -> None:
        origin = f"https://{self._rand_marker('origin')}.invalid"
        for url in urls:
            obs = self.request("GET", url, headers={"Origin": origin}, allow_redirects=False)
            if obs.error:
                continue
            acao = obs.headers.get("Access-Control-Allow-Origin")
            acac = obs.headers.get("Access-Control-Allow-Credentials")
            if acao in (origin, "*"):
                severity = "high" if acao == origin else "medium"
                description = "Reflective CORS policy observed: endpoint accepted an arbitrary Origin header."
                if acao == "*":
                    description = "Permissive CORS policy observed: endpoint returned wildcard Access-Control-Allow-Origin."
                self.add_issue(
                    title="Permissive CORS policy",
                    severity=severity,
                    description=description,
                    evidence={
                        "url": url,
                        "status_code": obs.status_code,
                        "request_origin": origin,
                        "access_control_allow_origin": acao,
                        "access_control_allow_credentials": acac,
                    },
                    remediation="Restrict CORS to explicitly trusted origins and avoid reflective origin behavior.",
                )

    def _check_host_header(self, urls: List[str]) -> None:
        canary = f"{self._rand_marker('host')}.invalid"
        for url in urls:
            obs = self.request("GET", url, headers={"Host": canary, "X-Forwarded-Host": canary}, allow_redirects=False)
            if obs.error:
                continue
            reflected = False
            location = obs.headers.get("Location", "")
            preview = obs.body_preview or ""
            if canary in location or canary in preview:
                reflected = True
            if reflected:
                self.add_issue(
                    title="Possible host header poisoning",
                    severity="medium",
                    description="A canary host value was reflected in a response header or body.",
                    evidence={
                        "url": url,
                        "status_code": obs.status_code,
                        "host_header": canary,
                        "x_forwarded_host": canary,
                        "location": location,
                        "body_preview": preview[:300],
                    },
                    remediation="Do not trust inbound Host or X-Forwarded-Host headers unless validated against an allowlist.",
                )
    
    def _check_open_redirect(self, urls: List[str]) -> None:
        if not self.active_checks:
            return

        test_domain = "https://example.com"  # safe external domain
        tested = set()

        redirect_params = [
            "redirect",
            "redirect_uri",
            "returnUrl",
            "url",
            "next",
            "target",
        ]

        for url in urls:
            if url in tested:
                continue
            tested.add(url)

            parsed = urlparse(url)
            path_lower = parsed.path.lower()

            # Focus on likely redirect surfaces
            if not any(x in path_lower for x in ["login", "oauth", "authorize", "signin"]):
                continue

            for param in redirect_params:
                try:
                    obs = self.request(
                        "GET",
                        url,
                        params={param: test_domain},
                        allow_redirects=False,  #important
                    )
                except Exception:
                    continue

                location = (obs.headers.get("Location") or "").lower()

                if test_domain.lower() in location:
                    self.add_issue(
                        title="Possible open redirect",
                        severity="medium",
                        description="The application appears to redirect users to a user-controlled external URL via a query parameter.",
                        evidence={
                            "url": url,
                            "parameter": param,
                            "status_code": obs.status_code,
                            "location_header": obs.headers.get("Location"),
                            "test_value": test_domain,
                            "test_command": f'curl -sk -I "{url}?{param}={quote(test_domain)}"',
                        },
                        remediation="Validate and restrict redirect destinations to trusted domains or use an allowlist of approved URLs.",
                    )
                    break
    
    def _check_portal_user_enumeration(self, discovered: Dict[str, Any]) -> None:
        """
        Check whether the ArcGIS Portal community users endpoint allows
        unauthenticated differentiation between nonexistent and valid usernames
        and discloses limited user profile information.
        """
        sharing_root = discovered.get("sharing_root")
        if not sharing_root:
            return

        base = sharing_root.rstrip("/") + "/community/users/"

        nonexistent = self._rand_marker("nouser")
        miss = self.request("GET", base + quote(nonexistent), params={"f": "pjson"}, expect_json=True)
        if miss.error:
            return

        miss_json = miss.json_body if isinstance(miss.json_body, dict) else {}
        miss_error = json.dumps(miss_json, sort_keys=True) if miss_json else (miss.body_preview or "")[:500]

        for username in LIKELY_PORTAL_USERNAMES:
            hit = self.request("GET", base + quote(username), params={"f": "pjson"}, expect_json=True)
            if hit.error:
                continue

            hit_json = hit.json_body if isinstance(hit.json_body, dict) else {}
            hit_sig = json.dumps(hit_json, sort_keys=True) if hit_json else (hit.body_preview or "")[:500]

            invalid_nonexistent = (
                "COM_0018" in miss_error
                or "does not exist" in miss_error.lower()
                or "inaccessible" in miss_error.lower()
            )
            valid_profile = bool(hit_json.get("username"))

            looks_different = invalid_nonexistent and valid_profile

            if looks_different:
                discovered.setdefault("candidate_usernames", [])
                if username not in discovered["candidate_usernames"]:
                    discovered["candidate_usernames"].append(username)

                visible_profile = {
                    k: hit_json.get(k)
                    for k in [
                        "username",
                        "fullName",
                        "firstName",
                        "lastName",
                        "access",
                        "culture",
                        "region",
                        "provider",
                        "created",
                        "modified",
                    ]
                    if k in hit_json
                }

                self.add_issue(
                    title="ArcGIS Portal user information disclosure",
                    severity="info",
                    description="The portal disclosed information about installation users without authentication. The /portal/sharing/community/users/<username>?f=pjson endpoint returned different responses for invalid and valid usernames, allowing unauthenticated user enumeration and limited profile disclosure.",
                    evidence={
                        "base_url": base,
                        "candidate_username": username,
                        "valid_lookup_url": f"{base}{quote(username)}?f=pjson",
                        "candidate_status": hit.status_code,
                        "valid_profile_fields": visible_profile,
                        "nonexistent_username": nonexistent,
                        "invalid_lookup_url": f"{base}{quote(nonexistent)}?f=pjson",
                        "nonexistent_status": miss.status_code,
                        "nonexistent_response": miss_json or (miss.body_preview or "")[:400],
                        "valid_test_command": f'curl -s -k "{base}{quote(username)}?f=pjson"',
                        "invalid_test_command": f'curl -s -k "{base}{quote(nonexistent)}?f=pjson"',
                    },
                    remediation="Require authentication for user-detail lookups where possible, minimize publicly visible profile information, and normalize responses so valid and invalid usernames are not distinguishable to unauthenticated users.",
                )
                break
                
    def _check_feature_upload_exposure(self) -> None:
        for svc in self.findings.get("rest", {}).get("services", []):
            uploads = svc.get("uploads") or {}
            if svc.get("type") != "FeatureServer":
                continue

            # Existing service-level upload surface finding
            if uploads.get("reachable") or uploads.get("suspected"):
                severity = "medium" if uploads.get("reachable") else "low"
                if not self._issue_exists("FeatureServer upload surface discovered", "service_url", svc.get("url")):
                    self.add_issue(
                        title="FeatureServer upload surface discovered",
                        severity=severity,
                        description="FeatureServer appears to expose or advertise an upload-related surface.",
                        evidence={
                            "service_name": svc.get("name"),
                            "service_url": svc.get("url"),
                            "uploads_url": uploads.get("url"),
                            "reachable": uploads.get("reachable"),
                            "status_code": uploads.get("status_code"),
                            "response": uploads.get("response") or uploads.get("body_preview"),
                            "capabilities": uploads.get("capabilities"),
                            "upload_probe": uploads.get("upload_probe"),
                        },
                        remediation="Confirm whether uploads are required on this FeatureServer and restrict or disable the upload surface where unnecessary.",
                    )

            # New combined attack-surface finding
            service_url = svc.get("url")
            capabilities = str((svc.get("metadata") or {}).get("capabilities") or "")
            relationships = svc.get("relationships") or {}
            supports_editing = bool(relationships.get("supports_editing"))

            layer_records = (svc.get("layers") or {}).get("layers", [])
            attachment_layers = []
            add_attachment_layers = []

            for layer in layer_records:
                layer_url = layer.get("url")
                layer_meta = layer.get("metadata") or {}

                if layer_meta.get("hasAttachments"):
                    attachment_layers.append({
                        "id": layer.get("id"),
                        "name": layer.get("name"),
                        "url": layer_url,
                    })

                if layer_url and self._has_issue_for_url(
                    "ArcGIS addAttachment endpoint exposed",
                    "layer_url",
                    layer_url,
                ):
                    add_attachment_layers.append({
                        "id": layer.get("id"),
                        "name": layer.get("name"),
                        "url": layer_url,
                    })

            upload_endpoint_exposed = bool((uploads.get("upload_probe") or {}).get("reachable"))
            upload_capability = "Uploads" in capabilities

            indicator_count = sum([
                1 if supports_editing else 0,
                1 if upload_capability else 0,
                1 if upload_endpoint_exposed else 0,
                1 if attachment_layers else 0,
                1 if add_attachment_layers else 0,
            ])

            # Require multiple indicators to avoid noisy findings
            if indicator_count >= 3 and (attachment_layers or add_attachment_layers or upload_endpoint_exposed):
                if not self._issue_exists("ArcGIS public file-upload attack surface exposed", "service_url", service_url):
                    self.add_issue(
                        title="ArcGIS public file-upload attack surface exposed",
                        severity="high",
                        description="This FeatureServer exposes multiple indicators consistent with a public file-upload attack surface, including editing capability, attachment support, and one or more reachable upload endpoints.",
                        evidence={
                            "service_name": svc.get("name"),
                            "service_url": service_url,
                            "capabilities": capabilities,
                            "supports_editing": supports_editing,
                            "upload_capability": upload_capability,
                            "uploads_url": uploads.get("url"),
                            "upload_endpoint_exposed": upload_endpoint_exposed,
                            "attachment_layer_count": len(attachment_layers),
                            "add_attachment_layer_count": len(add_attachment_layers),
                            "attachment_layers": attachment_layers[:20],
                            "add_attachment_layers": add_attachment_layers[:20],
                             "upload_probe_command": f'curl -sk -X POST "{uploads.get("url")}/upload" --data-urlencode "f=json"' if uploads.get("url") else None,

                            "sample_add_attachment_endpoint": (
                                f'{attachment_layers[0]["url"]}/{{OBJECTID}}/addAttachment'
                                if attachment_layers else None
                            ),

                            "add_attachment_probe_command": (
                                f'curl -sk -X POST "{attachment_layers[0]["url"]}/1/addAttachment" --data-urlencode "f=json"'
                                if attachment_layers else None
                            ),
                            "manual_upload_test_command":
                                f'curl -sk -X POST "{uploads.get("url")}/upload" '
                                f'-F "f=json" '
                                f'-F "file=@./proof.txt;type=text/plain"', #"file" or "itemFile" varies by ArcGIS version
                        },
                        remediation="Disable unnecessary upload and attachment features, require authentication and authorization for editing and upload operations, and validate all uploaded content securely.",
                    )
                
    def _has_issue_for_url(self, title: str, url_key: str, url_value: str) -> bool:
        for issue in self.findings.get("misconfigurations", {}).get("issues", []):
            if issue.get("title") != title:
                continue
            evidence = issue.get("evidence") or {}
            if evidence.get(url_key) == url_value:
                return True
        return False
    
    def _check_public_query_data_exposure(self) -> None:
        for svc in self.findings.get("rest", {}).get("services", []):
            svc_type = svc.get("type")
            if svc_type not in ("MapServer", "FeatureServer"):
                continue

            svc_name = svc.get("name")
            svc_url = svc.get("url")
            layer_data = svc.get("layers") or {}

            for bucket_name in ["layers", "tables"]:
                for layer in layer_data.get(bucket_name, []):
                    layer_url = layer.get("url")
                    layer_name = layer.get("name")
                    meta = layer.get("metadata") or {}
                    capabilities = str(meta.get("capabilities") or "")
                    supports_query = "Query" in capabilities or bool(meta.get("supportsAdvancedQueries"))

                    if not layer_url or not supports_query:
                        continue

                    count_obs = self.request(
                        "GET",
                        layer_url + "/query",
                        params={
                            "where": "1=1",
                            "returnCountOnly": "true",
                            "f": "json",
                        },
                        expect_json=True,
                        allow_redirects=True,
                    )

                    if count_obs.error or not isinstance(count_obs.json_body, dict):
                        continue

                    count_body = count_obs.json_body
                    count_err = count_body.get("error") if isinstance(count_body.get("error"), dict) else {}
                    count_msg = (
                        str(count_err.get("message") or "") + " " +
                        " ".join(str(x) for x in (count_err.get("details") or []))
                    ).lower()

                    if count_err and any(x in count_msg for x in ["token", "not authorized", "permission", "access denied", "login"]):
                        continue

                    count_value = count_body.get("count")
                    if count_value is None and "objectIds" in count_body and isinstance(count_body.get("objectIds"), list):
                        count_value = len(count_body.get("objectIds") or [])

                    sample_obs = self.request(
                        "GET",
                        layer_url + "/query",
                        params={
                            "where": "1=1",
                            "outFields": "*",
                            "returnGeometry": "false",
                            "resultRecordCount": 1,
                            "f": "json",
                        },
                        expect_json=True,
                        allow_redirects=True,
                    )

                    if sample_obs.error or not isinstance(sample_obs.json_body, dict):
                        continue

                    sample_body = sample_obs.json_body
                    sample_err = sample_body.get("error") if isinstance(sample_body.get("error"), dict) else {}
                    sample_msg = (
                        str(sample_err.get("message") or "") + " " +
                        " ".join(str(x) for x in (sample_err.get("details") or []))
                    ).lower()

                    if sample_err and any(x in sample_msg for x in ["token", "not authorized", "permission", "access denied", "login"]):
                        continue

                    features = sample_body.get("features") or []
                    field_names = [f.get("name") for f in (layer.get("fields") or []) if f.get("name")]
                    sample_attributes = {}
                    if features and isinstance(features[0], dict):
                        sample_attributes = (features[0].get("attributes") or {}) if isinstance(features[0].get("attributes"), dict) else {}

                        self.add_issue(
                            title="Public ArcGIS queryable data exposure",
                            severity="Medium",
                            description="A publicly reachable ArcGIS layer or table responded to unauthenticated query requests and returned dataset metadata or sample records.",
                            evidence={
                                "service_name": svc_name,
                                "service_type": svc_type,
                                "service_url": svc_url,
                                "layer_name": layer_name,
                                "layer_url": layer_url,
                                "layer_kind": bucket_name[:-1],
                                "record_count": count_value,
                                "field_names": field_names[:50],
                                "sample_attributes": dict(list(sample_attributes.items())[:20]),
                                "object_id_field": meta.get("objectIdField"),
                                "supported_query_formats": meta.get("supportedQueryFormats"),
                                "count_test_command": f'curl -sk "{layer_url}/query?where=1%3D1&returnCountOnly=true&f=json"',
                                "sample_test_command": f'curl -sk "{layer_url}/query?where=1%3D1&outFields=*&resultRecordCount=1&returnGeometry=false&f=json"',
                            },
                            remediation="Restrict anonymous access to layers and tables that are not intended for public use, and review data classification, query permissions, and downstream exposure risk.",
                        )
                        
    def _check_services_directory_exposure(self, discovered: Dict[str, Any]) -> None:

        rest_catalog = discovered.get("catalog")
        if not rest_catalog:
            return

        parsed = urlparse(rest_catalog)
        base_services_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        obs = self.request(
            "GET",
            base_services_url,
            allow_redirects=True
        )

        if obs.error:
            return

        preview = (obs.body_preview or "").lower()
        content_type = (obs.content_type or "").lower()

        # Detect disabled directory (like your screenshot)
        if "administrator has disabled the services directory" in preview:
            return

        # Detect actual services directory HTML UI
        if (
            "arcgis rest services directory" in preview
            or "services directory" in preview
            or ("text/html" in content_type and "<title>arcgis rest services directory" in preview)
        ):
            self.add_issue(
                title="ArcGIS Services Directory UI exposed",
                severity="medium",
                description="The ArcGIS REST Services Directory web interface is accessible. This allows interactive browsing of services and layers without using the JSON API.",
                evidence={
                    "url": base_services_url,
                    "status_code": obs.status_code,
                    "content_type": content_type,
                    "body_preview": (obs.body_preview or "")[:500],
                    "validation_command": f'curl -sk "{base_services_url}"'
                },
                remediation="Disable the ArcGIS Services Directory UI unless interactive browsing is required. The REST JSON API can remain enabled while disabling the HTML directory interface.",
            )                        
                        
    def _check_sensitive_field_exposure(self) -> None:
        keyword_groups = {
            "credentials": ["password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "auth", "key"],
            "identity": ["ssn", "social", "dob", "birth", "license", "passport"],
            "contact": ["email", "mail", "phone", "mobile", "cell", "fax"],
            "location": ["address", "street", "city", "state", "zip", "zipcode", "postal"],
            "account": ["user", "username", "login", "account"],
        }

        for svc in self.findings.get("rest", {}).get("services", []):
            svc_type = svc.get("type")
            if svc_type not in ("MapServer", "FeatureServer"):
                continue

            svc_name = svc.get("name")
            svc_url = svc.get("url")
            layer_data = svc.get("layers") or {}

            for bucket_name in ["layers", "tables"]:
                for layer in layer_data.get(bucket_name, []):
                    layer_url = layer.get("url")
                    layer_name = layer.get("name")
                    fields = layer.get("fields") or []
                    field_names = [str(f.get("name") or "") for f in fields if f.get("name")]

                    if not layer_url or not field_names:
                        continue

                    matched = {}
                    for category, keywords in keyword_groups.items():
                        hits = []
                        for field_name in field_names:
                            lowered = field_name.lower()
                            if any(k in lowered for k in keywords):
                                hits.append(field_name)
                        if hits:
                            matched[category] = sorted(list(dict.fromkeys(hits)))

                    if not matched:
                        continue

                    # Only raise this if the layer also appears queryable/publicly exposed.
                    meta = layer.get("metadata") or {}
                    capabilities = str(meta.get("capabilities") or "")
                    supports_query = "Query" in capabilities or bool(meta.get("supportsAdvancedQueries"))
                    if not supports_query:
                        continue

                    count_obs = self.request(
                        "GET",
                        layer_url + "/query",
                        params={
                            "where": "1=1",
                            "returnCountOnly": "true",
                            "f": "json",
                        },
                        expect_json=True,
                        allow_redirects=True,
                    )

                    if count_obs.error or not isinstance(count_obs.json_body, dict):
                        continue

                    count_body = count_obs.json_body
                    count_err = count_body.get("error") if isinstance(count_body.get("error"), dict) else {}
                    count_msg = (
                        str(count_err.get("message") or "") + " " +
                        " ".join(str(x) for x in (count_err.get("details") or []))
                    ).lower()

                    if count_err and any(x in count_msg for x in ["token", "not authorized", "permission", "access denied", "login"]):
                        continue

                    record_count = count_body.get("count")

                    severity = "medium"
                    if matched.get("credentials") or matched.get("identity"):
                        severity = "high"

                    self.add_issue(
                        title="Public ArcGIS layer exposes potentially sensitive field names",
                        severity=severity,
                        description="A publicly queryable ArcGIS layer or table appears to expose schema fields that may contain sensitive information.",
                        evidence={
                            "service_name": svc_name,
                            "service_type": svc_type,
                            "service_url": svc_url,
                            "layer_name": layer_name,
                            "layer_url": layer_url,
                            "layer_kind": bucket_name[:-1],
                            "record_count": record_count,
                            "matched_sensitive_fields": matched,
                            "field_names": field_names[:50],
                            "object_id_field": meta.get("objectIdField"),
                            "count_test_command": f'curl -sk "{layer_url}/query?where=1%3D1&returnCountOnly=true&f=json"',
                            "sample_test_command": f'curl -sk "{layer_url}/query?where=1%3D1&outFields=*&resultRecordCount=1&returnGeometry=false&f=json"',
                            "field_test_command": f'curl -sk "{layer_url}/query?where=1%3D1&outFields={quote(",".join(sorted({field for hits in matched.values() for field in hits})[:10]))}&resultRecordCount=1&returnGeometry=false&f=json"',
                        },
                        remediation="Review whether this layer or table should be publicly accessible, minimize exposed fields, and remove or restrict access to sensitive attributes.",
                    )
                    
    def _check_public_portal_content_enumeration(self, discovered: Dict[str, Any]) -> None:
        sharing_root = discovered.get("sharing_root")
        if not sharing_root:
            return

        search_candidates = [
            sharing_root.rstrip("/") + "/search",
            sharing_root.rstrip("/") + "/rest/search",
        ]

        seen_urls = set()
        for search_url in search_candidates:
            if search_url in seen_urls:
                continue
            seen_urls.add(search_url)

            obs = self.request(
                "GET",
                search_url,
                params={
                    "q": "*",
                    "num": 10,
                    "sortField": "numViews",
                    "sortOrder": "desc",
                    "f": "json",
                },
                expect_json=True,
                allow_redirects=True,
            )

            if obs.error or not isinstance(obs.json_body, dict):
                continue

            body = obs.json_body
            err = body.get("error") if isinstance(body.get("error"), dict) else {}
            msg = (
                str(err.get("message") or "") + " " +
                " ".join(str(x) for x in (err.get("details") or []))
            ).lower()

            if err and any(x in msg for x in ["token", "not authorized", "permission", "access denied", "login"]):
                continue

            results = body.get("results") or []
            if not isinstance(results, list) or not results:
                continue

            public_items = []
            downloadable_count = 0

            for item in results[:10]:
                if not isinstance(item, dict):
                    continue

                access = str(item.get("access") or "").lower()
                item_url = item.get("url")
                item_type = item.get("type")
                title = item.get("title")
                owner = item.get("owner")

                entry = {
                    "id": item.get("id"),
                    "title": title,
                    "owner": owner,
                    "type": item_type,
                    "access": access,
                    "url": item_url,
                    "views": item.get("numViews"),
                    "snippet": item.get("snippet"),
                    "description": item.get("description"),
                }

                if access == "public":
                    public_items.append(entry)

                if item.get("downloadable") is True:
                    downloadable_count += 1

            if public_items:
                severity = "medium"
                if len(public_items) >= 5:
                    severity = "high"

                self.add_issue(
                    title="Public ArcGIS portal content enumeration",
                    severity=severity,
                    description="The ArcGIS portal search API returned publicly discoverable content to an unauthenticated request.",
                    evidence={
                        "url": search_url,
                        "status_code": obs.status_code,
                        "total": body.get("total"),
                        "returned_results": len(results),
                        "public_item_count": len(public_items),
                        "downloadable_count": downloadable_count,
                        "items": public_items[:10],
                    },
                    remediation="Review portal sharing settings, restrict sensitive items from public visibility, and ensure anonymous search only exposes intended content.",
                )
                
    def _check_token_generation_misconfigurations(self, discovered: Dict[str, Any]) -> None:
        parsed = urlparse(self.base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        candidates = [
            self._join(origin, "/arcgis/tokens"),
            self._join(origin, "/arcgis/admin/generateToken"),
            self._join(origin, "/portal/sharing/rest/generateToken"),
            self._join(origin, "/portal/sharing/generateToken"),
        ]

        rest_info = discovered.get("rest_info")
        if rest_info:
            try:
                info = self.get_json(rest_info)
                auth = info.get("authInfo") or {}
                token_url = auth.get("tokenServicesUrl")
                if token_url:
                    candidates.append(token_url)
            except Exception:
                pass

        sharing_root = discovered.get("sharing_root")
        if sharing_root:
            candidates.append(sharing_root.rstrip("/") + "/generateToken")
            candidates.append(sharing_root.rstrip("/") + "/rest/generateToken")

        candidates = list(dict.fromkeys(candidates))

        for token_url in candidates:
            blank_form = {
                "username": "",
                "password": "",
                "client": "requestip",
                "f": "json",
                "expiration": 60,
            }

            obs = self.request(
                "POST",
                token_url,
                data=blank_form,
                expect_json=True,
                allow_redirects=True,
            )
            if obs.error or not isinstance(obs.json_body, dict):
                continue

            body = obs.json_body
            token = body.get("token")
            expires = body.get("expires")
            err = body.get("error") if isinstance(body.get("error"), dict) else {}
            msg = (
                str(err.get("message") or "") + " " +
                " ".join(str(x) for x in (err.get("details") or []))
            ).lower()

            if token:
                severity = "critical"
                description = "A token endpoint issued a token in response to a blank-credential request."
                if expires:
                    description += " The response also included an expiration value."

                self.add_issue(
                    title="Unsafe ArcGIS token issuance",
                    severity=severity,
                    description=description,
                    evidence={
                        "url": token_url,
                        "status_code": obs.status_code,
                        "request_client": "requestip",
                        "blank_username": True,
                        "blank_password": True,
                        "token_prefix": str(token)[:20],
                        "expires": expires,
                        "response": {
                            k: body.get(k)
                            for k in ["token", "expires", "ssl"]
                            if k in body
                        },
                    },
                    remediation="Require valid authentication for token issuance, disable unsafe token workflows, and review reverse-proxy or SSO integrations that may be weakening access control.",
                )
                continue

            # Informational/low-signal but useful auth behavior capture.
            if err:
                if any(x in msg for x in ["invalid username or password", "unable to generate token", "token required"]):
                    continue

                if "requestip" in msg or "referer" in msg or "client" in msg:
                    self.add_issue(
                        title="ArcGIS token endpoint reveals detailed client binding behavior",
                        severity="low",
                        description="A token endpoint returned detailed client-binding or token-generation behavior information that may help an attacker understand the authentication workflow.",
                        evidence={
                            "url": token_url,
                            "status_code": obs.status_code,
                            "request_client": "requestip",
                            "response": {
                                k: body.get(k)
                                for k in ["error"]
                                if k in body
                            },
                            "body_preview": (obs.body_preview or "")[:500],
                        },
                        remediation="Normalize token-generation error responses and avoid exposing unnecessary implementation detail to unauthenticated users.",
                    )
                    
    def _check_feature_editing_without_auth(self) -> None:
        if not self.active_checks:
            return

        for svc in self.findings.get("rest", {}).get("services", []):
            if svc.get("type") != "FeatureServer":
                continue

            svc_name = svc.get("name")
            svc_url = svc.get("url")
            layer_data = svc.get("layers") or {}

            for bucket_name in ["layers", "tables"]:
                for layer in layer_data.get(bucket_name, []):
                    layer_url = layer.get("url")
                    layer_name = layer.get("name")
                    meta = layer.get("metadata") or {}
                    capabilities = str(meta.get("capabilities") or "")
                    caps_lower = capabilities.lower()

                    supports_editing = any(
                        x in caps_lower for x in ["create", "update", "delete", "editing", "sync"]
                    )
                    if not layer_url or not supports_editing:
                        continue

                    add_result = self._attempt_unauthenticated_feature_add(layer_url, meta)
                    if not add_result.get("success"):
                        continue

                    created_object_id = add_result.get("object_id")
                    edit_method = add_result.get("method")
                    edit_url = add_result.get("edit_url")

                    verification = self._verify_added_feature(layer_url, created_object_id, meta)
                    cleanup = self._cleanup_added_feature(layer_url, created_object_id, edit_method)

                    self.add_issue(
                        title="FeatureServer edit operation reachable without authentication",
                        severity="high",
                        description="A FeatureServer layer responded to an unauthenticated edit-style request and returned ArcGIS editing result structures.",
                        evidence={
                            "service_name": svc_name,
                            "service_url": svc_url,
                            "layer_name": layer_name,
                            "layer_url": layer_url,
                            "layer_kind": bucket_name[:-1],
                            "edit_url": edit_url,
                            "edit_method": edit_method,
                            "capabilities": capabilities,
                            "status_code": add_result.get("status_code"),
                            "response": add_result.get("response"),
                            "proof_command": add_result.get("proof_command"),
                            "query_created_object_command": verification.get("verification_command"),
                            "cleanup_created_object_command": cleanup.get("cleanup_command"),
                            "created_object_id": created_object_id,
                            "verification_attempted": verification.get("attempted"),
                            "verification_success": verification.get("success"),
                            "verification_status_code": verification.get("status_code"),
                            "verification_response": verification.get("response"),
                            "verification_error": verification.get("error"),
                            "cleanup_attempted": cleanup.get("attempted"),
                            "cleanup_success": cleanup.get("success"),
                            "cleanup_status_code": cleanup.get("status_code"),
                            "cleanup_response": cleanup.get("response"),
                            "cleanup_error": cleanup.get("error"),
                        },
                        remediation="Require authentication and appropriate authorization for editing operations, and verify that anonymous users cannot access add/update/delete/applyEdits endpoints.",
                    )
                            
    def _cleanup_added_feature(self, layer_url: str, object_id: Any, method: str = "applyEdits") -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "attempted": False,
            "success": False,
            "method": method,
            "object_id": object_id,
            "status_code": None,
            "response": None,
            "error": None,
            "cleanup_command": None,
        }

        if object_id is None:
            result["error"] = "No object ID available for cleanup."
            return result

        result["attempted"] = True

        cleanup_attempts = []

        if method == "addFeatures":
            cleanup_attempts.append({
                "url": f"{layer_url}/deleteFeatures",
                "data": {
                    "f": "json",
                    "objectIds": str(object_id),
                },
                "cleanup_command": (
                    f'curl -sk -X POST "{layer_url}/deleteFeatures" '
                    f'-H "Content-Type: application/x-www-form-urlencoded" '
                    f'--data-urlencode \'objectIds={object_id}\' '
                    f'--data-urlencode \'f=json\''
                ),
            })
        else:
            # First try applyEdits delete
            cleanup_attempts.append({
                "url": f"{layer_url}/applyEdits",
                "data": {
                    "f": "json",
                    "deletes": str(object_id),
                },
                "cleanup_command": (
                    f'curl -sk -X POST "{layer_url}/applyEdits" '
                    f'-H "Content-Type: application/x-www-form-urlencoded" '
                    f'--data-urlencode \'deletes={object_id}\' '
                    f'--data-urlencode \'f=json\''
                ),
            })
            # Fallback to deleteFeatures
            cleanup_attempts.append({
                "url": f"{layer_url}/deleteFeatures",
                "data": {
                    "f": "json",
                    "objectIds": str(object_id),
                },
                "cleanup_command": (
                    f'curl -sk -X POST "{layer_url}/deleteFeatures" '
                    f'-H "Content-Type: application/x-www-form-urlencoded" '
                    f'--data-urlencode \'objectIds={object_id}\' '
                    f'--data-urlencode \'f=json\''
                ),
            })

        last_error = None

        for attempt in cleanup_attempts:
            try:
                obs = self.request(
                    "POST",
                    attempt["url"],
                    data=attempt["data"],
                    expect_json=True,
                    allow_redirects=True,
                )

                result["status_code"] = obs.status_code
                result["cleanup_command"] = attempt["cleanup_command"]

                body = obs.json_body if isinstance(obs.json_body, dict) else {}
                result["response"] = body if body else (obs.body_preview or "")[:500]

                delete_results = body.get("deleteResults") or []
                if delete_results and isinstance(delete_results[0], dict):
                    result["success"] = bool(delete_results[0].get("success"))
                    if result["success"]:
                        return result
                    last_error = str(delete_results[0])
                    continue

                if isinstance(body.get("error"), dict):
                    err = body["error"]
                    last_error = f'{err.get("code")}: {err.get("message")}'
                    continue

                last_error = "Unexpected cleanup response format."
            except Exception as exc:
                last_error = str(exc)

        result["error"] = last_error or "Cleanup did not succeed."
        return result
    
    def _attempt_unauthenticated_feature_add(self, layer_url: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Try to create a benign test feature using ArcGIS edit endpoints.
        Preference order:
          1. applyEdits
          2. addFeatures
        Returns method used, response, object_id, and proof command.
        """
        result: Dict[str, Any] = {
            "success": False,
            "method": None,
            "edit_url": None,
            "status_code": None,
            "object_id": None,
            "response": None,
            "error": None,
            "proof_command": None,
        }
        
        geometry_type = meta.get("geometryType")
        object_id_field = meta.get("objectIdField") or "OBJECTID"

        # Build a low-impact payload.
        attributes = {"Comments": "PENTEST-AUDIT-UNAUTH-ADD-TEST"}

        feature_obj: Dict[str, Any] = {"attributes": attributes}

        # Add minimal geometry if the layer is point-based.
        if geometry_type == "esriGeometryPoint":
            sr = (meta.get("extent") or {}).get("spatialReference") or {}
            wkid = sr.get("latestWkid") or sr.get("wkid") or 4326
            feature_obj["geometry"] = {
                "x": 0,
                "y": 0,
                "spatialReference": {"wkid": wkid},
            }

        feature_json = json.dumps([feature_obj], separators=(",", ":"))

        candidates = [
            {
                "method": "applyEdits",
                "url": f"{layer_url}/applyEdits",
                "data": {
                    "f": "json",
                    "adds": feature_json,
                    "rollbackOnFailure": "true",
                },
                "proof_command": (
                    f'curl -sk -X POST "{layer_url}/applyEdits" '
                    f'-H "Content-Type: application/x-www-form-urlencoded" '
                    f'--data-urlencode \'adds={feature_json}\' '
                    f'--data-urlencode \'rollbackOnFailure=true\' '
                    f'--data-urlencode \'f=json\''
                ),
            },
            {
                "method": "addFeatures",
                "url": f"{layer_url}/addFeatures",
                "data": {
                    "f": "json",
                    "features": feature_json,
                    "rollbackOnFailure": "true",
                },
                "proof_command": (
                    f'curl -sk -X POST "{layer_url}/addFeatures" '
                    f'-H "Content-Type: application/x-www-form-urlencoded" '
                    f'--data-urlencode \'features={feature_json}\' '
                    f'--data-urlencode \'rollbackOnFailure=true\' '
                    f'--data-urlencode \'f=json\''
                ),
            },
        ]

        for candidate in candidates:
            try:
                obs = self.request(
                    "POST",
                    candidate["url"],
                    data=candidate["data"],
                    expect_json=True,
                    allow_redirects=True,
                )
                result["status_code"] = obs.status_code
                body = obs.json_body if isinstance(obs.json_body, dict) else {}
                result["response"] = body if body else (obs.body_preview or "")[:500]

                add_results = body.get("addResults") or []
                if add_results and isinstance(add_results[0], dict) and add_results[0].get("success") is True:
                    result["success"] = True
                    result["method"] = candidate["method"]
                    result["edit_url"] = candidate["url"]
                    result["proof_command"] = candidate["proof_command"]
                    result["object_id"] = add_results[0].get("objectId")
                    return result

                # Not successful, but keep last useful error
                if isinstance(body.get("error"), dict):
                    err = body["error"]
                    result["error"] = f'{err.get("code")}: {err.get("message")}'
                elif add_results and isinstance(add_results[0], dict):
                    result["error"] = str(add_results[0])

            except Exception as exc:
                result["error"] = str(exc)

        return result
    
    def _verify_added_feature(self, layer_url: str, object_id: Any, meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Query back the created object to confirm persistence before cleanup.
        """
        result: Dict[str, Any] = {
            "attempted": False,
            "success": False,
            "status_code": None,
            "response": None,
            "error": None,
            "verification_command": None,
        }

        if object_id is None:
            result["error"] = "No object ID available for verification."
            return result

        object_id_field = meta.get("objectIdField") or "OBJECTID"
        where = f"{object_id_field}={object_id}"

        result["attempted"] = True
        result["verification_command"] = (
            f'curl -sk "{layer_url}/query?where={quote(where)}&outFields=*&returnGeometry=false&f=json"'
        )

        try:
            obs = self.request(
                "GET",
                f"{layer_url}/query",
                params={
                    "where": where,
                    "outFields": "*",
                    "returnGeometry": "false",
                    "f": "json",
                },
                expect_json=True,
                allow_redirects=True,
            )
            result["status_code"] = obs.status_code
            body = obs.json_body if isinstance(obs.json_body, dict) else {}
            result["response"] = body if body else (obs.body_preview or "")[:500]

            features = body.get("features") or []
            result["success"] = any(
                (f.get("attributes") or {}).get(object_id_field) == object_id
                for f in features if isinstance(f, dict)
            )

            if not result["success"] and isinstance(body.get("error"), dict):
                err = body["error"]
                result["error"] = f'{err.get("code")}: {err.get("message")}'
            elif not result["success"]:
                result["error"] = "Created object was not observed in verification query."

        except Exception as exc:
            result["error"] = str(exc)

        return result
                        
    def _check_feature_attachments(self, layer_url: str, meta: Dict[str, Any]) -> None:
        """
        Detect exposed ArcGIS FeatureServer attachments by first querying for
        available object IDs, then testing attachments on the first few IDs.
        """
        if not meta.get("hasAttachments", False):
            return # avoid unnecessary HTTP requets for layers that do not support attachments

        try:
            obj_field = meta.get("objectIdField") or "OBJECTID"

            # Step 1: get a small set of real object IDs from the layer. 
            # Request() wrapper instead of get_json() here in order to capture status code, raw body, attachment metadata
            ids_obs = self.request(
                "GET",
                f"{layer_url}/query",
                params={
                    "where": "1=1",
                    "returnIdsOnly": "true",
                    "f": "json",
                },
                expect_json=True,
                allow_redirects=True,
            )

            if not ids_obs or ids_obs.error or not isinstance(ids_obs.json_body, dict):
                return

            ids_body = ids_obs.json_body
            ids_err = ids_body.get("error") if isinstance(ids_body.get("error"), dict) else {}
            ids_msg = (
                str(ids_err.get("message") or "") + " " +
                " ".join(str(x) for x in (ids_err.get("details") or []))
            ).lower()

            if ids_err and any(x in ids_msg for x in ["token", "not authorized", "permission", "access denied", "login"]):
                return

            object_ids = ids_body.get("objectIds") or []
            if not isinstance(object_ids, list) or not object_ids:
                return

            test_ids = object_ids[:5]

            # Step 2: test attachments on the first few real IDs
            attach_obs = self.request(
                "GET",
                f"{layer_url}/queryAttachments",
                params={
                    "objectIds": ",".join(str(x) for x in test_ids),
                    "f": "json",
                },
                expect_json=True,
                allow_redirects=True,
            )

            if not attach_obs or attach_obs.error or not isinstance(attach_obs.json_body, dict):
                return

            body = attach_obs.json_body
            err = body.get("error") if isinstance(body.get("error"), dict) else {}
            msg = (
                str(err.get("message") or "") + " " +
                " ".join(str(x) for x in (err.get("details") or []))
            ).lower()

            if err and any(x in msg for x in ["token", "not authorized", "permission", "access denied", "login"]):
                return

            groups = body.get("attachmentGroups") or []
            if not isinstance(groups, list) or not groups:
                return

            for group in groups:
                parent_object_id = group.get("parentObjectId")
                attachment_infos = group.get("attachmentInfos") or []
                if not attachment_infos:
                    continue

                first = attachment_infos[0]
                attachment_id = first.get("id")
                attachment_name = first.get("name")
                content_type = first.get("contentType")
                size = first.get("size")

                download_url = f"{layer_url}/{parent_object_id}/attachments/{attachment_id}"

                self.add_issue(
                    title="ArcGIS attachments accessible without authentication",
                    severity="medium",
                    description="A FeatureServer layer allows unauthenticated access to attachments associated with records.",
                    evidence={
                        "layer_url": layer_url,
                        "object_id_field": obj_field,
                        "tested_object_ids": test_ids,
                        "object_id_tested": parent_object_id,
                        "attachment_id": attachment_id,
                        "attachment_name": attachment_name,
                        "attachment_content_type": content_type,
                        "attachment_size": size,
                        "download_url": download_url,
                        "enumeration_command": f'curl -sk "{layer_url}/query?where=1%3D1&returnIdsOnly=true&f=json"',
                        "attachment_query_command": f'curl -sk "{layer_url}/queryAttachments?objectIds={",".join(str(x) for x in test_ids)}&f=json"',
                        "download_command": f'curl -sk "{download_url}" -o "{attachment_name or "attachment.bin"}"',
                    },
                    remediation="Restrict attachment access or require authentication for attachment queries and downloads.",
                )
                break

        except Exception:
            pass                    
                        
    def _check_upload_directory_exposure(self, discovered: Dict[str, Any]) -> None:
        parsed = urlparse(self.base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        candidates = [
            self._join(origin, "/arcgis/uploads"),
            self._join(origin, "/arcgis/uploads/info"),
            self._join(origin, "/uploads"),
            self._join(origin, "/uploads/info"),
        ]

        admin_root = discovered.get("admin_root")
        if admin_root:
            admin_root = admin_root.rstrip("/")
            candidates.extend(
                [
                    admin_root + "/uploads",
                    admin_root + "/uploads/info",
                ]
            )

        candidates = list(dict.fromkeys(candidates))

        for url in candidates:
            obs = self.request(
                "GET",
                url,
                params={"f": "json"},
                expect_json=True,
                allow_redirects=True,
            )
            if obs.error or not isinstance(obs.json_body, dict):
                continue

            body = obs.json_body
            err = body.get("error") if isinstance(body.get("error"), dict) else {}
            msg = (
                str(err.get("message") or "") + " " +
                " ".join(str(x) for x in (err.get("details") or []))
            ).lower()

            if err and any(x in msg for x in ["token", "not authorized", "permission", "access denied", "login"]):
                continue

            upload_indicators = any(
                k in body for k in ["itemID", "items", "uploadId", "uploads", "id", "name"]
            )

            if upload_indicators:
                self.add_issue(
                    title="ArcGIS upload directory exposure",
                    severity="medium",
                    description="An ArcGIS upload-related endpoint returned upload metadata or directory-style JSON without authentication.",
                    evidence={
                        "url": url,
                        "status_code": obs.status_code,
                        "keys": sorted(list(body.keys()))[:40],
                        "response": {
                            k: body.get(k)
                            for k in ["itemID", "items", "uploadId", "uploads", "id", "name"]
                            if k in body
                        },
                        "body_preview": (obs.body_preview or "")[:500],
                    },
                    remediation="Restrict access to upload directory endpoints, require authentication where appropriate, and review whether uploaded file metadata should be publicly exposed.",
                )
                
    def _check_add_attachment_endpoint(self, layer_url: str, meta: Dict[str, Any]) -> None:
        if not self.active_checks:
            return
        """
        Probe ArcGIS layer attachment upload endpoint.
        """
        if not meta.get("hasAttachments"):
            return

        capabilities = str(meta.get("capabilities") or "")
        supports_query = (
            "Query" in capabilities
            or bool((meta.get("advancedQueryCapabilities") or {}).get("supportsAdvancedQueries"))
        )

        try:
            object_id_field = meta.get("objectIdField") or "OBJECTID"
            sample_object_id = None

            # Try to get one real object ID so the endpoint path is realistic
            if supports_query:
                sample_obs = self.request(
                    "GET",
                    f"{layer_url}/query",
                    params={
                        "where": "1=1",
                        "outFields": object_id_field,
                        "returnGeometry": "false",
                        "resultRecordCount": 1,
                        "f": "json",
                    },
                    expect_json=True,
                    allow_redirects=True,
                )

                if not sample_obs.error and isinstance(sample_obs.json_body, dict):
                    sample_features = sample_obs.json_body.get("features") or []
                    if sample_features:
                        attrs = sample_features[0].get("attributes") or {}
                        sample_object_id = attrs.get(object_id_field)

            # Fall back to 1 if no sample record is available
            if sample_object_id is None:
                sample_object_id = 1

            add_attachment_url = f"{layer_url}/{sample_object_id}/addAttachment"

            obs = self.request(
                "POST",
                add_attachment_url,
                data={"f": "json"},
                expect_json=True,
                allow_redirects=True,
            )

            body = obs.json_body if isinstance(obs.json_body, dict) else None
            err = body.get("error") if isinstance(body and body.get("error"), dict) else {}

            msg = str(err.get("message") or "")
            details = " ".join(str(x) for x in (err.get("details") or []))
            combined = (msg + " " + details).lower()

            reachable = False
            reason = None

            if body is not None:
                if any(k in body for k in ["addAttachmentResult", "success"]):
                    reachable = True
                    reason = "Attachment endpoint returned attachment-operation JSON."
                elif err.get("code") in (400, 401, 403, 498, 499):
                    reachable = True
                    reason = "Attachment endpoint appears to exist and returned an ArcGIS error/auth response."
                elif any(x in combined for x in ["attachment", "file", "upload", "token", "not authorized", "access denied"]):
                    reachable = True
                    reason = "Attachment endpoint appears to exist based on ArcGIS response content."
            else:
                if obs.status_code in (400, 401, 403):
                    reachable = True
                    reason = "Attachment endpoint returned an HTTP response consistent with an exposed upload surface."

            if reachable:
                result["probe_command"] = f'curl -sk -X POST "{add_attachment_url}" --data-urlencode "f=json"'
                if not self._issue_exists("ArcGIS addAttachment endpoint exposed", "layer_url", layer_url):
                    self.add_issue(
                        title="ArcGIS addAttachment endpoint exposed",
                        severity="medium",
                        description="A layer attachment upload endpoint appears reachable. Depending on authentication and authorization controls, this may permit attachment upload operations or expose an attack surface for file-handling abuse.",
                        evidence={
                            "layer_url": layer_url,
                            "object_id_field": object_id_field,
                            "sample_object_id": sample_object_id,
                            "add_attachment_url": add_attachment_url,
                            "status_code": obs.status_code,
                            "capabilities": capabilities,
                            "has_attachments": meta.get("hasAttachments"),
                            "reason": reason,
                            "error_code": err.get("code"),
                            "error_message": err.get("message"),
                            "probe_command": f'curl -sk -X POST "{add_attachment_url}" --data-urlencode \'f=json\'',
                            "body_preview": (obs.body_preview or "")[:400],
                        },
                        remediation="Ensure attachment upload endpoints require authentication and authorization, restrict which users may add attachments, and validate uploaded content securely.",
                    )

        except Exception:
            pass
            
    def _issue_exists(self, title: str, evidence_key: str, evidence_value: str) -> bool:
        for issue in self.findings.get("misconfigurations", {}).get("issues", []):
            if issue.get("title") == title and (issue.get("evidence") or {}).get(evidence_key) == evidence_value:
                return True
        return False                        

    def _check_proxy_ssrf(self, discovered: Dict[str, Any]) -> None:
        proxy_candidates = discovered.get("possible_proxy_endpoints", [])
        if not proxy_candidates:
            return

        for proxy_url in proxy_candidates:
            evidence = {"url": proxy_url}

            if not self.active_checks:
                evidence["inactive_test_disabled"] = True
                self.add_issue(
                    title="Proxy endpoint exposed",
                    severity="low",
                    description="A proxy endpoint was discovered. SSRF validation was not performed because active checks are disabled.",
                    evidence=evidence,
                    remediation="If you want to validate SSRF behavior, rerun with --active-checks and a harmless --ssrf-test-url.",
                )
                continue

            test_variants = [
                {
                    "name": "loopback_http",
                    "target": "http://127.0.0.1:1/",
                },
                {
                    "name": "loopback_http_encoded",
                    "target": "http:%2f%2f127.0.0.1:1%2f",
                    "pre_encoded": True,
                },
                {
                    "name": "localhost_http",
                    "target": "http://localhost:1/",
                },
                {
                    "name": "metadata_like",
                    "target": "http://169.254.169.254/",
                },
                {
                    "name": "external_harmless",
                    "target": self.ssrf_test_url,
                },
            ]

            # Keep file:// probe optional but included only during active checks.
            test_variants.append(
                {
                    "name": "file_scheme",
                    "target": "file:///etc/passwd",
                }
            )

            variant_results = []

            for variant in test_variants:
                target = variant["target"]
                if variant.get("pre_encoded"):
                    full_url = proxy_url + "?" + target
                else:
                    full_url = proxy_url + "?" + quote(target, safe=':/?=&')

                obs = self.request("GET", full_url, allow_redirects=True)
                variant_results.append(
                    {
                        "name": variant["name"],
                        "target": target,
                        "status_code": obs.status_code,
                        "content_type": obs.content_type,
                        "redirect_chain": obs.redirect_chain,
                        "body_preview": (obs.body_preview or "")[:250],
                        "error": obs.error,
                    }
                )

            evidence["inactive_test_disabled"] = False
            evidence["variant_results"] = variant_results

            suspicious_variants = []
            for vr in variant_results:
                preview = (vr.get("body_preview") or "").lower()
                status_code = vr.get("status_code")

                if vr.get("error"):
                    continue

                if status_code and status_code not in (None, 400, 404):
                    suspicious_variants.append(vr)
                    continue

                if any(
                    marker in preview
                    for marker in [
                        "root:x:",
                        "127.0.0.1",
                        "localhost",
                        "169.254.169.254",
                        "connection refused",
                        "no such host",
                        "name or service not known",
                        "actively refused",
                    ]
                ):
                    suspicious_variants.append(vr)

            if suspicious_variants:
                severity = "high"
                if len(suspicious_variants) == 1 and suspicious_variants[0].get("name") == "external_harmless":
                    severity = "medium"

                self.add_issue(
                    title="Proxy endpoint may enable SSRF or traversal behavior",
                    severity=severity,
                    description="A proxy endpoint responded to one or more user-controlled target variants in a way that suggests server-side fetching or proxy behavior. Manual validation is recommended to determine reachable destinations and impact.",
                    evidence={
                        "url": proxy_url,
                        "suspicious_variants": suspicious_variants,
                        "variant_results": variant_results,
                    },
                    remediation="Disable or restrict proxy functionality, validate destination schemes and hosts against a strict allowlist, and block loopback, link-local, internal, and file-scheme access.",
                )
            else:
                self.add_issue(
                    title="Proxy endpoint exposed",
                    severity="low",
                    description="A proxy endpoint is exposed. Active SSRF and traversal variant checks did not confirm abuse, but the surface should still be reviewed.",
                    evidence=evidence,
                    remediation="If the proxy is unnecessary, remove it. Otherwise restrict destinations, schemes, and authentication requirements.",
                )
                
    def _build_xss_payload_variants(self, marker: str) -> List[Dict[str, str]]:
        return [
            {
                "name": "html_tag_breakout",
                "payload": f'"><svg/onload=alert("{marker}")>',
            },
            {
                "name": "attribute_injection",
                "payload": f'" autofocus onfocus=alert("{marker}") x="',
            },
            {
                "name": "js_string_breakout",
                "payload": f'";alert("{marker}")//',
            },
        ]

    def _check_reflected_xss(self, urls: List[str]) -> None:
        if not self.active_checks:
            return

        marker = self._rand_marker("xss")
        payload_variants = self._build_xss_payload_variants(marker)
        tested_urls = set()

        def is_html_like(content_type: str, body: str) -> bool:
            ct = (content_type or "").lower()
            return (
                "text/html" in ct
                or "application/xhtml" in ct
                or "<html" in body.lower()
                or "<form" in body.lower()
            )

        for url in urls:
            parsed = urlparse(url)
            path_lower = parsed.path.lower()

            if not any(x in path_lower for x in XSS_TEST_PATH_MARKERS):
                continue

            if url in tested_urls:
                continue
            tested_urls.add(url)

            for param in XSS_TEST_PARAMETERS:
                found_for_param = False

                for variant in payload_variants:
                    payload = variant["payload"]

                    # GET check
                    obs = self.request(
                        "GET",
                        url,
                        params={param: payload},
                        allow_redirects=True,
                    )

                    if not obs.error:
                        body = obs.body_preview or ""
                        if is_html_like(obs.content_type or "", body):
                            classification = self._detect_reflection_style(body, payload, marker)

                            # Only report raw reflection to avoid false positives from encoding/sanitization
                            if classification["reflection_style"] == "raw" and classification["likely_executable"]:
                                self.add_issue(
                                    title="Possible reflected XSS",
                                    severity="medium",
                                    description="A benign XSS canary appeared to be reflected without encoding in an ArcGIS authentication or UI-related response. Manual browser validation is required.",
                                    evidence={
                                        "url": url,
                                        "method": "GET",
                                        "parameter": param,
                                        "payload_variant": variant["name"],
                                        "payload": payload,
                                        "status_code": obs.status_code,
                                        "content_type": obs.content_type,
                                        "reflection_style": classification["reflection_style"],
                                        "reflection_context": classification["context_snippet"],
                                        "body_preview": body[:500],
                                    },
                                    remediation="Apply output encoding, validate untrusted input, and consider a restrictive Content Security Policy.",
                                )
                                found_for_param = True
                                break

                    # Selected POST check for login-like endpoints
                    if any(x in path_lower for x in ["login", "signin", "oauth2", "logon"]):
                        post_obs = self.request(
                            "POST",
                            url,
                            data={param: payload},
                            allow_redirects=True,
                        )

                        if not post_obs.error:
                            post_body = post_obs.body_preview or ""
                            if is_html_like(post_obs.content_type or "", post_body):
                                classification = self._detect_reflection_style(post_body, payload, marker)

                                # Only report raw reflection to avoid false positives from encoding/sanitization
                                if classification["reflection_style"] == "raw" and classification["likely_executable"]:
                                    self.add_issue(
                                        title="Possible reflected XSS",
                                        severity="medium",
                                        description="A benign XSS canary appeared to be reflected without encoding in a POST response body for an ArcGIS authentication or UI-related surface. Manual browser validation is required.",
                                        evidence={
                                            "url": url,
                                            "method": "POST",
                                            "parameter": param,
                                            "payload_variant": variant["name"],
                                            "payload": payload,
                                            "status_code": post_obs.status_code,
                                            "content_type": post_obs.content_type,
                                            "reflection_style": classification["reflection_style"],
                                            "reflection_context": classification["context_snippet"],
                                            "body_preview": post_body[:500],
                                        },
                                        remediation="Apply output encoding, validate untrusted input, and consider a restrictive Content Security Policy.",
                                    )
                                    found_for_param = True
                                    break

                if found_for_param:
                    break
                                
    def _detect_reflection_style(self, body: str, payload: str, marker: str) -> Dict[str, Any]:
        """
        Classify how the payload/marker appears in the response body.

        Returns:
            {
                "reflected": bool,
                "reflection_style": "none" | "raw" | "html_escaped" | "marker_only" | "marker_only_encoded_context",
                "likely_executable": bool,
                "context_snippet": Optional[str],
            }
        """
        result = {
            "reflected": False,
            "reflection_style": "none",
            "likely_executable": False,
            "context_snippet": None,
        }

        if not body:
            return result

        escaped_payloads = {
            html.escape(payload),
            payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;"),
            payload.replace("<", "&#x3c;").replace(">", "&#x3e;"),
        }

        raw_present = payload in body
        escaped_present = any(ep and ep in body for ep in escaped_payloads)
        marker_present = marker in body

        pos = -1
        match_value = None

        if raw_present:
            pos = body.find(payload)
            match_value = payload
        elif escaped_present:
            for ep in escaped_payloads:
                if ep and ep in body:
                    pos = body.find(ep)
                    match_value = ep
                    break
        elif marker_present:
            pos = body.find(marker)
            match_value = marker

        if pos != -1:
            start = max(0, pos - 120)
            end = min(len(body), pos + max(120, len(match_value or "")))
            result["context_snippet"] = body[start:end]

        if raw_present:
            result["reflected"] = True
            result["reflection_style"] = "raw"
            result["likely_executable"] = True
            return result

        if escaped_present:
            result["reflected"] = True
            result["reflection_style"] = "html_escaped"
            result["likely_executable"] = False
            return result

        if marker_present:
            result["reflected"] = True
            context = result["context_snippet"] or ""
            encoded_indicators = ("&lt;", "&gt;", "&quot;", "&#x27;", "&#x2f;", "&#60;", "&#62;")
            if any(x in context.lower() for x in encoded_indicators):
                result["reflection_style"] = "marker_only_encoded_context"
            else:
                result["reflection_style"] = "marker_only"
            result["likely_executable"] = False
            return result

        return result
        
    def _check_possible_stored_xss_sink(self, layer_url: str, meta: Dict[str, Any], fields: List[Dict[str, Any]]) -> None:
        capabilities = str(meta.get("capabilities") or "")
        supports_editing = any(word in capabilities for word in ["Create", "Update", "Delete", "Editing"])
        supports_query = "Query" in capabilities or bool((meta.get("advancedQueryCapabilities") or {}).get("supportsAdvancedQueries"))

        if not (supports_editing and supports_query):
            return

        suspicious_fields = []
        candidate_field = None

        text_types = {
            "esriFieldTypeString",
            "string",
        }

        for field in fields:
            field_name = str(field.get("name") or "")
            alias = str(field.get("alias") or "")
            field_type = str(field.get("type") or "")
            editable = bool(field.get("editable"))

            combined = f"{field_name} {alias}".lower()

            if any(k in combined for k in XSS_SINK_FIELD_KEYWORDS):
                suspicious_fields.append({
                    "name": field.get("name"),
                    "alias": field.get("alias"),
                    "type": field.get("type"),
                    "editable": field.get("editable"),
                })

                if candidate_field is None and editable and field_type in text_types:
                    candidate_field = field_name

        if not suspicious_fields:
            return

        # Fallback: if no keyword-matched editable text field, choose first editable text field from suspicious set
        if candidate_field is None:
            for field in suspicious_fields:
                field_type = str(field.get("type") or "")
                editable = bool(field.get("editable"))
                if editable and field_type in text_types:
                    candidate_field = str(field.get("name") or "")
                    break

        object_id_field = meta.get("objectIdField") or "OBJECTID"
        manual_xss_test_payload = '<svg/onload=alert("XSS_TEST")>'

        manual_add_feature_test_command = None
        manual_query_created_object_command = None
        manual_cleanup_command = None

        if candidate_field:
            manual_add_feature_test_command = (
                f'curl -sk -X POST "{layer_url}/addFeatures" '
                f'-H "Content-Type: application/x-www-form-urlencoded" '
                f'--data-urlencode \'features=[{{"attributes":{{"{candidate_field}":"{manual_xss_test_payload}"}}}}]\' '
                f'--data-urlencode \'rollbackOnFailure=true\' '
                f'--data-urlencode \'f=json\''
            )

            manual_query_created_object_command = (
                f'curl -sk "{layer_url}/query?where={quote(str(object_id_field))}%3D<OBJECT_ID>&outFields=*&returnGeometry=false&f=json"'
            )

            manual_cleanup_command = (
                f'curl -sk -X POST "{layer_url}/deleteFeatures" '
                f'-H "Content-Type: application/x-www-form-urlencoded" '
                f'--data-urlencode \'objectIds=<OBJECT_ID>\' '
                f'--data-urlencode \'f=json\''
            )

        self.add_issue(
            title="Possible stored XSS sink in ArcGIS layer content",
            severity="medium",
            description="This ArcGIS layer appears to support both editing and querying, and it contains text-like fields that may later be rendered in popups, viewers, dashboards, or search/UI components. Manual validation is recommended to determine whether attacker-controlled content can become persistent script-bearing content.",
            evidence={
                "layer_url": layer_url,
                "capabilities": capabilities,
                "object_id_field": object_id_field,
                "suspicious_fields": suspicious_fields[:20],
                "candidate_field": candidate_field,
                "manual_xss_test_payload": manual_xss_test_payload if candidate_field else None,
                "manual_add_feature_test_command": manual_add_feature_test_command,
                "manual_query_created_object_command": manual_query_created_object_command,
                "manual_cleanup_command": manual_cleanup_command,
            },
            remediation="Review how layer attributes are rendered in ArcGIS popups, viewers, dashboards, and custom applications. Apply output encoding, enforce input validation where possible, and restrict or sanitize HTML/script content before storage or display.",
        )
                    
    def _check_query_injection(self, layer_url: str, meta: Dict[str, Any]) -> None:
        """
        Differential where-clause testing for possible unsafe query-expression handling.
        Runs only when active checks and query injection checks are enabled, and only
        against publicly queryable layers.
        """
        if not self.active_checks:
            return

        if not self.query_injection_checks:
            return

        capabilities = str(meta.get("capabilities") or "")
        supports_query = (
            "Query" in capabilities
            or bool((meta.get("advancedQueryCapabilities") or {}).get("supportsAdvancedQueries"))
        )

        if not supports_query:
            return

        object_id_field = meta.get("objectIdField") or "OBJECTID"

        try:
            # Step 1: get one real sample record to anchor the test
            baseline_obs = self.request(
                "GET",
                f"{layer_url}/query",
                params={
                    "where": "1=1",
                    "outFields": object_id_field,
                    "returnGeometry": "false",
                    "resultRecordCount": 1,
                    "f": "json",
                },
                expect_json=True,
                allow_redirects=True,
            )

            if baseline_obs.error or not isinstance(baseline_obs.json_body, dict):
                return

            baseline_body = baseline_obs.json_body
            if isinstance(baseline_body.get("error"), dict):
                return

            features = baseline_body.get("features") or []
            if not features:
                return

            attrs = features[0].get("attributes") or {}
            sample_object_id = attrs.get(object_id_field)
            if sample_object_id is None:
                return

            baseline_where = f"{object_id_field}={sample_object_id}"
            false_where = f"{object_id_field}={sample_object_id} AND 1=2"
            tautology_where = "1=1 OR 'x'='x'"

            def run_query(where_value: str) -> Dict[str, Any]:
                obs = self.request(
                    "GET",
                    f"{layer_url}/query",
                    params={
                        "where": where_value,
                        "outFields": "*",
                        "returnGeometry": "false",
                        "f": "json",
                    },
                    expect_json=True,
                    allow_redirects=True,
                )

                body = obs.json_body if isinstance(obs.json_body, dict) else {}
                feats = body.get("features") or []
                return {
                    "status_code": obs.status_code,
                    "content_length": obs.content_length,
                    "feature_count": len(feats),
                    "features": feats,
                    "body": body,
                    "error": body.get("error") if isinstance(body.get("error"), dict) else None,
                }

            baseline = run_query(baseline_where)

            if baseline.get("feature_count", 0) == 0:
                return

            # Verify the baseline object actually appears in the baseline results
            baseline_ids = [
                (f.get("attributes") or {}).get(object_id_field)
                for f in baseline.get("features", [])
            ]

            if sample_object_id not in baseline_ids:
                return

            false_test = run_query(false_where)
            tautology = run_query(tautology_where)

            # Check whether the tautology result set contains records beyond the baseline object
            tautology_ids = [
                (f.get("attributes") or {}).get(object_id_field)
                for f in tautology.get("features", [])
            ]

            bypassed_object_constraint = any(
                obj_id is not None and obj_id != sample_object_id
                for obj_id in tautology_ids
            )

            # If any test returned an ArcGIS error, don't force a finding
            if baseline["error"] or false_test["error"] or tautology["error"]:
                return

            baseline_count = baseline["feature_count"]
            false_count = false_test["feature_count"]
            tautology_count = tautology["feature_count"]

            suspicious = False
            reasons = []

            if baseline_count >= 1 and false_count == 0:
                reasons.append("False-condition query suppressed the baseline result set.")

            if tautology_count > baseline_count:
                suspicious = True
                reasons.append("Broad tautology query returned more records than the baseline constrained query.")

            if bypassed_object_constraint:
                suspicious = True
                reasons.append("Tautology query returned records with object IDs other than the baseline object, indicating the original object constraint was bypassed.")

            if (
                baseline["content_length"] is not None
                and false_test["content_length"] is not None
                and baseline["content_length"] > false_test["content_length"]
                and false_count == 0
            ):
                reasons.append("False-condition response body was materially smaller than baseline.")

            # Only raise a finding when the broadening behavior is observed
            if suspicious:
                sample_attributes = {}
                tautology_features = tautology.get("features") or []
                if tautology_features and isinstance(tautology_features[0], dict):
                    sample_attributes = (tautology_features[0].get("attributes") or {})

                self.add_issue(
                    title="Possible ArcGIS query expression injection",
                    severity="high",
                    description="A publicly reachable ArcGIS layer accepted crafted boolean expressions in the where parameter and returned materially broader results than a baseline constrained query.",
                    evidence={
                        "layer_url": layer_url,
                        "object_id_field": object_id_field,
                        "sample_object_id": sample_object_id,
                        "baseline_where": baseline_where,
                        "false_where": false_where,
                        "tautology_where": tautology_where,
                        "baseline_feature_count": baseline_count,
                        "false_feature_count": false_count,
                        "tautology_feature_count": tautology_count,
                        "baseline_content_length": baseline["content_length"],
                        "false_content_length": false_test["content_length"],
                        "tautology_content_length": tautology["content_length"],
                        "bypassed_object_constraint": bypassed_object_constraint,
                        "tautology_object_ids_sample": [x for x in tautology_ids[:20] if x is not None],
                        "reasons": reasons,
                        "sample_attributes": dict(list(sample_attributes.items())[:20]),
                        "baseline_command": f'curl -sk "{layer_url}/query?where={quote(baseline_where)}&outFields=*&returnGeometry=false&f=json"',
                        "false_test_command": f'curl -sk "{layer_url}/query?where={quote(false_where)}&outFields=*&returnGeometry=false&f=json"',
                        "tautology_test_command": f'curl -sk "{layer_url}/query?where={quote(tautology_where)}&outFields=*&returnGeometry=false&f=json"',
                    },
                    remediation="Validate and constrain user-supplied where-clause input, limit public query capability where not required, and review whether the layer should permit arbitrary boolean expressions from unauthenticated users.",
                )

        except Exception:
            pass
            
    def assess_version_risk(self) -> None:
        versions = self.findings.get("summary", {}).get("resolved_versions", [])
        if not versions:
            return
        version_risk: Dict[str, Any] = {}
        for version in versions:
            version_risk.setdefault("arcgis_server", []).append(
                {
                    "version": version,
                    "cve_details_url": VERSION_CVE_LINKS.get("arcgis_server", {}).get(version),
                    "fallback_search_url": FALLBACK_PRODUCT_SEARCH["arcgis_server"],
                }
            )
            version_risk.setdefault("portal_for_arcgis", []).append(
                {
                    "version": version,
                    "cve_details_url": VERSION_CVE_LINKS.get("portal_for_arcgis", {}).get(version),
                    "fallback_search_url": FALLBACK_PRODUCT_SEARCH["portal_for_arcgis"],
                }
            )
        self.findings["version_risk"] = version_risk

        for product, entries in version_risk.items():
            for entry in entries:
                if entry.get("cve_details_url"):
                    self.add_issue(
                        title="Detected ArcGIS version should be reviewed for published CVEs",
                        severity="informational",
                        description=f"Detected {product.replace('_', ' ')} version {entry['version']} has a mapped CVE reference page.",
                        evidence=entry,
                        remediation="Review vendor advisories and version-specific CVE references, then confirm the system is patched to the latest supported release.",
                        category="version_risk",
                    )
                else:
                    self.add_issue(
                        title="Detected ArcGIS version lacks an exact built-in CVE map",
                        severity="informational",
                        description=f"Detected {product.replace('_', ' ')} version {entry['version']} is not in the script's exact CVE map and requires manual review.",
                        evidence=entry,
                        remediation="Use the fallback product search URL and vendor advisories to review vulnerabilities relevant to this version.",
                        category="version_risk",
                    )
                    
    def _deduplicate_upload_findings(self) -> None:
        issues = self.findings.get("misconfigurations", {}).get("issues", [])
        if not issues:
            return

        has_high_upload_finding = any(
            issue.get("title") == "ArcGIS public file-upload attack surface exposed"
            and str(issue.get("severity", "")).lower() == "high"
            for issue in issues
        )

        if not has_high_upload_finding:
            return

        self.findings["misconfigurations"]["issues"] = [
            issue for issue in issues
            if issue.get("title") != "FeatureServer upload surface discovered"
        ]
        
    def build_report_ready_findings(self) -> None:
        findings_out: List[Dict[str, Any]] = []
        discovery = self.findings.get("discovery", {}).get("resolved", {})
        summary = self.findings.get("summary", {})
        services = self.findings.get("rest", {}).get("services", [])

        if discovery.get("login_portals"):
            findings_out.append(
                {
                    "title": "Exposed ArcGIS login and management surface",
                    "severity": "informational",
                    "narrative": "Multiple ArcGIS login, token, or management-related endpoints were reachable from the target. Even when authentication is required, the exposed surface can help an external tester identify product components, authentication workflows, and potential attack paths for follow-on review.",
                    "evidence": discovery.get("login_portals"),
                }
            )

        if summary.get("service_count", 0) > 0:
            public_services = [{"name": s.get("name"), "type": s.get("type"), "url": s.get("url")} for s in services]
            findings_out.append(
                {
                    "title": "ArcGIS REST service enumeration available",
                    "severity": "informational",
                    "narrative": "The ArcGIS REST catalog exposed folder and service metadata that allowed remote enumeration of published services. This can assist attackers in mapping business functions, geospatial data exposure, and application integration points.",
                    "evidence": {
                        "folder_count": summary.get("folder_count", 0),
                        "service_count": summary.get("service_count", 0),
                        "services": public_services[:100],
                    },
                }
            )

        queryable = summary.get("queryable_services", [])
        if queryable:
            findings_out.append(
                {
                    "title": "Queryable services identified",
                    "severity": "informational",
                    "narrative": "One or more services advertised query-related capabilities. Publicly reachable query functionality may increase data exposure and can warrant deeper review of attribute filtering, object access rules, and rate-limiting.",
                    "evidence": queryable,
                }
            )

        editable = summary.get("editable_services", [])
        if editable:
            findings_out.append(
                {
                    "title": "Editable services identified",
                    "severity": "medium",
                    "narrative": "One or more services advertised editing-related capabilities. If these services are reachable without the intended access controls, they may permit unauthorized data creation, modification, deletion, or abuse of related upload workflows.",
                    "evidence": editable,
                }
            )

        for issue in self.findings.get("misconfigurations", {}).get("issues", []):
            if issue.get("severity") == "info" and issue.get("title") != "ArcGIS Version Information Disclosure":
                continue
            findings_out.append(
                {
                    "title": issue.get("title"),
                    "severity": issue.get("severity"),
                    "narrative": issue.get("description"),
                    "evidence": issue.get("evidence"),
                    "remediation": issue.get("remediation"),
                }
            )

        self.findings["report_ready_findings"] = findings_out

    def build_summary(self) -> None:
        summary: Dict[str, Any] = {}
        rest = self.findings.get("rest", {})
        catalog_root = rest.get("catalog_root", {})
        services = rest.get("services", [])
        service_counter = Counter(s.get("type") for s in services if s.get("type"))
        layer_count = 0
        table_count = 0
        editable_services = []
        queryable_services = []
        versions = set()
        services_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        if catalog_root.get("currentVersion") is not None:
            versions.add(str(catalog_root.get("currentVersion")))
        rest_info = rest.get("info", {})
        if rest_info.get("currentVersion") is not None:
            versions.add(str(rest_info.get("currentVersion")))
        portal = self.findings.get("portal", {})
        if portal.get("self", {}).get("currentVersion") is not None:
            versions.add(str(portal["self"].get("currentVersion")))

        for svc in services:
            rel = svc.get("relationships") or {}
            entry = {"name": svc.get("name"), "url": svc.get("url")}
            services_by_type[svc.get("type") or "Unknown"].append(entry)
            if rel.get("supports_editing"):
                editable_services.append(entry)
            if rel.get("supports_query"):
                queryable_services.append(entry)
            layers = (svc.get("layers") or {}).get("layers", [])
            tables = (svc.get("layers") or {}).get("tables", [])
            layer_count += len(layers)
            table_count += len(tables)

        summary.update(
            {
                "resolved_versions": sorted(versions),
                "folder_count": len(catalog_root.get("folders", []) or []),
                "folders": [{"name": f.get("name"), "url": f.get("url"), "service_count": len(f.get("services") or []), "error": f.get("error")} for f in rest.get("folders", [])],
                "service_count": len(services),
                "service_types": dict(service_counter),
                "services_by_type": dict(services_by_type),
                "layer_count": layer_count,
                "table_count": table_count,
                "queryable_service_count": len(queryable_services),
                "editable_service_count": len(editable_services),
                "queryable_services": sorted(queryable_services, key=lambda x: x["name"] or "")[:100],
                "editable_services": sorted(editable_services, key=lambda x: x["name"] or "")[:100],
                "login_surface_count": len(self.findings.get("discovery", {}).get("resolved", {}).get("login_portals", [])),
                "misconfiguration_issue_count": len([i for i in self.findings.get("misconfigurations", {}).get("issues", []) if i.get("category") == "misconfiguration"]),
                "misconfiguration_severities": dict(Counter(i.get("severity") for i in self.findings.get("misconfigurations", {}).get("issues", []) if i.get("category") == "misconfiguration")),
                "error_count": len(self.findings.get("errors", [])),
            }
        )
        self.findings["summary"] = summary

    def run(self) -> Dict[str, Any]:
        self.log_stage("Probing common ArcGIS paths...")
        discovered = self.probe_common_paths()

        self.log_stage("Capturing HTTP fingerprint...")
        self.capture_http_fingerprint(discovered)

        self.log_stage("Capturing TLS fingerprint...")
        self.capture_tls_fingerprint(discovered)

        self.log_stage("Enumerating REST services and layers...")
        self.enumerate_rest(discovered)

        self.log_stage("Enumerating portal information...")
        self.enumerate_portal(discovered)

        self.log_stage("Enumerating admin endpoints...")
        self.enumerate_admin(discovered)

        self.log_stage("Building summary...")
        self.build_summary()
        
        if self.active_checks and self.query_injection_checks:
            self.log_stage("Query injection checks enabled...")
        
        if self.active_checks and self.xss_checks:
            self.log_stage("Reflected XSS checks enabled...")
            
        if self.active_checks and self.ssrf_test_url:
            self.log_stage("SSRF checks enabled...")

        self.log_stage("Assessing misconfigurations...")
        self.assess_misconfigurations(discovered)

        self.log_stage("Refreshing summary...")
        self.build_summary()
        
        self._add_arcgis_version_findings()

        self.log_stage("Assessing version risk...")
        self.assess_version_risk()
        
        self._deduplicate_upload_findings()

        self.log_stage("Building report-ready findings...")
        self.build_report_ready_findings()

        self.log_stage("Scan complete.")
        return self.findings

def colorize_severity(severity: str) -> str:
    s = (severity or "").lower()

    colors = {
        "high": "\033[91m",
        "medium": "\033[38;5;214m",
        "low": "\033[94m",
        "informational": "\033[90m",
    }

    reset = "\033[0m"
    color = colors.get(s, "")
    return f"{color}{s.upper()}{reset}"

def print_startup_banner(auditor, args):
    line = "=" * 58

    mode = "ACTIVE" if auditor.active_checks else "PASSIVE"
    mode_msg = (
        "intrusive testing enabled"
        if auditor.active_checks
        else "passive checks only"
    )

    xss_enabled = auditor.active_checks and auditor.xss_checks
    query_injection_enabled = auditor.active_checks and auditor.query_injection_checks
    ssrf_enabled = auditor.active_checks and bool(auditor.ssrf_test_url)

    features = [
        f"XSS={'ON' if xss_enabled else 'OFF'}",
        f"QueryInjection={'ON' if query_injection_enabled else 'OFF'}",
        f"SSRF={'ON' if ssrf_enabled else 'OFF'}",
    ]

    print(f"\n[ArcGISAudit] {line}")
    print(f"[ArcGISAudit] Target: {auditor.base_url}")
    print(f"[ArcGISAudit] Mode: {mode} ({mode_msg})")
    print(f"[ArcGISAudit] Features: {' | '.join(features)}")

    if args.insecure:
        print(f"[ArcGISAudit] TLS Verification: DISABLED")

    if args.username:
        print(f"[ArcGISAudit] Auth Mode: Username/Password")
    
    if getattr(args, "all", False):
        print(f"[ArcGISAudit] Mode: FULL SCAN (--all enabled)")

    print(f"[ArcGISAudit] {line}\n")
    
def print_logo() -> None:
    logo = r"""
    █████╗ ██████╗  ██████╗  ██████╗ ██╗███████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗
   ██╔══██╗██╔══██╗██╔════╝ ██╔════╝ ██║██╔════╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
   ███████║██████╔╝██║      ██║  ███╗██║███████╗███████║██║   ██║██║  ██║██║   ██║
   ██╔══██║██╔══██╗██║      ██║   ██║██║╚════██║██╔══██║██║   ██║██║  ██║██║   ██║
   ██║  ██║██║  ██║╚██████╗ ╚██████╔╝██║███████║██║  ██║╚██████╔╝██████╔╝██║   ██║
   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
    """
    print("\033[96m" + logo + "\033[0m")
    print("[ArcGISAudit] v1.0 | by clayhax")
        
def write_outputs(findings: Dict[str, Any], out_prefix: Path) -> Tuple[Path, Path]:
    json_path = out_prefix.with_suffix(".json")
    txt_path = out_prefix.with_suffix(".txt")
    json_path.write_text(json.dumps(findings, indent=2, sort_keys=True), encoding="utf-8")

    s = findings.get("summary", {})
    discovery = findings.get("discovery", {}).get("resolved", {})
    lines = [
        f"Target: {findings.get('target')}",
        f"Timestamp (UTC): {findings.get('timestamp_utc')}",
        "",
        "[Resolved Endpoints]",
        f"Catalog: {discovery.get('catalog')}",
        f"REST Info: {discovery.get('rest_info')}",
        f"Admin Root: {discovery.get('admin_root')}",
        f"Sharing Root: {discovery.get('sharing_root')}",
        f"PortalAdmin Root: {discovery.get('portaladmin_root')}",
        "",
        "[Summary]",
        f"Versions: {', '.join(s.get('resolved_versions', [])) or 'N/A'}",
        f"Folders: {s.get('folder_count', 0)}",
        f"Services: {s.get('service_count', 0)}",
        f"Layers: {s.get('layer_count', 0)}",
        f"Tables: {s.get('table_count', 0)}",
        f"Queryable Services: {s.get('queryable_service_count', 0)}",
        f"Editable Services: {s.get('editable_service_count', 0)}",
        f"Login Surfaces: {s.get('login_surface_count', 0)}",
        f"Misconfiguration Issues: {s.get('misconfiguration_issue_count', 0)}",
        f"Errors: {s.get('error_count', 0)}",
        "",
        "[Folders]",
    ]

    for folder in s.get("folders", []):
        lines.append(f"- {folder.get('name')}: {folder.get('url')} (services={folder.get('service_count', 0)})")
        if folder.get("error"):
            lines.append(f"  error: {folder.get('error')}")

    lines.extend(["", "[Service Types]"])
    for svc_type, count in sorted((s.get("service_types") or {}).items()):
        lines.append(f"- {svc_type}: {count}")
        for entry in s.get("services_by_type", {}).get(svc_type, []):
            lines.append(f"  - {entry.get('name')}: {entry.get('url')}")

    lines.extend(["", "[Queryable Services]"])
    for entry in s.get("queryable_services", []):
        lines.append(f"- {entry.get('name')}: {entry.get('url')}")

    lines.extend(["", "[Editable Services]"])
    for entry in s.get("editable_services", []):
        lines.append(f"- {entry.get('name')}: {entry.get('url')}")

    lines.extend(["", "[Login Surfaces]"])
    for item in discovery.get("login_portals", []):
        lines.append(f"- {item.get('url')} (status={item.get('status_code')}, title={item.get('title')})")

    lines.extend(["", "[Version Risk]"])
    for product, items in findings.get("version_risk", {}).items():
        for item in items:
            if item.get("cve_details_url"):
                lines.append(f"- {product} {item.get('version')} -> {item.get('cve_details_url')}")
            else:
                lines.append(f"- {product} {item.get('version')} -> no exact map, fallback: {item.get('fallback_search_url')}")
    
    lines.extend(["", "[Version Information Disclosure]"])
    for issue in findings.get("misconfigurations", {}).get("issues", []):
        if issue.get("title") != "ArcGIS Version Information Disclosure":
            continue
        ev = issue.get("evidence") or {}
        lines.append(f"- [INFO] {issue.get('title')}: {issue.get('description')}")
        if ev.get("version"):
            lines.append(f"  version: {ev.get('version')}")
        if ev.get("detected_at_urls"):
            for detected_url in ev.get("detected_at_urls", []):
                lines.append(f"  detected_at_url: {detected_url}")
        if ev.get("release_date"):
            lines.append(f"  release_date: {ev.get('release_date')}")
        if ev.get("mature_start"):
            lines.append(f"  mature_start: {ev.get('mature_start')}")

    lines.extend(["", "[Misconfiguration Issues]"])

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    sorted_issues = sorted(
       [
           issue
           for issue in findings.get("misconfigurations", {}).get("issues", [])
           if issue.get("category") == "misconfiguration"
       ],
       key=lambda issue: (
           severity_order.get(str(issue.get("severity", "")).lower(), 99),
           str(issue.get("title", "")).lower(),
       ),
    )

    prev_severity = None

    for issue in sorted_issues:
        severity = str(issue.get("severity", "")).lower()

        if prev_severity and severity != prev_severity:
            lines.append("")  # blank line between severity groups

        sev_display = colorize_severity(severity)
        lines.append(f"- [{sev_display}] {issue.get('title')}: {issue.get('description')}")

        ev = issue.get("evidence") or {}
        
        if ev.get("version"):
            lines.append(f"  version: {ev.get('version')}")
        if ev.get("detected_at_urls"):
            for detected_url in ev.get("detected_at_urls", []):
                lines.append(f"  detected_at_url: {detected_url}")
        if ev.get("release_date"):
            lines.append(f"  release_date: {ev.get('release_date')}")
        if ev.get("mature_start"):
            lines.append(f"  mature_start: {ev.get('mature_start')}")
        if ev.get("url"):
            lines.append(f"  url: {ev.get('url')}")
        if ev.get("service_url"):
            lines.append(f"  service_url: {ev.get('service_url')}")
        if ev.get("layer_url"):
            lines.append(f"  layer_url: {ev.get('layer_url')}")
        if ev.get("layer_name"):
            lines.append(f"  layer_name: {ev.get('layer_name')}")
        if ev.get("edit_url"):
            lines.append(f"  edit_url: {ev.get('edit_url')}")
        if ev.get("capabilities"):
            lines.append(f"  capabilities: {ev.get('capabilities')}")
        if ev.get("record_count") is not None:
            lines.append(f"  record_count: {ev.get('record_count')}")
        if ev.get("object_id_field"):
            lines.append(f"  object_id_field: {ev.get('object_id_field')}")
        if ev.get("field_names"):
            lines.append(f"  field_names: {', '.join(ev.get('field_names')[:20])}")
        if ev.get("matched_sensitive_fields"):
            lines.append(f"  matched_sensitive_fields: {json.dumps(ev.get('matched_sensitive_fields'), sort_keys=True)[:300]}")
        if ev.get("public_item_count") is not None:
            lines.append(f"  public_item_count: {ev.get('public_item_count')}")
        if ev.get("downloadable_count") is not None:
            lines.append(f"  downloadable_count: {ev.get('downloadable_count')}")
        if ev.get("returned_results") is not None:
            lines.append(f"  returned_results: {ev.get('returned_results')}")
        if ev.get("request_client"):
            lines.append(f"  request_client: {ev.get('request_client')}")
        if ev.get("token_prefix"):
            lines.append(f"  token_prefix: {ev.get('token_prefix')}")
        if ev.get("expires") is not None:
            lines.append(f"  expires: {ev.get('expires')}")
        if ev.get("uploads_url"):
            lines.append(f"  uploads_url: {ev.get('uploads_url')}")
        if ev.get("upload_probe_command"):
            lines.append(f"  upload_probe_command: {ev.get('upload_probe_command')}")
        if ev.get("add_attachment_probe_command"):
            lines.append(f"  add_attachment_probe_command: {ev.get('add_attachment_probe_command')}")
        if ev.get("sample_add_attachment_endpoint"):
            lines.append(f"  sample_add_attachment_endpoint: {ev.get('sample_add_attachment_endpoint')}")
        if ev.get("manual_upload_test_command"):
            lines.append("  manual_upload_test_command:")
            lines.append(f"    {ev.get('manual_upload_test_command')}")
        if ev.get("confidence"):
            lines.append(f"  confidence: {ev.get('confidence')}")
        if ev.get("reason"):
            lines.append(f"  reason: {ev.get('reason')}")
        if ev.get("request_origin"):
            lines.append(f"  request_origin: {ev.get('request_origin')}")
        if ev.get("access_control_allow_origin"):
            lines.append(f"  access_control_allow_origin: {ev.get('access_control_allow_origin')}")
        if ev.get("access_control_allow_credentials"):
            lines.append(f"  access_control_allow_credentials: {ev.get('access_control_allow_credentials')}")
        if ev.get("location"):
            lines.append(f"  location: {ev.get('location')}")
        if ev.get("candidate_username"):
            lines.append(f"  candidate_username: {ev.get('candidate_username')}")
            lines.append(f"  enumeration_endpoint: {ev.get('base_url')}{ev.get('candidate_username')}?f=pjson")
        if ev.get("nonexistent_username"):
            lines.append(f"  nonexistent_username: {ev.get('nonexistent_username')}")
        if ev.get("keys"):
            lines.append(f"  keys: {', '.join(ev.get('keys')[:20])}")
        if ev.get("reflection_style"):
            lines.append(f"  reflection_style: {ev.get('reflection_style')}")
        if ev.get("reflection_context"):
            lines.append(f"  reflection_context: {ev.get('reflection_context')[:300]}")
        if ev.get("parameter"):
            lines.append(f"  parameter: {ev.get('parameter')}")
        if ev.get("method"):
            lines.append(f"  method: {ev.get('method')}")
        if ev.get("payload_variant"):
            lines.append(f"  payload_variant: {ev.get('payload_variant')}")
        if ev.get("payload"):
            lines.append(f"  payload: {ev.get('payload')}")
        if ev.get("candidate_field"):
            lines.append(f"  candidate_field: {ev.get('candidate_field')}")
        if ev.get("manual_xss_test_payload"):
            lines.append(f"  manual_xss_test_payload: {ev.get('manual_xss_test_payload')}")
        if ev.get("manual_add_feature_test_command"):
            lines.append("  manual_add_feature_test_command:")
            lines.append(f"    {ev.get('manual_add_feature_test_command')}")
        if ev.get("manual_query_created_object_command"):
            lines.append("  manual_query_created_object_command:")
            lines.append(f"    {ev.get('manual_query_created_object_command')}")
        if ev.get("manual_cleanup_command"):
            lines.append("  manual_cleanup_command:")
            lines.append(f"    {ev.get('manual_cleanup_command')}")
        if ev.get("content_type"):
            lines.append(f"  content_type: {ev.get('content_type')}")
        if ev.get("response"):
            response_text = ev.get("response")
            if not isinstance(response_text, str):
                response_text = json.dumps(response_text, sort_keys=True)
            lines.append(f"  response: {response_text[:300]}")
        preview = ev.get("body_preview") or ev.get("response") or ev.get("candidate_response") or ev.get("sample_attributes") or ev.get("items")
        if preview:
            preview_text = preview if isinstance(preview, str) else json.dumps(preview, sort_keys=True)
            lines.append(f"  evidence_preview: {preview_text[:300]}")
        if issue.get("remediation"):
            lines.append(f"  remediation: {issue.get('remediation')}")
        if ev.get("variant_results"):
            lines.append(f"  variant_results: {json.dumps(ev.get('variant_results'), sort_keys=True)[:300]}")
        if ev.get("suspicious_variants"):
            lines.append(f"  suspicious_variants: {json.dumps(ev.get('suspicious_variants'), sort_keys=True)[:300]}")
        if ev.get("count_test_command"):
            lines.append(f"  count_test_command: {ev.get('count_test_command')}")
        if ev.get("sample_test_command"):
            lines.append(f"  sample_test_command: {ev.get('sample_test_command')}")
        if ev.get("field_test_command"):
            lines.append(f"  field_test_command: {ev.get('field_test_command')}")
        if ev.get("validation_command"):
            lines.append(f"  validation_command: {ev.get('validation_command')}")
        if ev.get("proof_command"):
            lines.append(f"  add_feature_proof_command: {ev.get('proof_command')}")
        if ev.get("query_created_object_command"):
            lines.append(f"  query_created_object_command: {ev.get('query_created_object_command')}")
        if ev.get("cleanup_created_object_command"):
            lines.append(f"  cleanup_created_object_command: {ev.get('cleanup_created_object_command')}")
        if ev.get("attachment_name"):
            lines.append(f"  attachment_name: {ev.get('attachment_name')}")
        if ev.get("attachment_content_type"):
            lines.append(f"  attachment_content_type: {ev.get('attachment_content_type')}")
        if ev.get("attachment_size") is not None:
            lines.append(f"  attachment_size: {ev.get('attachment_size')}")
        if ev.get("download_url"):
            lines.append(f"  download_url: {ev.get('download_url')}")
        if ev.get("tested_object_ids"):
            lines.append(f"  tested_object_ids: {', '.join(str(x) for x in ev.get('tested_object_ids')[:10])}")
        if ev.get("attachment_query_command"):
            lines.append(f"  attachment_query_command: {ev.get('attachment_query_command')}")
        if ev.get("enumeration_command"):
            lines.append(f"  enumeration_command: {ev.get('enumeration_command')}")
        if ev.get("download_command"):
            lines.append(f"  download_command: {ev.get('download_command')}")
        if ev.get("sample_object_id") is not None:
            lines.append(f"  sample_object_id: {ev.get('sample_object_id')}")
        if ev.get("baseline_where"):
            lines.append(f"  baseline_where: {ev.get('baseline_where')}")
        if ev.get("false_where"):
            lines.append(f"  false_where: {ev.get('false_where')}")
        if ev.get("tautology_where"):
            lines.append(f"  tautology_where: {ev.get('tautology_where')}")
        if ev.get("baseline_feature_count") is not None:
            lines.append(f"  baseline_feature_count: {ev.get('baseline_feature_count')}")
        if ev.get("false_feature_count") is not None:
            lines.append(f"  false_feature_count: {ev.get('false_feature_count')}")
        if ev.get("tautology_feature_count") is not None:
            lines.append(f"  tautology_feature_count: {ev.get('tautology_feature_count')}")
        if ev.get("baseline_content_length") is not None:
            lines.append(f"  baseline_content_length: {ev.get('baseline_content_length')}")
        if ev.get("false_content_length") is not None:
            lines.append(f"  false_content_length: {ev.get('false_content_length')}")
        if ev.get("tautology_content_length") is not None:
            lines.append(f"  tautology_content_length: {ev.get('tautology_content_length')}")
        if ev.get("reasons"):
            lines.append(f"  reasons: {'; '.join(ev.get('reasons')[:5])}")
        if ev.get("baseline_command"):
            lines.append(f"  baseline_command: {ev.get('baseline_command')}")
        if ev.get("false_test_command"):
            lines.append(f"  false_test_command: {ev.get('false_test_command')}")
        if ev.get("tautology_test_command"):
            lines.append(f"  tautology_test_command: {ev.get('tautology_test_command')}")
        if ev.get("bypassed_object_constraint") is not None:
            lines.append(f"  bypassed_object_constraint: {ev.get('bypassed_object_constraint')}")
        if ev.get("tautology_object_ids_sample"):
            lines.append(f"  tautology_object_ids_sample: {', '.join(str(x) for x in ev.get('tautology_object_ids_sample')[:20])}")
        if ev.get("add_attachment_url"):
            lines.append(f"  add_attachment_url: {ev.get('add_attachment_url')}")
        if ev.get("has_attachments") is not None:
            lines.append(f"  has_attachments: {ev.get('has_attachments')}")
        if ev.get("error_code") is not None:
            lines.append(f"  error_code: {ev.get('error_code')}")
        if ev.get("error_message"):
            lines.append(f"  error_message: {ev.get('error_message')}")
        if ev.get("probe_command"):
            lines.append(f"  probe_command: {ev.get('probe_command')}")
        if ev.get("supports_editing") is not None:
            lines.append(f"  supports_editing: {ev.get('supports_editing')}")
        if ev.get("upload_capability") is not None:
            lines.append(f"  upload_capability: {ev.get('upload_capability')}")
        if ev.get("upload_endpoint_exposed") is not None:
            lines.append(f"  upload_endpoint_exposed: {ev.get('upload_endpoint_exposed')}")
        if ev.get("attachment_layer_count") is not None:
            lines.append(f"  attachment_layer_count: {ev.get('attachment_layer_count')}")
        if ev.get("add_attachment_layer_count") is not None:
            lines.append(f"  add_attachment_layer_count: {ev.get('add_attachment_layer_count')}")
        if ev.get("attachment_layers"):
            lines.append(f"  attachment_layers: {json.dumps(ev.get('attachment_layers'), sort_keys=True)[:300]}")
        if ev.get("add_attachment_layers"):
            lines.append(f"  add_attachment_layers: {json.dumps(ev.get('add_attachment_layers'), sort_keys=True)[:300]}")
        if ev.get("edit_method"):
            lines.append(f"  edit_method: {ev.get('edit_method')}")
        if ev.get("created_object_id") is not None:
            lines.append(f"  created_object_id: {ev.get('created_object_id')}")
        if ev.get("verification_attempted") is not None:
            lines.append(f"  verification_attempted: {ev.get('verification_attempted')}")
        if ev.get("verification_success") is not None:
            lines.append(f"  verification_success: {ev.get('verification_success')}")
        if ev.get("verification_status_code") is not None:
            lines.append(f"  verification_status_code: {ev.get('verification_status_code')}")
        if ev.get("verification_error"):
            lines.append(f"  verification_error: {ev.get('verification_error')}")
        if ev.get("verification_command"):
            lines.append(f"  verification_command: {ev.get('verification_command')}")
        if ev.get("cleanup_attempted") is not None:
            lines.append(f"  cleanup_attempted: {ev.get('cleanup_attempted')}")
        if ev.get("cleanup_success") is not None:
            lines.append(f"  cleanup_success: {ev.get('cleanup_success')}")
        if ev.get("cleanup_status_code") is not None:
            lines.append(f"  cleanup_status_code: {ev.get('cleanup_status_code')}")
        if ev.get("cleanup_error"):
            lines.append(f"  cleanup_error: {ev.get('cleanup_error')}")
        if ev.get("cleanup_command"):
            lines.append(f"  cleanup_command: {ev.get('cleanup_command')}")
        if ev.get("verification_response"):
            verification_text = ev.get("verification_response")
            if not isinstance(verification_text, str):
                verification_text = json.dumps(verification_text, sort_keys=True)
            lines.append(f"  verification_response: {verification_text[:300]}")
        if ev.get("cleanup_response"):
            cleanup_text = ev.get("cleanup_response")
            if not isinstance(cleanup_text, str):
                cleanup_text = json.dumps(cleanup_text, sort_keys=True)
            lines.append(f"  cleanup_response: {cleanup_text[:300]}")

        lines.append("")  # blank line between each issue
        prev_severity = severity

    lines.extend(["", "[Report-Ready Findings]"])

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4,
        "info": 4,
    }

    # Collapse duplicate report-ready findings into a single entry with a count
    grouped = {}

    for finding in findings.get("report_ready_findings", []):
        severity = str(finding.get("severity", "")).lower()
        title = finding.get("title")
        narrative = finding.get("narrative")
        evidence = finding.get("evidence") or {}

        # Normalize duplicate CVE-review findings so ArcGIS Server / Portal versions
        if title == "Detected ArcGIS version should be reviewed for published CVEs":
            title = "Detected ArcGIS version should be reviewed for published CVEs"
            narrative = "Detected ArcGIS Server and/or Portal versions have mapped public CVE reference pages and should be reviewed for known vulnerabilities."
            key = (severity, title, narrative)
        else:
            key = (severity, title, narrative)

        if key not in grouped:
            grouped[key] = {
                "severity": severity,
                "title": title,
                "narrative": narrative,
                "count": 0,
            }

        grouped[key]["count"] += 1

    sorted_findings = sorted(
        grouped.values(),
        key=lambda f: (
            severity_order.get(f["severity"], 99),
            str(f["title"]).lower(),
        ),
    )

    prev_severity = None

    for finding in sorted_findings:
        severity = finding["severity"]

        if prev_severity and severity != prev_severity:
            lines.append("")

        sev_display = colorize_severity(severity)
        lines.append(f"- [{sev_display}] {finding['title']} (count: {finding['count']})")
        lines.append(f"  narrative: {finding['narrative']}")
        lines.append("")

        prev_severity = severity

    if findings.get("errors"):
        lines.extend(["", "[Errors]"])
        for err in findings["errors"][:100]:
            lines.append(f"- {err}")

    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    output_text = "\n".join(lines)

    # Print to terminal (with color)
    print(output_text)

    return json_path, txt_path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Comprehensive ArcGIS Server / ArcGIS Enterprise reconnaissance tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              python3 arcgis_audit.py https://target.example.com/arcgis
              python3 arcgis_audit.py https://target.example.com/arcgis --all
              python3 arcgis_audit.py https://target.example.com --threads 20 --out arcgis_recon
              python3 arcgis_audit.py https://target.example.com/arcgis --active-checks --ssrf-test-url https://example.com/
              python3 arcgis_audit.py https://target.example.com/arcgis --xss-checks
              python3 arcgis_audit.py https://target.example.com/arcgis --active-checks --xss-checks --query-injection-checks
              python3 arcgis_audit.py https://target.example.com/arcgis --admin-mode --username admin --password 'Secret123!'
            """
        ),
    )
    p.add_argument("target", help="ArcGIS target URL, host, or web adaptor base")
    p.add_argument("--username", help="ArcGIS / portal username for token generation")
    p.add_argument("--password", help="ArcGIS / portal password for token generation")
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Concurrent worker count (default: 12)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout in seconds (default: 15)")
    p.add_argument("--out", default="arcgis_audit_report", help="Output prefix (default: arcgis_audit_report)")
    p.add_argument("--max-services", type=int, default=None, help="Cap number of services to enumerate")
    p.add_argument("--max-layers-per-service", type=int, default=None, help="Cap number of layers/tables fetched per service")
    p.add_argument("--admin-mode", action="store_true", help="Attempt admin API enumeration when credentials allow it")
    p.add_argument("--active-checks", action="store_true", help="Enable light-touch active checks such as proxy behavior validation")
    p.add_argument("--ssrf-test-url", default="https://example.com/", help="Harmless URL used during proxy validation when --active-checks is enabled")
    p.add_argument("--xss-checks", action="store_true", help="Enable low-impact reflected XSS canary checks on selected login-like endpoints")
    p.add_argument("--query-injection-checks", action="store_true", help="Enable differential ArcGIS where-clause injection checks on publicly queryable layers")
    p.add_argument("--insecure", action="store_true", help="Disable TLS certificate validation")
    p.add_argument(
        "--all",
        action="store_true",
        help="Enable all checks (active, XSS, query injection, SSRF with default URL)",
    )
    return p.parse_args()


def main() -> int:
    start = time.time()
    args = parse_args()
    if args.all:
        args.active_checks = True
        args.xss_checks = True
        args.query_injection_checks = True

        # Only set SSRF default if user didn't provide one
        if not args.ssrf_test_url:
            args.ssrf_test_url = "http://example.com"
    auditor = ArcGISAuditor(
        base_url=args.target,
        username=args.username,
        password=args.password,
        verify_ssl=not args.insecure,
        timeout=args.timeout,
        threads=max(1, args.threads),
        max_services=args.max_services,
        max_layers_per_service=args.max_layers_per_service,
        admin_mode=args.admin_mode,
        active_checks=args.active_checks,
        ssrf_test_url=args.ssrf_test_url,
        xss_checks=args.xss_checks,
        query_injection_checks=args.query_injection_checks,
    )

    print_logo()
    print_startup_banner(auditor, args)
    print(f"[ArcGISAudit] Using base URL: {auditor.base_url}")

    platform = auditor.platform

    if platform.get("server"):
        version = platform.get("version")
        if version:
            print(f"[ArcGISAudit] Detected ArcGIS Server {version}")
        else:
            print("[ArcGISAudit] Detected ArcGIS Server")

    if platform.get("portal"):
        print("[ArcGISAudit] Portal detected")

    if platform.get("web_adaptor"):
        print(f"[ArcGISAudit] Web Adaptor path: /{platform['web_adaptor']}")

    print()

    findings = auditor.run()
    json_path, txt_path = write_outputs(findings, Path(args.out))

    print(f"[ArcGISAudit] Scan finished in {time.time() - start:.1f}s", flush=True)
    print()
    print(f"[+] JSON report written to: {json_path}")
    print(f"[+] Text summary written to: {txt_path}")
    print()
    print("[+] Summary:")
    print(json.dumps(findings.get("summary", {}), indent=2))
    if findings.get("errors"):
        print(f"[!] Encountered {len(findings['errors'])} non-fatal errors. Review the JSON report for details.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
