#!/usr/bin/env python3
"""RSSから情報流出関連の記事候補を収集する。自動収集結果は未確認として掲載する。"""
import json, re, urllib.request, urllib.error, xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlparse, urlunparse

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
JST = timezone(timedelta(hours=9))
KEYWORDS = re.compile(r"情報流出|流出|漏えい|漏洩|不正アクセス|サイバー攻撃|ランサム|data breach|cyberattack|ransomware|leak|exposed", re.I)
ORG_HINTS = re.compile(r"(.{2,60}?)", re.S)

def get_text(node, path):
    found = node.find(path)
    return (found.text or "").strip() if found is not None else ""

def normalize_url(url):
    try:
        p = urlparse(url.strip())
        if p.scheme not in ("http", "https") or not p.netloc:
            return ""
        # Keep query strings because some news redirect links need them.
        return urlunparse((p.scheme, p.netloc.lower(), p.path, "", p.query, ""))
    except Exception:
        return ""

def parse_date(raw):
    if not raw:
        return ""
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(JST).date().isoformat()
    except Exception:
        return ""

def fetch_feed(feed):
    req = urllib.request.Request(feed["url"], headers={"User-Agent": "InfoLeakChecker/1.0 (public RSS reader)"})
    with urllib.request.urlopen(req, timeout=25) as response:
        body = response.read(5_000_000)
    root = ET.fromstring(body)
    results = []
    # RSS 2.0 and Atom
    for item in root.findall(".//item"):
        title = get_text(item, "title")
        link = get_text(item, "link")
        description = re.sub(r"<[^>]+>", " ", get_text(item, "description"))
        pub = parse_date(get_text(item, "pubDate"))
        results.append((title, link, description, pub))
    ns = {"a": "http://www.w3.org/2005/Atom"}
    for entry in root.findall(".//a:entry", ns):
        title = get_text(entry, "a:title")
        link = ""
        for l in entry.findall("a:link", ns):
            href = l.attrib.get("href", "")
            if href and l.attrib.get("rel", "alternate") == "alternate":
                link = href
                break
        desc = get_text(entry, "a:summary") or get_text(entry, "a:content")
        rawdate = get_text(entry, "a:published") or get_text(entry, "a:updated")
        pub = ""
        if rawdate:
            try: pub = datetime.fromisoformat(rawdate.replace("Z", "+00:00")).astimezone(JST).date().isoformat()
            except Exception: pass
        results.append((title, link, re.sub(r"<[^>]+>", " ", desc), pub))
    return results

def main():
    sources = json.loads((DATA / "sources.json").read_text(encoding="utf-8"))
    previous = json.loads((DATA / "incidents.json").read_text(encoding="utf-8"))
    old = previous.get("incidents", [])
    by_url = {normalize_url(x.get("source_url", "")): x for x in old if normalize_url(x.get("source_url", ""))}
    today = datetime.now(JST).date().isoformat()
    added = 0
    for feed in sources.get("feeds", []):
        try:
            entries = fetch_feed(feed)
            print(f'Fetched {len(entries)} entries from {feed["name"]}')
        except Exception as exc:
            print(f'WARN: failed feed {feed["name"]}: {exc}')
            continue
        for title, url, description, pub in entries:
            url = normalize_url(url)
            if not title or not url or not KEYWORDS.search(title + " " + description):
                continue
            if url in by_url:
                by_url[url]["last_checked"] = today
                continue
            # RSS search results are discovery candidates, never automatic confirmation.
            clean_title = re.sub(r"\s+", " ", title).strip()
            summary = re.sub(r"\s+", " ", description).strip()
            summary = re.sub(r"&nbsp;|&amp;|&quot;|&#39;", " ", summary)
            if len(summary) > 280:
                summary = summary[:277] + "…"
            item = {
                "id": re.sub(r"[^a-z0-9]+", "-", url.lower())[-90:].strip("-") or f"candidate-{added}",
                "organization": "記事本文で確認してください",
                "title": clean_title,
                "summary": summary or "自動収集で見つかった候補です。詳細と公式発表の有無はリンク先で確認してください。",
                "country": feed.get("country", "未確認"),
                "status": "investigating",
                "published": pub or "未確認",
                "records": "未確認",
                "data_types": "未確認（公式発表を確認中）",
                "source_url": url,
                "followup_url": "",
                "last_checked": today,
                "source_type": "news_rss_candidate"
            }
            by_url[url] = item
            added += 1
    incidents = list(by_url.values())
    # Keep latest 250 candidates to avoid unbounded growth.
    incidents.sort(key=lambda x: (x.get("published", ""), x.get("last_checked", "")), reverse=True)
    output = {"last_updated": today, "incidents": incidents[:250]}
    (DATA / "incidents.json").write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Added {added} candidates; saved {min(len(incidents),250)} items.")

if __name__ == "__main__":
    main()
