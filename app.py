import re
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import streamlit as st

st.set_page_config(page_title="IOC Scraper & Hunt Formatter", layout="wide")

# Common benign domains/extensions to reduce false positives
IGNORE_DOMAINS = {
    "w3.org", "schema.org", "github.com", "twitter.com", "x.com",
    "linkedin.com", "youtube.com", "google.com", "microsoft.com",
    "virustotal.com", "mitre.org", "cve.org", "nist.gov"
}

FILE_EXTENSIONS = (
    "exe", "dll", "ps1", "bat", "sh", "py", "js", "vbs", "jar", "zip",
    "rar", "7z", "iso", "img", "lnk", "pdf", "doc", "docx", "xls", "xlsx",
    "txt", "log", "cfg", "conf", "ini", "json", "xml", "yml", "yaml", "tmp", "dat", "bin", "elf", "so"
)


def fetch_article_text(url: str) -> str:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/128.0.0.0 Safari/537.36"
        )
    }
    resp = requests.get(url.strip(), headers=headers, timeout=15)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    # Remove noisy navigation/script tags
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    return soup.get_text(separator="\n")


def refang(text: str) -> str:
    text = re.sub(r"hxxps?", lambda m: "https" if m.group(0).lower().endswith("s") else "http", text, flags=re.I)
    text = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", text)
    text = re.sub(r"\[:\]|\(:\)", ":", text)
    text = re.sub(r"\[/\]|\(/\)", "/", text)
    text = re.sub(r"\[at\]|\(at\)|\[@\]", "@", text, flags=re.I)
    return text


def dedup_preserve_order(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        cleaned = item.strip(".,;:\"'()[]{}<>")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            out.append(cleaned)
    return out


def extract_iocs(raw_text: str, source_urls: list[str]) -> dict[str, list[str]]:
    text = refang(raw_text)

    # Exclude the source blogs' own hostnames
    source_hosts = {urlparse(u).netloc.lower().removeprefix("www.") for u in source_urls if u.strip()}

    # 1. Hashes (SHA256, SHA1, MD5)
    sha256 = re.findall(r"\b[a-fA-F0-9]{64}\b", text)
    sha1 = re.findall(r"\b[a-fA-F0-9]{40}\b", text)
    md5 = re.findall(r"\b[a-fA-F0-9]{32}\b", text)
    hashes = dedup_preserve_order(sha256 + sha1 + md5)

    # 2. IPv4
    raw_ips = re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", text)
    ips = dedup_preserve_order([ip for ip in raw_ips if not ip.startswith(("0.", "127."))])

    # 3. URLs
    urls = dedup_preserve_order(re.findall(r"\bhttps?://[^\s<>\"'`]+", text, flags=re.I))

    # 4. Domains (excluding filenames, IPs, and benign domains)
    raw_domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,15}\b", text)
    domains = []
    for d in raw_domains:
        d_low = d.lower()
        tld = d_low.rsplit(".", 1)[-1]
        if tld in FILE_EXTENSIONS:
            continue
        if any(d_low == ig or d_low.endswith("." + ig) for ig in IGNORE_DOMAINS | source_hosts):
            continue
        domains.append(d_low)
    domains = dedup_preserve_order(domains)

    # 5. File Paths (Windows + common Unix roots)
    win_paths = re.findall(r"\b[a-zA-Z]:\\(?:[^\\\s<>\"'|?*]+\\)*[^\\\s<>\"'|?*]+", text)
    unix_paths = re.findall(r"(?<![\w:])/(?:etc|tmp|var|TEMP|usr|opt|home|root|bin|sbin|dev|mnt|srv)/[^\s<>\"'`]+", text)
    paths = dedup_preserve_order(win_paths + unix_paths)

    # 6. Software Packages (scoped npm, version-pinned strings, or install commands)
    scoped_pkgs = re.findall(r"@[a-z0-9-]+/[a-z0-9._-]+", text)
    pinned_pkgs = re.findall(r"\b([a-zA-Z0-9._-]+)(?:==|@)\d+\.\d+(?:\.\d+)?\b", text)
    cmd_pkgs = re.findall(r"\b(?:pip|pip3|npm|yarn|pnpm|gem|cargo)\s+(?:install|i|add)\s+([@a-zA-Z0-9._/-]+)", text)
    packages = dedup_preserve_order(scoped_pkgs + pinned_pkgs + cmd_pkgs)

    return {
        "IPs": ips,
        "Domains": domains,
        "URLs": urls,
        "Hashes": hashes,
        "File Paths": paths,
        "Packages": packages,
    }


# --- UI ---
st.title("IOC Scraper & Hunt Formatter")

col_in1, col_in2 = st.columns(2)
with col_in1:
    urls_input = st.text_area(
        "Article URLs (one per line)",
        height=120,
        placeholder="https://example.com/threat-report-1\nhttps://example.com/threat-report-2"
    )
with col_in2:
    raw_fallback = st.text_area(
        "Optional: Paste raw article text (or fallback if a site blocks scraping)",
        height=120,
        placeholder="Paste article text here..."
    )

if st.button("Extract IOCs", type="primary"):
    combined_text = raw_fallback + "\n"
    url_list = [u.strip() for u in urls_input.splitlines() if u.strip()]

    for u in url_list:
        try:
            combined_text += fetch_article_text(u) + "\n"
        except Exception as e:
            st.warning(f"Could not fetch {u} ({e}). Try pasting the article text on the right.")

    if combined_text.strip():
        st.session_state["extracted"] = extract_iocs(combined_text, url_list)
    else:
        st.error("Provide at least one valid URL or paste article text.")

if "extracted" in st.session_state:
    st.divider()
    st.subheader("1. Review & Prune False Positives")
    data = st.session_state["extracted"]

    selected_all = []
    cols = st.columns(3)
    for idx, (category, items) in enumerate(data.items()):
        with cols[idx % 3]:
            picked = st.multiselect(
                f"{category} ({len(items)})",
                options=items,
                default=items,
                key=f"ms_{category}"
            )
            selected_all.extend(picked)

    st.divider()
    st.subheader("2. Format for Hunt Query")

    # Formatting controls layout
    col1, col2, col3 = st.columns(3)
    with col1:
        wrap_quotes = st.toggle('Wrap in double quotes ("...")', value=True)
    with col2:
        asterisk_mode = st.selectbox(
            "Wildcard Asterisks (*)",
            options=[
                "None (Normal)",
                "Wrap inside quotes (*item*)",
                "Wrap outside quotes (*item*)",
                "Asterisk suffix only (item*)",
                "Asterisk prefix only (*item)"
            ],
            index=0
        )
    with col3:
        separator_mode = st.radio(
            "Delimiter",
            options=["Comma (, )", "Boolean OR ( OR )"],
            horizontal=True
        )

    wrap_parens = st.toggle("Wrap entire list in parentheses (...)", value=False)

    # Deduplicate across categories
    final_items = dedup_preserve_order(selected_all)

    if final_items:
        formatted = []
        for item in final_items:
            # Apply asterisk modifications
            if asterisk_mode == "Wrap inside quotes (*item*)":
                modified_item = f"*{item}*"
            elif asterisk_mode == "Wrap outside quotes (*item*)":
                # We handle outer asterisks after or during quote application
                modified_item = item
            elif asterisk_mode == "Asterisk suffix only (item*)":
                modified_item = f"{item}*"
            elif asterisk_mode == "Asterisk prefix only (*item)":
                modified_item = f"*{item}"
            else:
                modified_item = item

            # Apply quotes and outer asterisk positioning if needed
            if wrap_quotes:
                if asterisk_mode == "Wrap outside quotes (*item*)":
                    item_str = f'*"{modified_item}"*'
                else:
                    item_str = f'"{modified_item}"'
            else:
                item_str = modified_item

            formatted.append(item_str)

        sep = ", " if "Comma" in separator_mode else " OR "
        output_str = sep.join(formatted)
        if wrap_parens:
            output_str = f"({output_str})"

        st.caption(f"Total IOCs ready: **{len(final_items)}**")
        st.code(output_str, language="text")
    else:
        st.info("No IOCs selected.")