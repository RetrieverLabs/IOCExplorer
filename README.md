# 🛡️ IOC Scraper & Hunt Formatter

A lightweight Streamlit application designed for security analysts and threat hunters to quickly extract, refang, deduplicate, and format Indicators of Compromise (IOCs) from threat intelligence blogs or raw notes into ready-to-use SIEM and regex queries.

---

## ✨ Key Features

* **Dual Input:** Scrape live articles via URL (with automated anti-WAF user-agent headers) or paste raw article text directly as a fallback.
* **Smart Refanging & Extraction:** Automatically normalizes defanged indicators (`[.]`, `hxxp`, etc.) and extracts:
  * IPv4 Addresses
  * Domains & URLs
  * File Hashes (SHA256, SHA1, MD5)
  * File Paths (Windows & Unix)
  * Software Packages
* **Interactive Curation:** Categorized multiselect bins allow you to prune false positives before formatting.
* **SIEM Formatting Presets:** 
  * **CrowdStrike LogScale & Splunk Lists:** Clean double quotes and comma separation or `OR` chains.
  * **Regex Pipe Match:** Automatically escapes metacharacters (like dots), joins items with `|`, wraps them in `/.../i`, and supports custom field prefixes (e.g., `FileName=`, `RemoteIP4Address=`).
* **Master Copy-All & Grouped Outputs:** Generates both a master combined code block for one-click copying and granular per-category breakdowns.

---

## 🚀 Local Installation & Usage

1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git)
   cd YOUR_REPO_NAME
