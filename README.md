# 📧 Email Analyzer

Analyze `.eml` email files to extract delivery hops, evaluate authentication and encryption security, visualize paths on an interactive map, and generate a comprehensive HTML report.

---

## ✨ Features

- 🔍 Parses raw email headers to reconstruct SMTP delivery paths  
- 🛡️ Checks authentication results (SPF, DKIM, DMARC)  
- 🔒 Detects TLS usage for each hop  
- 🌍 Generates:
  - **Graph** visualization of hops (`--graph-out`)
  - **Interactive Folium map** (`--map-out`)
  - **HTML report** (`--html-out`)
- 🧭 Automatically embeds the Folium map directly into the HTML report  
- 🗺️ Map labels displayed in **English** (using CartoDB Positron tiles)

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/email-analyzer.git
cd email-analyzer
```

### 2. Create a virtual environment (recommended)

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic Example (from root path)

```bash
python src/main.py samples/sample.eml --graph-out email_hops --map-out email_map.html --html-out report.html
```

This command will:

- Parse the `sample.eml`
- Generate a hop graph (`email_hops.svg`)
- Create a Folium map (`email_map.html`)
- Build a full interactive report (`report.html`) with the map embedded inside the “Delivery Path Analysis” section

---

## 🧾 Example Output Files

| File | Description |
|------|--------------|
| `email_hops.svg` | Graph of SMTP delivery hops |
| `email_map.html` | Standalone Folium map |
| `report.html` | Final interactive HTML report with embedded map |

