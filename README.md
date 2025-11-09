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
git clone https://github.com/TomasKasperavicius/email-analyzer.git
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

---

## Project requirements

### Template of the report:

Template example:
https://www.overleaf.com/read/xycsjycbbtgg

Requirements for report:
- After the project will be delivered You should provide me with latex source.
- I Will be compiling the course year project "book" so everyone from the group could read joint project .pdf
- During the project implementation you can share overleaf report to me so I could help you with possible related work and some latex issues if any.

### Requirements for deliverables:
1. Any selected project can be implemented in student groups up to 3 or individually (in case local students involve Erasmus students group could be +1).
2. Your project has to be defended during the exercise session with the course professor and must work within the VU MIF Cloud or demonstrate that it works on the local computer of the professor. 
3. If projects must be implemented as Virtual Machines (VMs)  script, please provide a VM specific image and a script for the installation of the chosen project with documentation.
4. Vulnerable machines, as well as attack vector machines, must be dynamically created from VU MIF-ready templates and/or submitted as a list of commands to recreate the solution.
5. All scripts that recreate VMs must be submitted to Moodle as a single zip - with in different catalogs and or url to download.
6. Latex overleaf read only link shall be shared to course professor (or zip  submitted)

### Project topic:
EmailAnalizer: (https://datatracker.ietf.org/doc/html/rfc2822) Develop a program/script that analyzes Email headers and draws diagrams according to the patterns using Graphviz. Patterns could be a source of origin, paths for email transfer. In particular, the change in security (if email has been transferred over non-secure channels), etc, could be analyzed. The complete list of tasks could be negotiated.