# threat-model-parser

A Node.js CLI that parses [OWASP Threat Dragon](https://www.threatdragon.com/) v2 JSON models and produces:

- **HTML reports** — cover sheet, executive summary, per-diagram threat tables with severity/status colour coding and embedded SVG diagrams
- **SVG + PNG diagram exports** — standalone diagram files rendered from the model geometry

---

## Requirements

- Node.js 18+
- npm (for the `sharp` dependency used by PNG export)

## Installation

```bash
git clone https://github.com/scarayaa/threat-model-parser.git
cd threat-model-parser
npm install
```

---

## Usage

```
node threat-model-parser.js <model.json> [options]
```

### Options

| Flag | Description |
|---|---|
| `-o, --output <path>` | Write HTML to file instead of stdout. With `--diagrams-only`, sets the output directory (default: `.`) |
| `--no-mitigated` | Exclude threats with status `Mitigated` from all tables |
| `--no-out-of-scope` | Exclude elements marked as out-of-scope |
| `--no-empty` | Exclude elements that have no visible threats |
| `--no-diagram` | Skip SVG diagram rendering in the HTML report |
| `--properties` | Show element properties (encryption, protocol, privilege level, etc.) |
| `--diagrams-only` | Export each diagram as `<title>.svg` and `<title>.png` instead of generating an HTML report |
| `-h, --help` | Show help |

---

## Examples

**Generate an HTML report to a file:**
```bash
node threat-model-parser.js model.json -o report.html
```

**Exclude mitigated and out-of-scope items, show element properties:**
```bash
node threat-model-parser.js model.json --no-mitigated --no-out-of-scope --properties -o report.html
```

**Export all diagrams as SVG + PNG into a directory:**
```bash
node threat-model-parser.js model.json --diagrams-only -o ./diagrams
```

**Pipe HTML to stdout:**
```bash
node threat-model-parser.js model.json > report.html
```

---

## HTML Report Sections

| Section | Contents |
|---|---|
| Cover sheet | Model title, owner, reviewer, contributors, generation date |
| Executive summary | Description and threat count table broken down by severity (Critical / High / Medium / Low / TBD) and status (Open / Mitigated / N/A) |
| Diagram sections | SVG diagram + per-element threat tables with #, title, type, severity, status, score, description, and mitigations |

### Severity colours

| Severity | Colour |
|---|---|
| Critical | Dark red, bold |
| High | Red |
| Medium | Amber |
| Low | Green |

### Diagram rendering

The SVG renderer faithfully reproduces Threat Dragon's visual language:

- **Actor** — rectangle
- **Process** — ellipse
- **Store** — rectangle with double top/bottom rules
- **Data Flow** — arrowed polyline; bidirectional flows get arrowheads at both ends
- **Trust Boundary (box)** — dashed rectangle
- **Trust Boundary (line)** — dashed line
- Elements with **open threats** are highlighted in red; clean elements use dark grey

---

## Supported Model Formats

| Format | Notes |
|---|---|
| Threat Dragon v2 | `diagram.cells` with `cell.data` wrapper — fully supported |
| Threat Dragon v1 | `diagram.diagramJson.cells` with flat cell structure — automatically normalised |

---

## Project Structure

```
threat-model-parser/
├── threat-model-parser.js   # CLI entry point
├── package.json
├── package-lock.json
└── test/
    ├── input/               # Sample Threat Dragon model files
    └── output/              # Generated reports and diagram exports
```

---

## License

MIT
