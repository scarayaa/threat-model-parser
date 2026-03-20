#!/usr/bin/env node
/**
 * Threat Dragon - Threat Model Parser
 *
 * Usage:
 *   node threat-model-parser.js <model.json> [options]
 *   node threat-model-parser.js <model.json> -o report.html
 *
 * Options:
 *   -o, --output <file>      Write output to file instead of stdout
 *   --no-mitigated           Exclude mitigated threats
 *   --no-out-of-scope        Exclude out-of-scope elements
 *   --no-empty               Exclude elements with no threats
 *   --no-diagram             Skip the SVG diagram drawing
 *   --properties             Show element properties
 *   --diagrams-only          Export each diagram as <title>.svg and <title>.png
 *                            (skips HTML report; use -o to set output directory)
 */

'use strict';

const fs = require('fs');
const path = require('path');

// ── CLI parsing ──────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.error([
        'Usage: node threat-model-parser.js <model.json> [options]',
        '',
        'Options:',
        '  -o, --output <file>   Write HTML to file (default: stdout)',
        '                        With --diagrams-only: output directory (default: .)',
        '  --no-mitigated        Exclude mitigated threats',
        '  --no-out-of-scope     Exclude out-of-scope elements',
        '  --no-empty            Exclude elements with no visible threats',
        '  --no-diagram          Skip the SVG diagram drawing',
        '  --properties          Show element properties',
        '  --diagrams-only       Export diagrams as .svg + .png files instead of HTML',
        '  -h, --help            Show this help',
    ].join('\n'));
    process.exit(args.length === 0 ? 1 : 0);
}

const opts = {
    showMitigated:  true,
    showOutOfScope: true,
    showEmpty:      true,
    showDiagram:    true,
    showProperties: false,
    diagramsOnly:   false,
    outputFile:     null,
};

let inputFile = null;

for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
    case '--no-mitigated':    opts.showMitigated  = false; break;
    case '--no-out-of-scope': opts.showOutOfScope = false; break;
    case '--no-empty':        opts.showEmpty      = false; break;
    case '--no-diagram':      opts.showDiagram    = false; break;
    case '--properties':      opts.showProperties = true;  break;
    case '--diagrams-only':   opts.diagramsOnly   = true;  break;
    case '-o':
    case '--output':
        opts.outputFile = args[++i];
        break;
    default:
        if (!args[i].startsWith('-')) inputFile = args[i];
    }
}

if (!inputFile) {
    console.error('Error: no input file specified.');
    process.exit(1);
}

// ── Load model ───────────────────────────────────────────────────────────────

let model;
try {
    model = JSON.parse(fs.readFileSync(path.resolve(inputFile), 'utf8'));
} catch (e) {
    console.error(`Error reading ${inputFile}: ${e.message}`);
    process.exit(1);
}

// ── Model normalisation (v1 / v2) ────────────────────────────────────────────
//
// v1: diagram.diagramJson.cells  — threats on cell root, name in cell.attrs
// v2: diagram.cells              — threats in cell.data,  name in cell.data.name

function rawCells(diagram) {
    return diagram.cells || (diagram.diagramJson && diagram.diagramJson.cells) || [];
}

function normaliseCells(diagram) {
    return rawCells(diagram).map((cell) => {
        if (cell.data) return cell; // v2 already has data wrapper

        // v1 — synthesise a data object matching the v2 shape
        const label =
            (cell.attrs && cell.attrs.label  && cell.attrs.label.text)  ||
            (cell.attrs && cell.attrs['.label'] && cell.attrs['.label'].text) ||
            (cell.attrs && cell.attrs.text   && cell.attrs.text.text)   ||
            '';
        return {
            ...cell,
            data: {
                type:                 cell.type || '',
                name:                 label,
                description:          cell.description || '',
                outOfScope:           cell.outOfScope  || false,
                reasonOutOfScope:     cell.reasonOutOfScope || '',
                threats:              cell.threats || [],
                bidirection:          cell.bidirection,
                handlesCardPayment:   cell.handlesCardPayment,
                handlesGoodsOrServices: cell.handlesGoodsOrServices,
                isALog:               cell.isALog,
                isEncrypted:          cell.isEncrypted,
                isSigned:             cell.isSigned,
                isWebApplication:     cell.isWebApplication,
                privilegeLevel:       cell.privilegeLevel,
                providesAuthentication: cell.providesAuthentication,
                protocol:             cell.protocol,
                publicNetwork:        cell.publicNetwork,
                storesCredentials:    cell.storesCredentials,
                storesInventory:      cell.storesInventory,
            },
        };
    });
}

// ── Threat filtering ─────────────────────────────────────────────────────────

function filterThreats(threats) {
    if (!threats || threats.length === 0) return [];
    return threats.filter((t) => {
        if (!opts.showMitigated && t.status && t.status.toLowerCase() === 'mitigated') return false;
        return true;
    });
}

function entitiesWithThreats(cells) {
    return cells.filter((cell) => {
        const data = cell.data;
        if (!data || !data.threats) return false;
        if (!opts.showOutOfScope && data.outOfScope) return false;
        const visible = filterThreats(data.threats);
        if (!opts.showEmpty && visible.length === 0) return false;
        return true;
    });
}

// ── Threat stats ─────────────────────────────────────────────────────────────

function computeStats(diagrams) {
    const all = diagrams.flatMap((d) => normaliseCells(d))
        .filter((c) => c.data && c.data.threats)
        .flatMap((c) => c.data.threats);
    const open = all.filter((t) => t.status === 'Open');
    return {
        total:         all.length,
        mitigated:     all.filter((t) => t.status === 'Mitigated').length,
        notApplicable: all.filter((t) => t.status === 'NotApplicable').length,
        notMitigated:  open.length,
        openCritical:  open.filter((t) => t.severity === 'Critical').length,
        openHigh:      open.filter((t) => t.severity === 'High').length,
        openMedium:    open.filter((t) => t.severity === 'Medium').length,
        openLow:       open.filter((t) => t.severity === 'Low').length,
        openTbd:       open.filter((t) => t.severity === 'TBD').length,
        openUnknown:   open.filter((t) => !t.severity).length,
    };
}

// ── Translation helpers ───────────────────────────────────────────────────────

const SEVERITY_LABEL = { TBD: 'TBD', Low: 'Low', Medium: 'Medium', High: 'High', Critical: 'Critical' };
const STATUS_LABEL   = { NotApplicable: 'N/A', Open: 'Open', Mitigated: 'Mitigated' };

const SHAPE_LABEL = {
    actor: 'Actor', flow: 'Data Flow', flowstencil: 'Data Flow',
    process: 'Process', store: 'Store', text: 'Descriptive text',
    trustboundary: 'Trust Boundary',
};

function shapeLabel(typeStr) {
    if (!typeStr) return 'Element';
    const key = typeStr.replace(/^(tm\.|td\.)/, '').toLowerCase();
    return SHAPE_LABEL[key] || typeStr.replace(/^(tm\.|td\.)/, '');
}

// ── HTML escaping ─────────────────────────────────────────────────────────────

function esc(str) {
    if (str === undefined || str === null) return '';
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Properties list ───────────────────────────────────────────────────────────

function propertiesList(data) {
    const items = [];
    if (data.bidirection)            items.push('Bidirectional');
    if (data.handlesCardPayment)     items.push('Card payment');
    if (data.handlesGoodsOrServices) items.push('Goods or Services');
    if (data.isALog)                 items.push('Is a Log');
    if (data.isEncrypted)            items.push('Encrypted');
    if (data.isSigned)               items.push('Signed');
    if (data.isWebApplication)       items.push('Web Application');
    if (data.privilegeLevel)         items.push(`Privilege Level: ${data.privilegeLevel}`);
    if (data.providesAuthentication) items.push('Provides Authentication');
    if (data.protocol)               items.push(`Protocol (${data.protocol})`);
    if (data.publicNetwork)          items.push('Public Network');
    if (data.storesCredentials)      items.push('Stores Credentials');
    if (data.storesInventory)        items.push('Stores Inventory');
    return items.length ? `Properties: ${items.join(', ')}` : '';
}

// ── SVG diagram renderer ──────────────────────────────────────────────────────
//
// Draws a faithful SVG representation of the diagram using the same visual
// language as Threat Dragon:
//   Actor        — plain rectangle
//   Process      — circle
//   Store        — rectangle with double top/bottom lines
//   Trust Boundary (line)  — dashed line
//   Trust Boundary (box)   — dashed rectangle
//   Data Flow    — arrowed line, bidirectional gets two arrowheads
//   Text block   — italic text only
//
// Threat-state colouring mirrors the app:
//   open threats  → red stroke/fill tint
//   no open threats → dark-grey stroke

const SVG_PAD = 40; // canvas padding around content

function cellName(cell) {
    // v2: cell.data.name; v1: already normalised into cell.data.name
    const n = (cell.data && cell.data.name) || '';
    return n.replace(/\n/g, ' ');
}

function hasOpenThreats(cell) {
    const threats = (cell.data && cell.data.threats) || cell.threats || [];
    return threats.some((t) => t.status === 'Open');
}

// Resolve the canonical shape key from either v1 type or v2 shape field
function resolveShape(cell) {
    const s = (cell.shape || '').toLowerCase();
    const t = (cell.type  || '').toLowerCase();

    if (s === 'flow' || t === 'tm.flow')          return 'flow';
    if (s === 'actor' || t === 'tm.actor')         return 'actor';
    if (s === 'process' || t === 'tm.process')     return 'process';
    if (s === 'store' || t === 'tm.store')         return 'store';
    if (s === 'trust-boundary-box')                return 'boundary-box';
    if (t === 'tm.boundary')                       return 'boundary-line';
    if (s === 'td-text-block' || t === 'tm.text')  return 'text';
    // fallback
    if (s.includes('boundary') || t.includes('boundary')) return 'boundary-box';
    if (s.includes('flow')     || t.includes('flow'))      return 'flow';
    return 'actor';
}

// Centre of a node cell (used for edge routing)
function cellCentre(cell) {
    const p = cell.position || {};
    const sz = cell.size || {};
    return {
        x: (p.x || 0) + (sz.width  || 0) / 2,
        y: (p.y || 0) + (sz.height || 0) / 2,
    };
}

// Build an index: cell id → cell
function buildIndex(cells) {
    const idx = {};
    for (const c of cells) if (c.id) idx[c.id] = c;
    return idx;
}

// Resolve edge endpoint to {x,y}: either a cell-centre or a fixed coordinate
function resolveEndpoint(ref, idx) {
    if (!ref) return null;
    if (ref.id   || ref.cell) return cellCentre(idx[ref.id || ref.cell] || {});
    if (ref.x !== undefined)  return { x: ref.x, y: ref.y };
    return null;
}

// Wrap SVG text into <tspan> lines, max lineWidth chars, at most maxLines
function svgTextLines(text, lineWidth, maxLines) {
    if (!text) return [];
    const words = text.split(/\s+/);
    const lines = [];
    let cur = '';
    for (const w of words) {
        if ((cur + ' ' + w).trim().length > lineWidth && cur) {
            lines.push(cur);
            cur = w;
        } else {
            cur = (cur + ' ' + w).trim();
        }
        if (lines.length >= maxLines - 1) break;
    }
    if (cur) lines.push(cur.length > lineWidth ? cur.slice(0, lineWidth - 1) + '…' : cur);
    if (lines.length > maxLines) lines.length = maxLines;
    return lines;
}

// Render multiline SVG text centred at (cx, cy)
function svgLabel(text, cx, cy, fontSize, fill, lineWidth, maxLines) {
    const lines = svgTextLines(text, lineWidth, maxLines);
    if (!lines.length) return '';
    const lh = fontSize * 1.3;
    const startY = cy - ((lines.length - 1) * lh) / 2;
    return lines.map((l, i) =>
        `<text x="${cx.toFixed(1)}" y="${(startY + i * lh).toFixed(1)}" ` +
        `font-size="${fontSize}" fill="${fill}" text-anchor="middle" dominant-baseline="middle" ` +
        `font-family="sans-serif">${esc(l)}</text>`
    ).join('\n');
}

// Arrow marker definitions (referenced by id)
function svgDefs() {
    return `<defs>
  <marker id="arrow-open" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
    <polygon points="0 0, 10 3.5, 0 7" fill="#c0392b"/>
  </marker>
  <marker id="arrow-closed" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
    <polygon points="0 0, 10 3.5, 0 7" fill="#555"/>
  </marker>
  <marker id="arrow-open-start" markerWidth="10" markerHeight="7" refX="1" refY="3.5" orient="auto-start-reverse">
    <polygon points="0 0, 10 3.5, 0 7" fill="#c0392b"/>
  </marker>
  <marker id="arrow-closed-start" markerWidth="10" markerHeight="7" refX="1" refY="3.5" orient="auto-start-reverse">
    <polygon points="0 0, 10 3.5, 0 7" fill="#555"/>
  </marker>
</defs>`;
}

// Render a single node cell to SVG elements
function svgNode(cell, offsetX, offsetY) {
    const shape  = resolveShape(cell);
    const pos    = cell.position || {};
    const sz     = cell.size    || {};
    const x = (pos.x || 0) - offsetX;
    const y = (pos.y || 0) - offsetY;
    const w = sz.width  || 100;
    const h = sz.height || 60;
    const cx = x + w / 2;
    const cy = y + h / 2;
    const open   = hasOpenThreats(cell);
    const stroke = open ? '#c0392b' : '#555';
    const fill   = open ? '#fdecea' : '#f8f9fa';
    const name   = cellName(cell);

    if (shape === 'boundary-box') {
        return `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${w}" height="${h}" ` +
            `fill="none" stroke="#7f8c8d" stroke-width="1.5" stroke-dasharray="8 4" rx="4"/>`;
    }

    if (shape === 'text') {
        return `<text x="${cx.toFixed(1)}" y="${cy.toFixed(1)}" font-size="11" fill="#555" ` +
            `font-style="italic" text-anchor="middle" dominant-baseline="middle" ` +
            `font-family="sans-serif">${esc(name)}</text>`;
    }

    if (shape === 'actor') {
        const lw = Math.max(12, Math.floor(w / 7));
        return [
            `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${w}" height="${h}" ` +
                `fill="${fill}" stroke="${stroke}" stroke-width="1.5" rx="3"/>`,
            svgLabel(name, cx, cy, 11, '#212529', lw, 3),
        ].join('\n');
    }

    if (shape === 'process') {
        const rx = w / 2;
        const ry = h / 2;
        const lw = Math.max(10, Math.floor(rx * 1.2 / 7));
        return [
            `<ellipse cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" rx="${rx}" ry="${ry}" ` +
                `fill="${fill}" stroke="${stroke}" stroke-width="1.5"/>`,
            svgLabel(name, cx, cy, 11, '#212529', lw, 3),
        ].join('\n');
    }

    if (shape === 'store') {
        const lineGap = Math.min(8, h * 0.15);
        const lw = Math.max(12, Math.floor(w / 7));
        return [
            `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${w}" height="${h}" ` +
                `fill="${fill}" stroke="${stroke}" stroke-width="1.5"/>`,
            // double-line top
            `<line x1="${x.toFixed(1)}" y1="${(y + lineGap).toFixed(1)}" ` +
                `x2="${(x + w).toFixed(1)}" y2="${(y + lineGap).toFixed(1)}" ` +
                `stroke="${stroke}" stroke-width="1"/>`,
            // double-line bottom
            `<line x1="${x.toFixed(1)}" y1="${(y + h - lineGap).toFixed(1)}" ` +
                `x2="${(x + w).toFixed(1)}" y2="${(y + h - lineGap).toFixed(1)}" ` +
                `stroke="${stroke}" stroke-width="1"/>`,
            svgLabel(name, cx, cy, 11, '#212529', lw, 2),
        ].join('\n');
    }

    return '';
}

// Build polyline points string through optional waypoints
function buildPath(src, tgt, vertices) {
    const pts = [src, ...(vertices || []), tgt];
    return pts.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
}

// Clip an arrow endpoint to the actual boundary of its node shape.
// cell       — the node cell (unshifted coordinates)
// fromPt     — the point the arrow is coming from (SVG/shifted coordinates)
// offsetX/Y  — the coordinate shift applied to the canvas
// Returns the intersection point in SVG coordinates.
function clipToShapeBoundary(cell, fromPt, offsetX, offsetY) {
    const shape = resolveShape(cell);
    const pos = cell.position || {};
    const sz  = cell.size    || {};
    const cx = (pos.x || 0) + (sz.width  || 0) / 2 - offsetX;
    const cy = (pos.y || 0) + (sz.height || 0) / 2 - offsetY;
    const w  = sz.width  || 100;
    const h  = sz.height || 60;
    const dx = cx - fromPt.x;
    const dy = cy - fromPt.y;
    if (Math.sqrt(dx * dx + dy * dy) < 1) return { x: cx, y: cy };

    if (shape === 'process') {
        // Intersection of ray with ellipse
        const rx = w / 2, ry = h / 2;
        const u = fromPt.x - cx, v = fromPt.y - cy;
        const A = dx * dx / (rx * rx) + dy * dy / (ry * ry);
        const B = 2 * (u * dx / (rx * rx) + v * dy / (ry * ry));
        const C = u * u / (rx * rx) + v * v / (ry * ry) - 1;
        const disc = B * B - 4 * A * C;
        if (disc < 0 || A < 1e-10) return { x: cx, y: cy };
        const sq = Math.sqrt(disc);
        const t  = Math.min(
            ...[ (-B + sq) / (2 * A), (-B - sq) / (2 * A) ].filter(t => t > 1e-4)
        );
        if (!isFinite(t)) return { x: cx, y: cy };
        return { x: fromPt.x + t * dx, y: fromPt.y + t * dy };
    }

    // Rectangle (actor, store, or fallback)
    const rx = (pos.x || 0) - offsetX;
    const ry = (pos.y || 0) - offsetY;
    const edges = [
        { axis: 'x', val: rx,     lo: ry,     hi: ry + h },
        { axis: 'x', val: rx + w, lo: ry,     hi: ry + h },
        { axis: 'y', val: ry,     lo: rx,     hi: rx + w },
        { axis: 'y', val: ry + h, lo: rx,     hi: rx + w },
    ];
    let tMin = Infinity, result = { x: cx, y: cy };
    for (const e of edges) {
        const denom = e.axis === 'x' ? dx : dy;
        if (Math.abs(denom) < 1e-10) continue;
        const t    = ((e.val) - (e.axis === 'x' ? fromPt.x : fromPt.y)) / denom;
        if (t <= 1e-4 || t >= tMin) continue;
        const other = e.axis === 'x' ? fromPt.y + t * dy : fromPt.x + t * dx;
        if (other < e.lo - 1e-4 || other > e.hi + 1e-4) continue;
        tMin   = t;
        result = e.axis === 'x' ? { x: e.val, y: other } : { x: other, y: e.val };
    }
    return result;
}

// Geometric midpoint of a polyline (by arc length) and the direction at that point.
// Returns { x, y, dx, dy } where (dx,dy) is the unit tangent of the containing segment.
function polylineMidpoint(pts) {
    if (pts.length === 1) return { ...pts[0], dx: 1, dy: 0 };
    // Compute cumulative arc lengths
    const lens = [0];
    for (let i = 1; i < pts.length; i++) {
        const dx = pts[i].x - pts[i - 1].x;
        const dy = pts[i].y - pts[i - 1].y;
        lens.push(lens[i - 1] + Math.sqrt(dx * dx + dy * dy));
    }
    const half = lens[lens.length - 1] / 2;
    // Find the segment that contains the halfway point
    for (let i = 1; i < lens.length; i++) {
        if (lens[i] >= half) {
            const t  = (half - lens[i - 1]) / (lens[i] - lens[i - 1]);
            const dx = pts[i].x - pts[i - 1].x;
            const dy = pts[i].y - pts[i - 1].y;
            const len = Math.sqrt(dx * dx + dy * dy) || 1;
            return {
                x:  pts[i - 1].x + t * dx,
                y:  pts[i - 1].y + t * dy,
                dx: dx / len,
                dy: dy / len,
            };
        }
    }
    return { ...pts[pts.length - 1], dx: 1, dy: 0 };
}

// Render a flow/boundary-line edge cell
function svgEdge(cell, idx, offsetX, offsetY) {
    const shape  = resolveShape(cell);
    const src    = resolveEndpoint(cell.source, idx);
    const tgt    = resolveEndpoint(cell.target, idx);
    if (!src || !tgt) return '';

    const shift = (p) => ({ x: p.x - offsetX, y: p.y - offsetY });
    const sCtr = shift(src);
    const tCtr = shift(tgt);
    const verts = (cell.vertices || []).map(shift);

    // Clip endpoints to shape boundaries so arrows land on the perimeter, not the centre
    const srcCellId = cell.source && (cell.source.id || cell.source.cell);
    const tgtCellId = cell.target && (cell.target.id || cell.target.cell);
    const srcCell   = srcCellId ? idx[srcCellId] : null;
    const tgtCell   = tgtCellId ? idx[tgtCellId] : null;
    const firstDir  = verts.length ? verts[0]              : tCtr;
    const lastDir   = verts.length ? verts[verts.length - 1] : sCtr;
    const s = srcCell ? clipToShapeBoundary(srcCell, firstDir, offsetX, offsetY) : sCtr;
    const t = tgtCell ? clipToShapeBoundary(tgtCell, lastDir,  offsetX, offsetY) : tCtr;

    const pts = buildPath(s, t, verts);

    if (shape === 'boundary-line') {
        return `<polyline points="${pts}" fill="none" stroke="#7f8c8d" stroke-width="1.5" stroke-dasharray="8 4"/>`;
    }

    // flow
    const open    = hasOpenThreats(cell);
    const color   = open ? '#c0392b' : '#555';
    const markEnd = open ? 'url(#arrow-open)' : 'url(#arrow-closed)';
    const data    = cell.data || {};
    const bidir   = data.isBidirectional || data.bidirection;
    const markStart = bidir ? (open ? 'url(#arrow-open-start)' : 'url(#arrow-closed-start)') : 'none';

    const name = cellName(cell);
    let label = '';
    if (name) {
        // Place label at geometric midpoint, offset perpendicularly 14px away from the line
        const allPts = [s, ...verts, t];
        const mid    = polylineMidpoint(allPts);
        // Perpendicular unit vector (rotate tangent 90°), always bias upward/left
        let px = -mid.dy;
        let py =  mid.dx;
        if (py > 0) { px = -px; py = -py; } // prefer the upward normal
        const OFFSET = 14;
        const lx = mid.x + px * OFFSET;
        const ly = mid.y + py * OFFSET;

        // Estimate pill background size (approx 6px per char at font-size 10)
        const estW = Math.max(30, name.length * 5.8 + 8);
        const estH = 14;
        label = [
            `<rect x="${(lx - estW / 2).toFixed(1)}" y="${(ly - estH / 2 - 1).toFixed(1)}" ` +
                `width="${estW.toFixed(1)}" height="${estH}" rx="3" ` +
                `fill="white" fill-opacity="0.85" stroke="${color}" stroke-width="0.5"/>`,
            `<text x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" font-size="10" fill="${color}" ` +
                `text-anchor="middle" font-family="sans-serif" dominant-baseline="middle">${esc(name)}</text>`,
        ].join('\n');
    }

    return [
        `<polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" ` +
            `marker-end="${markEnd}" marker-start="${markStart}"/>`,
        label,
    ].join('\n');
}

function renderDiagramSVG(diagram) {
    const cells = rawCells(diagram);
    if (!cells.length) return '';

    const idx = buildIndex(cells);

    // Compute bounding box (nodes only — edges are contained within node extents)
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const c of cells) {
        if (!c.position) continue;
        const { x, y } = c.position;
        const { width: w = 0, height: h = 0 } = c.size || {};
        minX = Math.min(minX, x);
        minY = Math.min(minY, y);
        maxX = Math.max(maxX, x + w);
        maxY = Math.max(maxY, y + h);
    }
    // Also account for fixed-coordinate edges (v1 boundary lines)
    for (const c of cells) {
        for (const ep of [c.source, c.target]) {
            if (ep && ep.x !== undefined) {
                minX = Math.min(minX, ep.x); minY = Math.min(minY, ep.y);
                maxX = Math.max(maxX, ep.x); maxY = Math.max(maxY, ep.y);
            }
        }
        for (const v of (c.vertices || [])) {
            minX = Math.min(minX, v.x); minY = Math.min(minY, v.y);
            maxX = Math.max(maxX, v.x); maxY = Math.max(maxY, v.y);
        }
    }
    if (!isFinite(minX)) return '';

    const offsetX = minX - SVG_PAD;
    const offsetY = minY - SVG_PAD;
    const svgW    = maxX - minX + SVG_PAD * 2;
    const svgH    = maxY - minY + SVG_PAD * 2;

    // Rendering order: boundary-boxes first (background), then nodes, then edges on top
    const boundaries = cells.filter((c) => resolveShape(c) === 'boundary-box');
    const edges      = cells.filter((c) => ['flow', 'boundary-line'].includes(resolveShape(c)));
    const nodes      = cells.filter((c) => !['flow', 'boundary-line', 'boundary-box'].includes(resolveShape(c)));

    const parts = [
        svgDefs(),
        ...boundaries.map((c) => svgNode(c, offsetX, offsetY)),
        ...nodes.map((c)      => svgNode(c, offsetX, offsetY)),
        ...edges.map((c)      => svgEdge(c, idx, offsetX, offsetY)),
    ].filter(Boolean);

    return `<div class="diagram-svg-wrap">
<svg xmlns="http://www.w3.org/2000/svg" width="100%" viewBox="0 0 ${svgW.toFixed(1)} ${svgH.toFixed(1)}"
     style="max-height:600px;border:1px solid #dee2e6;border-radius:4px;background:#fff;">
${parts.join('\n')}
</svg>
</div>`;
}

// ── Report HTML building blocks ───────────────────────────────────────────────

function renderCoversheet(summary, detail, contributors) {
    const contribNames = (contributors || []).map((c) => esc(c.name || c)).join(', ');
    return `
<section class="page coversheet">
  <div class="cover-title">
    <h1>${esc(summary.title)}</h1>
  </div>
  <div class="cover-meta">
    <ul>
      <li><strong>Owner</strong>: ${esc(summary.owner)}</li>
      <li><strong>Reviewer</strong>: ${esc(detail.reviewer)}</li>
      <li><strong>Contributors</strong>: ${contribNames || '—'}</li>
      <li><strong>Date Generated</strong>: ${new Date().toDateString()}</li>
    </ul>
  </div>
</section>`;
}

function renderExecutiveSummary(description, stats) {
    const rows = [
        ['Total Threats',            stats.total,         'td-summary-total'],
        ['Total Mitigated',          stats.mitigated,     'td-summary-mitigated'],
        stats.notApplicable
            ? ['Total Not Applicable', stats.notApplicable, 'td-summary-not-applicable']
            : null,
        ['Total Open',               stats.notMitigated,  'td-summary-not-mitigated'],
        ['Open / Critical Severity', stats.openCritical,  'td-summary-open-critical'],
        ['Open / High Severity',     stats.openHigh,      'td-summary-open-high'],
        ['Open / Medium Severity',   stats.openMedium,    'td-summary-open-medium'],
        ['Open / Low Severity',      stats.openLow,       'td-summary-open-low'],
        stats.openTbd     ? ['Open / TBD Severity',     stats.openTbd,     'td-summary-open-tbd']     : null,
        stats.openUnknown ? ['Open / Unknown Severity', stats.openUnknown, 'td-summary-open-unknown'] : null,
    ].filter(Boolean);

    const tableRows = rows.map(([label, value, cls]) =>
        `<tr><th>${esc(label)}</th><td class="${cls}">${value}</td></tr>`
    ).join('\n');

    return `
<section class="page executive-summary">
  <h2>Executive Summary</h2>
  <h3>Description</h3>
  <p class="summary-text">${esc(description) || '<em>Not provided</em>'}</p>
  <h3>Summary</h3>
  <table class="summary-table">
    <tbody>${tableRows}</tbody>
  </table>
</section>`;
}

function renderThreatRow(threat) {
    const severity = SEVERITY_LABEL[threat.severity] || threat.severity || '';
    const status   = STATUS_LABEL[threat.status]     || threat.status   || '';
    return `
<tr>
  <td>${esc(threat.number)}</td>
  <td>${esc(threat.title)}</td>
  <td>${esc(threat.type)}</td>
  <td class="sev-${(threat.severity || '').toLowerCase()}">${esc(severity)}</td>
  <td class="status-${(threat.status || '').toLowerCase()}">${esc(status)}</td>
  <td>${esc(threat.score)}</td>
  <td>${esc(threat.description)}</td>
  <td>${esc(threat.mitigation)}</td>
</tr>`;
}

function renderEntity(cell) {
    const data    = cell.data;
    const name    = (data.name || '').replace(/\n/g, ' ');
    const type    = shapeLabel(data.type);
    const threats = filterThreats(data.threats || []);

    const headerNote     = data.outOfScope ? ' <em>— Out of Scope</em>' : '';
    const outOfScopeNote = data.outOfScope && data.reasonOutOfScope
        ? `<p class="entity-description"><strong>Reason for out of scope:</strong> ${esc(data.reasonOutOfScope)}</p>`
        : '';
    const descNote  = data.description
        ? `<p class="entity-description">Description: ${esc(data.description)}</p>`
        : '';
    const propsNote = opts.showProperties
        ? `<p class="entity-description">${esc(propertiesList(data))}</p>`
        : '';
    const threatRows = threats.length
        ? threats.map(renderThreatRow).join('')
        : '<tr><td colspan="8"><em>No threats</em></td></tr>';

    return `
<div class="entity-block">
  <h3 class="entity-title">${esc(name)} (${esc(type)})${headerNote}</h3>
  ${outOfScopeNote}${descNote}${propsNote}
  <table class="threat-table">
    <thead>
      <tr>
        <th>#</th><th>Title</th><th>Type</th><th>Severity</th>
        <th>Status</th><th>Score</th><th>Description</th><th>Mitigations</th>
      </tr>
    </thead>
    <tbody>${threatRows}</tbody>
  </table>
</div>`;
}

function renderDiagram(diagram) {
    const cells   = normaliseCells(diagram);
    const visible = entitiesWithThreats(cells);

    const svgPart = opts.showDiagram ? renderDiagramSVG(diagram) : '';

    const entityBlocks = visible.length
        ? visible.map(renderEntity).join('\n')
        : '<p><em>No elements with threats in this diagram.</em></p>';

    return `
<section class="page diagram-section">
  <h2 class="diagram-title">${esc(diagram.title)}</h2>
  ${diagram.description ? `<p class="diagram-description">${esc(diagram.description)}</p>` : ''}
  ${svgPart}
  ${entityBlocks}
</section>`;
}

// ── CSS ───────────────────────────────────────────────────────────────────────

const CSS = `
*, *::before, *::after { box-sizing: border-box; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 12px;
  color: #212529;
  margin: 0;
  padding: 0;
  background: #fff;
}

.page {
  max-width: 1100px;
  margin: 40px auto;
  padding: 32px 40px;
  border: 1px solid #dee2e6;
  border-radius: 4px;
  page-break-after: always;
}

/* Coversheet */
.coversheet { text-align: left; }
.cover-title {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 300px;
}
.cover-title h1 { font-size: 48px; font-weight: 900; text-align: center; }
.cover-meta { margin-top: 40px; }
.cover-meta ul { list-style: none; padding: 0; }
.cover-meta li { text-align: right; margin: 6px 0; font-size: 13px; }

/* Executive summary */
.executive-summary h2 { font-size: 22px; border-bottom: 2px solid #dee2e6; padding-bottom: 8px; }
.executive-summary h3 { font-size: 15px; margin-top: 20px; }
.summary-text { white-space: pre-wrap; }
.summary-table { border-collapse: collapse; margin-top: 10px; }
.summary-table th, .summary-table td { padding: 6px 16px; border: 1px solid #dee2e6; }
.summary-table th { text-align: left; background: #f8f9fa; font-weight: 600; }
.summary-table td { text-align: right; min-width: 60px; }

/* Diagrams */
.diagram-section h2.diagram-title { font-size: 20px; border-bottom: 2px solid #dee2e6; padding-bottom: 6px; }
.diagram-description { color: #6c757d; margin-bottom: 16px; white-space: pre-wrap; }
.diagram-svg-wrap { margin: 16px 0 24px; }

/* Entities */
.entity-block { margin-top: 28px; }
.entity-title { font-size: 16px; font-weight: bold; margin-bottom: 8px; }
.entity-description { padding: 6px 12px; white-space: pre-wrap; color: #495057; }

/* Threat table */
.threat-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 8px;
  font-size: 11px;
}
.threat-table th, .threat-table td {
  border: 1px solid #dee2e6;
  padding: 5px 8px;
  vertical-align: top;
}
.threat-table thead th {
  background: #f8f9fa;
  font-weight: 600;
  white-space: nowrap;
}
.threat-table tbody tr:nth-child(odd) { background: #fdfdfd; }
.threat-table td { white-space: pre-wrap; }

/* Severity colours */
.sev-critical { color: #721c24; font-weight: bold; }
.sev-high     { color: #842029; }
.sev-medium   { color: #664d03; }
.sev-low      { color: #155724; }
.sev-tbd      { color: #6c757d; }

/* Status colours */
.status-open          { color: #842029; }
.status-mitigated     { color: #155724; }
.status-notapplicable { color: #6c757d; }

@media print {
  .page { border: none; margin: 0; padding: 20px; }
}
`;

// ── Standalone SVG document builder ──────────────────────────────────────────
//
// renderDiagramSVG returns an SVG fragment wrapped in a <div>. This function
// strips that wrapper and returns a self-contained SVG document with an XML
// declaration, suitable for saving as a .svg file.

function buildStandaloneSVG(diagram) {
    const cells = rawCells(diagram);
    if (!cells.length) return null;

    const idx = buildIndex(cells);

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const c of cells) {
        if (!c.position) continue;
        const { x, y } = c.position;
        const { width: w = 0, height: h = 0 } = c.size || {};
        minX = Math.min(minX, x);
        minY = Math.min(minY, y);
        maxX = Math.max(maxX, x + w);
        maxY = Math.max(maxY, y + h);
    }
    for (const c of cells) {
        for (const ep of [c.source, c.target]) {
            if (ep && ep.x !== undefined) {
                minX = Math.min(minX, ep.x); minY = Math.min(minY, ep.y);
                maxX = Math.max(maxX, ep.x); maxY = Math.max(maxY, ep.y);
            }
        }
        for (const v of (c.vertices || [])) {
            minX = Math.min(minX, v.x); minY = Math.min(minY, v.y);
            maxX = Math.max(maxX, v.x); maxY = Math.max(maxY, v.y);
        }
    }
    if (!isFinite(minX)) return null;

    const offsetX = minX - SVG_PAD;
    const offsetY = minY - SVG_PAD;
    const svgW    = maxX - minX + SVG_PAD * 2;
    const svgH    = maxY - minY + SVG_PAD * 2;

    const boundaries = cells.filter((c) => resolveShape(c) === 'boundary-box');
    const edges      = cells.filter((c) => ['flow', 'boundary-line'].includes(resolveShape(c)));
    const nodes      = cells.filter((c) => !['flow', 'boundary-line', 'boundary-box'].includes(resolveShape(c)));

    const parts = [
        svgDefs(),
        ...boundaries.map((c) => svgNode(c, offsetX, offsetY)),
        ...nodes.map((c)      => svgNode(c, offsetX, offsetY)),
        ...edges.map((c)      => svgEdge(c, idx, offsetX, offsetY)),
    ].filter(Boolean);

    return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        `<svg xmlns="http://www.w3.org/2000/svg" width="${svgW.toFixed(1)}" height="${svgH.toFixed(1)}" viewBox="0 0 ${svgW.toFixed(1)} ${svgH.toFixed(1)}" style="background:#fff;">`,
        parts.join('\n'),
        '</svg>',
    ].join('\n');
}

// ── Diagram-only export ───────────────────────────────────────────────────────

function slugify(title) {
    return (title || 'diagram')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
}

async function exportDiagrams(diagrams, outDir) {
    let sharp;
    try {
        sharp = require('sharp');
    } catch (e) {
        console.error('Error: PNG export requires the "sharp" package.\n  Run: npm install sharp');
        process.exit(1);
    }

    fs.mkdirSync(outDir, { recursive: true });

    const slugs = {};
    for (const diagram of diagrams) {
        const svgDoc = buildStandaloneSVG(diagram);
        if (!svgDoc) {
            console.error(`Skipping "${diagram.title}" — no renderable cells.`);
            continue;
        }

        // Deduplicate filenames when titles collide after slugification
        let slug = slugify(diagram.title);
        if (slugs[slug] !== undefined) {
            slugs[slug]++;
            slug = `${slug}-${slugs[slug]}`;
        } else {
            slugs[slug] = 0;
        }

        const svgPath = path.join(outDir, `${slug}.svg`);
        const pngPath = path.join(outDir, `${slug}.png`);

        fs.writeFileSync(svgPath, svgDoc, 'utf8');
        console.error(`SVG  → ${svgPath}`);

        await sharp(Buffer.from(svgDoc)).png().toFile(pngPath);
        console.error(`PNG  → ${pngPath}`);
    }
}

// ── Assemble document ─────────────────────────────────────────────────────────

const { summary, detail } = model;
const contributors = detail.contributors || [];
const diagrams = (detail.diagrams || [])
    .slice()
    .sort((a, b) => (a.title < b.title ? -1 : a.title > b.title ? 1 : 0));

// ── Output ────────────────────────────────────────────────────────────────────

if (opts.diagramsOnly) {
    const outDir = opts.outputFile ? path.resolve(opts.outputFile) : process.cwd();
    exportDiagrams(diagrams, outDir).catch((e) => {
        console.error('Export failed:', e.message);
        process.exit(1);
    });
} else {
    const stats = computeStats(detail.diagrams || []);

    const sections = [
        renderCoversheet(summary, detail, contributors),
        renderExecutiveSummary(summary.description, stats),
        ...diagrams.map(renderDiagram),
    ];

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Threat Model Report — ${esc(summary.title)}</title>
  <style>${CSS}</style>
</head>
<body>
${sections.join('\n')}
</body>
</html>
`;

    if (opts.outputFile) {
        fs.writeFileSync(path.resolve(opts.outputFile), html, 'utf8');
        console.error(`Report written to ${opts.outputFile}`);
    } else {
        process.stdout.write(html);
    }
}
