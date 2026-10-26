#!/usr/bin/env node
'use strict';
/**
 * flutter-security-audit triage scanner (zero dependencies).
 *
 *   node scan.cjs <project-dir> [--out leads.json] [--min-severity low]
 *                               [--fail-on high] [--include-tests] [--quiet]
 *
 * Output is a list of LEADS for the audit workflow to validate.
 * A lead is never a confirmed vulnerability on its own.
 *
 * Suppress a line with a trailing comment:  // fsa-ignore: FSA-XXX-000 reason
 */

const fs = require('fs');
const path = require('path');
const RULES = require('./rules.cjs');

const VERSION = '0.1.0';
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const SKIP_DIRS = new Set([
  '.git', '.dart_tool', 'build', 'node_modules', 'Pods', '.symlinks',
  '.gradle', '.idea', '.vscode', '.fvm', 'ephemeral', '.pub-cache', 'coverage',
]);
const MAX_FILE_BYTES = 1024 * 1024;
// Test code and fixtures are skipped unless --include-tests is passed.
const TEST_PATH = /(^|\/)(test|tests|integration_test|test_driver|testing|fixtures?)\/|_test\.dart$/;

function parseArgs(argv) {
  const args = { dir: null, out: null, minSeverity: 'info', failOn: null, quiet: false, includeTests: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') args.out = argv[++i];
    else if (a === '--min-severity') args.minSeverity = argv[++i];
    else if (a === '--fail-on') args.failOn = argv[++i];
    else if (a === '--quiet') args.quiet = true;
    else if (a === '--include-tests') args.includeTests = true;
    else if (a === '-h' || a === '--help') args.help = true;
    else if (!args.dir) args.dir = a;
    else throw new Error(`Unexpected argument: ${a}`);
  }
  for (const key of ['minSeverity', 'failOn']) {
    if (args[key] && !SEVERITIES.includes(args[key])) {
      throw new Error(`--${key === 'minSeverity' ? 'min-severity' : 'fail-on'} must be one of ${SEVERITIES.join(', ')}`);
    }
  }
  return args;
}

function* walk(dir, root) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.isSymbolicLink()) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      yield* walk(full, root);
    } else if (e.isFile()) {
      yield path.relative(root, full).split(path.sep).join('/');
    }
  }
}

function lineInfo(text, index) {
  let line = 1;
  let start = 0;
  for (let i = 0; i < index; i++) {
    if (text.charCodeAt(i) === 10) { line++; start = i + 1; }
  }
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  return { line, text: text.slice(start, end) };
}

function redact(snippet) {
  // Never echo full secrets into reports: long tokens that mix letters and digits
  // keep only their first 6 chars. Plain identifiers (PaymentResultActivity) stay readable.
  return snippet
    .replace(/[A-Za-z0-9_\-:+/=]{20,}/g, (tok) =>
      (/\d/.test(tok) && /[A-Za-z]/.test(tok) ? tok.slice(0, 6) + '…' : tok))
    .trim()
    .slice(0, 200);
}

function scan(rootDir, opts = {}) {
  const minIdx = SEVERITIES.indexOf(opts.minSeverity || 'info');
  const root = path.resolve(rootDir);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    throw new Error(`Not a directory: ${rootDir}`);
  }
  const leads = [];
  let filesScanned = 0;

  let testFilesSkipped = 0;
  for (const rel of walk(root, root)) {
    if (!opts.includeTests && TEST_PATH.test(rel)) { testFilesSkipped++; continue; }
    const rules = RULES.filter((r) => r.files.test(rel) && SEVERITIES.indexOf(r.severity) >= minIdx);
    if (!rules.length) continue;
    const full = path.join(root, rel);
    let stat;
    try { stat = fs.statSync(full); } catch { continue; }
    if (stat.size > MAX_FILE_BYTES) continue;
    const text = fs.readFileSync(full, 'utf8');
    if (text.includes('\u0000')) continue; // binary
    filesScanned++;

    for (const rule of rules) {
      if (rule.exclude && rule.exclude.test(rel)) continue;
      const re = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g');
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        if (rule.matchExclude && rule.matchExclude.test(m[0])) continue;
        const info = lineInfo(text, m.index);
        if (rule.exclude && rule.exclude.test(info.text)) continue;
        const ignore = info.text.match(/fsa-ignore(?::\s*([A-Z0-9,\- ]+))?/);
        if (ignore && (!ignore[1] || ignore[1].includes(rule.id))) continue;
        leads.push({
          rule: rule.id,
          title: rule.title,
          severity_hint: rule.severity,
          file: rel,
          line: info.line,
          snippet: redact(m[0].includes('\n') ? m[0].replace(/\s+/g, ' ') : info.text),
          masvs: rule.masvs,
          guide: rule.guide,
          message: rule.message,
          fix: rule.fix,
        });
      }
    }
  }

  leads.sort((a, b) =>
    SEVERITIES.indexOf(b.severity_hint) - SEVERITIES.indexOf(a.severity_hint) ||
    a.file.localeCompare(b.file) || a.line - b.line);

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const l of leads) counts[l.severity_hint]++;

  return {
    tool: 'flutter-security-audit/scan',
    version: VERSION,
    target: path.basename(root),
    generated_at: new Date().toISOString(),
    files_scanned: filesScanned,
    test_files_skipped: testFilesSkipped,
    rules_loaded: RULES.length,
    counts,
    note: 'Leads are triage hints. Each must be traced and validated before it is reported as a finding.',
    leads,
  };
}

function printHuman(result) {
  const colors = { critical: 35, high: 31, medium: 33, low: 36, info: 90 };
  const tty = process.stdout.isTTY;
  const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
  console.log(`\nflutter-security-audit · ${result.target} · ${result.files_scanned} files · ${result.rules_loaded} rules\n`);
  if (!result.leads.length) { console.log('No leads. Run the full skill workflow for logic, auth and backend issues.\n'); return; }
  for (const l of result.leads) {
    console.log(`${c(colors[l.severity_hint], l.severity_hint.toUpperCase().padEnd(8))} ${l.rule}  ${l.title}`);
    console.log(`         ${l.file}:${l.line}`);
    console.log(`         ${c(90, l.snippet)}`);
  }
  const summary = SEVERITIES.slice().reverse().map((s) => `${s}: ${result.counts[s]}`).join('  ');
  console.log(`\n${result.leads.length} leads  (${summary})`);
  console.log('Leads are hints, not findings. Validate each one (see SKILL.md, phase 3).\n');
}

function main() {
  let args;
  try { args = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); process.exit(2); }
  if (args.help || !args.dir) {
    console.log('Usage: node scan.cjs <flutter-project-dir> [--out leads.json] [--min-severity info|low|medium|high|critical] [--fail-on <severity>] [--include-tests] [--quiet]');
    process.exit(args.help ? 0 : 2);
  }
  let result;
  try { result = scan(args.dir, { minSeverity: args.minSeverity, includeTests: args.includeTests }); } catch (e) { console.error(e.message); process.exit(2); }
  if (args.out) {
    fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
    fs.writeFileSync(args.out, JSON.stringify(result, null, 2) + '\n');
  }
  if (!args.quiet) printHuman(result);
  if (args.failOn) {
    const threshold = SEVERITIES.indexOf(args.failOn);
    if (result.leads.some((l) => SEVERITIES.indexOf(l.severity_hint) >= threshold)) process.exit(1);
  }
}

if (require.main === module) main();
module.exports = { scan, SEVERITIES };
