#!/usr/bin/env node
const fs = require('fs');

const CRED_TOKEN = /(?<![\w.-])(?:_secrets(?![\w.-])|\.credentials(?![\w.-])|sftp\.json(?![\w.])|wp-config\.php(?![\w.])|token\.json(?![\w.])|id_rsa(?![\w.])|id_ed25519(?![\w.])|id_ecdsa(?![\w.])|\.netrc(?![\w.])|\.git-credentials(?![\w.])|\.pgpass(?![\w.])|\.aws\/credentials(?![\w.-])|\.aws\/config(?![\w.-])|\.kube\/config(?![\w.-])|\.docker\/config\.json(?![\w.-])|\.env(?:\.[\w-]+|rc)?(?![\w]))|\.(?:pem|key|p12|pfx|ppk)(?![\w.])/i;
const ENV_DUMP = /^(?:sudo\s+|command\s+)?(?:printenv|env)(?:\.exe)?(?:\s+-(?!(?:-?help|-?version|h|V)(?![\w-]))\S+)*\s*$|^export\s+-p\s*$|^(?:Get-ChildItem|Get-Item|gci|ls|dir)\b[^|;&]*(?<![\w-])env:(?![\\/]?\w)/i;
const DUMP_VERB = /(?:^|[\s;&|(`\/])(cat|bat|batcat|head|tail|less|more|nl|xxd|od|strings|type|Get-Content|gc)(?:\.exe)?\b/i;
const GREP_VERB = /(?:^|[\s;&|(`\/])(grep|egrep|fgrep|rg|findstr|Select-String|sls)(?:\.exe)?\b/i;
const SCRIPT_VERB = /(?:^|[\s;&|(`\/])(sed|awk|jq)(?:\.exe)?\b/i;
const GIT_DUMP = /(?:^|[\s;&|(`\/])git(?:\.exe)?\s+(?:\S+\s+)*?(show|diff|log|blame|cat-file|stash)\b/i;
const INTERP = /\b(python[\w.]*|node|bash|sh|zsh|pwsh|powershell)(\.exe)?\b[^|;&]*$/i;
const READ_PRIMITIVE = /\b(open\s*\(|readFile\w*|read_text|read_bytes|ReadAllText|ReadAllBytes|ReadAllLines|readlines|fs\.read|io\.open|slurp)/i;
const HAS_INLINE_FLAG = /(?:^|[\s'"=/-])-(?:c|e)\b|(?:^|[\s'"=/-])-Command\b/i;

function norm(s) {
  return String(s).replace(/\\/g, '/');
}

function credInText(s) {
  return CRED_TOKEN.test(norm(s));
}

function isCredPath(p) {
  if (!p) return false;
  const n = norm(p).toLowerCase();
  const parts = n.split('/');
  const base = parts[parts.length - 1] || '';
  if (parts.indexOf('_secrets') !== -1 || parts.indexOf('.credentials') !== -1) return true;
  if (['sftp.json', 'wp-config.php', 'token.json', 'id_rsa', 'id_ed25519', 'id_ecdsa', '.netrc', '.git-credentials', '.pgpass'].includes(base)) return true;
  const parent = parts[parts.length - 2] || '';
  if (parent === '.aws' && (base === 'credentials' || base === 'config')) return true;
  if (parent === '.kube' && base === 'config') return true;
  if (parent === '.docker' && base === 'config.json') return true;
  if (base === '.env' || base === '.envrc' || base.startsWith('.env.')) return true;
  if (/\.(pem|key|p12|pfx|ppk)$/.test(base)) return true;
  return false;
}

function extractHeredocs(cmd) {
  const out = { text: '', codeBodies: [] };
  const re = /<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1[^\n]*\n([\s\S]*?)(?:\n\2(?:\s|$)|$)/g;
  let m;
  let last = 0;
  while ((m = re.exec(cmd)) !== null) {
    const before = cmd.slice(last, m.index);
    out.text += before;
    if (INTERP.test(before)) out.codeBodies.push(m[3]);
    last = m.index + m[0].length;
  }
  out.text += cmd.slice(last);
  return out;
}

function maskQuotes(text) {
  const store = [];
  const masked = text.replace(/"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'/g, function (m) {
    store.push(m);
    return '\x00' + (store.length - 1) + '\x00';
  });
  return { masked: masked, store: store };
}

function unmask(tok, store) {
  return tok.replace(/\x00(\d+)\x00/g, function (_, i) { return store[+i]; });
}

function inlineCode(text) {
  if (!HAS_INLINE_FLAG.test(text)) return [];
  const bodies = [];
  const re = /(?:^|[\s;&|(`])(?:python[\w.]*|node|pwsh|powershell|bash|zsh|sh)(?:\.exe)?\b[^|;&\n]{0,200}?(?:-c|-e|-Command)\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/gi;
  let m;
  while ((m = re.exec(text)) !== null) bodies.push(m[1].slice(1, -1));
  return bodies;
}

function hereStrings(text) {
  const bodies = [];
  const re = /(?:python[\w.]*|node|bash|zsh|sh|pwsh|powershell)(?:\.exe)?\b[^|;&\n]{0,200}?<<<\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\S+)/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    let b = m[1];
    if ((b[0] === '"' || b[0] === "'") && b[b.length - 1] === b[0]) b = b.slice(1, -1);
    bodies.push(b);
  }
  return bodies;
}

function grepBlocks(segMasked, store) {
  const toks = segMasked.trim().split(/\s+/).filter(Boolean);
  let start = 0;
  for (let k = 0; k < toks.length; k++) {
    if (GREP_VERB.test(' ' + toks[k])) { start = k + 1; break; }
  }
  let explicitPattern = false;
  const positionals = [];
  const targets = [];
  for (let k = start; k < toks.length; k++) {
    const t = toks[k];
    let m;
    if (t === '--') { for (let j = k + 1; j < toks.length; j++) positionals.push(toks[j]); break; }
    if (t[0] === '-') {
      if ((m = t.match(/^-f(.+)$/)) || (m = t.match(/^--file=(.+)$/i))) { explicitPattern = true; targets.push(m[1]); continue; }
      if (/^(?:-f|--file)$/i.test(t)) { explicitPattern = true; if (toks[k + 1] !== undefined) targets.push(toks[++k]); continue; }
      if (/^-e.+$/.test(t) || /^--regexp=.+$/i.test(t)) { explicitPattern = true; continue; }
      if (/^(?:-e|--regexp|-Pattern)$/i.test(t)) { explicitPattern = true; k++; continue; }
      if ((m = t.match(/^(?:-Path|-LiteralPath)=(.+)$/i))) { targets.push(m[1]); continue; }
      if (/^(?:-Path|-LiteralPath)$/i.test(t)) { if (toks[k + 1] !== undefined) targets.push(toks[++k]); continue; }
      if (/^(?:-m|-A|-B|-C|-d|--include|--exclude|--max-count|-Context)$/i.test(t)) { k++; continue; }
      continue;
    }
    positionals.push(t);
  }
  const files = (explicitPattern ? positionals : positionals.slice(1)).concat(targets);
  return files.some(function (x) { return credInText(unmask(x, store)); });
}

function segmentBlocks(segMasked, store) {
  const full = unmask(segMasked, store);
  if (!credInText(full)) return false;
  if (GREP_VERB.test(full)) return grepBlocks(segMasked, store);
  const bare = segMasked.replace(/\x00\d+\x00/g, '');
  if (SCRIPT_VERB.test(bare) || GIT_DUMP.test(bare)) return credInText(bare);
  if (DUMP_VERB.test(full)) return true;
  return false;
}

function codeBlocks(body) {
  if (envDumps(body, [])) return true;
  if (!credInText(body)) return false;
  if (READ_PRIMITIVE.test(body)) return true;
  return body.split(/\n/).some(function (line) {
    if (DUMP_VERB.test(line) && credInText(line)) return true;
    if (SCRIPT_VERB.test(line)) {
      return credInText(line.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, ''));
    }
    return false;
  });
}

function envDumps(masked, store) {
  return masked.split(/[|;&\n]+/).some(function (seg) {
    return ENV_DUMP.test(unmask(seg, store).trim());
  });
}

function cmdTouchesCred(cmd) {
  if (!cmd) return false;
  const her = extractHeredocs(cmd);
  const joined = her.text.replace(/\\\r?\n/g, ' ');
  const mq = maskQuotes(joined);
  if (envDumps(mq.masked, mq.store)) return true;
  const codes = her.codeBodies.concat(inlineCode(joined), hereStrings(joined));
  if (codes.some(codeBlocks)) return true;
  if (!credInText(cmd)) return false;
  const segments = mq.masked.split(/[|;&\n]+/);
  return segments.some(function (s) { return segmentBlocks(s, mq.store); });
}

function readStdin() {
  try {
    return fs.readFileSync(0, 'utf8');
  } catch (e) {
    if (e && e.code === 'EAGAIN') {
      try { return fs.readFileSync('/dev/stdin', 'utf8'); } catch (_) { return null; }
    }
    return null;
  }
}

const raw = readStdin();
if (raw === null) process.exit(0);

let data;
try {
  data = JSON.parse(raw);
} catch (e) {
  process.exit(0);
}

let blocked = false;
try {
  const tool = data.tool_name || '';
  const input = data.tool_input || {};
  if (tool === 'Read') blocked = isCredPath(input.file_path);
  else if (tool === 'Grep') blocked = isCredPath(input.path);
  else if (tool === 'Bash') blocked = cmdTouchesCred(input.command);
} catch (e) {
  process.exit(0);
}

if (blocked) {
  process.stderr.write(
    'BLOCKED by cred-file guard: this command would READ credentials into context, either a ' +
    'credential/secret file (.env, wp-config.php, sftp.json, id_rsa, *.key/.pem, _secrets/*, ' +
    '.credentials/*, .aws/credentials, .kube/config, and similar) or a bulk environment-variable ' +
    'dump (printenv, bare env, gci env:). That would put plaintext secrets into the transcript, ' +
    'which is sent to the model provider and persisted in session logs. Run a script that consumes ' +
    'the value machine-side and prints only success/fail plus non-secret metadata instead, or read a ' +
    'single non-secret variable by name. Merely MENTIONING these filenames (grep/search patterns, ' +
    'prose, notes) is allowed and does not trigger this guard.'
  );
  process.exit(2);
}
process.exit(0);
