const { spawnSync } = require('child_process');
const path = require('path');
const HOOK = path.join(__dirname, '..', 'hooks', 'block-cred-file-access.js');

const bash = (cmd) => ({ tool_name: 'Bash', tool_input: { command: cmd } });

const CASES = [
  ['BLOCK', 'plain cat sftp.json', bash('cat C:/projects/app/.vscode/sftp.json')],
  ['BLOCK', 'type backslash wp-config', bash('type ..\\wp-config.php')],
  ['BLOCK', 'head .env.local', bash('head -5 .env.local')],
  ['BLOCK', 'grep unquoted cred path', bash('grep pass .vscode/sftp.json')],
  ['BLOCK', 'grep quoted full cred path', bash('grep pass "C:/projects/app/.vscode/sftp.json"')],
  ['BLOCK', 'python heredoc open()', bash("python - <<'EOF'\nprint(open('.vscode/sftp.json').read())\nEOF")],
  ['BLOCK', 'python -c open()', bash('python -c "print(open(\'.env\').read())"')],
  ['BLOCK', 'python -c escaped quotes', bash('python -c "print(open(\\".env\\").read())"')],
  ['BLOCK', "python -c no space before flag", bash("python -c'print(open(\".env\").read())'")],
  ['BLOCK', 'backslash .credentials path', bash('cat C:\\Users\\me\\.credentials\\token.json')],
  ['BLOCK', 'command substitution', bash('echo $(cat .env)')],
  ['BLOCK', 'sed unquoted cred target', bash("sed -n '1,20p' wp-config.php")],
  ['BLOCK', 'line continuation', bash('cat \\\n.env')],
  ['BLOCK', 'jq unquoted cred target', bash("jq '.hosts' sftp.json")],
  ['BLOCK', 'single & chain', bash('ls & cat sftp.json')],
  ['BLOCK', 'powershell -Command gc', bash('powershell -Command "gc sftp.json"')],
  ['BLOCK', 'powershell Get-Content -Raw', bash('Get-Content -Raw wp-config.php')],
  ['BLOCK', 'Read tool .env', { tool_name: 'Read', tool_input: { file_path: 'C:\\projects\\app\\.env' } }],
  ['BLOCK', 'Read tool _secrets', { tool_name: 'Read', tool_input: { file_path: 'C:/x/_secrets/creds.txt' } }],
  ['BLOCK', 'Read tool .envrc', { tool_name: 'Read', tool_input: { file_path: 'C:/x/.envrc' } }],
  ['BLOCK', 'Read tool id_ed25519', { tool_name: 'Read', tool_input: { file_path: '/home/me/.ssh/id_ed25519' } }],
  ['BLOCK', 'Grep tool path _secrets no slash', { tool_name: 'Grep', tool_input: { path: 'C:/x/_secrets' } }],
  ['BLOCK', 'bash -c cat .env', bash('bash -c "cat .env"')],
  ['BLOCK', 'sh -c cat wp-config', bash("sh -c 'cat wp-config.php'")],
  ['BLOCK', 'bash -c sed cred target', bash('bash -c "sed -n \'1,20p\' wp-config.php"')],
  ['BLOCK', 'bash here-string cat .env', bash("bash <<< 'cat .env'")],
  ['BLOCK', 'cat .envrc', bash('cat .envrc')],
  ['BLOCK', 'cat redirect .env', bash('cat < .env')],
  ['BLOCK', 'more redirect wp-config', bash('more < wp-config.php')],
  ['BLOCK', 'bat .env', bash('bat .env')],
  ['BLOCK', 'cat ssh ed25519 key', bash('cat ~/.ssh/id_ed25519')],
  ['BLOCK', 'cat .netrc', bash('cat ~/.netrc')],
  ['BLOCK', 'grep quoted spaced path target', bash('grep pass "C:/Users/me/My Secrets/.env"')],
  ['BLOCK', 'grep HOME var target', bash('grep pass "$HOME/.env"')],
  ['BLOCK', 'grep USERPROFILE target', bash('grep pass "%USERPROFILE%\\.env"')],
  ['BLOCK', 'grep parens path target', bash('grep pass "C:/Users/me/Project (live)/.env"')],
  ['BLOCK', 'grep -R bare _secrets dir', bash('grep -R pass _secrets')],
  ['BLOCK', 'grep -R bare .credentials dir', bash('grep -R pass .credentials')],
  ['BLOCK', 'grep quoted relative backslash target', bash('grep pass "..\\wp-config.php"')],
  ['BLOCK', 'git show ref:wp-config.php', bash('git show mybranch:wp-config.php')],
  ['BLOCK', 'git diff .env', bash('git diff .env')],
  ['BLOCK', 'git log -p wp-config', bash('git log -p wp-config.php')],
  ['BLOCK', 'git blame wp-config', bash('git blame wp-config.php')],
  ['BLOCK', 'git -C repo diff .env', bash('git -C repo diff .env')],
  ['BLOCK', 'git -C path show ref:wp-config', bash('git -C /srv/app show HEAD:wp-config.php')],
  ['BLOCK', 'cat real .pem basename', bash('cat certs/private.pem')],
  ['BLOCK', 'Read real .pem basename', { tool_name: 'Read', tool_input: { file_path: '/etc/ssl/server.pem' } }],
  ['BLOCK', 'grep quoted bare cred filename target', bash('grep pass "sftp.json"')],
  ['BLOCK', 'grep pattern then quoted cred file', bash('grep DB_PASSWORD "wp-config.php"')],
  ['BLOCK', 'grep -e pattern then cred file', bash('grep -e DB_PASS .env')],
  ['BLOCK', 'rg pattern with cred file operand', bash('rg secret wp-config.php')],
  ['BLOCK', 'grep -f patternfile then cred target', bash('grep -f patterns.txt .env')],
  ['BLOCK', 'rg -f patternfile then cred target', bash('rg -f patterns.txt .env')],
  ['BLOCK', 'grep -e attached then cred target', bash('grep -eDB_PASS .env')],
  ['BLOCK', 'grep --regexp= then cred target', bash('grep --regexp=DB_PASS .env')],
  ['BLOCK', 'grep -f reads cred as patternfile', bash('grep -f .env access.log')],
  ['BLOCK', 'bare printenv dump', bash('printenv')],
  ['BLOCK', 'bare env dump', bash('env')],
  ['BLOCK', 'env piped to grep', bash('env | grep DB_PASSWORD')],
  ['BLOCK', 'export -p dump', bash('export -p')],
  ['BLOCK', 'printenv after chain', bash('cd /app && printenv')],
  ['BLOCK', 'powershell Get-ChildItem Env:', bash('Get-ChildItem Env:')],
  ['BLOCK', 'powershell gci env:', bash('gci env:')],
  ['BLOCK', 'cat aws credentials', bash('cat ~/.aws/credentials')],
  ['BLOCK', 'cat aws config', bash('cat ~/.aws/config')],
  ['BLOCK', 'cat kube config', bash('cat ~/.kube/config')],
  ['BLOCK', 'cat docker config.json', bash('cat ~/.docker/config.json')],
  ['BLOCK', 'Read tool aws credentials', { tool_name: 'Read', tool_input: { file_path: '/home/me/.aws/credentials' } }],
  ['BLOCK', 'Read tool kube config', { tool_name: 'Read', tool_input: { file_path: '/home/me/.kube/config' } }],
  ['BLOCK', 'env -0 null-delimited dump', bash('env -0')],
  ['BLOCK', 'sudo env dump', bash('sudo env')],
  ['BLOCK', 'quoted powershell env drive', bash('Get-ChildItem "Env:"')],
  ['BLOCK', 'bash -c printenv body', bash('bash -c "printenv"')],
  ['BLOCK', 'env -u residual dump', bash('env -u PATH')],
  ['BLOCK', 'env --unset= residual dump', bash('env --unset=PATH')],
  ['BLOCK', 'env --unset spaced residual dump', bash('env --unset PATH')],
  ['BLOCK', 'sudo env -u residual dump', bash('sudo env -u HOME')],
  ['BLOCK', 'powershell -Command gci env body', bash('powershell -Command "gci Env:"')],

  ['ALLOW', 'printenv single non-secret var', bash('printenv PATH')],
  ['ALLOW', 'env assignment prefix runs command', bash('env NODE_ENV=production node app.js')],
  ['ALLOW', 'env mentioned inside quoted echo', bash('echo "check the env file first"')],
  ['ALLOW', 'ls env directory not env drive', bash('ls ~/project/env/')],
  ['ALLOW', 'cat aws-notes not aws creds', bash('cat aws-notes.md')],
  ['ALLOW', 'printenv redirected to file not context', bash('printenv > vars.txt')],
  ['ALLOW', 'kube config-map hyphen suffix', bash('cat ~/.kube/config-map.yaml')],
  ['ALLOW', 'aws config-notes hyphen suffix', bash('cat ~/.aws/config-notes.md')],
  ['ALLOW', 'nested aws example config not direct', { tool_name: 'Read', tool_input: { file_path: '/repo/docs/.aws/examples/config' } }],
  ['ALLOW', 'env clears then runs command', bash('env -i node app.js')],
  ['ALLOW', 'env -u prefix runs command', bash('env -u NODE_OPTIONS npm test')],
  ['ALLOW', 'envsubst not env dump', bash('envsubst < template.txt')],
  ['ALLOW', 'env help flag', bash('env --help')],
  ['ALLOW', 'printenv version flag', bash('printenv --version')],
  ['ALLOW', 'powershell env single var', bash('Get-ChildItem Env:Path')],
  ['ALLOW', 'powershell env single var backslash', bash('Get-Item Env:\\PATH')],
  ['BLOCK', 'powershell env drive root backslash', bash('gci Env:\\')],
  ['ALLOW', 'notes heredoc prose', bash("cat >> NOTES.md <<'EOF'\nthe guard fired on sftp.json and wp-config.php mentions today\nEOF")],
  ['ALLOW', 'grep quoted regex pattern pipe head', bash('grep -n "sftp.json|token" src/client.py | head -20')],
  ['ALLOW', 'grep quoted bare filename pattern', bash('grep -rn "wp-config.php" docs/')],
  ['ALLOW', 'rg quoted pattern with alternation', bash("rg 'sftp\\.json|_secrets' tools/")],
  ['ALLOW', 'machine-side deploy consumer', bash('python tools/deploy.py prod wp-content/themes/x/file.php')],
  ['ALLOW', 'echo mention then head other file', bash('echo "=== sftp.json targets ===" ; head -10 docs/INDEX.md')],
  ['ALLOW', 'node hook payload', bash('node block-cred-file-access.js < p1.json')],
  ['ALLOW', 'script with cred-adjacent name', bash('python tools/list_targets.py')],
  ['ALLOW', 'cache purge tool', bash('python tools/purge.py --site prod --url https://example.com/page')],
  ['ALLOW', 'head unrelated json', bash('head -20 payload.json')],
  ['ALLOW', 'remote exec wrapper', bash('python tools/remote_exec.py prod --code "echo 1;"')],
  ['ALLOW', 'Read tool normal file', { tool_name: 'Read', tool_input: { file_path: './src/client.py' } }],
  ['ALLOW', 'Read tool README', { tool_name: 'Read', tool_input: { file_path: 'README.md' } }],
  ['ALLOW', 'git diff --stat', bash('git diff --stat')],
  ['ALLOW', 'git commit message mentions cred', bash('git commit -m "harden wp-config.php loading"')],
  ['ALLOW', 'git show non-cred file', bash('git show HEAD:src/index.js')],
  ['ALLOW', 'sed quoted pattern on safe file', bash("sed -n '/sftp.json/p' src/client.py")],
  ['ALLOW', 'awk quoted program on safe file', bash("awk '/wp-config.php/ {print $1}' access_log")],
  ['ALLOW', 'jq quoted filter safe file', bash("jq '.env_name' config-map.json")],
  ['ALLOW', 'bash -c sed safe pattern', bash('bash -c "sed -n \'/sftp.json/p\' src/client.py"')],
  ['ALLOW', 'filename containing secrets word', bash('cat no_secrets_policy.md')],
  ['ALLOW', 'filename containing cred token mid-name', bash('cat docs/how-sftp.json.md')],
  ['ALLOW', 'curl pipe grep escaped .env pattern', bash('curl -sL https://example.com/docs | grep -i "\\.env"')],
  ['ALLOW', 'grep regex word-class .env pattern', bash('grep -E "\\w+\\.env" README.md')],
  ['ALLOW', 'grep escaped .env with boundary', bash('grep "\\.env\\b" docs/hooks.md')],
  ['ALLOW', 'rg cred name as pattern safe dir', bash('rg sftp.json tools/')],
  ['ALLOW', 'grep cred name as pattern in dir', bash('grep -rn wp-config.php src/')],
  ['ALLOW', 'cat .environment not a cred file', bash('cat config.environment')],
  ['ALLOW', 'Read .environment not a cred file', { tool_name: 'Read', tool_input: { file_path: 'src/config.environment' } }],
  ['ALLOW', 'cat double-extension non-key', bash('cat report.key.md')],
  ['ALLOW', 'grep -f patternfile safe target', bash('grep -f patterns.txt access.log')],
];

let pass = 0, fail = 0, block = 0, allow = 0;
const failures = [];
for (const [want, name, payload] of CASES) {
  want === 'BLOCK' ? block++ : allow++;
  const r = spawnSync(process.execPath, [HOOK], { input: JSON.stringify(payload), encoding: 'utf8' });
  if (r.error || r.signal || r.status === null) {
    fail++;
    failures.push(`ERROR want=${want} (spawn ${r.error ? r.error.code : r.signal || 'null-status'})  ${name}`);
    console.log(`FAIL  want=${want} got=ERROR  ${name}`);
    continue;
  }
  if (r.status !== 0 && r.status !== 2) {
    fail++;
    failures.push(`BAD-EXIT ${r.status} want=${want}  ${name} :: ${(r.stderr || '').slice(0, 80)}`);
    console.log(`FAIL  want=${want} got=EXIT${r.status}  ${name}`);
    continue;
  }
  const got = r.status === 2 ? 'BLOCK' : 'ALLOW';
  const ok = got === want;
  ok ? pass++ : fail++;
  if (!ok) failures.push(`want=${want} got=${got}  ${name}`);
  console.log(`${ok ? 'PASS' : 'FAIL'}  want=${want} got=${got}  ${name}`);
}

const bomb = bash('sh '.repeat(60000));
const t0 = Date.now();
const rb = spawnSync(process.execPath, [HOOK], { input: JSON.stringify(bomb), encoding: 'utf8', timeout: 5000 });
const dt = Date.now() - t0;
const perfOk = !rb.error && rb.signal !== 'SIGTERM' && rb.status === 0 && dt < 3000;
perfOk ? pass++ : fail++;
if (!perfOk) failures.push(`ReDoS perf guard: ${dt}ms status=${rb.status} signal=${rb.signal}`);
console.log(`${perfOk ? 'PASS' : 'FAIL'}  perf  180KB command handled in ${dt}ms (limit 3000)`);

console.log(`\n${block} block + ${allow} allow + 1 perf = ${CASES.length + 1} cases`);
console.log(`${pass} passed, ${fail} failed`);
if (failures.length) console.log('\nFAILURES:\n  ' + failures.join('\n  '));
process.exit(fail ? 1 : 0);
