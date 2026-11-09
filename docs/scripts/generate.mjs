// Builds the reference pages from the repository sources before `nuxt dev` / `nuxt generate`.
// Output (gitignored, rewritten on every run):
//   content/3.reference/  JS API + types (guest-js/index.ts), Tauri commands (src/commands.rs), permissions (permissions/)
//   content/9.changelog.md  CHANGELOG.md with frontmatter and site links
// Edit the sources, never the generated pages.
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'
import { parse as parseToml } from 'smol-toml'

const root = fileURLToPath(new URL('../../', import.meta.url))
const content = fileURLToPath(new URL('../content/', import.meta.url))
const refDir = `${content}3.reference/`
const repo = 'https://github.com/s00d/tauri-plugin-keyring-store/blob/main/'

const read = (rel) => readFileSync(root + rel, 'utf8')
const page = (title, description, source, body) =>
  `---\ntitle: ${JSON.stringify(title)}\ndescription: ${JSON.stringify(description)}\ngenerated: true\n---\n\n` +
  `<!-- Generated from ${source} by docs/scripts/generate.mjs. Edit the source, not this file. -->\n\n${body.trim()}\n`
// Inline code inside a table cell: one line, `|` escaped for GFM.
const cell = (text) => (text ? '`' + text.replace(/\s+/g, ' ').replace(/\|/g, '\\|') + '`' : '')
const oneLine = (text) => (text || '').replace(/\s*\n\s*/g, ' ').replace(/\|/g, '\\|').trim()
function check(cond, message) {
  if (!cond) throw new Error(`generate.mjs: ${message}`)
}

// ---------------------------------------------------------------- JS API (TypeScript compiler API)

function sourceFile(rel) {
  return ts.createSourceFile(rel, read(rel), ts.ScriptTarget.Latest, true)
}

function jsdoc(node) {
  const docs = ts.getJSDocCommentsAndTags(node).filter(ts.isJSDoc)
  const doc = docs.at(-1)
  if (!doc) return { text: '', tags: {} }
  const tags = {}
  for (const tag of doc.tags ?? []) tags[tag.tagName.text] = ts.getTextOfJSDocComment(tag.comment) ?? ''
  return { text: ts.getTextOfJSDocComment(doc.comment) ?? '', tags }
}

function docBlock({ text, tags }) {
  const out = []
  if ('deprecated' in tags) out.push(`**Deprecated.** ${tags.deprecated}`.trim())
  if (text) out.push(text)
  // Rustdoc-style intra-doc links (`[`name`]`) have no target on the site.
  return out.join('\n\n').replace(/\[(`[^`]+`)\](?!\()/g, '$1')
}

// `name<T>(a: A, b?: B): R` from a function declaration, arrow function or method.
function fnSig(name, fn, sf) {
  const tp = fn.typeParameters ? `<${fn.typeParameters.map((t) => t.getText(sf)).join(', ')}>` : ''
  const params = fn.parameters.map((p) => p.getText(sf)).join(', ')
  return `${name}${tp}(${params})${fn.type ? `: ${fn.type.getText(sf)}` : ''}`.replace(/\s+/g, ' ').replace(/\(\s/g, '(').replace(/,?\s\)/g, ')')
}

const hasModifier = (node, kind) => node.modifiers?.some((m) => m.kind === kind) ?? false
const isFn = (node) => node && (ts.isArrowFunction(node) || ts.isFunctionExpression(node))

// Public surface = every `export` of guest-js/index.ts (one file).
const indexSf = sourceFile('guest-js/index.ts')
const api = { functions: [], constants: [], classes: [], interfaces: [], aliases: [] }
// Every class of the file, exported or not: an exported class may extend a private one (KeyringVault).
const allClasses = new Map(indexSf.statements.filter(ts.isClassDeclaration).map((c) => [c.name.text, c]))

// Public methods of a class, inherited ones (from a class in the same file) included.
function classMembers(cls) {
  const base = cls.heritageClauses?.find((h) => h.token === ts.SyntaxKind.ExtendsKeyword)?.types[0]?.expression.getText(indexSf)
  const own = cls.members
    .filter((m) => ts.isMethodDeclaration(m) && !hasModifier(m, ts.SyntaxKind.PrivateKeyword) && !hasModifier(m, ts.SyntaxKind.ProtectedKeyword))
    .map((m) => {
      const isStatic = hasModifier(m, ts.SyntaxKind.StaticKeyword)
      const full = `${cls.name.text}.${m.name.getText(indexSf)}`
      return { name: full, sig: (isStatic ? 'static ' : '') + fnSig(m.name.getText(indexSf), m, indexSf), doc: docBlock(jsdoc(m)) }
    })
  const inherited = base && allClasses.has(base)
    ? classMembers(allClasses.get(base)).map((e) => ({ ...e, name: `${cls.name.text}.${e.name.split('.').pop()}` }))
    : []
  const ownNames = new Set(own.map((e) => e.name))
  return [...own, ...inherited.filter((e) => !ownNames.has(e.name))]
}

for (const st of indexSf.statements) {
  if (!hasModifier(st, ts.SyntaxKind.ExportKeyword)) continue
  const doc = jsdoc(st)
  if ('internal' in doc.tags) continue
  if (ts.isFunctionDeclaration(st)) {
    api.functions.push({ name: st.name.text, sig: fnSig(st.name.text, st, indexSf), doc: docBlock(doc) })
  } else if (ts.isClassDeclaration(st)) {
    const ext = st.heritageClauses?.map((h) => h.getText(indexSf)).join(' ')
    api.classes.push({ name: st.name.text, ext, doc: docBlock(doc), members: classMembers(st) })
  } else if (ts.isVariableStatement(st)) {
    for (const d of st.declarationList.declarations) {
      const name = d.name.getText(indexSf)
      if (isFn(d.initializer)) api.functions.push({ name, sig: fnSig(name, d.initializer, indexSf), doc: docBlock(jsdoc(st)) })
      else api.constants.push({ name, sig: `const ${d.getText(indexSf)}`, doc: docBlock(jsdoc(st)) })
    }
  } else if (ts.isInterfaceDeclaration(st)) api.interfaces.push(st)
  else if (ts.isTypeAliasDeclaration(st)) api.aliases.push(st)
}
check(api.classes.some((c) => c.name === 'KeyringSession'), 'guest-js/index.ts does not export KeyringSession')
check(api.functions.some((f) => f.name === 'getPasswords'), 'guest-js/index.ts does not export getPasswords()')
const allMembers = () => [...api.classes.flatMap((c) => c.members), ...api.functions]
const undocumented = allMembers().filter((e) => !e.doc).map((e) => e.name)
if (undocumented.length) console.warn(`generate.mjs: no JSDoc: ${undocumented.join(', ')}`)

const anchor = (name) => name.toLowerCase().replace(/\./g, '')
const entries = (list) =>
  list.map((e) => `### \`${e.name}()\`\n\n\`\`\`ts\n${e.sig}\n\`\`\`\n${e.doc ? `\n${e.doc}\n` : ''}`).join('\n')
const summary = (list) =>
  '| Function | Description |\n|----------|-------------|\n' +
  list.map((e) => `| [${cell(e.name + '()')}](#${anchor(e.name)}) | ${oneLine(e.doc.split('\n\n')[0])} |`).join('\n')

function jsApiPage() {
  const body = [
    'Everything `tauri-plugin-keyring-store-api` exports, generated from',
    `[\`guest-js/index.ts\`](${repo}guest-js/index.ts). Option and result types are on the [types page](/reference/types);`,
    'how the pieces fit together is in the [guides](/guides/sessions). Every method is a thin wrapper over one',
    '[Tauri command](/reference/commands); errors arrive as a rejected promise with the error string.',
    '',
    summary(allMembers()),
    '',
    ...api.classes.flatMap((c) => [
      `## \`${c.name}\``,
      '',
      c.doc,
      c.ext ? `\n${cell(c.ext)}; inherited methods are listed too.\n` : '',
      entries(c.members),
    ]),
    '## Functions',
    '',
    entries(api.functions),
    '## Constants',
    '',
    api.constants.map((e) => `### \`${e.name}\`\n\n\`\`\`ts\n${e.sig}\n\`\`\`\n${e.doc ? `\n${e.doc}\n` : ''}`).join('\n'),
  ].join('\n')
  return page('JavaScript API', 'Every class, method and function of tauri-plugin-keyring-store-api, generated from guest-js/index.ts.', 'guest-js/index.ts', body)
}

function typesPage() {
  const sf = indexSf
  const head = (name, st) => {
    const doc = docBlock(jsdoc(st))
    return `### \`${name}\`\n\n${doc ? `${doc}\n\n` : ''}`
  }
  const interfaces = api.interfaces.map((st) => {
    const ext = st.heritageClauses?.map((h) => h.getText(sf)).join(' ')
    const rows = st.members.map((m) => {
      const d = docBlock(jsdoc(m))
      // `readTimeout?: number // milliseconds`: a trailing line comment is the description too.
      const trailing = sf.text.slice(m.end, sf.text.indexOf('\n', m.end)).match(/\/\/\s*(.*)$/)?.[1] ?? ''
      const desc = oneLine([d, trailing].filter(Boolean).join(' '))
      if (ts.isIndexSignatureDeclaration(m)) return `| ${cell(m.parameters[0].getText(sf).replace(/^/, '[') + ']')} | ${cell(m.type.getText(sf))} | ${desc} |`
      const opt = m.questionToken ? '?' : ''
      return `| ${cell(m.name.getText(sf) + opt)} | ${cell(m.type?.getText(sf) ?? 'unknown')} | ${desc} |`
    })
    const name = st.name.text + (st.typeParameters ? `<${st.typeParameters.map((t) => t.getText(sf)).join(', ')}>` : '')
    return `${head(name, st)}${ext ? `Extends ${cell(ext.replace(/^extends\s+/, ''))}.\n\n` : ''}| Property | Type | Description |\n|----------|------|-------------|\n${rows.join('\n')}\n`
  })
  const aliases = api.aliases.map((st) => `${head(st.name.text, st)}\`\`\`ts\n${st.getText(sf).replace(/^export\s+/, '')}\n\`\`\`\n`)
  check(interfaces.length > 0, 'no exported interfaces found in guest-js/index.ts')

  const body = [
    'Every interface and type alias `tauri-plugin-keyring-store-api` exports, generated from',
    `[\`guest-js/index.ts\`](${repo}guest-js/index.ts). Request types are sent to the [commands](/reference/commands)`,
    'as is (camelCase); event payload types describe what the backend emits.',
    '',
    '## Interfaces',
    '',
    interfaces.join('\n'),
    '## Type aliases',
    '',
    aliases.join('\n'),
  ].join('\n')
  return page('Types', 'Request, event and result types of tauri-plugin-keyring-store-api, generated from guest-js/index.ts.', 'guest-js/index.ts', body)
}

// ---------------------------------------------------------------- Permissions (permissions/**)

function tomlFiles(dir) {
  return readdirSync(root + dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? tomlFiles(`${dir}/${e.name}`) : e.name.endsWith('.toml') ? [`${dir}/${e.name}`] : [],
  )
}

const permissions = [] // { identifier, description, allow: [], deny: [] }
for (const file of tomlFiles('permissions/autogenerated').sort()) {
  for (const p of parseToml(read(file)).permission ?? []) {
    permissions.push({ identifier: p.identifier, description: p.description ?? '', allow: p.commands?.allow ?? [], deny: p.commands?.deny ?? [] })
  }
}
const defaults = parseToml(read('permissions/default.toml')).default ?? { description: '', permissions: [] }
check(permissions.length > 0, 'no permissions found under permissions/autogenerated')
const permissionIds = new Set(permissions.map((p) => p.identifier))

function permissionsPage() {
  const inDefault = new Set(defaults.permissions)
  const rows = permissions
    .map((p) => `| ${cell(`keyring-store:${p.identifier}`)} | ${oneLine(p.description)} | ${inDefault.has(p.identifier) ? '✓' : ''} |`)
    .join('\n')
  const body = [
    `Generated from [\`permissions/default.toml\`](${repo}permissions/default.toml) and`,
    `[\`permissions/autogenerated/\`](${repo}permissions/autogenerated), which Tauri writes from the command list.`,
    'How to use them in a capability: [Permissions guide](/guides/permissions).',
    '',
    '## Default permission set',
    '',
    'Identifier: `keyring-store:default`',
    '',
    defaults.description.trim(),
    '',
    `It includes ${defaults.permissions.length} permissions:`,
    '',
    defaults.permissions.map((p) => `\`${p}\``).join(', '),
    '',
    '## All permissions',
    '',
    '| Identifier | Description | In default |',
    '|------------|-------------|------------|',
    rows,
  ].join('\n')
  return page('Permissions', 'Every permission identifier of the plugin, generated from permissions/.', 'permissions/', body)
}

// ---------------------------------------------------------------- Tauri commands (src/commands.rs)

// Splits `a: T<X, Y>, b: U` on top-level commas.
function splitTopLevel(text) {
  const parts = []
  let depth = 0
  let cur = ''
  for (const ch of text) {
    if ('(<['.includes(ch)) depth++
    if (')>]'.includes(ch)) depth--
    if (ch === ',' && depth === 0) {
      parts.push(cur)
      cur = ''
    } else cur += ch
  }
  if (cur.trim()) parts.push(cur)
  return parts.map((p) => p.trim()).filter(Boolean)
}

const camel = (s) => s.replace(/_([a-z])/g, (_, c) => c.toUpperCase())

// Rust doc -> page text: `# Parameters` / `# Returns` only repeat the table below, so they go;
// other `# Section` headings become bold lines (a markdown `#` would be a page title).
function rustDoc(lines) {
  const out = []
  let skip = false
  for (const line of lines) {
    const h = line.match(/^#+\s+(.*)$/)
    if (h) {
      skip = /^(Parameters|Returns)$/.test(h[1].trim())
      if (!skip) out.push(`**${h[1].trim()}**`, '')
      continue
    }
    if (!skip) out.push(line)
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n').trim()
}

function parseCommands(src) {
  const lines = src.split('\n')
  const commands = []
  let doc = []
  let cfg = ''
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (line.startsWith('///')) {
      doc.push(line.replace(/^\/\/\/ ?/, ''))
      continue
    }
    if (line !== '#[tauri::command]' && line !== '#[command]') {
      if (line.startsWith('#[cfg(')) cfg = line.slice(2, -1)
      else if (!line.startsWith('#[')) {
        doc = []
        cfg = ''
      }
      continue
    }
    // Skip further attributes, then read the signature up to the body's `{`.
    let j = i + 1
    while (lines[j].trim().startsWith('#[')) j++
    let sig = ''
    while (!sig.includes('{')) sig += lines[j++] + '\n'
    sig = sig.slice(0, sig.indexOf('{'))
    const m = sig.match(/pub(?:\([^)]*\))?\s+(async\s+)?fn\s+(\w+)\s*(<[^(]*>)?\s*\(/)
    check(m, `cannot parse command signature near line ${i + 1} of src/commands.rs`)
    const open = sig.indexOf('(', m.index + m[0].length - 1)
    let depth = 0
    let close = open
    for (; close < sig.length; close++) {
      if (sig[close] === '(') depth++
      if (sig[close] === ')' && --depth === 0) break
    }
    const params = splitTopLevel(sig.slice(open + 1, close))
      .map((p) => {
        const [name, ...type] = p.replace(/^#\[[^\]]*\]\s*/, '').split(':')
        return { name: name.trim(), type: type.join(':').trim() }
      })
      // Injected by Tauri, not passed from JS.
      .filter((p) => !/^(AppHandle|State|Window|WebviewWindow|Webview)\b/.test(p.type))
    const ret = sig.slice(close + 1).replace(/^\s*->\s*/, '').trim()
    const ok = ret.match(/^Result<([\s\S]*?)(,\s*Error)?>$/)?.[1].trim() ?? ret
    // `#[cfg(feature = "x")]` / `#[cfg(not(...))]` pairs: document the first (feature on) variant once.
    if (commands.some((c) => c.name === m[2])) {
      doc = []
      cfg = ''
      i = j - 1
      continue
    }
    commands.push({
      cfg,
      name: m[2],
      async: Boolean(m[1]),
      params,
      returns: ok.replace(/\s+/g, ' '),
      // "See <site>/reference/commands" lines point back at this very page.
      doc: rustDoc(doc),
    })
    doc = []
    cfg = ''
    i = j - 1
  }
  return commands
}

function commandsPage() {
  const commands = parseCommands(read('src/commands.rs'))
  check(commands.length > 0, 'no #[tauri::command] functions found in src/commands.rs')

  const noPermission = commands.filter((c) => !permissionIds.has(`allow-${c.name.replace(/_/g, '-')}`)).map((c) => c.name)
  if (noPermission.length) console.warn(`generate.mjs: commands without an allow-* permission: ${noPermission.join(', ')}`)

  const summary = commands.map((c) => `| [${cell(c.name)}](#${c.name}) | ${oneLine(c.doc.split('\n')[0])} |`).join('\n')
  const details = commands
    .map((c) => {
      const permission = `allow-${c.name.replace(/_/g, '-')}`
      const params = c.params.length
        ? '| Argument (JS) | Rust parameter | Type |\n|---------------|----------------|------|\n' +
          c.params.map((p) => `| ${cell(camel(p.name))} | ${cell(p.name)} | ${cell(p.type)} |`).join('\n')
        : 'No arguments.'
      return [
        `### \`${c.name}\``,
        '',
        c.doc,
        '',
        '```ts',
        `invoke('plugin:keyring-store|${c.name}'${c.params.length ? `, { ${c.params.map((p) => camel(p.name)).join(', ')} }` : ''})`,
        '```',
        '',
        params,
        '',
        `Returns ${cell(c.returns)}. ${c.async ? 'Rust: `async fn`.' : 'Rust: plain (sync) `fn`.'}` +
          (permissionIds.has(permission) ? ` Permission: ${cell(`keyring-store:${permission}`)}.` : '') +
          (c.cfg ? ` Compiled with ${cell(c.cfg)}; otherwise the command rejects with a crypto error.` : ''),
        '',
      ].join('\n')
    })
    .join('\n')

  const body = [
    `The \`#[tauri::command]\` functions in [\`src/commands.rs\`](${repo}src/commands.rs), which the JS package calls`,
    'with `invoke(\'plugin:keyring-store|<name>\', args)`. You normally use the [JavaScript API](/reference/javascript-api)',
    'instead; this list is for calling commands directly. From Rust, see [Rust backend](/guides/rust).',
    'Arguments are sent in camelCase; the `State` parameter is injected by Tauri and not listed. `PathBuf` and',
    '`BytesDto` arguments take a JS string (a `BytesDto` also takes a byte array). Every keyring call runs on a',
    'blocking thread, so an OS prompt never stalls the async runtime.',
    '',
    '| Command | Description |',
    '|---------|-------------|',
    summary,
    '',
    '## Commands',
    '',
    details,
  ].join('\n')
  return page('Tauri commands', 'Every Tauri command of the plugin with its arguments, generated from src/commands.rs.', 'src/commands.rs', body)
}

// ---------------------------------------------------------------- Changelog (CHANGELOG.md)

function changelogPage() {
  let body = read('CHANGELOG.md').replace(/^# .*\n/, '')
  // Relative links would 404 on the site.
  body = body.replace(/\]\((?!https?:|#|\/|mailto:)([^)]+)\)/g, (_, target) => `](${repo}${target})`)
  return page('Changelog', 'All notable changes to tauri-plugin-keyring-store and tauri-plugin-keyring-store-api.', 'CHANGELOG.md', body)
}

// ---------------------------------------------------------------- write

rmSync(refDir, { recursive: true, force: true })
mkdirSync(refDir, { recursive: true })
const out = {
  [`${refDir}.navigation.yml`]: 'title: API reference\nicon: i-lucide-file-code\n',
  [`${refDir}1.javascript-api.md`]: jsApiPage(),
  [`${refDir}2.types.md`]: typesPage(),
  [`${refDir}3.commands.md`]: commandsPage(),
  [`${refDir}4.permissions.md`]: permissionsPage(),
  [`${content}9.changelog.md`]: changelogPage(),
}
for (const [file, text] of Object.entries(out)) {
  writeFileSync(file, text)
  console.log(`generated ${file.slice(root.length)}`)
}
