import fs from 'node:fs'
import path from 'node:path'

const root = process.cwd()
const appPath = path.join(root, 'src', 'App.tsx')
const contractPath = path.join(root, 'src', 'contracts', 'api.ts')
const source = fs.readFileSync(appPath, 'utf8')
const contractSource = fs.readFileSync(contractPath, 'utf8')
const failures = []
const checkedImports = []
const scannedSourceFiles = []

for (const match of source.matchAll(/import\('\.\/([^']+)'\)/g)) {
  const relative = match[1]
  const resolved = [
    path.join(root, 'src', `${relative}.tsx`),
    path.join(root, 'src', `${relative}.ts`),
    path.join(root, 'src', `${relative}.jsx`),
    path.join(root, 'src', `${relative}.js`),
    path.join(root, 'src', relative, 'index.tsx'),
    path.join(root, 'src', relative, 'index.ts'),
  ].find(fs.existsSync)
  if (!resolved) {
    failures.push(`Missing lazy route module: ./src/${relative}`)
    continue
  }
  const size = fs.statSync(resolved).size
  checkedImports.push({ module: relative, bytes: size })
  if (size < 150) failures.push(`Suspiciously tiny routed module (${size} bytes): ./src/${relative}`)
}

const routePaths = [...source.matchAll(/<Route path="([^"]+)"/g)].map((m) => m[1])
for (const required of ['/dashboard', '/scan', '/validations/new', '/vulnerabilities', '/compliance', '/digital-twin', '/assurance/graph', '/reports']) {
  if (!routePaths.includes(required)) failures.push(`Required UI route missing: ${required}`)
}
if (!routePaths.includes('/')) failures.push('Protected workspace has no canonical root redirect')
if (!routePaths.some((route) => route === '/digital-twin')) failures.push('Digital Twin route is not registered')

if (/`\/api\/v1\//.test(contractSource) || /'\/api\/v1\//.test(contractSource)) {
  failures.push('Frontend API contracts must be relative to the centralized /api/v1 baseURL')
}

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['node_modules', 'dist', '.git'].includes(entry.name)) continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(full)
    else if (/\.(ts|tsx)$/.test(entry.name)) scannedSourceFiles.push(full)
  }
}
walk(path.join(root, 'src'))

const staticMetricPatterns = [
  /\bAssets:\s*\d+\b/i,
  /\bServices:\s*\d+\b/i,
  /\bRelationships:\s*\d+\b/i,
  /\bAttack Paths:\s*\d+\b/i,
  /\bControls:\s*\d+\b/i,
  /\bFindings:\s*\d+\s*(?:→|->)\s*\d+\b/i,
  /\bRisk\s*\d+\/100\b/i,
  /\bRisk\s*Score[^\n]{0,80}\b\d+\b/i,
]
const stubPatterns = [
  /coming soon/i,
  /not implemented/i,
  /lorem ipsum/i,
  /mock data/i,
  /dummy data/i,
  /placeholder data/i,
]

for (const file of scannedSourceFiles) {
  if (file.endsWith(path.join('services', 'api.ts'))) continue
  const text = fs.readFileSync(file, 'utf8')
  const relative = path.relative(root, file)
  if (/new\s+WebSocket\s*\(/.test(text)) failures.push(`Direct WebSocket construction outside api service: ${relative}`)
  if (/axios\.(get|post|put|patch|delete)\s*\(/.test(text)) failures.push(`Direct axios call outside api service: ${relative}`)
  for (const pattern of staticMetricPatterns) {
    if (pattern.test(text)) failures.push(`Static security metric detected in UI source: ${relative} (${pattern})`)
  }
  for (const pattern of stubPatterns) {
    if (pattern.test(text)) failures.push(`Stub/placeholder text detected in UI source: ${relative} (${pattern})`)
  }
}

const result = {
  status: failures.length ? 'failed' : 'passed',
  checked_lazy_modules: checkedImports.length,
  scanned_source_files: scannedSourceFiles.length,
  protected_routes: routePaths.length,
  failures,
}
console.log(JSON.stringify(result, null, 2))
if (failures.length) process.exit(1)
