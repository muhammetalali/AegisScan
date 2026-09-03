import fs from 'node:fs'
import path from 'node:path'

const root = process.cwd()
const appPath = path.join(root, 'src', 'App.tsx')
const source = fs.readFileSync(appPath, 'utf8')
const failures = []
const checkedImports = []

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

const sourceFiles = []
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['node_modules', 'dist', '.git'].includes(entry.name)) continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(full)
    else if (/\.(ts|tsx)$/.test(entry.name)) sourceFiles.push(full)
  }
}
walk(path.join(root, 'src'))
for (const file of sourceFiles) {
  if (file.endsWith(path.join('services', 'api.ts'))) continue
  const text = fs.readFileSync(file, 'utf8')
  if (/new\s+WebSocket\s*\(/.test(text)) failures.push(`Direct WebSocket construction outside api service: ${path.relative(root, file)}`)
  if (/axios\.(get|post|put|patch|delete)\s*\(/.test(text)) failures.push(`Direct axios call outside api service: ${path.relative(root, file)}`)
}

const result = {
  status: failures.length ? 'failed' : 'passed',
  checked_lazy_modules: checkedImports.length,
  protected_routes: routePaths.length,
  failures,
}
console.log(JSON.stringify(result, null, 2))
if (failures.length) process.exit(1)
