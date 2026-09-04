import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(process.cwd(), 'src/pages')
const extensions = new Set(['.tsx', '.ts'])
const files = []

const walk = dir => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(full)
    else if (extensions.has(path.extname(entry.name))) files.push(full)
  }
}
walk(root)

const suspicious = []
for (const file of files) {
  const text = fs.readFileSync(file, 'utf8')
  const withoutComments = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '')
  const jsxText = [...withoutComments.matchAll(/>\s*([A-Za-z][^<{\n]{2,})\s*</g)].map(m => m[1].trim())
  const hardcodedAttrs = [...withoutComments.matchAll(/\b(?:placeholder|title|aria-label)\s*=\s*"([A-Za-z][^"]{2,})"/g)].map(m => m[1].trim())
  const literals = [...jsxText, ...hardcodedAttrs].filter(value => !/^(svg|path|div|span|main|section|form|input|button|option)$/i.test(value))
  if (literals.length && !text.includes('useLanguageStore')) suspicious.push({ file: path.relative(process.cwd(), file), literals: [...new Set(literals)].slice(0, 20) })
}

console.log(`i18n audit scanned ${files.length} source files.`)
if (!suspicious.length) {
  console.log('I18N_AUDIT=PASS')
  process.exit(0)
}
console.log('Files containing hardcoded user-facing literals without the language store import:')
for (const item of suspicious) {
  console.log(`- ${item.file}`)
  for (const literal of item.literals) console.log(`  • ${literal}`)
}
console.log('I18N_AUDIT=REVIEW')
