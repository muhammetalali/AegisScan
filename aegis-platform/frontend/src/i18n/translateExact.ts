/** Translate only complete UI literals, never fragments of user data or larger words. */
export const translateExact = (raw: string, catalog: Record<string, string>): string => {
  const literal = raw.trim()
  if (!literal || !Object.prototype.hasOwnProperty.call(catalog, literal)) return raw
  const translated = catalog[literal]
  if (!translated || translated === literal) return raw
  const position = raw.indexOf(literal)
  return raw.slice(0, position) + translated + raw.slice(position + literal.length)
}
