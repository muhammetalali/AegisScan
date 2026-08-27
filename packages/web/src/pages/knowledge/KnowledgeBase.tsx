import { BookOpen, Shield, FileText, Lightbulb } from 'lucide-react'
export const KnowledgeBase = () => {
  const items = [
    { title:'HSTS Best Practice', desc:'Enforce Strict-Transport-Security with preload', tag:'Headers' },
    { title:'TLS 1.2+ Remediation', desc:'Disable TLS 1.0/1.1, enable 1.2+', tag:'TLS' },
    { title:'IDOR Prevention', desc:'Object-level authorization checks', tag:'Auth' },
    { title:'XSS Remediation', desc:'Encode output, CSP, input validation', tag:'Injection' },
  ]
  return (
    <div className="space-y-4">
      <div><h1 className="text-2xl font-bold flex items-center gap-2"><BookOpen className="h-6 w-6 text-primary" /> Knowledge Center</h1><p className="text-sm text-muted-foreground">Best Practices • Remediation Guides • Policies • Lessons Learned • FAQs — linked to Findings</p></div>
      <div className="grid md:grid-cols-2 gap-3">
        {items.map(it=>(
          <div key={it.title} className="rounded-xl border bg-card p-4">
            <div className="flex items-center gap-2"><Shield className="h-4 w-4 text-primary" /><span className="text-sm font-medium">{it.title}</span><span className="ml-auto text-[11px] px-1.5 py-0.5 rounded bg-muted">{it.tag}</span></div>
            <p className="text-sm text-muted-foreground mt-1">{it.desc}</p>
            <div className="mt-2 text-xs text-primary">Related Finding → Evidence → Control</div>
          </div>
        ))}
      </div>
      <div className="rounded-xl border bg-card p-4">
        <h3 className="text-sm font-semibold flex items-center gap-1"><Lightbulb className="h-4 w-4" /> Lessons Learned</h3>
        <ul className="mt-2 text-sm list-disc ps-5 text-muted-foreground"><li>Validate inputs server-side, not only client-side</li><li>Enforce HSTS on all subdomains</li><li>Review IDOR on every new API endpoint</li></ul>
      </div>
    </div>
  )
}
