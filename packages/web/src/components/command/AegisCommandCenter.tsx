import { motion } from "framer-motion";
import { AlertTriangle, ArrowUpRight, CheckCircle2, Crosshair, ShieldCheck, Zap } from "lucide-react";
import { Link } from "react-router-dom";

export interface AegisCommandSignal {
  id: string;
  title: string;
  detail: string;
  severity: "critical" | "high" | "medium" | "success";
  action?: string;
  actionUrl?: string;
}

interface AegisCommandCenterProps {
  posture: number;
  delta?: number;
  signals: AegisCommandSignal[];
  decisionsRequired: number;
}

const tone = {
  critical: "text-red-400 border-red-500/20 bg-red-500/5",
  high: "text-orange-400 border-orange-500/20 bg-orange-500/5",
  medium: "text-amber-400 border-amber-500/20 bg-amber-500/5",
  success: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5",
};

const icon = {
  critical: AlertTriangle,
  high: Crosshair,
  medium: Zap,
  success: CheckCircle2,
};

export function AegisCommandCenter({ posture, delta, signals, decisionsRequired }: AegisCommandCenterProps) {
  const hasDelta = typeof delta === "number" && Number.isFinite(delta);
  return (
    <section className="aegis-content aegis-surface aegis-surface-grid overflow-hidden rounded-2xl border border-white/10">
      <div className="flex flex-col gap-4 border-b border-white/10 p-5 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.24em] text-cyan-300">
            <span className="aegis-live-dot" /> Aegis Command Center
          </div>
          <h2 className="text-xl font-semibold tracking-tight text-white">Security decisions, signals and outcomes</h2>
          <p className="mt-1 text-sm text-slate-400">Operational state derived from the current platform telemetry.</p>
        </div>
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-4 py-3 text-right">
          <div className="text-[10px] font-bold uppercase tracking-widest text-emerald-300">Assurance fabric</div>
          <div className="mt-1 flex items-center justify-end gap-2 text-sm text-emerald-200"><ShieldCheck size={15} /> Live</div>
        </div>
      </div>

      <div className="grid gap-px bg-white/5 md:grid-cols-3">
        <div className="bg-slate-950/50 p-5">
          <div className="text-xs font-medium text-slate-500">Security Posture</div>
          <div className="mt-2 flex items-end gap-2"><span className="text-4xl font-semibold tracking-tight text-white">{posture.toFixed(1)}</span><span className="pb-1 text-sm text-slate-500">/ 100</span></div>
          <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/10"><motion.div initial={{ width: 0 }} animate={{ width: `${Math.max(0, Math.min(100, posture))}%` }} transition={{ duration: 1 }} className="h-full rounded-full bg-emerald-400" /></div>
          {hasDelta ? <div className="mt-2 text-xs text-emerald-300">{delta >= 0 ? "↑" : "↓"} {Math.abs(delta).toFixed(1)} this period</div> : <div className="mt-2 text-xs text-slate-500">Trend unavailable</div>}
        </div>
        <div className="bg-slate-950/50 p-5"><div className="text-xs font-medium text-slate-500">Active Signals</div><div className="mt-2 text-4xl font-semibold text-white">{signals.length}</div><div className="mt-2 text-xs text-slate-500">Derived from current telemetry</div></div>
        <div className="bg-slate-950/50 p-5"><div className="text-xs font-medium text-slate-500">Decisions Required</div><div className="mt-2 text-4xl font-semibold text-white">{decisionsRequired}</div><div className="mt-2 text-xs text-amber-300">Current risk requiring attention</div></div>
      </div>

      <div className="p-5">
        <div className="mb-3 text-xs font-bold uppercase tracking-widest text-slate-500">Active security signals</div>
        <div className="space-y-2">
          {!signals.length && <div className="rounded-xl border border-white/10 p-4 text-sm text-slate-400">No active security signals are recorded.</div>}
          {signals.map((signal, index) => {
            const Icon = icon[signal.severity];
            return <motion.div key={signal.id} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.05 }} className={`flex flex-col gap-3 rounded-xl border p-3 lg:flex-row lg:items-center ${tone[signal.severity]}`}>
              <Icon size={18} />
              <div className="min-w-0 flex-1"><div className="text-sm font-semibold text-slate-100">{signal.title}</div><div className="mt-0.5 text-xs text-slate-400">{signal.detail}</div></div>
              {signal.action && signal.actionUrl && <Link to={signal.actionUrl} className="aegis-command-surface rounded-lg px-3 py-2 text-xs font-semibold text-slate-200 hover:text-white">{signal.action}<ArrowUpRight className="ml-1 inline" size={13} /></Link>}
            </motion.div>;
          })}
        </div>
      </div>
    </section>
  );
}

export default AegisCommandCenter;
