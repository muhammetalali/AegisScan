import { motion, useMotionValue, useSpring, useTransform } from 'framer-motion'
import { Activity, ArrowUpRight, Gauge, ShieldCheck } from 'lucide-react'
import { type PointerEvent, useRef } from 'react'

type RecentValidation = {
  id?: string
  validation_id?: string
  target_value?: string
  target?: string
  status?: string
}

type Props = {
  score?: number
  critical?: number
  high?: number
  assets?: number
  validations?: number
  recent: RecentValidation[]
  onExplore?: () => void
}

const clamp = (value: number, min = 0, max = 100) => Math.min(max, Math.max(min, value))

export const SecurityCommandHero = ({ score, critical, high, assets, validations, recent, onExplore }: Props) => {
  const stageRef = useRef<HTMLDivElement>(null)
  const pointerX = useMotionValue(0)
  const pointerY = useMotionValue(0)
  const rotateY = useSpring(useTransform(pointerX, [-1, 1], [-8, 8]), { stiffness: 180, damping: 22 })
  const rotateX = useSpring(useTransform(pointerY, [-1, 1], [7, -7]), { stiffness: 180, damping: 22 })

  const handlePointerMove = (event: PointerEvent<HTMLDivElement>) => {
    const rect = stageRef.current?.getBoundingClientRect()
    if (!rect) return
    pointerX.set((event.clientX - rect.left) / rect.width * 2 - 1)
    pointerY.set((event.clientY - rect.top) / rect.height * 2 - 1)
  }

  const resetPointer = () => {
    pointerX.set(0)
    pointerY.set(0)
  }

  const normalizedScore = score == null ? null : clamp(Math.round(score))
  const scoreAngle = normalizedScore == null ? -90 : -90 + (normalizedScore / 100) * 360
  const recentItems = recent.slice(0, 3)

  const nodes = [
    { label: 'Critical', value: Number(critical ?? 0), tone: 'danger', x: '7%', y: '21%', delay: 0 },
    { label: 'High', value: Number(high ?? 0), tone: 'warning', x: '78%', y: '18%', delay: 0.08 },
    { label: 'Assets', value: Number(assets ?? 0), tone: 'primary', x: '80%', y: '69%', delay: 0.16 },
    { label: 'Validations', value: Number(validations ?? 0), tone: 'violet', x: '5%', y: '70%', delay: 0.24 },
  ]

  return (
    <section className="relative overflow-hidden rounded-[2rem] border border-border/70 bg-[radial-gradient(circle_at_50%_10%,color-mix(in_srgb,var(--primary)_11%,transparent),transparent_34%),linear-gradient(145deg,color-mix(in_srgb,var(--card)_96%,var(--primary)_4%),color-mix(in_srgb,var(--background)_86%,black_14%))] shadow-[0_30px_90px_rgba(0,0,0,.18)]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_80%_45%,color-mix(in_srgb,var(--primary)_7%,transparent),transparent_25%),radial-gradient(circle_at_20%_70%,color-mix(in_srgb,#8b5cf6_6%,transparent),transparent_20%)]" />
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/60 to-transparent" />

      <div className="relative grid min-h-[430px] gap-8 p-6 sm:p-8 lg:grid-cols-[1fr_minmax(420px,1.05fr)] lg:items-center lg:p-10">
        <div className="relative z-10 flex min-h-[320px] flex-col justify-center">
          <div className="mb-5 inline-flex w-fit items-center gap-2 rounded-full border border-primary/20 bg-primary/5 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.18em] text-primary">
            <span className="h-1.5 w-1.5 rounded-full bg-primary shadow-[0_0_14px_var(--primary)]" />
            Security command center
          </div>

          <h1 className="max-w-3xl text-4xl font-semibold tracking-[-0.04em] text-foreground sm:text-5xl lg:text-[4.25rem] lg:leading-[0.98]">
            See the state of your
            <span className="block bg-gradient-to-r from-primary via-sky-300 to-violet-400 bg-clip-text text-transparent">security surface.</span>
          </h1>
          <p className="mt-5 max-w-xl text-sm leading-7 text-muted-foreground sm:text-base">A live operational view built from your recorded assets, validations and findings — designed to move from signal to decision without losing evidence.</p>

          <div className="mt-7 flex flex-wrap items-center gap-3">
            <button type="button" onClick={onExplore} className="group inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground shadow-[0_12px_30px_color-mix(in_srgb,var(--primary)_24%,transparent)] transition-transform duration-200 hover:-translate-y-0.5">
              Explore command center
              <ArrowUpRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
            </button>
            <div className="inline-flex items-center gap-2 rounded-xl border border-border/80 bg-background/25 px-3 py-2.5 text-xs text-muted-foreground backdrop-blur">
              <Activity className="h-3.5 w-3.5 text-primary" />
              Evidence-first telemetry
            </div>
          </div>

          {recentItems.length > 0 && (
            <div className="mt-8 flex flex-wrap gap-2">
              {recentItems.map((item, index) => {
                const id = item.id || item.validation_id || `validation-${index}`
                return (
                  <div key={id} className="max-w-[220px] rounded-xl border border-border/70 bg-background/25 px-3 py-2 backdrop-blur">
                    <div className="truncate font-mono text-[10px] text-foreground/85">{id}</div>
                    <div className="mt-0.5 truncate text-[10px] text-muted-foreground">{item.target_value || item.target || 'Validation execution'}</div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        <motion.div
          ref={stageRef}
          onPointerMove={handlePointerMove}
          onPointerLeave={resetPointer}
          style={{ rotateX, rotateY }}
          className="relative mx-auto flex min-h-[340px] w-full max-w-[580px] items-center justify-center [transform-style:preserve-3d]"
        >
          <div className="absolute inset-[8%] rounded-full border border-primary/10 [transform:translateZ(-30px)]" />
          <div className="absolute inset-[17%] rounded-full border border-primary/10 [transform:translateZ(-10px)]" />
          <div className="absolute h-72 w-72 rounded-full bg-primary/8 blur-2xl" />

          {nodes.map(node => (
            <motion.div
              key={node.label}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.45, delay: node.delay }}
              whileHover={{ scale: 1.05, z: 36 }}
              className={`absolute rounded-2xl border bg-background/50 px-3.5 py-3 shadow-[0_18px_40px_rgba(0,0,0,.18)] backdrop-blur-xl [transform-style:preserve-3d] ${
                node.tone === 'danger' ? 'border-red-400/30' : node.tone === 'warning' ? 'border-amber-400/30' : node.tone === 'violet' ? 'border-violet-400/30' : 'border-primary/30'
              }`}
              style={{ left: node.x, top: node.y }}
            >
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${node.tone === 'danger' ? 'bg-red-400' : node.tone === 'warning' ? 'bg-amber-400' : node.tone === 'violet' ? 'bg-violet-400' : 'bg-primary'}`} />
                <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{node.label}</span>
              </div>
              <div className="mt-1 text-xl font-semibold tracking-tight">{node.value}</div>
            </motion.div>
          ))}

          <motion.div
            className="relative z-10 flex h-64 w-64 items-center justify-center rounded-full border border-white/10 bg-[radial-gradient(circle_at_35%_28%,rgba(255,255,255,.18),transparent_20%),radial-gradient(circle_at_50%_45%,color-mix(in_srgb,var(--primary)_22%,transparent),transparent_58%),linear-gradient(145deg,color-mix(in_srgb,var(--card)_94%,var(--primary)_6%),color-mix(in_srgb,var(--background)_82%,black_18%))] shadow-[inset_0_2px_0_rgba(255,255,255,.12),0_35px_90px_rgba(0,0,0,.3)] [transform-style:preserve-3d]"
            animate={{ rotateZ: [0, 2, 0, -2, 0] }}
            transition={{ duration: 10, repeat: Infinity, ease: 'easeInOut' }}
          >
            <div className="absolute inset-4 rounded-full border border-primary/10" />
            <div className="absolute inset-7 rounded-full border border-dashed border-primary/20" style={{ transform: `rotate(${scoreAngle}deg)` }} />
            <div className="relative text-center [transform:translateZ(34px)]">
              <div className="mx-auto mb-3 grid h-11 w-11 place-items-center rounded-2xl border border-primary/20 bg-primary/10 text-primary shadow-[0_0_30px_color-mix(in_srgb,var(--primary)_18%,transparent)]">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Security score</div>
              <div className="mt-1 text-5xl font-semibold tracking-[-0.06em]">{normalizedScore == null ? '—' : normalizedScore}</div>
              <div className="mt-1 text-[11px] text-muted-foreground">{normalizedScore == null ? 'Waiting for real posture data' : normalizedScore >= 80 ? 'Healthy posture' : normalizedScore >= 60 ? 'Attention recommended' : 'Priority attention'}</div>
            </div>
            <div className="absolute -inset-2 rounded-full border border-primary/15 shadow-[0_0_50px_color-mix(in_srgb,var(--primary)_10%,transparent)]" />
          </motion.div>

          <motion.div className="absolute left-1/2 top-1/2 h-[92%] w-[92%] -translate-x-1/2 -translate-y-1/2 rounded-full border border-primary/8 [transform:translateZ(-5px)]" animate={{ rotate: 360 }} transition={{ duration: 30, repeat: Infinity, ease: 'linear' }} />

          <div className="absolute bottom-0 left-1/2 flex -translate-x-1/2 items-center gap-2 rounded-full border border-border/70 bg-background/50 px-3 py-1.5 text-[10px] text-muted-foreground backdrop-blur-xl">
            <Gauge className="h-3.5 w-3.5 text-primary" />
            Live posture layer
          </div>
        </motion.div>
      </div>
    </section>
  )
}
