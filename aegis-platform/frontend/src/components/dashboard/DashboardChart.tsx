type ChartPoint = { label: string; value: number }

const severityColors = ['#dc2626', '#f97316', '#eab308', '#3b82f6', '#64748b']
const fallbackColor = severityColors[severityColors.length - 1]

export const DashboardTrendChart = ({ points }: { points: ChartPoint[] }) => {
  const width = 640
  const height = 220
  const inset = 24
  const availableWidth = width - inset * 2
  const availableHeight = height - inset * 2
  const coordinates = points.map((point, index) => ({
    ...point,
    x: inset + (points.length === 1 ? availableWidth / 2 : index * availableWidth / (points.length - 1)),
    y: inset + (100 - Math.max(0, Math.min(100, point.value))) * availableHeight / 100,
  }))

  return (
    <div className="h-56 w-full" role="img" aria-label={`Security score trend: ${points.map(point => `${point.label} ${point.value}`).join(', ')}`}>
      <svg viewBox={`0 0 ${width} ${height}`} className="h-full w-full" aria-hidden="true">
        {[0, 25, 50, 75, 100].map(value => {
          const y = inset + (100 - value) * availableHeight / 100
          return <line key={value} x1={inset} x2={width - inset} y1={y} y2={y} className="stroke-border" strokeDasharray="4 6" />
        })}
        <polyline points={coordinates.map(point => `${point.x},${point.y}`).join(' ')} fill="none" className="stroke-primary" strokeWidth="3" strokeLinejoin="round" strokeLinecap="round" />
        {coordinates.map(point => <circle key={`${point.label}-${point.x}`} cx={point.x} cy={point.y} r="4" className="fill-primary stroke-background" strokeWidth="2" />)}
      </svg>
    </div>
  )
}

export const DashboardDonutChart = ({ points }: { points: ChartPoint[] }) => {
  const total = points.reduce((sum, point) => sum + point.value, 0)
  let cursor = 0
  const stops = points.map((point, index) => {
    const start = cursor
    cursor += total ? point.value / total * 100 : 0
    return `${severityColors[index] ?? fallbackColor} ${start}% ${cursor}%`
  })

  return (
    <div className="grid h-56 grid-cols-[minmax(120px,1fr)_1fr] items-center gap-5" role="img" aria-label={`Risk distribution: ${points.map(point => `${point.label} ${point.value}`).join(', ')}`}>
      <div className="relative mx-auto aspect-square w-full max-w-40 rounded-full" style={{ background: total ? `conic-gradient(${stops.join(', ')})` : '#64748b' }} aria-hidden="true">
        <div className="absolute inset-[24%] grid place-items-center rounded-full bg-card text-center"><span className="text-2xl font-black">{total}</span><span className="text-[10px] text-muted-foreground">findings</span></div>
      </div>
      <div className="space-y-2 text-xs">{points.map((point, index) => <div key={point.label} className="flex items-center justify-between gap-3"><span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: severityColors[index] ?? fallbackColor }} />{point.label}</span><strong>{point.value}</strong></div>)}</div>
    </div>
  )
}

export const DashboardBarChart = ({ points }: { points: ChartPoint[] }) => {
  const maximum = Math.max(1, ...points.map(point => point.value))
  return (
    <div className="flex h-52 items-end justify-around gap-3 pt-5" role="img" aria-label={`Findings by severity: ${points.map(point => `${point.label} ${point.value}`).join(', ')}`}>
      {points.map((point, index) => <div key={point.label} className="flex h-full min-w-0 flex-1 flex-col justify-end text-center"><strong className="mb-2 text-xs">{point.value}</strong><div className="mx-auto w-full max-w-12 rounded-t-md" style={{ height: `${point.value > 0 ? Math.max(3, point.value / maximum * 100) : 0}%`, backgroundColor: severityColors[index] ?? fallbackColor }} aria-hidden="true" /><span className="mt-2 truncate text-[10px] text-muted-foreground">{point.label}</span></div>)}
    </div>
  )
}
