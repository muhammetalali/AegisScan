import { cn } from '@/utils/cn'
export const Skeleton = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('animate-pulse rounded-md bg-muted', className)} {...props} />
)
export const CardSkeleton = () => (
  <div className="rounded-xl border bg-card p-4 space-y-3">
    <div className="h-4 w-1/3 bg-muted rounded animate-pulse" />
    <div className="h-8 w-1/2 bg-muted rounded animate-pulse" />
    <div className="h-3 w-full bg-muted rounded animate-pulse" />
  </div>
)
export const TableSkeleton = ({ rows=5 }: { rows?: number }) => (
  <div className="rounded-xl border bg-card p-4 space-y-3">
    <div className="h-4 w-24 bg-muted rounded animate-pulse" />
    {Array.from({length: rows}).map((_,i)=>(<div key={i} className="h-10 bg-muted rounded animate-pulse" />))}
  </div>
)
