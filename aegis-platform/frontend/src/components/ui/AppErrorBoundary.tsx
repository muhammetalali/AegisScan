import React from 'react'

type AppErrorBoundaryProps = {
  children: React.ReactNode
  context?: string
}

type AppErrorBoundaryState = {
  error: Error | null
}

export class AppErrorBoundary extends React.Component<AppErrorBoundaryProps, AppErrorBoundaryState> {
  state: AppErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): AppErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[AegisScan] UI render failure', {
      context: this.props.context ?? 'application',
      error,
      componentStack: info.componentStack,
      path: typeof window !== 'undefined' ? window.location.pathname : undefined,
    })
  }

  private reset = () => {
    this.setState({ error: null })
  }

  private reload = () => {
    window.location.reload()
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children

    return (
      <div className="app-error-screen" role="alert">
        <div className="app-error-card">
          <div className="app-error-mark">!</div>
          <div className="app-error-kicker">AegisScan UI</div>
          <h1>تعذر تحميل هذه الصفحة</h1>
          <p>
            حدث خطأ غير متوقع أثناء تشغيل الواجهة. لم يتم إخفاء الخطأ أو استبدال البيانات بنتيجة وهمية.
          </p>
          <div className="app-error-detail">
            <strong>{this.props.context ?? 'Application'}</strong>
            <code>{error.message || 'Unknown rendering error'}</code>
          </div>
          <div className="app-error-actions">
            <button type="button" className="app-error-primary" onClick={this.reload}>إعادة تحميل</button>
            <button type="button" className="app-error-secondary" onClick={this.reset}>المحاولة مجددًا</button>
          </div>
        </div>
      </div>
    )
  }
}

export const isChunkLoadError = (error: unknown) => {
  const message = error instanceof Error ? error.message : String(error ?? '')
  return /failed to fetch dynamically imported module|importing a module script failed|chunkloaderror|loading chunk/i.test(message)
}

const CHUNK_RECOVERY_KEY = 'aegisscan:chunk-recovery'

export function lazyWithRetry<T extends React.ComponentType<any>>(loader: () => Promise<{ default: T }>) {
  return React.lazy(async () => {
    try {
      const result = await loader()
      sessionStorage.removeItem(CHUNK_RECOVERY_KEY)
      return result
    } catch (firstError) {
      if (!isChunkLoadError(firstError)) throw firstError

      const alreadyRecovered = sessionStorage.getItem(CHUNK_RECOVERY_KEY) === '1'
      if (!alreadyRecovered) {
        sessionStorage.setItem(CHUNK_RECOVERY_KEY, '1')
        window.location.reload()
        return new Promise<{ default: T }>(() => undefined)
      }

      return loader()
    }
  })
}
