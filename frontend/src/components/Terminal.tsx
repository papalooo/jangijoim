import React, { useEffect, useRef } from 'react'
import { useScanStore } from '../store/useScanStore'
import { Terminal as TerminalIcon, AlertCircle, CheckCircle, Info, Send } from 'lucide-react'
import { cn } from '../lib/utils'

export const Terminal: React.FC = () => {
  const logs = useScanStore((state) => state.logs)
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [logs])

  const renderLog = (log: any, index: number) => {
    switch (log.type) {
      case 'status':
        return (
          <div key={index} className="text-blue-400 font-bold mb-1">
            <span className="text-muted-foreground mr-2">[{log.timestamp}]</span>
            <span className="mr-2">🔄</span>
            {log.message}
          </div>
        )
      case 'log':
        return (
          <div key={index} className="text-emerald-400 mb-1">
            <span className="text-muted-foreground mr-2">[{log.timestamp}]</span>
            <span className="mr-2">📡</span>
            {log.message}
          </div>
        )
      case 'request':
        return (
          <div key={index} className="bg-white/5 p-2 rounded my-2 border border-white/10">
            <div className="flex items-center gap-2 text-yellow-400 font-mono text-sm mb-1">
              <Send size={14} />
              <span>{log.method} {log.url}</span>
            </div>
            {log.body && (
              <pre className="text-xs text-muted-foreground overflow-x-auto">
                {typeof log.body === 'object' ? JSON.stringify(log.body, null, 2) : log.body}
              </pre>
            )}
          </div>
        )
      case 'execution_result':
        return (
          <div key={index} className={cn(
            "p-2 rounded my-2 border",
            log.is_exploited ? "bg-red-500/10 border-red-500/30 text-red-400" : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
          )}>
            <div className="flex items-center gap-2 font-bold mb-1">
              {log.is_exploited ? <AlertCircle size={16} /> : <CheckCircle size={16} />}
              <span>{log.is_exploited ? "EXPLOIT SUCCESSFUL" : "EXPLOIT BLOCKED"}</span>
            </div>
            <div className="text-xs font-mono">
              Status: {log.status_code} | Time: {log.exec_time_ms}ms
            </div>
          </div>
        )
      case 'error':
        return (
          <div key={index} className="text-red-500 font-bold mb-1">
            <span className="text-muted-foreground mr-2">[{log.timestamp}]</span>
            <span className="mr-2">❌</span>
            {log.message}
          </div>
        )
      default:
        return null
    }
  }

  return (
    <div className="flex flex-col h-full bg-black/40 rounded-lg border border-white/10 overflow-hidden backdrop-blur-md shadow-2xl">
      <div className="flex items-center gap-2 px-4 py-2 bg-white/5 border-b border-white/10">
        <TerminalIcon size={16} className="text-primary" />
        <span className="text-xs font-bold tracking-widest uppercase">Live Execution Stream</span>
      </div>
      <div 
        ref={scrollRef}
        className="flex-1 p-4 font-mono text-sm overflow-y-auto terminal-scroll selection:bg-primary selection:text-primary-foreground"
      >
        {logs.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-muted-foreground animate-pulse">
            <Info size={48} className="mb-4 opacity-20" />
            <p>Waiting for pipeline events...</p>
          </div>
        ) : (
          logs.map((log, i) => renderLog(log, i))
        )}
      </div>
    </div>
  )
}
