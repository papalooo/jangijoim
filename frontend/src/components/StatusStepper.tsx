import React from 'react'
import { useScanStore } from '../store/useScanStore'
import type { ScanStatus } from '../store/useScanStore'
import { Search, Map, Cpu, ShieldCheck, FileCheck, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { cn } from '../lib/utils'

const steps: { status: ScanStatus; label: string; icon: any }[] = [
  { status: 'SCANNING', label: 'Analysis', icon: Search },
  { status: 'MAPPING', label: 'Mapping', icon: Map },
  { status: 'VERIFYING', label: 'Reasoning', icon: Cpu },
  { status: 'TESTING', label: 'Exploiting', icon: ShieldCheck },
  { status: 'COMPLETED', label: 'Finalizing', icon: FileCheck },
]

export const StatusStepper: React.FC = () => {
  const currentStatus = useScanStore((state) => state.status)

  const getStatusIndex = (status: ScanStatus) => {
    if (status === 'QUEUED') return -1
    if (status === 'FAILED') return steps.findIndex(s => s.status === 'COMPLETED')
    return steps.findIndex(s => s.status === status)
  }

  const currentIndex = getStatusIndex(currentStatus)

  return (
    <div className="flex items-center justify-between w-full px-8 py-6 bg-white/5 border border-white/10 rounded-lg backdrop-blur-sm">
      {steps.map((step, index) => {
        const isCompleted = index < currentIndex || currentStatus === 'COMPLETED'
        const isActive = index === currentIndex && currentStatus !== 'COMPLETED'
        const isFailed = currentStatus === 'FAILED' && index === steps.length - 1
        const Icon = step.icon

        return (
          <React.Fragment key={step.status}>
            <div className="flex flex-col items-center gap-2 relative">
              <div className={cn(
                "w-12 h-12 rounded-full flex items-center justify-center transition-all duration-500 shadow-xl",
                isCompleted ? "bg-primary text-primary-foreground" : 
                isActive ? "bg-blue-500 text-white animate-pulse shadow-blue-500/20" : 
                isFailed ? "bg-destructive text-destructive-foreground" :
                "bg-muted text-muted-foreground"
              )}>
                {isCompleted ? <CheckCircle2 size={24} /> : 
                 isActive ? <Loader2 size={24} className="animate-spin" /> : 
                 isFailed ? <XCircle size={24} /> :
                 <Icon size={24} />}
              </div>
              <span className={cn(
                "text-[10px] font-bold uppercase tracking-tighter",
                isActive ? "text-blue-400" : isCompleted ? "text-primary" : "text-muted-foreground"
              )}>
                {step.label}
              </span>
            </div>
            {index < steps.length - 1 && (
              <div className="flex-1 h-[2px] mx-4 bg-muted overflow-hidden">
                <div 
                  className="h-full bg-primary transition-all duration-1000 ease-out"
                  style={{ width: isCompleted ? '100%' : '0%' }}
                />
              </div>
            )}
          </React.Fragment>
        )
      })}
    </div>
  )
}
