import React, { useEffect, useState } from 'react'
import axios from 'axios'
import { History, ExternalLink, ChevronRight, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { cn } from '../lib/utils'
import { useScanStore } from '../store/useScanStore'

interface ScanHistoryProps {
  onSelectJob?: () => void;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({ onSelectJob }) => {
  const [history, setHistory] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const { setJobId, setStatus, setTargetInfo } = useScanStore()

  const fetchHistory = async () => {
    try {
      const response = await axios.get('/scan/history')
      setHistory(response.data)
    } catch (error) {
      console.error("Failed to fetch history", error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchHistory()
  }, [])

  const handleRevisit = async (job: any) => {
    setJobId(job.job_id)
    setStatus(job.status)
    setTargetInfo(job.target_host, '')
    if (onSelectJob) onSelectJob()
    // Actual data will be fetched by the App's useEffect via REST/WS
  }

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center">
        <Loader2 className="animate-spin text-primary" size={32} />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold flex items-center gap-2 text-white">
          <History className="text-primary" />
          Recent Scan History
        </h2>
        <button 
          onClick={fetchHistory}
          className="text-xs text-primary hover:underline"
        >
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 gap-3">
        {history.length === 0 ? (
          <div className="p-8 text-center bg-white/5 border border-white/10 rounded-xl text-slate-500">
            No scan history found.
          </div>
        ) : (
          history.map((job) => (
            <div 
              key={job.job_id}
              onClick={() => handleRevisit(job)}
              className="group p-4 bg-white/5 border border-white/10 rounded-xl flex items-center justify-between hover:bg-white/10 hover:border-primary/30 transition-all cursor-pointer"
            >
              <div className="flex items-center gap-4">
                <div className={cn(
                  "p-2 rounded-lg",
                  job.status === 'COMPLETED' ? "bg-emerald-500/20 text-emerald-400" :
                  job.status === 'FAILED' ? "bg-red-500/20 text-red-400" :
                  "bg-blue-500/20 text-blue-400 animate-pulse"
                )}>
                  {job.status === 'COMPLETED' ? <CheckCircle2 size={20} /> : 
                   job.status === 'FAILED' ? <XCircle size={20} /> : 
                   <Loader2 size={20} className="animate-spin" />}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-bold text-slate-200">{job.target_host}</p>
                    <ExternalLink size={12} className="text-slate-500" />
                  </div>
                  <p className="text-[10px] font-mono text-slate-500">{job.job_id}</p>
                </div>
              </div>

              <div className="flex items-center gap-6 text-right">
                <div className="hidden md:block">
                  <p className="text-[10px] font-bold text-slate-500 uppercase">Findings</p>
                  <p className="text-sm font-bold text-primary">{job.vuln_count} items</p>
                </div>
                <div className="hidden md:block">
                  <p className="text-[10px] font-bold text-slate-500 uppercase">Start Time</p>
                  <p className="text-xs text-slate-400">{new Date(job.start_time).toLocaleString()}</p>
                </div>
                <ChevronRight size={20} className="text-slate-700 group-hover:text-primary transition-colors" />
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
