import React, { useState } from 'react'
import axios from 'axios'
import { useScanStore } from '../store/useScanStore'
import { Play, Globe, Folder, Loader2 } from 'lucide-react'
import { cn } from '../lib/utils'

export const ScanForm: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('')
  const [sourceDir, setSourceDir] = useState('')
  const [loading, setLoading] = useState(false)
  
  const { setJobId, reset, setTargetInfo, status } = useScanStore()

  const handleStart = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!targetUrl || !sourceDir) return

    setLoading(true)
    reset()
    setTargetInfo(targetUrl, sourceDir)

    try {
      const response = await axios.post('/scan/start', null, {
        params: { target_url: targetUrl, source_dir: sourceDir }
      })
      setJobId(response.data.job_id)
    } catch (error) {
      console.error("Failed to start scan", error)
      alert("Failed to start scan engine. Make sure the backend is running.")
    } finally {
      setLoading(false)
    }
  }

  const isRunning = status !== 'QUEUED' && status !== 'COMPLETED' && status !== 'FAILED'

  return (
    <form onSubmit={handleStart} className="space-y-4 p-6 bg-white/5 rounded-lg border border-white/10 backdrop-blur-sm">
      <div className="space-y-2">
        <label className="text-xs font-bold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
          <Globe size={14} />
          Target URL
        </label>
        <input
          type="url"
          placeholder="http://localhost:3000"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          disabled={isRunning}
          className="w-full bg-black/40 border border-white/10 rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
          required
        />
      </div>

      <div className="space-y-2">
        <label className="text-xs font-bold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
          <Folder size={14} />
          Source Directory
        </label>
        <input
          type="text"
          placeholder="/path/to/project"
          value={sourceDir}
          onChange={(e) => setSourceDir(e.target.value)}
          disabled={isRunning}
          className="w-full bg-black/40 border border-white/10 rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
          required
        />
      </div>

      <button
        type="submit"
        disabled={loading || isRunning}
        className={cn(
          "w-full flex items-center justify-center gap-2 py-3 rounded-md font-bold transition-all shadow-lg",
          isRunning 
            ? "bg-muted text-muted-foreground cursor-not-allowed" 
            : "bg-primary text-primary-foreground hover:bg-primary/90 active:scale-95"
        )}
      >
        {loading ? (
          <Loader2 className="animate-spin" />
        ) : isRunning ? (
          "SCAN IN PROGRESS"
        ) : (
          <>
            <Play size={18} fill="currentColor" />
            START SECURITY PIPELINE
          </>
        )}
      </button>
    </form>
  )
}
