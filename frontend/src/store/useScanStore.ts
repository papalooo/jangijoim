import { create } from 'zustand'

export type ScanStatus = 'QUEUED' | 'SCANNING' | 'MAPPING' | 'VERIFYING' | 'TESTING' | 'COMPLETED' | 'FAILED'

interface LogEntry {
  type: 'log' | 'request' | 'execution_result' | 'error' | 'status'
  message?: string
  level?: string
  timestamp: string
  [key: string]: any
}

interface ScanState {
  jobId: string | null
  status: ScanStatus
  logs: LogEntry[]
  vulnerabilities: any[]
  targetUrl: string
  sourceDir: string
  setJobId: (id: string) => void
  setStatus: (status: ScanStatus) => void
  addLog: (log: any) => void
  setVulnerabilities: (vulns: any[]) => void
  reset: () => void
  setTargetInfo: (url: string, dir: string) => void
}

export const useScanStore = create<ScanState>((set) => ({
  jobId: null,
  status: 'QUEUED',
  logs: [],
  vulnerabilities: [],
  targetUrl: '',
  sourceDir: '',
  setJobId: (id) => set({ jobId: id }),
  setStatus: (status) => set({ status }),
  addLog: (log) => set((state) => ({ 
    logs: [...state.logs, { ...log, timestamp: new Date().toLocaleTimeString() }] 
  })),
  setVulnerabilities: (vulns) => set({ vulnerabilities: vulns }),
  setTargetInfo: (url, dir) => set({ targetUrl: url, sourceDir: dir }),
  reset: () => set({ jobId: null, status: 'QUEUED', logs: [], vulnerabilities: [] }),
}))
