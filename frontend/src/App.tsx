import { useEffect, useState } from 'react'
import { Terminal } from './components/Terminal'
import { ScanForm } from './components/ScanForm'
import { StatusStepper } from './components/StatusStepper'
import { VulnerabilityList } from './components/VulnerabilityList'
import { ScanHistory } from './components/ScanHistory'
import { Settings } from './components/Settings'
import { ExploitLab } from './components/ExploitLab'
import { useScanStore } from './store/useScanStore'
import { Shield, LayoutDashboard, Settings as SettingsIcon, History, ChevronRight, FlaskConical } from 'lucide-react'
import axios from 'axios'

function App() {
  const { jobId, setStatus, addLog, setVulnerabilities } = useScanStore()
  const [activeTab, setActiveTab] = useState('dashboard')

  useEffect(() => {
    if (!jobId) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/${jobId}`)

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      
      if (data.type === 'status') {
        setStatus(data.status)
        addLog({ type: 'status', message: data.message })
        if (data.status === 'COMPLETED') {
          fetchScanData(jobId)
        }
      } else if (data.type === 'vulnerabilities') {
        setVulnerabilities(data.data)
      } else {
        addLog(data)
      }
    }

    // 초기 로딩 시 데이터 동기화
    fetchScanData(jobId)

    return () => ws.close()
  }, [jobId])

  const fetchScanData = async (id: string) => {
    try {
      const response = await axios.get(`/scan/status/${id}`)
      setVulnerabilities(response.data.vulnerabilities || [])
      setStatus(response.data.metadata.current_status)
    } catch (error) {
      console.error("Failed to fetch scan data", error)
    }
  }

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return (
          <section className="grid grid-cols-1 xl:grid-cols-12 gap-8">
            <div className="xl:col-span-8 space-y-8">
              <StatusStepper />
              <div className="h-[500px]">
                <Terminal />
              </div>
              <VulnerabilityList />
            </div>

            <div className="xl:col-span-4">
              <ScanForm />
              
              <div className="mt-8 grid grid-cols-2 gap-4">
                <div className="p-4 bg-white/5 border border-white/10 rounded-xl">
                  <p className="text-[10px] font-bold text-slate-500 uppercase mb-1">Target Host</p>
                  <p className="text-xs font-mono truncate">{useScanStore.getState().targetUrl || 'N/A'}</p>
                </div>
                <div className="p-4 bg-white/5 border border-white/10 rounded-xl">
                  <p className="text-[10px] font-bold text-slate-500 uppercase mb-1">Job ID</p>
                  <p className="text-xs font-mono truncate">{jobId?.slice(0, 8) || 'N/A'}</p>
                </div>
              </div>
            </div>
          </section>
        )
      case 'exploit-lab':
        return <ExploitLab />
      case 'history':
        return <ScanHistory onSelectJob={() => setActiveTab('dashboard')} />
      case 'settings':
        return <Settings />
      default:
        return null
    }
  }

  return (
    <div className="flex h-screen bg-[#0a0a0c] text-slate-200 overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-64 border-r border-white/5 bg-black/20 backdrop-blur-xl flex flex-col">
        <div className="p-6 flex items-center gap-3">
          <div className="w-10 h-10 bg-primary rounded-xl flex items-center justify-center shadow-[0_0_20px_rgba(34,197,94,0.3)]">
            <Shield className="text-primary-foreground" size={24} fill="currentColor" />
          </div>
          <h1 className="font-black text-xl tracking-tighter text-white">JANGIJOIM</h1>
        </div>

        <nav className="flex-1 px-4 py-4 space-y-2">
          {[
            { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
            { id: 'exploit-lab', label: 'Exploit Lab', icon: FlaskConical },
            { id: 'history', label: 'Scan History', icon: History },
            { id: 'settings', label: 'Settings', icon: SettingsIcon },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                activeTab === item.id 
                  ? 'bg-primary/10 text-primary border border-primary/20 shadow-[0_0_15px_rgba(34,197,94,0.1)]' 
                  : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'
              }`}
            >
              <item.icon size={18} />
              {item.label}
            </button>
          ))}
        </nav>

        <div className="p-4 border-t border-white/5">
          <div className="p-4 bg-gradient-to-br from-primary/20 to-transparent rounded-xl border border-primary/10">
            <p className="text-[10px] font-bold text-primary uppercase mb-1">Engine Status</p>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-primary rounded-full animate-pulse" />
              <span className="text-xs font-mono text-slate-300">FastAPI Online</span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden relative">
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-primary/5 rounded-full blur-[120px] -z-10 pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-[300px] h-[300px] bg-blue-500/5 rounded-full blur-[100px] -z-10 pointer-events-none" />

        <header className="h-20 border-b border-white/5 flex items-center justify-between px-8 bg-black/10 backdrop-blur-md">
          <div className="flex items-center gap-2 text-sm text-slate-500">
            <span>Home</span>
            <ChevronRight size={14} />
            <span className="text-slate-200 capitalize">{activeTab}</span>
          </div>
          <div className="flex items-center gap-4">
            <div className="px-3 py-1 rounded-full bg-white/5 border border-white/10 text-[10px] font-mono font-bold text-slate-400">
              v1.2.0-STABLE
            </div>
            <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-slate-700 to-slate-800 border border-white/10" />
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-8 space-y-8 custom-scrollbar">
          {renderContent()}
        </div>
      </main>
    </div>
  )
}

export default App
