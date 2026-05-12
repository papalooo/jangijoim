import React from 'react'
import { Settings as SettingsIcon, Cpu, Zap, Globe } from 'lucide-react'

export const Settings: React.FC = () => {
  return (
    <div className="space-y-8 max-w-2xl">
      <h2 className="text-xl font-bold flex items-center gap-2 text-white">
        <SettingsIcon className="text-primary" />
        Pipeline Settings
      </h2>

      <div className="space-y-6">
        {/* LLM Config */}
        <div className="p-6 bg-white/5 border border-white/10 rounded-xl space-y-4">
          <div className="flex items-center gap-2 text-primary font-bold uppercase text-xs tracking-wider">
            <Cpu size={16} />
            LLM Intelligence
          </div>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-bold text-slate-200">Gemini Model</p>
                <p className="text-xs text-slate-500">Currently using gemini-2.0-flash-exp</p>
              </div>
              <div className="px-3 py-1 rounded bg-primary/20 text-primary text-[10px] font-bold">ACTIVE</div>
            </div>
            <div>
              <label className="text-xs text-slate-500 mb-1 block">API Key (Environment)</label>
              <input 
                type="password" 
                value="••••••••••••••••" 
                disabled 
                className="w-full bg-black/40 border border-white/10 rounded-md px-3 py-2 text-xs font-mono"
              />
            </div>
          </div>
        </div>

        {/* Scan Config */}
        <div className="p-6 bg-white/5 border border-white/10 rounded-xl space-y-4">
          <div className="flex items-center gap-2 text-blue-400 font-bold uppercase text-xs tracking-wider">
            <Zap size={16} />
            Scanner Engine
          </div>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-bold text-slate-200">Parallel Analysis</p>
                <p className="text-xs text-slate-500">Max concurrent LLM agent calls</p>
              </div>
              <input type="number" defaultValue={3} className="w-16 bg-black/40 border border-white/10 rounded px-2 py-1 text-sm" />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-bold text-slate-200">Adaptive Fallback (ZAP)</p>
                <p className="text-xs text-slate-500">Enable deep scan if initial results are low</p>
              </div>
              <div className="w-10 h-5 bg-slate-700 rounded-full relative">
                <div className="absolute right-1 top-1 w-3 h-3 bg-white rounded-full" />
              </div>
            </div>
          </div>
        </div>

        {/* Target Config */}
        <div className="p-6 bg-white/5 border border-white/10 rounded-xl space-y-4">
          <div className="flex items-center gap-2 text-yellow-400 font-bold uppercase text-xs tracking-wider">
            <Globe size={16} />
            Default Targets
          </div>
          <div className="space-y-2">
            <p className="text-xs text-slate-400">Default Target: <span className="text-slate-200">http://juice-shop:3000</span></p>
            <p className="text-xs text-slate-400">Source Mapping: <span className="text-slate-200">/app/juice-shop-src</span></p>
          </div>
        </div>
      </div>
      
      <div className="flex justify-end gap-3">
        <button className="px-4 py-2 text-xs font-bold text-slate-400 hover:text-white transition-colors">Discard</button>
        <button className="px-4 py-2 text-xs font-bold bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-all">Save Configuration</button>
      </div>
    </div>
  )
}
