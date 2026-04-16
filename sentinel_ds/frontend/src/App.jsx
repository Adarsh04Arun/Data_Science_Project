import { useState, useEffect } from 'react'
import DataPipelineTab from './DataPipelineTab.jsx'
import EDATab from './EDATab.jsx'
import ModelArchitectureTab from './ModelArchitectureTab.jsx'
import RLBanditTab from './RLBanditTab.jsx'
import LiveMetricsTab from './LiveMetricsTab.jsx'
import LiveTrainingTab from './LiveTrainingTab.jsx'
import TestModelTab from './TestModelTab.jsx'

const API_URL = '/api/state'
const POLL_MS = 3000

const TABS = [
  { id: 'dashboard', label: '🖥 Dashboard',       icon: '' },
  { id: 'pipeline',  label: '📊 Data Pipeline',   icon: '' },
  { id: 'eda',       label: '🔬 EDA',             icon: '' },
  { id: 'model',     label: '🧠 Model',           icon: '' },
  { id: 'bandit',    label: '🎰 RL Bandit',       icon: '' },
  { id: 'training',  label: '🔴 Live Training',   icon: '' },
  { id: 'metrics',   label: '📈 Metrics',         icon: '' },
  { id: 'test',      label: '🧪 Test Model',      icon: '' },
]

function App() {
  const [state, setState] = useState(null)
  const [clock, setClock] = useState('')
  const [activeTab, setActiveTab] = useState('dashboard')

  // ── Poll API ───────────────────────────────────────────
  useEffect(() => {
    const fetchState = async () => {
      try {
        const res = await fetch(API_URL)
        const data = await res.json()
        setState(data)
      } catch (e) {
        console.error('API fetch failed:', e)
      }
    }
    fetchState()
    const id = setInterval(fetchState, POLL_MS)
    return () => clearInterval(id)
  }, [])

  // ── Live Clock ─────────────────────────────────────────
  useEffect(() => {
    const tick = () => {
      const now = new Date()
      setClock(now.toLocaleString('en-IN', {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: false,
        timeZone: 'Asia/Kolkata',
      }).replace(',', '') + ' IST')
    }
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])

  if (!state) {
    return (
      <div className="dashboard" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh' }}>
        <p style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', fontSize: '1rem' }}>
          Connecting to Adaptive Triage Engine...
        </p>
      </div>
    )
  }

  const logs = state.logs || []
  const reports = state.reports || []
  const hits = state.endpoint_hits || {}
  const maxHit = Math.max(...Object.values(hits), 1)

  return (
    <div className="dashboard">
      {/* ── Header ──────────────────────────────────────── */}
      <header className="header">
        <div>
          <h1 className="header__title">🛡 ADAPTIVE TRIAGE ENGINE</h1>
          <p className="header__subtitle">AI-DRIVEN AUTONOMOUS CYBER THREAT HUNTING AGENT</p>
        </div>
        <div className="header__clock">{clock}</div>
      </header>

      {/* ── Tab Navigation ──────────────────────────────── */}
      <nav className="tab-nav">
        {TABS.map(tab => (
          <button
            key={tab.id}
            className={`tab-nav__btn ${activeTab === tab.id ? 'tab-nav__btn--active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* ── Tab Content ─────────────────────────────────── */}
      {activeTab === 'dashboard' && (
        <DashboardView state={state} logs={logs} reports={reports} hits={hits} maxHit={maxHit} />
      )}
      {activeTab === 'pipeline' && <DataPipelineTab />}
      {activeTab === 'eda' && <EDATab />}
      {activeTab === 'model' && <ModelArchitectureTab />}
      {activeTab === 'bandit' && <RLBanditTab />}
      {activeTab === 'training' && <LiveTrainingTab />}
      {activeTab === 'metrics' && <LiveMetricsTab />}
      {activeTab === 'test' && <TestModelTab />}
    </div>
  )
}


/* ═══════════════════════════════════════════════════════════
   Dashboard View (original)
   ═══════════════════════════════════════════════════════════ */

function DashboardView({ state, logs, reports, hits, maxHit }) {
  return (
    <>
      {/* ── Critical Banner ─────────────────────────────── */}
      {state.critical_active && (
        <div className="critical-banner">
          <span className="critical-banner__dot"></span>
          CRITICAL THREAT ACTIVE — IMMEDIATE CONTAINMENT REQUIRED
        </div>
      )}

      {/* ── KPI Cards ───────────────────────────────────── */}
      <div className="kpi-row">
        <KpiCard value={state.events_captured}  label="Events Captured"  color="blue" />
        <KpiCard value={state.failed_requests}  label="Failed Requests"  color="red" />
        <KpiCard value={state.active_threats}   label="Active Threats"   color="orange" />
        <KpiCard value={state.flagged_ips}      label="Flagged IPs"      color="green" />
      </div>

      {/* ── Main Grid ───────────────────────────────────── */}
      <div className="main-grid">
        {/* Left Column */}
        <div>
          <div className="section-header">
            <span className="section-header__dot"></span>
            LIVE TRAFFIC FEED
          </div>
          <TrafficFeed logs={logs} />

          <div className="section-header" style={{ marginTop: '1.5rem' }}>
            <span className="section-header__dot"></span>
            AGENT ACTION DISTRIBUTION
          </div>
          <EndpointHits hits={hits} maxHit={maxHit} />
        </div>

        {/* Right Column */}
        <div>
          <div className="section-header">
            <span className="section-header__dot"></span>
            DETECTION ENGINE · AI SOC ANALYST REPORTS
          </div>
          <div className="reports-scroll">
            {reports.map((r, i) => (
              <ReportCard key={i} report={r} />
            ))}
          </div>
        </div>
      </div>
    </>
  )
}


/* ═══════════════════════════════════════════════════════════
   Sub-components
   ═══════════════════════════════════════════════════════════ */

function KpiCard({ value, label, color }) {
  return (
    <div className="kpi-card">
      <div className={`kpi-card__value kpi-card__value--${color}`}>{value ?? 0}</div>
      <div className="kpi-card__label">{label}</div>
    </div>
  )
}


function TrafficFeed({ logs }) {
  return (
    <div className="traffic-feed">
      {logs.map((log, i) => {
        const tag = (log.tag || '').toLowerCase()
        let cls = 'traffic-entry traffic-entry--allowed'
        let tagCls = ''
        if (tag.includes('blocked')) { cls = 'traffic-entry traffic-entry--blocked'; tagCls = 'traffic-entry__tag--blocked'; }
        else if (tag.includes('denied'))  { cls = 'traffic-entry traffic-entry--denied';  tagCls = 'traffic-entry__tag--denied'; }
        else if (tag.includes('fail'))    { cls = 'traffic-entry traffic-entry--fail';    tagCls = 'traffic-entry__tag--fail'; }

        return (
          <div key={i} className={cls}>
            <span className="traffic-entry__time">{log.time}</span>
            {' '}
            {log.method} {log.endpoint} ? {log.ip}
            {' '}
            <span className={`traffic-entry__tag ${tagCls}`}>[{log.tag}]</span>
          </div>
        )
      })}
    </div>
  )
}


function EndpointHits({ hits, maxHit }) {
  const sorted = Object.entries(hits).sort((a, b) => b[1] - a[1])
  const total = Object.values(hits).reduce((s, v) => s + v, 0) || 1

  return (
    <div className="endpoint-list">
      {sorted.map(([ep, count]) => (
        <div key={ep} className="endpoint-row">
          <span className="endpoint-row__name">{ep}</span>
          <div className="endpoint-row__bar-wrap">
            <div
              className="endpoint-row__bar"
              style={{ width: `${(count / maxHit) * 100}%` }}
            />
          </div>
          <span className="endpoint-row__pct">{Math.round((count / total) * 100)}%</span>
        </div>
      ))}
    </div>
  )
}


function ReportCard({ report }) {
  const sevClass = report.severity === 'CRITICAL'
    ? 'report-card__severity--critical'
    : 'report-card__severity--high'

  const fillClass = report.severity === 'CRITICAL'
    ? 'report-card__confidence-fill--critical'
    : 'report-card__confidence-fill--high'

  return (
    <div className="report-card">
      <div>
        <span className={`report-card__severity ${sevClass}`}>{report.severity}</span>
        <span className="report-card__name">{report.name}</span>
      </div>

      <div className="report-card__meta">
        <span>⏱ {report.time}</span>
        <span>⬤ {report.target_ip}</span>
        <span>CONFIDENCE {report.confidence}%</span>
      </div>

      <div className="report-card__confidence-bar">
        <div
          className={`report-card__confidence-fill ${fillClass}`}
          style={{ width: `${report.confidence}%` }}
        />
      </div>

      <div className="rule-pills">
        {(report.rules || []).map((rule, i) => (
          <span key={i} className="rule-pill">{rule}</span>
        ))}
      </div>

      <div className="mitigation-box">
        <span className="mitigation-box__icon">⊘</span>
        MITIGATION: {report.mitigation}
      </div>
    </div>
  )
}


export default App
