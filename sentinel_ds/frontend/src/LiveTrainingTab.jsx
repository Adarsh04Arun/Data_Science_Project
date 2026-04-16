import { useEffect, useState, useRef } from 'react'

const POLL_MS = 1500

export default function LiveTrainingTab() {
  const [progress, setProgress] = useState(null)
  const logRef = useRef(null)

  useEffect(() => {
    const poll = async () => {
      try {
        const res = await fetch('/api/progress')
        const data = await res.json()
        setProgress(data)
      } catch (e) {
        console.error('Progress poll failed:', e)
      }
    }
    poll()
    const id = setInterval(poll, POLL_MS)
    return () => clearInterval(id)
  }, [])

  // Auto-scroll console to bottom
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [progress?.console_log])

  const phase = progress?.phase || 'idle'
  const completed = progress?.completed || false
  const logs = progress?.console_log || []

  // Progress bar percentage
  let pct = 0
  if (phase === 'training' && progress?.train_chunks > 0) {
    pct = Math.round((progress.current_chunk / progress.train_chunks) * 100)
  } else if (phase === 'simulation' && progress?.sim_total > 0) {
    pct = Math.round((progress.sim_step / progress.sim_total) * 100)
  } else if (phase === 'complete') {
    pct = 100
  }

  return (
    <div className="tab-content">
      <div className="tab-hero">
        <h2 className="tab-hero__title">🔴 Live Pipeline Execution</h2>
        <p className="tab-hero__subtitle">Real-time view of the training & simulation pipeline</p>
      </div>

      {/* Status Banner */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          PIPELINE STATUS
        </div>
        <div className={`pipeline-status ${completed ? 'pipeline-status--ok' : phase === 'idle' ? 'pipeline-status--pending' : 'pipeline-status--running'}`}>
          <span className="pipeline-status__dot"></span>
          {progress?.status || 'Waiting for pipeline...'}
        </div>
      </div>

      {/* Phase Indicator */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          EXECUTION PHASE
        </div>
        <div className="phase-track">
          <PhaseStep label="Loading" icon="📁" active={phase === 'loading'} done={['training','validation','simulation','plotting','complete'].includes(phase)} />
          <div className="phase-arrow">→</div>
          <PhaseStep label="Training" icon="🌲" active={phase === 'training'} done={['validation','simulation','plotting','complete'].includes(phase)} />
          <div className="phase-arrow">→</div>
          <PhaseStep label="Validation" icon="✅" active={phase === 'validation'} done={['simulation','plotting','complete'].includes(phase)} />
          <div className="phase-arrow">→</div>
          <PhaseStep label="Simulation" icon="🎰" active={phase === 'simulation'} done={['plotting','complete'].includes(phase)} />
          <div className="phase-arrow">→</div>
          <PhaseStep label="Plotting" icon="📊" active={phase === 'plotting'} done={phase === 'complete'} />
          <div className="phase-arrow">→</div>
          <PhaseStep label="Complete" icon="🏁" active={phase === 'complete'} done={false} />
        </div>
      </div>

      {/* Progress Bar */}
      {phase !== 'idle' && (
        <div className="info-section">
          <div className="section-header">
            <span className="section-header__dot"></span>
            {phase === 'training' ? `TRAINING PROGRESS — Chunk ${progress?.current_chunk || 0}/${progress?.train_chunks || 0}` :
             phase === 'simulation' ? `SIMULATION PROGRESS — Step ${(progress?.sim_step || 0).toLocaleString()}/${(progress?.sim_total || 0).toLocaleString()}` :
             'PROGRESS'}
          </div>
          <div className="progress-bar-wrap">
            <div className="progress-bar-fill" style={{ width: `${pct}%` }}>
              <span className="progress-bar-text">{pct}%</span>
            </div>
          </div>
        </div>
      )}

      {/* Live Metrics */}
      {(phase === 'simulation' || phase === 'complete' || phase === 'plotting') && (
        <div className="info-section">
          <div className="section-header">
            <span className="section-header__dot"></span>
            LIVE METRICS
          </div>
          <div className="stat-grid">
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--blue">{progress?.recall?.toFixed(4) || '—'}</div>
              <div className="stat-box__label">Recall</div>
            </div>
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--orange">{progress?.precision?.toFixed(4) || '—'}</div>
              <div className="stat-box__label">Precision</div>
            </div>
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--purple">{progress?.f1?.toFixed(4) || '—'}</div>
              <div className="stat-box__label">F1-Score</div>
            </div>
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--green">{(progress?.cumulative_reward || 0).toLocaleString()}</div>
              <div className="stat-box__label">Cumulative Reward</div>
            </div>
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--cyan">{progress?.epsilon?.toFixed(4) || '—'}</div>
              <div className="stat-box__label">UCB Explore Factor</div>
            </div>
          </div>
        </div>
      )}

      {/* Training accuracy */}
      {(phase === 'training') && (
        <div className="info-section">
          <div className="section-header">
            <span className="section-header__dot"></span>
            TRAINING ACCURACY
          </div>
          <div className="stat-grid">
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--green">{progress?.training_acc?.toFixed(4) || '—'}</div>
              <div className="stat-box__label">Current Chunk Accuracy</div>
            </div>
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--blue">{progress?.current_chunk || 0}/{progress?.train_chunks || 0}</div>
              <div className="stat-box__label">Chunks Processed</div>
            </div>
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--cyan">{progress?.total_chunks || 0}</div>
              <div className="stat-box__label">Total Dataset Chunks</div>
            </div>
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--orange">{progress?.test_chunks || 0}</div>
              <div className="stat-box__label">Test Chunks Remaining</div>
            </div>
          </div>
        </div>
      )}

      {/* Live Console */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          LIVE CONSOLE OUTPUT
        </div>
        <div className="live-console" ref={logRef}>
          {logs.length === 0 ? (
            <div className="live-console__empty">
              Waiting for pipeline output... Run <span className="live-console__cmd">python3 main.py</span> in your terminal.
            </div>
          ) : (
            logs.map((line, i) => (
              <div key={i} className={`live-console__line ${
                line.includes('[Train]') ? 'live-console__line--train' :
                line.includes('[Sim]') ? 'live-console__line--sim' :
                line.includes('[Pipeline]') ? 'live-console__line--pipeline' :
                line.includes('[Validation]') ? 'live-console__line--train' :
                line.includes('[Features]') ? 'live-console__line--pipeline' :
                ''
              }`}>
                <span className="live-console__num">{String(i + 1).padStart(3, '0')}</span>
                {line}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}


function PhaseStep({ label, icon, active, done }) {
  let cls = 'phase-step'
  if (active) cls += ' phase-step--active'
  else if (done) cls += ' phase-step--done'
  
  return (
    <div className={cls}>
      <div className="phase-step__icon">{done && !active ? '✓' : icon}</div>
      <div className="phase-step__label">{label}</div>
    </div>
  )
}
