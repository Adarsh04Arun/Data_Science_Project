import { useEffect, useState } from 'react'

export default function LiveMetricsTab() {
  const [stats, setStats] = useState(null)

  useEffect(() => {
    fetch('/api/pipeline-stats').then(r => r.json()).then(setStats).catch(() => {})
  }, [])

  const pipelineRan = stats?.pipeline_run
  const plots = stats?.plots_available || []

  return (
    <div className="tab-content">
      <div className="tab-hero">
        <h2 className="tab-hero__title">📈 Live Pipeline Metrics</h2>
        <p className="tab-hero__subtitle">Visual results from the most recent simulation run</p>
      </div>

      {/* Pipeline Status */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          PIPELINE STATUS
        </div>
        <div className={`pipeline-status ${pipelineRan ? 'pipeline-status--ok' : 'pipeline-status--pending'}`}>
          <span className="pipeline-status__dot"></span>
          {pipelineRan
            ? `Pipeline completed — ${stats?.total_events?.toLocaleString() || 0} events processed, ${stats?.total_threats?.toLocaleString() || 0} threats detected`
            : 'Pipeline not yet executed. Run python3 main.py to generate metrics.'
          }
        </div>
      </div>

      {/* Summary Stats */}
      {pipelineRan && (
        <div className="info-section">
          <div className="section-header">
            <span className="section-header__dot"></span>
            SIMULATION SUMMARY
          </div>
          <div className="stat-grid">
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--blue">{stats?.total_events?.toLocaleString()}</div>
              <div className="stat-box__label">Total Events Simulated</div>
            </div>
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--red">{stats?.total_threats?.toLocaleString()}</div>
              <div className="stat-box__label">Active Threats Detected</div>
            </div>
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--green">{plots.length}/3</div>
              <div className="stat-box__label">Plots Generated</div>
            </div>
            <div className="stat-box">
              <div className="stat-box__value stat-box__value--orange">{stats?.features_used}</div>
              <div className="stat-box__label">Features Used</div>
            </div>
          </div>
        </div>
      )}

      {/* Plots */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          GENERATED PLOTS
        </div>

        {plots.length === 0 && (
          <div className="explanation-card">
            <div className="explanation-card__row">
              <span className="explanation-card__badge explanation-card__badge--orange">Note</span>
              <span>No plots available yet. Run the full pipeline to generate visualization charts.</span>
            </div>
          </div>
        )}

        <div className="plot-grid plot-grid--full">
          {plots.includes('recall_precision.png') && (
            <div className="plot-card plot-card--wide">
              <h3 className="plot-card__title">Recall & Precision Over Time</h3>
              <img src="/api/plots/recall_precision.png" alt="Recall & Precision" />
              <p className="plot-card__label">
                Shows how effectively the bandit identifies real threats (recall) vs how many of its escalations
                are actually threats (precision). High recall (&gt;0.8) means very few threats slip through.
              </p>
            </div>
          )}

          {plots.includes('cumulative_reward.png') && (
            <div className="plot-card plot-card--wide">
              <h3 className="plot-card__title">Cumulative Reward Over Time</h3>
              <img src="/api/plots/cumulative_reward.png" alt="Cumulative Reward" />
              <p className="plot-card__label">
                An upward trend proves the agent is learning. The steep −1000 penalty for missed threats
                drives the agent toward aggressive escalation of suspicious flows.
              </p>
            </div>
          )}

          {plots.includes('action_distribution.png') && (
            <div className="plot-card plot-card--wide">
              <h3 className="plot-card__title">Action Distribution per Analyst Load Phase</h3>
              <img src="/api/plots/action_distribution.png" alt="Action Distribution" />
              <p className="plot-card__label">
                Demonstrates adaptive behavior — when analyst load is high, false-alarm penalty increases,
                pushing the agent to be more selective about escalations under stress.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
