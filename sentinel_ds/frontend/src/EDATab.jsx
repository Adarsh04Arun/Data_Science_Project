import { useEffect, useState } from "react";

// Uses relative URL to route through Vite proxy

export default function EDATab() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`/api/eda-stats`)
      .then((r) => r.json())
      .then((d) => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="tab-content">
        <div className="tab-hero">
          <h2 className="tab-hero__title">🔬 Exploratory Data Analysis</h2>
          <p className="tab-hero__subtitle" style={{ color: "var(--accent-cyan)" }}>
            Loading EDA statistics...
          </p>
        </div>
      </div>
    );
  }

  if (!data || data.error) {
    return (
      <div className="tab-content">
        <div className="tab-hero">
          <h2 className="tab-hero__title">🔬 Exploratory Data Analysis</h2>
          <p className="tab-hero__subtitle" style={{ color: "var(--accent-red)" }}>
            {data?.error || "Failed to load EDA data. Is the backend running?"}
          </p>
        </div>
      </div>
    );
  }

  const importance = data.feature_importance || [];
  const classDist = data.class_distribution || {};
  const featStats = data.feature_stats || [];
  const hyperparams = data.hyperparameters || {};
  const maxImp = importance.length > 0 ? importance[0].importance : 1;
  // Log scale so lower features are visible when one dominates
  const logScale = (v) => {
    if (v <= 0 || maxImp <= 0) return 2;
    return Math.max(2, (Math.log10(v + 1e-6) / Math.log10(maxImp + 1e-6)) * 100);
  };

  const totalFlows = (classDist.benign || 0) + (classDist.attack || 0);
  const benignPct = totalFlows > 0 ? ((classDist.benign / totalFlows) * 100).toFixed(1) : 0;
  const attackPct = totalFlows > 0 ? ((classDist.attack / totalFlows) * 100).toFixed(1) : 0;

  const attackTypes = classDist.attack_types || {};
  const maxAttack = Math.max(...Object.values(attackTypes), 1);

  return (
    <div className="tab-content">
      <div className="tab-hero">
        <h2 className="tab-hero__title">🔬 Exploratory Data Analysis</h2>
        <p className="tab-hero__subtitle">
          Dataset insights, feature importance, and model configuration
        </p>
      </div>

      {/* ── Overview Cards ──────────────────────────── */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          DATASET OVERVIEW
        </div>
        <div className="stat-grid">
          <StatBox label="Total Flows" value={totalFlows.toLocaleString()} color="cyan" />
          <StatBox label="Features Used" value={data.n_features} color="green" />
          <StatBox label="Dataset Files" value="29" color="blue" />
          <StatBox label="Dataset Groups" value="3" color="purple" />
          <StatBox label="Benign Flows" value={`${benignPct}%`} color="green" />
          <StatBox label="Attack Flows" value={`${attackPct}%`} color="orange" />
        </div>
      </div>

      {/* ── Class Distribution ─────────────────────── */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          CLASS DISTRIBUTION
          <span className="section-header__badge">Imbalanced Dataset</span>
        </div>

        {/* Main benign vs attack bar */}
        <div className="eda-class-bar">
          <div className="eda-class-bar__segment eda-class-bar__segment--benign"
               style={{ width: `${benignPct}%` }}>
            <span>Benign {benignPct}%</span>
          </div>
          <div className="eda-class-bar__segment eda-class-bar__segment--attack"
               style={{ width: `${attackPct}%` }}>
            <span>Attack {attackPct}%</span>
          </div>
        </div>

        {/* Attack type breakdown */}
        <div className="eda-attack-breakdown">
          <div className="eda-attack-breakdown__title">Attack Family Breakdown</div>
          {Object.entries(attackTypes).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
            <div key={type} className="eda-attack-row">
              <span className="eda-attack-row__label">{type}</span>
              <div className="eda-attack-row__bar-wrap">
                <div className="eda-attack-row__bar"
                     style={{ width: `${(count / maxAttack) * 100}%` }} />
              </div>
              <span className="eda-attack-row__count">{count.toLocaleString()}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Feature Importance ─────────────────────── */}
      {importance.length > 0 && (
        <div className="info-section">
          <div className="section-header">
            <span className="section-header__dot"></span>
            FEATURE IMPORTANCE
            <span className="section-header__badge">XGBoost gain-based</span>
          </div>
          <div className="eda-importance">
            {importance.map((item, i) => (
              <div key={item.feature} className="eda-importance__row">
                <span className="eda-importance__rank">#{i + 1}</span>
                <span className="eda-importance__name">{item.feature}</span>
                <div className="eda-importance__bar-wrap">
                  <div className="eda-importance__bar"
                       style={{ width: `${logScale(item.importance)}%` }} />
                </div>
                <span className="eda-importance__value">
                  {fmtPct(item.importance)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Feature Statistics ─────────────────────── */}
      {featStats.length > 0 && (
        <div className="info-section">
          <div className="section-header">
            <span className="section-header__dot"></span>
            FEATURE STATISTICS — BENIGN VS ATTACK
            <span className="section-header__badge">Sampled from training data</span>
          </div>
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Feature</th>
                  <th style={{ color: "#4ade80" }}>Benign Mean</th>
                  <th style={{ color: "#4ade80" }}>Benign Std</th>
                  <th style={{ color: "#f87171" }}>Attack Mean</th>
                  <th style={{ color: "#f87171" }}>Attack Std</th>
                  <th>Divergence</th>
                </tr>
              </thead>
              <tbody>
                {featStats.map((s) => {
                  const diff = Math.abs(s.benign_mean - s.attack_mean);
                  const maxStd = Math.max(s.benign_std, s.attack_std, 1);
                  const divergence = diff / maxStd;
                  const divColor = divergence > 2 ? "#4ade80" : divergence > 0.5 ? "#fbbf24" : "#64748b";
                  return (
                    <tr key={s.feature}>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>
                        {s.feature}
                      </td>
                      <td>{fmtNum(s.benign_mean)}</td>
                      <td>{fmtNum(s.benign_std)}</td>
                      <td>{fmtNum(s.attack_mean)}</td>
                      <td>{fmtNum(s.attack_std)}</td>
                      <td>
                        <span style={{ color: divColor, fontWeight: 600 }}>
                          {divergence.toFixed(2)}σ
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <p style={{ color: "var(--text-dim)", fontSize: "0.7rem", marginTop: "0.5rem", fontFamily: "var(--font-mono)" }}>
            Divergence = |μ_benign − μ_attack| / max(σ_benign, σ_attack). Higher = more discriminative.
          </p>
        </div>
      )}

      {/* ── Model Hyperparameters ─────────────────── */}
      {Object.keys(hyperparams).length > 0 && (
        <div className="info-section">
          <div className="section-header">
            <span className="section-header__dot"></span>
            MODEL HYPERPARAMETERS
            <span className="section-header__badge">XGBoost Classifier</span>
          </div>
          <div className="stat-grid">
            {Object.entries(hyperparams).map(([key, val]) => (
              <StatBox key={key} label={key} value={String(val)} color="cyan" />
            ))}
          </div>
        </div>
      )}

      {/* ── Data Processing Pipeline ─────────────── */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          DATA PROCESSING PIPELINE
        </div>
        <div className="eda-pipeline">
          <PipelineStep icon="📁" title="Raw Data" desc="29 files · 4.5M+ flows · Parquet + CSV" active />
          <PipelineArrow />
          <PipelineStep icon="🧹" title="Cleaning" desc="Remove Inf/NaN · Strip whitespace · Normalize column names" active />
          <PipelineArrow />
          <PipelineStep icon="⚙️" title="Feature Selection" desc={`80+ → ${data.n_features} features · Drop correlated · Keep predictive`} active />
          <PipelineArrow />
          <PipelineStep icon="📏" title="Scaling" desc="StandardScaler · partial_fit() · Incremental on chunks" active />
          <PipelineArrow />
          <PipelineStep icon="🏷️" title="Labelling" desc="Benign → 0 · All attacks → 1 · Binary classification" active />
          <PipelineArrow />
          <PipelineStep icon="🎯" title="Training" desc="XGBoost on GPU · 500K-row chunks · Isotonic calibration" active />
        </div>
      </div>
    </div>
  );
}

function StatBox({ label, value, color }) {
  return (
    <div className="stat-box">
      <div className={`stat-box__value stat-box__value--${color}`}>{value}</div>
      <div className="stat-box__label">{label}</div>
    </div>
  );
}

function PipelineStep({ icon, title, desc, active }) {
  return (
    <div className={`flow-step ${active ? "flow-step--active" : ""}`}>
      <div className="flow-step__icon">{icon}</div>
      <div className="flow-step__title">{title}</div>
      <div className="flow-step__desc">{desc}</div>
    </div>
  );
}

function PipelineArrow() {
  return <div className="flow-arrow">→</div>;
}

function fmtNum(v) {
  if (v == null || isNaN(v)) return "—";
  if (Math.abs(v) >= 1e6) return `${(v / 1e6).toFixed(1)}M`;
  if (Math.abs(v) >= 1e3) return `${(v / 1e3).toFixed(1)}K`;
  return v.toFixed(2);
}

function fmtPct(v) {
  const pct = v * 100;
  if (pct >= 10) return `${pct.toFixed(1)}%`;
  if (pct >= 1) return `${pct.toFixed(2)}%`;
  if (pct >= 0.01) return `${pct.toFixed(3)}%`;
  return `${pct.toFixed(4)}%`;
}
