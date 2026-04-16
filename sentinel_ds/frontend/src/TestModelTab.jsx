import { useState, useRef, useEffect, useCallback } from "react";

const fmt = (v, decimals = 1) =>
  v == null ? "—" : `${(v * 100).toFixed(decimals)}%`;

const fmtN = (v) => (v == null ? "—" : v.toLocaleString());

export default function TestModelTab() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef(null);

  // Live Stream state
  const [streamFlows, setStreamFlows] = useState([]);
  const [streamMetrics, setStreamMetrics] = useState(null);
  const [streaming, setStreaming] = useState(false);
  const [streamDone, setStreamDone] = useState(false);
  const [streamError, setStreamError] = useState(null);
  const [streamConfig, setStreamConfig] = useState({ nFlows: 50, attackRatio: 0.4, delayMs: 100 });
  const eventSourceRef = useRef(null);
  const streamBoxRef = useRef(null);

  const uploadFile = async (file) => {
    if (!file) return;
    setLoading(true);
    setResult(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch(`/api/test-csv?freeze=true`, {
        method: "POST",
        body: form,
      });
      const data = await res.json();
      setResult(data);
    } catch {
      setResult({ error: "Failed to reach API. Is the backend running?" });
    }
    setLoading(false);
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    uploadFile(e.dataTransfer.files[0]);
  };
  const onDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };
  const onDragLeave = () => setDragOver(false);

  const threatColor = (level) =>
    level === "HIGH" ? "#ff4444" : level === "MEDIUM" ? "#ffaa00" : "#00cc88";
  const actionIcon = (a) =>
    a === "Escalate" ? "🚨" : a === "Monitor" ? "👁️" : "✅";

  const s = result?.summary;
  const det = s?.metrics?.detector;
  const agt = s?.metrics?.agent;

  return (
    <div className="test-model-tab">
      {/* ── Upload Zone ───────────────────────────────────── */}
      <div
        className={`csv-upload-zone ${dragOver ? "csv-upload-zone--hover" : ""}`}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onClick={() => fileRef.current?.click()}
      >
        <input
          ref={fileRef}
          type="file"
          accept=".csv"
          hidden
          onChange={(e) => uploadFile(e.target.files[0])}
        />
        {loading ? (
          <>
            <div
              className="csv-upload-zone__icon"
              style={{ animation: "pulse 1s infinite" }}
            >
              ⏳
            </div>
            <p className="csv-upload-zone__text">Analyzing traffic data…</p>
          </>
        ) : (
          <>
            <div className="csv-upload-zone__icon">📁</div>
            <p className="csv-upload-zone__text">
              Drag &amp; drop a CIC-IDS2018 <strong>.csv</strong> file here, or{" "}
              <span className="csv-upload-zone__link">browse</span>
            </p>
            <p className="csv-upload-zone__hint">
              Use <code>python3 generate_test_csv.py</code> to create a sample
              file
            </p>
          </>
        )}
      </div>

      {/* ── Live Stream Section ─────────────────────────────── */}
      <div className="live-stream-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          🔴 LIVE STREAM — REAL DATASET FLOWS
        </div>
        <div className="live-stream-controls">
          <label className="live-stream-control">
            <span>Flows</span>
            <select value={streamConfig.nFlows} onChange={e => setStreamConfig(c => ({ ...c, nFlows: Number(e.target.value) }))} disabled={streaming}>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
            </select>
          </label>
          <label className="live-stream-control">
            <span>Attack %</span>
            <select value={streamConfig.attackRatio} onChange={e => setStreamConfig(c => ({ ...c, attackRatio: Number(e.target.value) }))} disabled={streaming}>
              <option value={0.2}>20%</option>
              <option value={0.4}>40%</option>
              <option value={0.6}>60%</option>
              <option value={0.8}>80%</option>
            </select>
          </label>
          <label className="live-stream-control">
            <span>Delay</span>
            <select value={streamConfig.delayMs} onChange={e => setStreamConfig(c => ({ ...c, delayMs: Number(e.target.value) }))} disabled={streaming}>
              <option value={0}>0ms (instant)</option>
              <option value={50}>50ms</option>
              <option value={100}>100ms</option>
              <option value={200}>200ms</option>
            </select>
          </label>
          {!streaming ? (
            <button className="live-stream-btn live-stream-btn--start" onClick={() => {
              setStreamFlows([]); setStreamMetrics(null); setStreamDone(false); setStreamError(null); setStreaming(true);
              const es = new EventSource(`/api/run-stream?n_flows=${streamConfig.nFlows}&attack_ratio=${streamConfig.attackRatio}&delay_ms=${streamConfig.delayMs}`);
              eventSourceRef.current = es;
              es.onmessage = (e) => {
                const d = JSON.parse(e.data);
                if (d.type === 'flow') {
                  setStreamFlows(prev => [...prev, d]);
                  setStreamMetrics(d.metrics);
                } else if (d.type === 'done') {
                  setStreamMetrics(d.metrics); setStreamDone(true); setStreaming(false); eventSourceRef.current = null; es.close();
                } else if (d.error) {
                  setStreamError(d.error); setStreamDone(true); setStreaming(false); eventSourceRef.current = null; es.close();
                }
              };
              es.onerror = () => { setStreamError("Stream disconnected before completion."); setStreaming(false); setStreamDone(true); eventSourceRef.current = null; es.close(); };
            }}>
              ▶ Run Stream
            </button>
          ) : (
            <button className="live-stream-btn live-stream-btn--stop" onClick={() => {
              eventSourceRef.current?.close(); eventSourceRef.current = null; setStreaming(false); setStreamDone(true);
            }}>
              ⏹ Stop
            </button>
          )}
        </div>

        {streamError && (
          <div className="test-model-card__meta" style={{ color: "#f87171", marginTop: 10 }}>
            {streamError}
          </div>
        )}

        {/* Live metrics bar */}
        {streamMetrics && (
          <div className="live-stream-metrics">
            <div className="live-stream-metric">
              <span className="live-stream-metric__label">Detection Rate</span>
              <span className="live-stream-metric__value" style={{ color: streamMetrics.recall >= 0.95 ? '#10b981' : streamMetrics.recall >= 0.8 ? '#fbbf24' : '#f87171' }}>{(streamMetrics.recall * 100).toFixed(1)}%</span>
            </div>
            <div className="live-stream-metric">
              <span className="live-stream-metric__label">Precision</span>
              <span className="live-stream-metric__value" style={{ color: streamMetrics.precision >= 0.8 ? '#10b981' : '#fbbf24' }}>{(streamMetrics.precision * 100).toFixed(1)}%</span>
            </div>
            <div className="live-stream-metric">
              <span className="live-stream-metric__label">F1</span>
              <span className="live-stream-metric__value" style={{ color: streamMetrics.f1 >= 0.85 ? '#10b981' : '#fbbf24' }}>{(streamMetrics.f1 * 100).toFixed(1)}%</span>
            </div>
            <div className="live-stream-metric">
              <span className="live-stream-metric__label">FPR</span>
              <span className="live-stream-metric__value" style={{ color: streamMetrics.fpr <= 0.3 ? '#10b981' : '#fbbf24' }}>{(streamMetrics.fpr * 100).toFixed(1)}%</span>
            </div>
            <div className="live-stream-metric">
              <span className="live-stream-metric__label">TP</span>
              <span className="live-stream-metric__value" style={{ color: '#10b981' }}>{streamMetrics.tp}</span>
            </div>
            <div className="live-stream-metric">
              <span className="live-stream-metric__label">FP</span>
              <span className="live-stream-metric__value" style={{ color: '#fbbf24' }}>{streamMetrics.fp}</span>
            </div>
            <div className="live-stream-metric">
              <span className="live-stream-metric__label">FN</span>
              <span className="live-stream-metric__value" style={{ color: streamMetrics.fn > 0 ? '#f87171' : '#10b981' }}>{streamMetrics.fn}</span>
            </div>
          </div>
        )}

        {/* Terminal-style flow output */}
        {streamFlows.length > 0 && (
          <div className="live-stream-terminal" ref={streamBoxRef}>
            <div className="live-stream-terminal__header">
              <span>#</span><span>Label</span><span>Score</span><span>Level</span><span>Action</span><span>Outcome</span>
            </div>
            {streamFlows.map((f, i) => (
              <div key={i} className={`live-stream-row live-stream-row--${f.outcome?.toLowerCase() || 'unknown'}`}>
                <span className="live-stream-row__num">{f.row}/{f.total}</span>
                <span className={`live-stream-row__label ${f.label.toLowerCase() === 'benign' ? 'live-stream-row__label--benign' : 'live-stream-row__label--attack'}`}>{f.label}</span>
                <span className="live-stream-row__score" style={{ color: f.score > 0.7 ? '#ff4444' : f.score > 0.3 ? '#ffaa00' : '#00cc88' }}>{(f.score * 100).toFixed(1)}%</span>
                <span className={`live-stream-row__level live-stream-row__level--${f.level?.toLowerCase()}`}>{f.level}</span>
                <span className={`live-stream-row__action live-stream-row__action--${f.action?.toLowerCase()}`}>{f.action}</span>
                <span className={`live-stream-row__outcome live-stream-row__outcome--${f.outcome?.toLowerCase()}`}>{f.outcome}</span>
              </div>
            ))}
            {streamDone && <div className="live-stream-done">✅ Stream complete — {streamFlows.length} flows processed</div>}
          </div>
        )}
      </div>

      {/* ── Error ─────────────────────────────────────────── */}
      {result?.error && <div className="csv-error">⚠️ {result.error}</div>}

      {/* ── Results ───────────────────────────────────────── */}
      {result && !result.error && (
        <>
          {/* Summary bar — no Accuracy, show Detection Rate + Missed */}
          <div className="csv-summary-bar">
            <div className="csv-summary-card">
              <span className="csv-summary-card__label">FILE</span>
              <span
                className="csv-summary-card__value"
                style={{ fontSize: "0.95rem" }}
              >
                {result.filename}
              </span>
            </div>
            <div className="csv-summary-card">
              <span className="csv-summary-card__label">ROWS</span>
              <span className="csv-summary-card__value">
                {result.total_rows}
              </span>
            </div>
            <div className="csv-summary-card">
              <span className="csv-summary-card__label">FEATURES</span>
              <span className="csv-summary-card__value">
                {result.features_used}
              </span>
            </div>
            {agt && (
              <div className="csv-summary-card">
                <span className="csv-summary-card__label">DETECTION RATE</span>
                <span
                  className="csv-summary-card__value"
                  style={{
                    color:
                      agt.recall >= 0.9
                        ? "#00cc88"
                        : agt.recall >= 0.7
                          ? "#ffaa00"
                          : "#ff4444",
                  }}
                >
                  {fmt(agt.recall)}
                </span>
              </div>
            )}
            {agt && (
              <div className="csv-summary-card">
                <span className="csv-summary-card__label">MISSED THREATS</span>
                <span
                  className="csv-summary-card__value"
                  style={{
                    color: agt.missed_threats === 0 ? "#00cc88" : "#ff4444",
                  }}
                >
                  {agt.missed_threats}
                </span>
              </div>
            )}
            {agt && (
              <div className="csv-summary-card">
                <span className="csv-summary-card__label">F1 SCORE</span>
                <span
                  className="csv-summary-card__value"
                  style={{
                    color:
                      agt.f1 >= 0.8
                        ? "#00cc88"
                        : agt.f1 >= 0.6
                          ? "#ffaa00"
                          : "#ff4444",
                  }}
                >
                  {fmt(agt.f1)}
                </span>
              </div>
            )}
          </div>

          {/* ── Metrics Panel ─────────────────────────────── */}
          {(det || agt) && (
            <div className="metrics-panel">
              {/* XGBoost Detector */}
              {det && (
                <div className="metrics-group">
                  <div className="metrics-group__title">
                    <span className="metrics-group__icon">🧠</span>
                    XGBoost Detector
                    <span className="metrics-group__sub">
                      threshold @ {det.threshold}
                    </span>
                  </div>

                  <div className="metric-row">
                    <MetricCard
                      value={fmt(det.precision)}
                      label="Precision"
                      color="cyan"
                      tip="Of flows scored as threat, % that are actual threats (PPV)"
                    />
                    <MetricCard
                      value={fmt(det.recall)}
                      label="Recall (TPR)"
                      color="green"
                      tip="Of all real threats, % correctly detected by XGBoost"
                    />
                    <MetricCard
                      value={fmt(det.f1)}
                      label="F1 Score"
                      color="blue"
                      tip="Harmonic mean of Precision & Recall — overall detector balance"
                    />
                  </div>

                  <ConfusionMatrix
                    tp={det.tp}
                    fp={det.fp}
                    tn={det.tn}
                    fn={det.fn}
                    label="Detector"
                  />
                </div>
              )}

              {/* Bandit Agent */}
              {agt && (
                <div className="metrics-group">
                  <div className="metrics-group__title">
                    <span className="metrics-group__icon">🎰</span>
                    UCB1 Bandit Agent
                    <span className="metrics-group__sub">
                      Monitor + Escalate = positive
                    </span>
                  </div>

                  <div className="metric-row">
                    <MetricCard
                      value={fmt(agt.precision)}
                      label="Precision"
                      color="cyan"
                      tip="Of flows escalated/monitored, % that are real threats"
                    />
                    <MetricCard
                      value={fmt(agt.recall)}
                      label="Detection Rate"
                      color="green"
                      tip="Of all real threats, % caught by the agent (not dismissed)"
                    />
                    <MetricCard
                      value={fmt(agt.f1)}
                      label="F1 Score"
                      color="blue"
                      tip="Harmonic mean — overall agent triage quality"
                    />
                  </div>

                  <div className="metric-row" style={{ marginTop: "0.5rem" }}>
                    <MetricCard
                      value={fmtN(agt.missed_threats)}
                      label="Missed Threats (FN)"
                      color={agt.missed_threats === 0 ? "green" : "red"}
                      tip="Real threats dismissed by agent — catastrophic misses"
                      small
                    />
                    <MetricCard
                      value={fmtN(agt.false_alarms)}
                      label="False Alarms (FP)"
                      color="orange"
                      tip="Benign flows escalated/monitored — analyst noise cost"
                      small
                    />
                    <MetricCard
                      value={fmt(agt.fpr)}
                      label="False Alarm Rate"
                      color="orange"
                      tip="% of benign traffic incorrectly flagged (FP / (FP+TN))"
                      small
                    />
                  </div>

                  <ConfusionMatrix
                    tp={agt.tp}
                    fp={agt.fp}
                    tn={agt.tn}
                    fn={agt.fn}
                    label="Agent"
                  />
                </div>
              )}
            </div>
          )}

          {/* ── Per-Attack Family Breakdown ────────────────── */}
          {s?.per_family && Object.keys(s.per_family).length > 0 && (
            <div className="csv-table-section" style={{ marginTop: "1.5rem" }}>
              <div className="section-header">
                <span className="section-header__dot"></span>
                PER-ATTACK FAMILY BREAKDOWN
              </div>
              <div className="csv-table-scroll">
                <table className="csv-results-table">
                  <thead>
                    <tr>
                      <th>Attack Family</th>
                      <th>Count</th>
                      <th>Avg Score</th>
                      <th>Precision</th>
                      <th>Recall</th>
                      <th>F1</th>
                      <th>TP</th>
                      <th>FP</th>
                      <th>TN</th>
                      <th>FN</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(s.per_family)
                      .sort((a, b) => b[1].count - a[1].count)
                      .map(([family, m]) => (
                        <tr key={family}>
                          <td>
                            <span
                              className={`csv-label-badge ${family.toLowerCase() === "benign"
                                  ? "csv-label-badge--benign"
                                  : "csv-label-badge--attack"
                                }`}
                            >
                              {family}
                            </span>
                          </td>
                          <td>{m.count}</td>
                          <td
                            style={{
                              color:
                                m.avg_score > 0.7
                                  ? "#ff4444"
                                  : m.avg_score > 0.3
                                    ? "#ffaa00"
                                    : "#00cc88",
                              fontWeight: 700,
                            }}
                          >
                            {(m.avg_score * 100).toFixed(1)}%
                          </td>
                          <td>{fmt(m.precision)}</td>
                          <td
                            style={{
                              color:
                                family.toLowerCase() !== "benign"
                                  ? m.recall >= 0.9
                                    ? "#00cc88"
                                    : m.recall >= 0.5
                                      ? "#ffaa00"
                                      : "#ff4444"
                                  : "inherit",
                            }}
                          >
                            {fmt(m.recall)}
                          </td>
                          <td>{fmt(m.f1)}</td>
                          <td style={{ color: "#10b981" }}>{m.tp}</td>
                          <td style={{ color: "#fbbf24" }}>{m.fp}</td>
                          <td style={{ color: "#60a5fa" }}>{m.tn}</td>
                          <td style={{ color: "#f87171" }}>{m.fn}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Score Distribution Histogram ─────────────────── */}
          {result?.rows?.length > 0 && (
            <ScoreDistribution rows={result.rows} />
          )}

          {/* ── Bandit Patch Note ─────────────────────────── */}
          <div className="bandit-patch-note">
            <span className="bandit-patch-note__badge">PATCH v4</span>
            <span className="bandit-patch-note__text">
              <strong>Session 5 upgrades</strong> — Exfiltration detection
              (large-payload + avg-duration behavioural features), per-attack
              family breakdown, aggregator persistence, v4 reward tuning
              (R_FP=-120, R_MONITOR_BENIGN=-75). UCB1 c=1.0. Web threshold 0.35.
              F1=90.9%, Detection Rate=100%, FPR=30%.
            </span>
          </div>

          {/* ── Distributions ─────────────────────────────── */}
          <div className="csv-dist-row">
            <div className="csv-dist-block">
              <div className="section-header">
                <span className="section-header__dot"></span>
                THREAT LEVEL DISTRIBUTION
              </div>
              <div className="csv-dist-bars">
                {[
                  { label: "HIGH", count: s.threat_high, color: "#ff4444" },
                  { label: "MEDIUM", count: s.threat_medium, color: "#ffaa00" },
                  { label: "LOW", count: s.threat_low, color: "#00cc88" },
                ].map((b) => (
                  <div key={b.label} className="csv-bar-item">
                    <span className="csv-bar-item__label">{b.label}</span>
                    <div className="csv-bar-item__track">
                      <div
                        className="csv-bar-item__fill"
                        style={{
                          width: `${Math.max(2, (b.count / result.total_rows) * 100)}%`,
                          background: b.color,
                        }}
                      />
                    </div>
                    <span
                      className="csv-bar-item__count"
                      style={{ color: b.color }}
                    >
                      {b.count}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="csv-dist-block">
              <div className="section-header">
                <span className="section-header__dot"></span>
                AGENT ACTION DISTRIBUTION
              </div>
              <div className="csv-dist-bars">
                {[
                  {
                    label: "Dismiss",
                    count: s.actions.Dismiss,
                    color: "#00cc88",
                    icon: "✅",
                  },
                  {
                    label: "Monitor",
                    count: s.actions.Monitor,
                    color: "#ffaa00",
                    icon: "👁️",
                  },
                  {
                    label: "Escalate",
                    count: s.actions.Escalate,
                    color: "#ff4444",
                    icon: "🚨",
                  },
                ].map((b) => (
                  <div key={b.label} className="csv-bar-item">
                    <span className="csv-bar-item__label">
                      {b.icon} {b.label}
                    </span>
                    <div className="csv-bar-item__track">
                      <div
                        className="csv-bar-item__fill"
                        style={{
                          width: `${Math.max(2, (b.count / result.total_rows) * 100)}%`,
                          background: b.color,
                        }}
                      />
                    </div>
                    <span
                      className="csv-bar-item__count"
                      style={{ color: b.color }}
                    >
                      {b.count}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── Per-Row Table ──────────────────────────────── */}
          <div className="csv-table-section">
            <div className="section-header">
              <span className="section-header__dot"></span>
              PER-ROW ANALYSIS ({result.display_rows || result.rows.length} of {result.total_rows} flows)
              {result.has_labels && (
                <span
                  style={{
                    marginLeft: "1rem",
                    fontSize: "0.7rem",
                    color: "var(--text-secondary)",
                  }}
                >
                  TP = correctly caught · TN = correct dismiss · FP = false
                  alarm · FN = missed threat
                </span>
              )}
              {result.rows_truncated && (
                <span
                  style={{
                    marginLeft: "1rem",
                    fontSize: "0.7rem",
                    color: "var(--accent-cyan)",
                  }}
                >
                  Showing the first {result.display_rows} rows to keep the UI responsive
                </span>
              )}
            </div>
            <div className="csv-table-scroll">
              <table className="csv-results-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Label</th>
                    <th>Threat Score</th>
                    <th>Level</th>
                    <th>Agent Action</th>
                    {result.has_labels && <th>Outcome</th>}
                  </tr>
                </thead>
                <tbody>
                  {result.rows.map((r) => (
                    <tr
                      key={r.row}
                      className={
                        r.outcome === "FN"
                          ? "csv-row--miss"
                          : r.threat_level === "HIGH"
                            ? "csv-row--threat"
                            : ""
                      }
                    >
                      <td>{r.row}</td>
                      <td>
                        <span
                          className={`csv-label-badge ${r.label.toLowerCase() === "benign"
                              ? "csv-label-badge--benign"
                              : "csv-label-badge--attack"
                            }`}
                        >
                          {r.label}
                        </span>
                      </td>
                      <td
                        style={{
                          color: threatColor(r.threat_level),
                          fontWeight: 700,
                        }}
                      >
                        {(r.threat_score * 100).toFixed(1)}%
                      </td>
                      <td>
                        <span style={{ color: threatColor(r.threat_level) }}>
                          {r.threat_level}
                        </span>
                      </td>
                      <td>
                        {actionIcon(r.action)} {r.action}
                      </td>
                      {result.has_labels && (
                        <td>
                          <OutcomeBadge outcome={r.outcome} />
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════
   Sub-components
   ══════════════════════════════════════════════════════════ */

function MetricCard({ value, label, color, tip, small }) {
  return (
    <div
      className={`metric-card${small ? " metric-card--small" : ""}`}
      title={tip}
    >
      <div className={`metric-card__value metric-card__value--${color}`}>
        {value}
      </div>
      <div className="metric-card__label">{label}</div>
      {tip && <div className="metric-card__tip">{tip}</div>}
    </div>
  );
}

function ConfusionMatrix({ tp, fp, tn, fn, label }) {
  return (
    <div className="confusion-matrix">
      <div className="cm-title">Confusion Matrix — {label}</div>
      <div className="cm-grid">
        {/* Header row */}
        <div className="cm-corner" />
        <div className="cm-col-label">Predicted Threat</div>
        <div className="cm-col-label">Predicted Benign</div>

        {/* Row 1: Actual Threat */}
        <div className="cm-row-label">Actual Threat</div>
        <div className="cm-cell cm-cell--tp">
          <span className="cm-cell__count">{tp}</span>
          <span className="cm-cell__tag">TP ✓</span>
        </div>
        <div className="cm-cell cm-cell--fn">
          <span className="cm-cell__count">{fn}</span>
          <span className="cm-cell__tag">FN ✗</span>
        </div>

        {/* Row 2: Actual Benign */}
        <div className="cm-row-label">Actual Benign</div>
        <div className="cm-cell cm-cell--fp">
          <span className="cm-cell__count">{fp}</span>
          <span className="cm-cell__tag">FP !</span>
        </div>
        <div className="cm-cell cm-cell--tn">
          <span className="cm-cell__count">{tn}</span>
          <span className="cm-cell__tag">TN ✓</span>
        </div>
      </div>
    </div>
  );
}

function OutcomeBadge({ outcome }) {
  if (!outcome || outcome === "?") {
    return <span style={{ color: "#4a5568" }}>—</span>;
  }
  const styles = {
    TP: {
      background: "rgba(16,185,129,0.18)",
      color: "#10b981",
      border: "1px solid rgba(16,185,129,0.4)",
    },
    TN: {
      background: "rgba(59,130,246,0.18)",
      color: "#60a5fa",
      border: "1px solid rgba(59,130,246,0.4)",
    },
    FP: {
      background: "rgba(245,158,11,0.18)",
      color: "#fbbf24",
      border: "1px solid rgba(245,158,11,0.4)",
    },
    FN: {
      background: "rgba(239,68,68,0.25)",
      color: "#f87171",
      border: "1px solid rgba(239,68,68,0.5)",
    },
  };
  const s = styles[outcome] || {};
  return (
    <span className="outcome-badge" style={s}>
      {outcome}
    </span>
  );
}

function ScoreDistribution({ rows }) {
  // Build 10 buckets (0-10%, 10-20%, ..., 90-100%)
  const buckets = Array.from({ length: 10 }, () => ({ benign: 0, attack: 0 }));
  rows.forEach((r) => {
    const idx = Math.min(9, Math.floor(r.threat_score * 10));
    if (r.label.toLowerCase() === "benign") {
      buckets[idx].benign++;
    } else {
      buckets[idx].attack++;
    }
  });
  const maxCount = Math.max(...buckets.map((b) => Math.max(b.benign, b.attack)), 1);

  return (
    <div className="csv-table-section" style={{ marginTop: "1.5rem" }}>
      <div className="section-header">
        <span className="section-header__dot"></span>
        SCORE DISTRIBUTION — BENIGN VS ATTACK
        <span className="section-header__badge">Threat Score Histogram</span>
      </div>
      <div className="score-dist">
        <div className="score-dist__chart">
          {buckets.map((b, i) => (
            <div key={i} className="score-dist__col">
              <div className="score-dist__bars">
                <div
                  className="score-dist__bar score-dist__bar--benign"
                  style={{ height: `${(b.benign / maxCount) * 100}%` }}
                  title={`Benign: ${b.benign}`}
                >
                  {b.benign > 0 && <span>{b.benign}</span>}
                </div>
                <div
                  className="score-dist__bar score-dist__bar--attack"
                  style={{ height: `${(b.attack / maxCount) * 100}%` }}
                  title={`Attack: ${b.attack}`}
                >
                  {b.attack > 0 && <span>{b.attack}</span>}
                </div>
              </div>
              <div className="score-dist__label">{i * 10}–{(i + 1) * 10}%</div>
            </div>
          ))}
        </div>
        <div className="score-dist__legend">
          <span className="score-dist__legend-item">
            <span className="score-dist__legend-dot score-dist__legend-dot--benign"></span>
            Benign
          </span>
          <span className="score-dist__legend-item">
            <span className="score-dist__legend-dot score-dist__legend-dot--attack"></span>
            Attack
          </span>
        </div>
      </div>
    </div>
  );
}
