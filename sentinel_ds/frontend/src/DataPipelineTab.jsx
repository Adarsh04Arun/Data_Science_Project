import { useEffect, useState } from "react";

const DATASET_GROUPS = [
  {
    name: "Large-Scale Intrusion Detection Dataset",
    short: "BCCC-CSE-CIC-IDS2018",
    files: 10,
    type: "Parquet",
    color: "#22d3ee",
    file_list: [
      "Botnet-Friday-02-03-2018",
      "Bruteforce-Wednesday-14-02-2018",
      "DDoS1-Tuesday-20-02-2018",
      "DDoS2-Wednesday-21-02-2018",
      "DoS1-Thursday-15-02-2018",
      "DoS2-Friday-16-02-2018",
      "Infil1-Wednesday-28-02-2018",
      "Infil2-Thursday-01-03-2018",
      "Web1-Thursday-22-02-2018",
      "Web2-Friday-23-02-2018",
    ],
  },
  {
    name: "Intrusion Detection Dataset",
    short: "BCCC-CIC-IDS2017",
    files: 18,
    type: "CSV",
    color: "#a78bfa",
    file_list: [
      "botnet_ares",
      "ddos_loit",
      "dos_golden_eye",
      "dos_hulk",
      "dos_slowhttptest",
      "dos_slowloris",
      "friday_benign",
      "ftp_patator",
      "heartbleed",
      "monday_benign",
      "portscan",
      "ssh_patator-new",
      "thursday_benign",
      "tuesday_benign",
      "web_brute_force",
      "web_sql_injection",
      "web_xss",
      "wednesday_benign",
    ],
  },
  {
    name: "Cloud DDoS Attacks",
    short: "BCCC-cPacket-Cloud-DDoS-2024",
    files: 1,
    type: "Parquet",
    color: "#f59e0b",
    file_list: ["bccc-cpacket-cloud-ddos-2024-merged"],
  },
];

export default function DataPipelineTab() {
  const [stats, setStats] = useState(null);
  const [dataSample, setDataSample] = useState(null);
  const [openGroup, setOpenGroup] = useState(null);

  useEffect(() => {
    fetch("/api/pipeline-stats")
      .then((r) => r.json())
      .then(setStats)
      .catch(() => {});
    fetch("/api/data-sample")
      .then((r) => r.json())
      .then(setDataSample)
      .catch(() => {});
  }, []);

  const groups = stats?.dataset_groups || DATASET_GROUPS;
  const totalFiles = stats?.total_files || 29;

  return (
    <div className="tab-content">
      <div className="tab-hero">
        <h2 className="tab-hero__title">📊 Data Pipeline</h2>
        <p className="tab-hero__subtitle">
          From raw network captures to model-ready features
        </p>
      </div>

      {/* ── Dataset Sources ───────────────────────────────── */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          DATASET SOURCES
          <span className="section-header__badge">
            {totalFiles} files · 3 datasets
          </span>
        </div>

        <div className="dataset-source-grid">
          {groups.map((g, i) => (
            <div
              key={i}
              className="dataset-source-card"
              style={{ "--ds-color": g.color }}
            >
              <div className="dataset-source-card__header">
                <div>
                  <div className="dataset-source-card__name">{g.name}</div>
                  <div className="dataset-source-card__short">{g.short}</div>
                </div>
                <div className="dataset-source-card__badges">
                  <span className="dataset-source-card__badge dataset-source-card__badge--type">
                    {g.type}
                  </span>
                  <span className="dataset-source-card__badge dataset-source-card__badge--count">
                    {g.files} files
                  </span>
                </div>
              </div>

              <button
                className="dataset-source-card__toggle"
                onClick={() => setOpenGroup(openGroup === i ? null : i)}
              >
                {openGroup === i ? "▲ Hide files" : "▼ Show files"}
              </button>

              {openGroup === i && (
                <div className="dataset-files-list">
                  {(g.file_list || []).map((f, j) => (
                    <div key={j} className="dataset-file-entry">
                      <span className="dataset-file-entry__icon">
                        {g.type === "Parquet" ? "📦" : "📄"}
                      </span>
                      <span className="dataset-file-entry__name">{f}</span>
                      <span className="dataset-file-entry__ext">
                        .{g.type.toLowerCase()}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* ── Flow Diagram ──────────────────────────────────── */}
      <div className="flow-diagram">
        <div className="flow-step flow-step--active">
          <div className="flow-step__icon">📁</div>
          <div className="flow-step__title">Multi-Source Dataset</div>
          <div className="flow-step__desc">
            {totalFiles} files across 3 datasets (CIC-IDS2018, CIC-IDS2017,
            Cloud-DDoS-2024) — Parquet + CSV formats with millions of labelled
            network flows
          </div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step flow-step--active">
          <div className="flow-step__icon">🔄</div>
          <div className="flow-step__title">Chunked Loading</div>
          <div className="flow-step__desc">
            PyArrow iter_batches() yields{" "}
            {stats?.chunk_size?.toLocaleString() || "500,000"}-row chunks to
            avoid OOM crashes on 8 GB VRAM
          </div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step flow-step--active">
          <div className="flow-step__icon">🧹</div>
          <div className="flow-step__title">Cleaning</div>
          <div className="flow-step__desc">
            Replace Inf/−Inf → NaN, drop all NaN rows per chunk before any
            processing
          </div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step flow-step--active">
          <div className="flow-step__icon">⚙️</div>
          <div className="flow-step__title">Feature Engineering</div>
          <div className="flow-step__desc">
            Select {stats?.features_used || 61} key features, downcast float64 →
            float32, incremental StandardScaler (saved to scaler.joblib)
          </div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step flow-step--active">
          <div className="flow-step__icon">🎯</div>
          <div className="flow-step__title">Binary Labels</div>
          <div className="flow-step__desc">
            "Benign" → 0, all attacks (DDoS, Botnet, Brute Force, Infiltration,
            Web…) → 1
          </div>
        </div>
      </div>

      {/* ── Raw Data Sample — Before ──────────────────────── */}
      {dataSample && dataSample.raw_rows?.length > 0 && (
        <div className="info-section">
          <div className="section-header">
            <span className="section-header__dot"></span>
            RAW DATA — BEFORE PROCESSING
            <span className="section-header__badge">
              Source: {dataSample.source_file}
            </span>
          </div>
          <p className="data-meta">
            {dataSample.total_columns} columns · Sample of{" "}
            {dataSample.raw_rows.length} rows · dtypes: float64, object
          </p>
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  {dataSample.raw_columns.map((col) => (
                    <th key={col}>
                      {col}
                      <span className="data-table__dtype">
                        {dataSample.dtypes_before?.[col]}
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {dataSample.raw_rows.map((row, i) => (
                  <tr key={i}>
                    {dataSample.raw_columns.map((col) => (
                      <td
                        key={col}
                        className={
                          row[col] === "Inf" || row[col] === "NaN"
                            ? "data-table__bad"
                            : col === "Label"
                              ? row[col] === "Benign"
                                ? "data-table__benign"
                                : "data-table__threat"
                              : ""
                        }
                      >
                        {row[col]}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Processed Data Sample — After ────────────────── */}
      {dataSample && dataSample.processed_rows?.length > 0 && (
        <div className="info-section">
          <div className="section-header">
            <span className="section-header__dot"></span>
            PROCESSED DATA — AFTER FEATURE ENGINEERING
            <span className="section-header__badge">
              {dataSample.dtype_after}
            </span>
          </div>
          <p className="data-meta">
            {stats?.features_used || 61} selected features · Labels binarised
            (Benign→0, Attack→1) · Scaled with StandardScaler
          </p>
          <div className="data-table-wrap">
            <table className="data-table data-table--processed">
              <thead>
                <tr>
                  {dataSample.processed_columns.map((col) => (
                    <th key={col}>{col}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {dataSample.processed_rows.map((row, i) => (
                  <tr key={i}>
                    {dataSample.processed_columns.map((col) => (
                      <td
                        key={col}
                        className={
                          col === "is_threat"
                            ? row[col] === "1"
                              ? "data-table__threat"
                              : "data-table__benign"
                            : ""
                        }
                      >
                        {row[col]}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Processing Statistics ─────────────────────────── */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          PROCESSING STATISTICS
        </div>
        <div className="stat-grid">
          <StatBox
            label="Total Dataset Files"
            value={totalFiles}
            color="cyan"
          />
          <StatBox
            label="Events Processed"
            value={stats?.total_events?.toLocaleString() || "—"}
            color="blue"
          />
          <StatBox
            label="Features Selected"
            value={stats?.features_used || 61}
            color="green"
          />
          <StatBox
            label="Train / Test Split"
            value={`${(stats?.train_ratio || 0.8) * 100}% / ${(1 - (stats?.train_ratio || 0.8)) * 100}%`}
            color="orange"
          />
          <StatBox
            label="Chunk Size"
            value={stats?.chunk_size?.toLocaleString() || "500,000"}
            color="cyan"
          />
          <StatBox label="Parquet Files" value={11} color="purple" />
          <StatBox label="CSV Files" value={18} color="purple" />
          <StatBox label="Scaler" value="StandardScaler" color="green" />
        </div>
      </div>

      {/* ── Memory Strategy ───────────────────────────────── */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          MEMORY OPTIMIZATION STRATEGY
        </div>
        <div className="explanation-card">
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--red">
              Problem
            </span>
            <span>
              16 GB+ dataset on 8 GB VRAM GPU (RTX 5060 Ti) running inside WSL
              causes OOM crashes
            </span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--green">
              Solution
            </span>
            <span>
              Sequential chunking via PyArrow — never loads more than one chunk
              into memory at once
            </span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--cyan">
              Optimization
            </span>
            <span>
              Downcast float64 → float32 cuts memory usage in half. Uses
              partial_fit() for incremental scaling
            </span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--orange">
              Fallback
            </span>
            <span>
              GPU (CUDA) first attempt → automatic CPU fallback if CUDA
              unavailable or OOM
            </span>
          </div>
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
