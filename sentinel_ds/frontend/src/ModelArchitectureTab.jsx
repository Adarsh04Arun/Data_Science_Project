export default function ModelArchitectureTab() {
  return (
    <div className="tab-content">
      <div className="tab-hero">
        <h2 className="tab-hero__title">🧠 Model Architecture</h2>
        <p className="tab-hero__subtitle">GPU-accelerated XGBoost threat detection with incremental training, early stopping & validation</p>
      </div>

      {/* Architecture Diagram */}
      <div className="flow-diagram">
        <div className="flow-step flow-step--active">
          <div className="flow-step__icon">📦</div>
          <div className="flow-step__title">Feature Chunks</div>
          <div className="flow-step__desc">X (float32 matrix), y (binary labels) from Phase 1</div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step flow-step--highlight">
          <div className="flow-step__icon">🌲</div>
          <div className="flow-step__title">XGBoost Classifier</div>
          <div className="flow-step__desc">tree_method="hist" on GPU (CUDA), partial_train() with early stopping</div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step flow-step--active">
          <div className="flow-step__icon">✅</div>
          <div className="flow-step__title">Validation</div>
          <div className="flow-step__desc">Last 2 training chunks held out — reports honest accuracy</div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step flow-step--active">
          <div className="flow-step__icon">📊</div>
          <div className="flow-step__title">Threat Probability</div>
          <div className="flow-step__desc">predict_proba() → continuous score [0.0, 1.0] for each flow</div>
        </div>
      </div>

      {/* XGBoost Config */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          XGBOOST CONFIGURATION (v2 — TUNED)
        </div>
        <div className="code-block">
          <pre>{`XGBClassifier(
    n_estimators     = 250,        # 250 boosting rounds (up from 100)
    max_depth        = 8,          # Deeper trees for complex patterns
    learning_rate    = 0.08,       # Lower rate + more trees = less overfit
    subsample        = 0.75,       # Row subsampling for regularisation
    colsample_bytree = 0.75,       # Feature subsampling per tree
    gamma            = 3,          # Min loss reduction to split
    min_child_weight = 7,          # Prevents learning from noise
    reg_alpha        = 0.1,        # L1 regularisation
    reg_lambda       = 1.5,        # L2 regularisation
    tree_method      = "hist",     # Histogram-based (fast on GPU)
    device           = "cuda",     # NVIDIA RTX 5060 Ti (8GB VRAM)
    scale_pos_weight = dynamic,    # Calculated per chunk: len(neg)/len(pos)
    eval_metric      = "logloss",  # Binary cross-entropy
)`}</pre>
        </div>
      </div>

      {/* Incremental Training */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          INCREMENTAL TRAINING WITH EARLY STOPPING
        </div>
        <div className="explanation-card">
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--cyan">Step 1</span>
            <span>Load chunk from PyArrow iter_batches() — 500K rows of network flow data</span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--cyan">Step 2</span>
            <span>Preprocess: select 60 features, scale with partial_fit(), downcast to float32</span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--cyan">Step 3</span>
            <span>Calculate dynamic <strong>scale_pos_weight</strong> = neg_count / pos_count for this chunk's class distribution</span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--cyan">Step 4</span>
            <span>Split chunk 90/10 internally — 90% trains via xgb_model continuation, 10% used as <strong>early stopping eval set</strong></span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--cyan">Step 5</span>
            <span>Repeat for training chunks. Last 2 chunks reserved as a <strong>validation set</strong> (never trained on)</span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--green">Result</span>
            <span>Model trains incrementally with honest validation accuracy, automatic feature importance extraction, and top-5 feature logging</span>
          </div>
        </div>
      </div>

      {/* Class Imbalance */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          HANDLING CLASS IMBALANCE
        </div>
        <div className="imbalance-visual">
          <div className="imbalance-bar">
            <div className="imbalance-bar__benign" style={{ width: '85%' }}>
              <span>Benign (~85%)</span>
            </div>
            <div className="imbalance-bar__threat" style={{ width: '15%' }}>
              <span>Threat (~15%)</span>
            </div>
          </div>
          <p className="imbalance-note">
            <strong>scale_pos_weight = dynamic</strong> — calculated per chunk as <code>neg_count / pos_count</code>.
            Unlike a static weight of 5.0, this adapts to each file's actual threat ratio (e.g., Botnet files have different
            distributions than DDoS files), ensuring optimal class weighting throughout incremental training.
          </p>
        </div>
      </div>

      {/* Plots */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          TRAINING RESULTS
        </div>
        <div className="plot-grid">
          <div className="plot-card">
            <img src="/api/plots/recall_precision.png" alt="Recall, Precision & F1" onError={(e) => e.target.style.display='none'} />
            <p className="plot-card__label">Rolling Recall, Precision & F1-Score over simulation steps</p>
          </div>
        </div>
      </div>
    </div>
  )
}
