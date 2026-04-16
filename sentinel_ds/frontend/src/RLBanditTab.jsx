export default function RLBanditTab() {
  return (
    <div className="tab-content">
      <div className="tab-hero">
        <h2 className="tab-hero__title">🎰 Reinforcement Learning — Contextual Bandit</h2>
        <p className="tab-hero__subtitle">UCB1 adaptive triage with threat-density awareness and persistent Q-table</p>
      </div>

      {/* Core Concept */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          CORE CONCEPT
        </div>
        <div className="explanation-card">
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--cyan">What</span>
            <span>A Contextual Bandit using <strong>UCB1 exploration</strong> that learns which triage action to take based on threat probability, analyst workload, and recent threat density</span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--green">Why</span>
            <span>Static thresholds can't adapt — when analysts are overloaded or threats burst, we need smarter decisions to minimize missed threats while reducing alert fatigue</span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--orange">How</span>
            <span>Uses a discretised Q-table <strong>(20 × 20 × 5 × 3 = 6,000 entries)</strong> updated online. UCB1 explores <em>uncertain</em> states instead of wasting budget on random actions</span>
          </div>
        </div>
      </div>

      {/* Context → Action Flow */}
      <div className="flow-diagram">
        <div className="flow-step flow-step--active">
          <div className="flow-step__icon">🎯</div>
          <div className="flow-step__title">Context x(t)</div>
          <div className="flow-step__desc">[threat_score, analyst_load, threat_density] — discretised into 20 × 20 × 5 buckets</div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step flow-step--highlight">
          <div className="flow-step__icon">🧠</div>
          <div className="flow-step__title">UCB1 Policy</div>
          <div className="flow-step__desc">action = argmax[ Q(s,a) + c × √(ln(N) / N(s,a)) ] — intelligent exploration</div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step flow-step--active">
          <div className="flow-step__icon">⚡</div>
          <div className="flow-step__title">Action a(t)</div>
          <div className="flow-step__desc">Dismiss (0) | Monitor (1) | Escalate (2)</div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step flow-step--active">
          <div className="flow-step__icon">🏆</div>
          <div className="flow-step__title">Reward r(t)</div>
          <div className="flow-step__desc">Asymmetric reward scaled by threat_score & analyst load</div>
        </div>
      </div>

      {/* Actions */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          TRIAGE ACTIONS
        </div>
        <div className="action-cards">
          <div className="action-card action-card--green">
            <div className="action-card__id">Action 0</div>
            <div className="action-card__name">DISMISS</div>
            <div className="action-card__desc">Mark flow as benign, no analyst intervention needed</div>
          </div>
          <div className="action-card action-card--orange">
            <div className="action-card__id">Action 1</div>
            <div className="action-card__name">MONITOR</div>
            <div className="action-card__desc">Flag for passive monitoring — valid middle-ground for medium-confidence threats</div>
          </div>
          <div className="action-card action-card--red">
            <div className="action-card__id">Action 2</div>
            <div className="action-card__name">ESCALATE</div>
            <div className="action-card__desc">Immediate analyst review, IP block, high-priority escalation</div>
          </div>
        </div>
      </div>

      {/* Reward Function */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          REWARD FUNCTION (v2 — REFINED)
        </div>
        <div className="reward-table-wrap">
          <table className="reward-table">
            <thead>
              <tr>
                <th>Scenario</th>
                <th>True Label</th>
                <th>Action</th>
                <th>Reward</th>
                <th>Rationale</th>
              </tr>
            </thead>
            <tbody>
              <tr className="reward-table__row--critical">
                <td>Missed Threat</td>
                <td>Threat (1)</td>
                <td>Dismiss (0)</td>
                <td className="reward-value reward-value--negative">−1000 × (1+ts)</td>
                <td>Catastrophic — penalised harder for high-confidence misses</td>
              </tr>
              <tr className="reward-table__row--good">
                <td>Correct Escalation</td>
                <td>Threat (1)</td>
                <td>Escalate (2)</td>
                <td className="reward-value reward-value--positive">+100 × (1+ts)</td>
                <td>Rewarded more for catching high-confidence threats</td>
              </tr>
              <tr className="reward-table__row--good">
                <td>Smart Monitor</td>
                <td>Threat (1)</td>
                <td>Monitor (1)</td>
                <td className="reward-value reward-value--positive">+50 × (1−load)</td>
                <td>Better than dismissing — rewarded when analysts are free</td>
              </tr>
              <tr className="reward-table__row--good">
                <td>Correct Dismiss</td>
                <td>Benign (0)</td>
                <td>Dismiss (0)</td>
                <td className="reward-value reward-value--positive">+10</td>
                <td>No wasted analyst time on safe traffic</td>
              </tr>
              <tr className="reward-table__row--warn">
                <td>False Alarm</td>
                <td>Benign (0)</td>
                <td>Escalate (2)</td>
                <td className="reward-value reward-value--negative">−50 × (1+load)</td>
                <td>Waste scales with analyst workload — worse when busy</td>
              </tr>
              <tr className="reward-table__row--warn">
                <td>Wasted Monitor</td>
                <td>Benign (0)</td>
                <td>Monitor (1)</td>
                <td className="reward-value reward-value--negative">−5</td>
                <td>Small penalty for monitoring irrelevant traffic</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* UCB1 Exploration */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          UCB1 EXPLORATION (REPLACES ε-GREEDY)
        </div>
        <div className="explanation-card">
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--red">Problem</span>
            <span>ε-greedy explores <em>uniformly at random</em>, wasting tries on obviously bad actions (e.g., dismissing a 0.95 threat score)</span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--green">Solution</span>
            <span><strong>UCB1</strong> — explores <em>uncertain</em> state-action pairs using: action = argmax[ Q(s,a) + c × √(ln(N) / N(s,a)) ]</span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--cyan">Exploit</span>
            <span>Q(s,a) = current estimated value of taking action a in state s</span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--orange">Explore</span>
            <span>c × √(ln(N) / N(s,a)) = exploration bonus that grows for rarely-visited state-action pairs</span>
          </div>
        </div>
      </div>

      {/* Q-Table */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          Q-TABLE STRUCTURE (v2)
        </div>
        <div className="explanation-card">
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--cyan">Shape</span>
            <span>(20 threat buckets) × (20 load buckets) × (5 density buckets) × (3 actions) = <strong>6,000 Q-values</strong></span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--green">Update</span>
            <span>Q[s,a] += α(s,a) × (reward − Q[s,a]) where α decays per visit: α = 0.15 / (1 + 0.001 × visits)</span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--orange">Context</span>
            <span>3D context: threat_score (XGBoost output) + analyst_load (SOC workload) + <strong>threat_density</strong> (rolling 100-step average — burst detection)</span>
          </div>
          <div className="explanation-card__row">
            <span className="explanation-card__badge explanation-card__badge--red">Persistence</span>
            <span>Q-table saved to disk after each run via <code>np.save()</code> and auto-loaded on next run — enables <strong>continuous learning</strong> across sessions</span>
          </div>
        </div>
      </div>

      {/* Plots */}
      <div className="info-section">
        <div className="section-header">
          <span className="section-header__dot"></span>
          BANDIT LEARNING RESULTS
        </div>
        <div className="plot-grid">
          <div className="plot-card">
            <img src="/api/plots/action_distribution.png" alt="Action Distribution" onError={(e) => e.target.style.display='none'} />
            <p className="plot-card__label">Action distribution per analyst-load phase — shows adaptive behavior</p>
          </div>
          <div className="plot-card">
            <img src="/api/plots/cumulative_reward.png" alt="Cumulative Reward" onError={(e) => e.target.style.display='none'} />
            <p className="plot-card__label">Cumulative reward over time — upward trend = agent is learning</p>
          </div>
        </div>
      </div>
    </div>
  )
}
