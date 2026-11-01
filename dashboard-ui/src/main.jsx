import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import Plot from 'react-plotly.js';
import Plotly from 'plotly.js-dist-min';
import JSZip from 'jszip';
import './styles.css';

const API = import.meta.env.VITE_DASHBOARD_API || 'http://localhost:4000';
const MODES = ['none', 'static', 'adaptive', 'identity', 'adaptive_identity'];
const COLORS = { none: '#6b7280', static: '#0072b2', adaptive: '#009e73', identity: '#e69f00', adaptive_identity: '#cc79a7' };
const PAPER_REFERENCE = 'Reported in paper, different environment';

async function get(path) {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) {
    let detail = '';
    try { detail = (await response.json()).error || ''; } catch (_) {}
    throw new Error(detail || `${path}: HTTP ${response.status}`);
  }
  return response.json();
}

function Caption({ text, benchmark }) {
  const meta = benchmark?.meta || {};
  return <p className="caption">{text} · n={meta.seeds?.length || 0} runs · seeds={meta.seeds?.join(', ') || 'none'}</p>;
}

function EmptyState({ title, detail }) {
  return <div className="empty-state"><div className="empty-icon">◌</div><h3>{title}</h3><p>{detail}</p></div>;
}

function PlotFrame({ children, title, description, actions }) {
  return <section className="panel"><div className="panel-heading"><div><p className="section-kicker">Evidence view</p><h2>{title}</h2><p className="section-description">{description}</p></div>{actions}</div>{children}</section>;
}

function download(name, content, type) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([content], { type }));
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}

function csvFor(benchmark) {
  return `mode,seed,total_requests,violations_missed,violations_blocked,false_denies,policy_changes\n${
    Object.entries(benchmark.modes || {}).flatMap(([mode, data]) =>
      (data.runs || []).map((run) => `${mode},${run.seed},${run.total_requests},${run.violations_missed},${run.violations_blocked},${run.false_denies},${run.policy_changes}`),
    ).join('\n')}`;
}

function ExportButtons({ benchmark, label, graphId }) {
  return <div className="export-buttons">
    <button onClick={() => download(`${label}.json`, JSON.stringify(benchmark, null, 2), 'application/json')}>JSON</button>
    <button onClick={() => download(`${label}.csv`, csvFor(benchmark), 'text/csv')}>CSV</button>
    {graphId && <><button onClick={() => Plotly.downloadImage(document.getElementById(graphId), { format: 'png', filename: label })}>PNG</button><button onClick={() => Plotly.downloadImage(document.getElementById(graphId), { format: 'svg', filename: label })}>SVG</button></>}
  </div>;
}

function Summary({ mode, stats }) {
  const s = stats?.mode_statistics?.[mode] || {};
  const metric = (key) => s[key] || { mean: 0, ci_95: [0, 0], n: 0 };
  return <article className="mode-card" style={{ '--mode-color': COLORS[mode] }}>
    <div className="mode-label"><span className="mode-dot" />{mode.replace('_', ' ')}</div>
    <strong>{metric('violations_missed').mean.toFixed(1)}</strong><span> missed violations</span>
    <dl><dt>95% CI</dt><dd>{metric('violations_missed').ci_95.join('–')}</dd><dt>False denies</dt><dd>{metric('false_denies').mean.toFixed(1)}</dd><dt>Exposure</dt><dd>{metric('exposure_seconds').mean.toFixed(1)} s</dd><dt>Effective</dt><dd>{metric('time_to_effective_ms').mean.toFixed(1)} ms</dd></dl>
    <small>n={metric('violations_missed').n}{metric('violations_missed').low_sample_size ? ' · low sample size' : ''}</small>
  </article>;
}

function Violations({ benchmark, stats, paper }) {
  const values = MODES.map((mode) => stats.mode_statistics?.[mode]?.violations_missed?.mean || 0);
  const errors = MODES.map((mode) => { const s = stats.mode_statistics?.[mode]?.violations_missed; return s ? Math.max(0, s.ci_95[1] - s.mean) : 0; });
  const traces = [{ x: MODES, y: values, error_y: { type: 'data', array: errors, visible: true }, marker: { color: MODES.map((mode) => COLORS[mode]) }, type: 'bar', name: 'measured' }];
  if (paper) traces.push({ x: ['paper reference'], y: [45], type: 'scatter', mode: 'markers', marker: { color: '#b91c1c', size: 14 }, name: 'reported in paper, different environment' });
  return <PlotFrame title="Violations that got through" description="Lower is better. Bars are measured results; error bars are bootstrap 95% confidence intervals." actions={<ExportButtons benchmark={benchmark} label="violations" graphId="violations-plot" />}><Plot divId="violations-plot" className="plot" data={traces} layout={{ title: 'Measured missed violations', yaxis: { title: 'violations (count)' }, xaxis: { title: 'policy mode' }, margin: { t: 45, b: 70 }, paper_bgcolor: 'transparent', plot_bgcolor: 'transparent' }} useResizeHandler config={{ responsive: true, displaylogo: false }} /><Caption text={paper ? `${PAPER_REFERENCE}: 45 violations is shown only as a separate reference marker.` : 'No paper values are included in the measured chart.'} benchmark={benchmark} /></PlotFrame>;
}

function Exposure({ benchmark, paper }) {
  const traces = MODES.map((mode) => ({ y: benchmark.modes?.[mode]?.exposure_seconds?.map((item) => item.value) || [], name: mode, type: 'box', marker: { color: COLORS[mode] }, boxpoints: 'all' }));
  const hasData = traces.some((trace) => trace.y.length);
  return <PlotFrame title="Exposure duration" description="Time a malicious episode remains exposed before containment, measured in seconds." actions={<ExportButtons benchmark={benchmark} label="exposure" graphId={hasData ? 'exposure-plot' : undefined} />}>{hasData ? <Plot divId="exposure-plot" className="plot" data={traces} layout={{ yaxis: { title: 'exposure (seconds)' }, xaxis: { title: 'policy mode' }, margin: { t: 25, b: 70 }, paper_bgcolor: 'transparent', plot_bgcolor: 'transparent' }} useResizeHandler config={{ responsive: true, displaylogo: false }} /> : <EmptyState title="No exposure episodes exported" detail="The benchmark contains no attack_episodes samples. Run the simulator with a scenario that creates episodes, then regenerate benchmark.json." />}<Caption text={paper ? `${PAPER_REFERENCE}: paper exposure values are not plotted on this measured axis.` : 'Measured per-episode exposure with individual observations.'} benchmark={benchmark} /></PlotFrame>;
}

function RiskEvolution({ benchmark }) {
  const traces = MODES.filter((mode) => benchmark.risk_timeseries?.[mode]?.points?.length).map((mode) => {
    const points = benchmark.risk_timeseries[mode].points;
    return { x: points.map((point) => point.t_rel_s), y: points.map((point) => point.risk_u), name: mode, mode: 'lines+markers', line: { color: COLORS[mode] } };
  });
  const events = MODES.flatMap((mode) => (benchmark.risk_timeseries?.[mode]?.events || []).map((event) => ({ ...event, mode })));
  if (!traces.length) return <PlotFrame title="Risk evolution" description="User risk over relative episode time, with tau thresholds and enforcement events."><EmptyState title="No risk time-series exported" detail="risk_score_history is empty in this benchmark. Start the risk engine during the identity/adaptive runs, then regenerate the benchmark." /><Caption text="No risk points or event markers are available." benchmark={benchmark} /></PlotFrame>;
  const shapes = [{ type: 'line', y0: benchmark.meta.theta.tau1, y1: benchmark.meta.theta.tau1, x0: 0, x1: 1, xref: 'paper', line: { dash: 'dash', color: '#64748b' } }, { type: 'line', y0: benchmark.meta.theta.tau2, y1: benchmark.meta.theta.tau2, x0: 0, x1: 1, xref: 'paper', line: { dash: 'dot', color: '#b91c1c' } }];
  events.forEach((event) => shapes.push({ type: 'line', x0: event.t_rel_s, x1: event.t_rel_s, y0: 0, y1: 1, line: { color: COLORS[event.mode], dash: 'dashdot' } }));
  return <PlotFrame title="Risk evolution" description="The risk trajectory explains when a policy decision became necessary."><Plot className="plot" data={traces} layout={{ yaxis: { title: 'user risk ρu(t)', range: [0, 1] }, xaxis: { title: 'relative time (seconds)' }, shapes, paper_bgcolor: 'transparent', plot_bgcolor: 'transparent' }} useResizeHandler config={{ responsive: true, displaylogo: false }} /><Caption text={`Thresholds tau1=${benchmark.meta.theta.tau1} and tau2=${benchmark.meta.theta.tau2}; vertical lines show exported events (${events.length}).`} benchmark={benchmark} /></PlotFrame>;
}

function Latency({ benchmark, stats }) {
  const metrics = ['update_latency_ms', 'enforcement_call_ms', 'time_to_effective_ms'];
  const summaries = metrics.map((metric) => ({ metric, stats: stats.mode_statistics?.identity?.[metric] || {} })).filter(({ stats: item }) => item.n > 0);
  const traces = summaries.map(({ metric, stats: item }) => ({ x: [metric], y: [item.mean], error_y: { type: 'data', array: [Math.max(0, item.ci_95[1] - item.mean)], visible: true }, type: 'bar', name: metric }));
  return <PlotFrame title="Latency" description="Separate timing stages: API policy update, Keycloak enforcement calls, and first effective rejection." actions={<ExportButtons benchmark={benchmark} label="latency" graphId={traces.length ? 'latency-plot' : undefined} />}>{traces.length ? <Plot divId="latency-plot" className="plot" data={traces} layout={{ yaxis: { title: 'milliseconds' }, margin: { t: 25, b: 95 }, paper_bgcolor: 'transparent', plot_bgcolor: 'transparent' }} useResizeHandler config={{ responsive: true, displaylogo: false }} /> : <EmptyState title="No latency samples exported" detail="The benchmark has no policy_updates or identity_enforcement_events timing samples. Start the adaptive risk engine and regenerate the benchmark." />}<table><thead><tr><th>Metric</th><th>Mean</th><th>Std</th><th>P95</th><th>n</th></tr></thead><tbody>{metrics.map((metric) => { const item = stats.mode_statistics?.identity?.[metric] || {}; return <tr key={metric}><td>{metric.replaceAll('_', ' ')}</td><td>{item.mean ?? 0}</td><td>{item.std ?? 0}</td><td>{item.p95 ?? 0}</td><td>{item.n ?? 0}</td></tr>; })}</tbody></table><Caption text="No zero values are interpreted as measured latency; n=0 means the timing source was absent." benchmark={benchmark} /></PlotFrame>;
}

function Ablation({ benchmark }) {
  const rows = benchmark.ablation || [];
  return <section><h2>Ablation</h2><Plot className="plot" data={[{ x: rows.map((row) => row.mode), y: rows.map((row) => row.violations), type: 'bar', marker: { color: '#0072b2' } }]} layout={{ yaxis: { title: 'violations (count)' }, xaxis: { title: 'ablation mode' } }} useResizeHandler /><Caption text="Measured ablation data supplied by the benchmark manifest." benchmark={benchmark} /></section>;
}

function Scalability({ benchmark }) {
  const rows = benchmark.scalability || [];
  return <section><h2>Scalability</h2><Plot className="plot" data={[{ x: rows.map((row) => row.tenants), y: rows.map((row) => row.avg_update_latency_ms), type: 'scatter', mode: 'lines+markers', name: 'update latency' }, { x: rows.map((row) => row.tenants), y: rows.map((row) => row.violations), type: 'scatter', mode: 'lines+markers', name: 'violations', yaxis: 'y2' }]} layout={{ xaxis: { title: 'tenants (count)' }, yaxis: { title: 'update latency (milliseconds)' }, yaxis2: { title: 'violations (count)', overlaying: 'y', side: 'right' } }} useResizeHandler /><Caption text="Measured scalability data supplied by the benchmark manifest." benchmark={benchmark} /></section>;
}

function Live() {
  const [live, setLive] = useState({ users: [], decisions: [], quarantines: [], db_status: 'connecting' });
  useEffect(() => {
    const source = new EventSource(`${API}/dash/live/stream`);
    source.onmessage = (event) => {
      try { setLive(JSON.parse(event.data)); } catch (_) { setLive((current) => ({ ...current, db_status: 'invalid response', error: 'The live stream returned invalid JSON.' })); }
    };
    source.onerror = () => setLive((current) => ({ ...current, db_status: 'unavailable', error: 'Cannot connect to the dashboard API SSE stream.' }));
    return () => source.close();
  }, []);
  const connected = live.db_status === 'connected';
  return <PlotFrame title="Live monitor" description="Read-only PostgreSQL view of current risk, decisions, and active identity quarantines."><div className={`live-status ${connected ? 'is-connected' : 'is-warning'}`}><span className="status-dot" />{connected ? 'Database connected' : `Database ${live.db_status || 'unavailable'}`}<span className="live-time">{live.timestamp ? `Updated ${new Date(live.timestamp).toLocaleTimeString()}` : ''}</span></div>{live.error && <p className="inline-alert">{live.error}. Verify the dashboard API is running with the dashboard_ro credentials.</p>}<div className="live-grid"><div className="live-card"><h3>Risk by user</h3>{live.users.length ? live.users.map((user) => <div className="risk-row" key={user.user_id}><span>{user.user_id}</span><meter min="0" max="1" value={user.risk} /><b>{Number(user.risk).toFixed(2)}</b></div>) : <EmptyState title="No live risk scores" detail={connected ? 'The risk engine has not written current scores.' : 'Live data is unavailable.'} />}</div><div className="live-card"><h3>Active quarantines</h3>{live.quarantines.length ? <ul className="event-list">{live.quarantines.map((item) => <li key={item.user_id}><strong>{item.user_id}</strong><span>{item.applied_at ? new Date(item.applied_at).toLocaleString() : 'time unavailable'}</span></li>)}</ul> : <p className="muted">No active quarantines.</p>}<h3>Recent decisions</h3>{live.decisions.length ? <ul className="event-list">{live.decisions.map((item) => <li key={item.id}><strong>{item.user_id} · {item.decision}</strong><span>{item.decision_reason || 'no reason recorded'}</span></li>)}</ul> : <p className="muted">No recent decisions.</p>}</div></div></PlotFrame>;
}

async function exportBundle(benchmark) {
  const zip = new JSZip();
  zip.file('benchmark.json', JSON.stringify(benchmark, null, 2));
  zip.file('manifest.json', JSON.stringify(benchmark.meta || {}, null, 2));
  zip.file('runs.csv', csvFor(benchmark));
  download('ac-scp-evidence-export.zip', await zip.generateAsync({ type: 'blob' }), 'application/zip');
}

function App() {
  const [benchmark, setBenchmark] = useState(null); const [stats, setStats] = useState(null); const [tab, setTab] = useState('Overview'); const [error, setError] = useState(''); const [paper, setPaper] = useState(false);
  useEffect(() => {
    let active = true;
    const refresh = () => Promise.all([get('/dash/benchmark'), get('/dash/stats')])
      .then(([benchmarkData, statsData]) => {
        if (!active) return;
        setBenchmark(benchmarkData);
        setStats(statsData);
        setError('');
      })
      .catch((err) => {
        if (active && !benchmark) setError(err.message);
      });
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);
  const tabs = useMemo(() => ['Overview', 'Violations', 'Exposure', 'Risk evolution', 'Latency', 'Operations', 'Live monitor', ...(benchmark?.ablation?.length ? ['Ablation'] : []), ...(benchmark?.scalability?.length ? ['Scalability'] : [])], [benchmark]);
  if (error) return <main><h1>AC-SCP Evidence Dashboard</h1><p className="error">{error}</p><p>Run the live benchmark matrix without <code>--dry-run</code>, then restart the dashboard API.</p></main>;
  if (!benchmark || !stats) return <main><p>Loading empirical evidence…</p></main>;
  return <main>{benchmark.meta?.mock && <div className="mock-banner">MOCK DATA - NOT RESULTS</div>}<header><div><p className="eyebrow">AC-SCP · PHASE 5 / EVIDENCE LAB</p><h1>Security policy evidence</h1><p className="hero-copy">Compare measured enforcement modes, understand the timing chain, and inspect live operations.</p></div><div className="header-actions"><button className="secondary" onClick={() => setPaper(!paper)}>{paper ? 'Hide paper layer' : 'Show paper layer'}</button><button className="primary" onClick={() => exportBundle(benchmark)}>Export evidence</button><button className="icon-button" aria-label="Toggle theme" onClick={() => document.body.classList.toggle('dark')}>◐</button></div></header><div className="research-note"><strong>{paper ? 'Paper reference layer is visible.' : 'Measured data only.'}</strong><span>{paper ? `${PAPER_REFERENCE}. It is never mixed into measured statistics.` : 'Use the paper layer only for contextual comparison, not as a local result.'}</span></div><nav>{tabs.map((name) => <button className={tab === name ? 'active' : ''} onClick={() => setTab(name)} key={name}>{name}</button>)}</nav>{tab === 'Overview' && <><div className="cards">{MODES.map((mode) => <Summary key={mode} mode={mode} stats={stats} />)}</div><div className="manifest"><span>Manifest <b>{benchmark.meta.git_commit?.slice(0, 10)}</b></span><span>{benchmark.meta.seeds?.length} held-out seeds</span><span>{benchmark.meta.requests_per_run} requests/run</span><span>Token lifespan {benchmark.meta.access_token_lifespan}s</span><span>Revocation: {benchmark.meta.revocation_check_mode}</span></div></>}{tab === 'Violations' && <Violations benchmark={benchmark} stats={stats} paper={paper} />}{tab === 'Exposure' && <Exposure benchmark={benchmark} paper={paper} />}{tab === 'Risk evolution' && <RiskEvolution benchmark={benchmark} />}{tab === 'Latency' && <Latency benchmark={benchmark} stats={stats} />}{tab === 'Live monitor' && <Live />}{tab === 'Ablation' && <Ablation benchmark={benchmark} />}{tab === 'Scalability' && <Scalability benchmark={benchmark} />}{tab === 'Operations' && <section className="panel"><div className="panel-heading"><div><p className="section-kicker">Operations</p><h2>Operational quality</h2><p className="section-description">False denies, policy churn, and validation overhead across measured modes.</p></div></div><div className="cards">{MODES.map((mode) => <Summary key={mode} mode={mode} stats={stats} />)}</div><Caption text="Operational metrics are sourced from stats.json." benchmark={benchmark} /></section>}</main>;
}

createRoot(document.getElementById('root')).render(<App />);
