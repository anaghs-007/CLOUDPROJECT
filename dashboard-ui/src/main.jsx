import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import Plot from 'react-plotly.js';
import Plotly from 'plotly.js-dist-min';
import JSZip from 'jszip';
import './styles.css';

const API = import.meta.env.VITE_DASHBOARD_API || 'http://localhost:4000';
const MODES = ['none', 'static', 'adaptive', 'identity', 'adaptive_identity'];
const COLORS = { none: '#6b7280', static: '#0072b2', adaptive: '#009e73', identity: '#e69f00', adaptive_identity: '#cc79a7' };

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
  return <article className="mode-card" style={{ borderTopColor: COLORS[mode] }}>
    <h3>{mode}</h3>
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
  return <section><h2>Violations that got through</h2><ExportButtons benchmark={benchmark} label="violations" graphId="violations-plot" /><Plot divId="violations-plot" className="plot" data={traces} layout={{ title: 'Measured missed violations', yaxis: { title: 'violations (count)' }, xaxis: { title: 'policy mode' }, margin: { t: 45, b: 70 } }} useResizeHandler /><Caption text={`Error bars are bootstrap 95% CI${paper ? '; paper marker is a separately labelled reference.' : '.'}`} benchmark={benchmark} /></section>;
}

function Exposure({ benchmark }) {
  const traces = MODES.map((mode) => ({ y: benchmark.modes?.[mode]?.exposure_seconds?.map((item) => item.value) || [], name: mode, type: 'box', marker: { color: COLORS[mode] }, boxpoints: 'all' }));
  return <section><h2>Exposure duration</h2><ExportButtons benchmark={benchmark} label="exposure" graphId="exposure-plot" /><Plot divId="exposure-plot" className="plot" data={traces} layout={{ yaxis: { title: 'exposure (seconds)' }, xaxis: { title: 'policy mode' }, margin: { t: 25, b: 70 } }} useResizeHandler /><Caption text="Measured per-episode exposure with individual observations." benchmark={benchmark} /></section>;
}

function RiskEvolution({ benchmark }) {
  const traces = MODES.filter((mode) => benchmark.risk_timeseries?.[mode]?.points?.length).map((mode) => {
    const points = benchmark.risk_timeseries[mode].points;
    return { x: points.map((point) => point.t_rel_s), y: points.map((point) => point.risk_u), name: mode, mode: 'lines+markers', line: { color: COLORS[mode] } };
  });
  const events = MODES.flatMap((mode) => (benchmark.risk_timeseries?.[mode]?.events || []).map((event) => ({ ...event, mode })));
  const shapes = [{ type: 'line', y0: benchmark.meta.theta.tau1, y1: benchmark.meta.theta.tau1, x0: 0, x1: 1, xref: 'paper', line: { dash: 'dash', color: '#64748b' } }, { type: 'line', y0: benchmark.meta.theta.tau2, y1: benchmark.meta.theta.tau2, x0: 0, x1: 1, xref: 'paper', line: { dash: 'dot', color: '#b91c1c' } }];
  events.forEach((event) => shapes.push({ type: 'line', x0: event.t_rel_s, x1: event.t_rel_s, y0: 0, y1: 1, line: { color: COLORS[event.mode], dash: 'dashdot' } }));
  return <section><h2>Risk evolution</h2><Plot className="plot" data={traces} layout={{ yaxis: { title: 'user risk ρu(t)', range: [0, 1] }, xaxis: { title: 'relative time (seconds)' }, shapes }} useResizeHandler /><Caption text="Risk lines include tau1/tau2 and vertical enforcement, rejection, and restore markers." benchmark={benchmark} /></section>;
}

function Latency({ benchmark, stats }) {
  const metrics = ['update_latency_ms', 'enforcement_call_ms', 'time_to_effective_ms'];
  const traces = metrics.map((metric) => ({ x: MODES.flatMap((mode) => benchmark.modes?.[mode]?.[metric] || []), name: metric, type: 'histogram', opacity: 0.62 }));
  return <section><h2>Latency distributions</h2><ExportButtons benchmark={benchmark} label="latency" graphId="latency-plot" /><Plot divId="latency-plot" className="plot" data={traces} layout={{ barmode: 'overlay', xaxis: { title: 'latency (milliseconds)' }, yaxis: { title: 'observations' } }} useResizeHandler /><table><thead><tr><th>metric</th><th>mean</th><th>std</th><th>p95</th><th>n</th></tr></thead><tbody>{metrics.map((metric) => { const s = stats.mode_statistics?.identity?.[metric] || {}; return <tr key={metric}><td>{metric}</td><td>{s.mean || 0}</td><td>{s.std || 0}</td><td>{s.p95 || 0}</td><td>{s.n || 0}</td></tr>; })}</tbody></table><Caption text="API update latency, identity enforcement latency, and time-to-effective are distinct measured quantities." benchmark={benchmark} /></section>;
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
  useEffect(() => { const source = new EventSource(`${API}/dash/live/stream`); source.onmessage = (event) => setLive(JSON.parse(event.data)); return () => source.close(); }, []);
  return <section><h2>Live monitor <small>({live.db_status})</small></h2>{live.error && <p className="error">Database unavailable: {live.error}</p>}<div className="live-grid"><div><h3>Risk by user</h3>{live.users.length ? live.users.map((user) => <div className="risk-row" key={user.user_id}><span>{user.user_id}</span><meter min="0" max="1" value={user.risk} /><b>{Number(user.risk).toFixed(2)}</b></div>) : <p>No live risk scores.</p>}</div><div><h3>Active quarantines</h3>{live.quarantines.length ? <ul>{live.quarantines.map((item) => <li key={item.user_id}>{item.user_id} · {item.applied_at}</li>)}</ul> : <p>No active quarantines.</p>}<h3>Recent decisions</h3>{live.decisions.length ? <ul>{live.decisions.map((item) => <li key={item.id}>{item.user_id} · {item.decision} · {item.decision_reason || 'none'}</li>)}</ul> : <p>No recent decisions.</p>}</div></div></section>;
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
  useEffect(() => { Promise.all([get('/dash/benchmark'), get('/dash/stats')]).then(([benchmarkData, statsData]) => { setBenchmark(benchmarkData); setStats(statsData); }).catch((err) => setError(err.message)); }, []);
  const tabs = useMemo(() => ['Overview', 'Violations', 'Exposure', 'Risk evolution', 'Latency', 'Operations', 'Live monitor', ...(benchmark?.ablation?.length ? ['Ablation'] : []), ...(benchmark?.scalability?.length ? ['Scalability'] : [])], [benchmark]);
  if (error) return <main><h1>AC-SCP Evidence Dashboard</h1><p className="error">{error}</p><p>Run the live benchmark matrix without <code>--dry-run</code>, then restart the dashboard API.</p></main>;
  if (!benchmark || !stats) return <main><p>Loading empirical evidence…</p></main>;
  return <main>{benchmark.meta?.mock && <div className="mock-banner">MOCK DATA - NOT RESULTS</div>}<header><div><p className="eyebrow">AC-SCP · Phase 5</p><h1>Empirical evidence dashboard</h1><p>Measured modes, latency, exposure, risk and live operations.</p></div><div><button onClick={() => setPaper(!paper)}>{paper ? 'Hide' : 'Show'} paper reference</button> <button onClick={() => exportBundle(benchmark)}>Export all figures + tables</button><button onClick={() => document.body.classList.toggle('dark')}>Toggle theme</button></div></header><nav>{tabs.map((name) => <button className={tab === name ? 'active' : ''} onClick={() => setTab(name)} key={name}>{name}</button>)}</nav>{tab === 'Overview' && <><div className="cards">{MODES.map((mode) => <Summary key={mode} mode={mode} stats={stats} />)}</div><p className="manifest">manifest {benchmark.meta.git_commit} · generated {benchmark.meta.timestamp} · token lifespan {benchmark.meta.access_token_lifespan}s · revocation {benchmark.meta.revocation_check_mode}</p></>}{tab === 'Violations' && <Violations benchmark={benchmark} stats={stats} paper={paper} />}{tab === 'Exposure' && <Exposure benchmark={benchmark} />}{tab === 'Risk evolution' && <RiskEvolution benchmark={benchmark} />}{tab === 'Latency' && <Latency benchmark={benchmark} stats={stats} />}{tab === 'Live monitor' && <Live />}{tab === 'Ablation' && <Ablation benchmark={benchmark} />}{tab === 'Scalability' && <Scalability benchmark={benchmark} />}{tab === 'Operations' && <section><h2>Operations</h2><div className="cards">{MODES.map((mode) => <Summary key={mode} mode={mode} stats={stats} />)}</div><Caption text="False denies, policy churn, and validation overhead are included in the exported stats contract." benchmark={benchmark} /></section>}</main>;
}

createRoot(document.getElementById('root')).render(<App />);
