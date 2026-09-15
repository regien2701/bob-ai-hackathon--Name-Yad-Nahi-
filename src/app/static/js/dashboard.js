/**
 * dashboard.js — ThreatIntel Correlator
 * Handles: Chart.js charts, sparklines, alert table row expansion, auto-refresh, sample data load
 */

/* =========================================================
   Helpers
   ========================================================= */
function hexToRgba(hex, alpha) {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}

/** Format an ISO timestamp string for display */
function formatTimestamp(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    });
  } catch (_) {
    return iso;
  }
}

/** Round a score and return a string */
function formatScore(score) {
  if (score === null || score === undefined) return '—';
  return Number(score).toFixed(1);
}

/** Return a CSS class suffix for a priority string */
function formatPriority(priority) {
  const p = (priority || '').toUpperCase();
  if (p === 'HIGH')   return 'high';
  if (p === 'MEDIUM') return 'medium';
  if (p === 'LOW')    return 'low';
  return 'unknown';
}


/* =========================================================
   Priority Donut Chart
   ========================================================= */
function initPriorityChart(priorityCounts) {
  const canvas = document.getElementById('priorityChart');
  if (!canvas) return;

  const labels  = [];
  const data    = [];
  const colors  = [];
  const colorMap = {
    HIGH:    '#ff3d3d',
    MEDIUM:  '#ff8c00',
    LOW:     '#00d4b8',
    UNKNOWN: '#4a5568',
  };

  for (const [key, val] of Object.entries(priorityCounts)) {
    labels.push(key);
    data.push(val);
    colors.push(colorMap[key] || '#4a5568');
  }

  if (data.length === 0) return;

  const total = data.reduce((a, b) => a + b, 0);

  new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors.map(c => hexToRgba(c, 0.85)),
        borderColor: '#050f18',
        borderWidth: 3,
        hoverOffset: 8,
        hoverBorderColor: colors,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#8b9dc3',
            font: { size: 11, family: "'JetBrains Mono', monospace" },
            padding: 12,
            boxWidth: 10,
            generateLabels: (chart) => {
              const ds = chart.data.datasets[0];
              return chart.data.labels.map((label, i) => ({
                text: `${label}  ${Math.round(ds.data[i] / total * 100)}%`,
                fillStyle: ds.backgroundColor[i],
                strokeStyle: ds.borderColor,
                lineWidth: 0,
                hidden: false,
                index: i,
              }));
            },
          },
        },
        tooltip: {
          backgroundColor: '#0a1628',
          borderColor: '#1a2744',
          borderWidth: 1,
          titleColor: '#00d4b8',
          bodyColor: '#c8d6f0',
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.parsed} alerts (${Math.round(ctx.parsed / total * 100)}%)`,
          },
        },
      },
    },
  });
}


/* =========================================================
   Tactic Horizontal Bar Chart
   ========================================================= */
function initTacticChart(tacticCounts) {
  const canvas = document.getElementById('tacticChart');
  if (!canvas || !tacticCounts || tacticCounts.length === 0) return;

  const labels = tacticCounts.map(t => t.tactic);
  const data   = tacticCounts.map(t => t.count);
  const maxVal = Math.max(...data, 1);

  // Gradient colors: most active → red, mid → orange, low → cyan
  const barColors = data.map(v => {
    const ratio = v / maxVal;
    if (ratio > 0.7)  return 'rgba(255,61,61,0.75)';
    if (ratio > 0.35) return 'rgba(255,140,0,0.75)';
    return 'rgba(0,212,184,0.75)';
  });

  new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Alerts',
        data,
        backgroundColor: barColors,
        borderColor: barColors.map(c => c.replace('0.75', '1')),
        borderWidth: 1,
        borderRadius: 3,
        borderSkipped: false,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0a1628',
          borderColor: '#1a2744',
          borderWidth: 1,
          titleColor: '#00d4b8',
          bodyColor: '#c8d6f0',
          callbacks: {
            label: (ctx) => ` ${ctx.parsed.x} alerts`,
          },
        },
      },
      scales: {
        x: {
          beginAtZero: true,
          ticks: { color: '#4a5a7a', font: { size: 10, family: "'JetBrains Mono', monospace" } },
          grid:  { color: 'rgba(0,212,184,0.06)', drawBorder: false },
        },
        y: {
          ticks: { color: '#8b9dc3', font: { size: 11 } },
          grid:  { display: false },
        },
      },
    },
  });
}


/* =========================================================
   KPI Sparkline mini-charts
   ========================================================= */
function initSparklines(priorityCounts) {
  const sparkConfigs = [
    { id: 'spark-total',     color: '#ff3d3d', data: [18, 24, 21, 29, 33, 28, 35, 31, 38, 42] },
    { id: 'spark-high',      color: '#ff8c00', data: [3, 5, 4, 7, 6, 9, 8, 11, 10, 13] },
    { id: 'spark-incidents', color: '#2979ff', data: [1, 2, 1, 3, 2, 4, 3, 5, 4, 6] },
    { id: 'spark-fp',        color: '#00e676', data: [2, 3, 2, 4, 3, 2, 4, 3, 5, 4] },
  ];

  sparkConfigs.forEach(({ id, color, data }) => {
    const canvas = document.getElementById(id);
    if (!canvas) return;

    new Chart(canvas, {
      type: 'line',
      data: {
        labels: data.map((_, i) => i),
        datasets: [{
          data,
          borderColor: color,
          borderWidth: 1.5,
          pointRadius: 0,
          tension: 0.4,
          fill: true,
          backgroundColor: hexToRgba(color, 0.08),
        }],
      },
      options: {
        responsive: false,
        animation: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: {
          x: { display: false },
          y: { display: false },
        },
      },
    });
  });
}


/* =========================================================
   Alert Table — click row to expand / collapse inline detail
   ========================================================= */
function initAlertTable() {
  const table = document.getElementById('alerts-table');
  if (!table) return;

  table.querySelectorAll('tr.row-clickable').forEach(row => {
    row.addEventListener('click', () => {
      const alertId    = row.dataset.alertId;
      const detailRow  = document.getElementById(`detail-row-${alertId}`);
      const panel      = document.getElementById(`detail-panel-${alertId}`);
      if (!detailRow) return;

      const isOpen = row.dataset.expanded === 'true';
      if (isOpen) {
        detailRow.classList.add('hidden');
        panel.classList.remove('open');
        row.dataset.expanded = 'false';
        row.classList.remove('row-expanded');
      } else {
        detailRow.classList.remove('hidden');
        panel.classList.add('open');
        row.dataset.expanded = 'true';
        row.classList.add('row-expanded');
      }
    });
  });
}


/* =========================================================
   Auto-refresh KPI stats every 30 seconds
   ========================================================= */
function startAutoRefresh() {
  setInterval(async () => {
    try {
      const res  = await fetch('/api/v1/stats');
      if (!res.ok) return;
      const data = await res.json();
      updateKpiCard('kpi-total-alerts',  data.total_alerts);
      updateKpiCard('kpi-high-incidents', data.high_incidents);
      updateKpiCard('kpi-open-incidents', data.open_incidents);
      updateKpiCard('kpi-fp-rate',        data.fp_count);
    } catch (_) {
      // Silently ignore network errors during auto-refresh
    }
  }, 30_000);
}

function updateKpiCard(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}


/* =========================================================
   Live clock in topbar
   ========================================================= */
function startClock() {
  const el = document.getElementById('topbar-clock');
  if (!el) return;
  const tick = () => {
    const now = new Date();
    const d = now.toLocaleDateString(undefined, { month: 'short', day: '2-digit', year: 'numeric' });
    const t = now.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    el.textContent = `${d}  ${t}`;
  };
  tick();
  setInterval(tick, 1000);
}


/* =========================================================
   "Load Sample Data" button on empty-state dashboard
   ========================================================= */
document.addEventListener('DOMContentLoaded', () => {
  // Start clock
  startClock();

  // Sample data button
  const btnSample = document.getElementById('btn-load-sample');
  if (btnSample) {
    btnSample.addEventListener('click', async () => {
      const overlay = document.getElementById('loading-overlay');
      const msg     = document.getElementById('loading-message');
      if (overlay) overlay.classList.add('active');
      if (msg)     msg.textContent = 'Loading sample data…';
      btnSample.disabled = true;
      try {
        const res = await fetch('/api/v1/alerts/sample', { method: 'POST' });
        if (res.ok) {
          window.location.href = '/';
        } else {
          const data = await res.json().catch(() => ({}));
          alert('Error: ' + (data.error || 'Failed to load sample data'));
          if (overlay) overlay.classList.remove('active');
          btnSample.disabled = false;
        }
      } catch (e) {
        alert('Network error: ' + e.message);
        if (overlay) overlay.classList.remove('active');
        btnSample.disabled = false;
      }
    });
  }
});
