/**
 * dashboard.js — ThreatIntel Correlator
 * Handles: Chart.js charts, sparklines, alert table row expansion, auto-refresh, sample data load
 */

/* =========================================================
   Priority Donut Chart (Alert Severity)
   ========================================================= */
function initPriorityChart(priorityCounts) {
  const canvas = document.getElementById('priorityChart');
  if (!canvas) return;

  const labels  = [];
  const data    = [];
  const colors  = [];
  const colorMap = {
    HIGH:    '#ff3b3b',
    MEDIUM:  '#f59e0b',
    LOW:     '#22c55e',
    UNKNOWN: '#4d6278',
  };

  for (const [key, val] of Object.entries(priorityCounts)) {
    labels.push(key);
    data.push(val);
    colors.push(colorMap[key] || '#4d6278');
  }

  if (data.length === 0) return;

  const total = data.reduce((a, b) => a + b, 0);

  new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors,
        borderColor: '#111820',
        borderWidth: 3,
        hoverOffset: 6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#607b96',
            font: { size: 11, family: "'Space Grotesk', sans-serif" },
            padding: 12,
            boxWidth: 10,
            generateLabels: (chart) => {
              const ds = chart.data.datasets[0];
              return chart.data.labels.map((label, i) => ({
                text: `${label}  ${ds.data[i]} (${Math.round(ds.data[i]/total*100)}%)`,
                fillStyle: ds.backgroundColor[i],
                strokeStyle: ds.backgroundColor[i],
                lineWidth: 0,
                index: i,
              }));
            },
          },
        },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.parsed} alerts (${Math.round(ctx.parsed/total*100)}%)`,
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

  new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Alerts',
        data,
        backgroundColor: 'rgba(0,212,200,0.55)',
        borderColor:     '#00d4c8',
        borderWidth: 1,
        borderRadius: 3,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.parsed.x} alerts`,
          },
        },
      },
      scales: {
        x: {
          beginAtZero: true,
          ticks: { color: '#4d6278', font: { size: 11, family: "'JetBrains Mono', monospace" } },
          grid:  { color: 'rgba(30,45,61,0.8)' },
        },
        y: {
          ticks: { color: '#cdd6e0', font: { size: 11, family: "'Space Grotesk', sans-serif" } },
          grid:  { display: false },
        },
      },
    },
  });
}


/* =========================================================
   KPI Sparklines (mini trend lines on KPI cards)
   ========================================================= */
function initSparklines(priorityCounts) {
  // Generate synthetic-looking sparkline data based on actual counts
  const makeSparkData = (finalVal, steps = 8) => {
    const arr = [];
    let v = Math.max(0, finalVal * 0.5);
    for (let i = 0; i < steps - 1; i++) {
      v = Math.max(0, v + (Math.random() - 0.45) * finalVal * 0.3);
      arr.push(Math.round(v));
    }
    arr.push(finalVal);
    return arr;
  };

  const sparkConfigs = [
    { id: 'spark-total',     color: '#00d4c8', val: Object.values(priorityCounts).reduce((a,b) => a+b, 0) },
    { id: 'spark-high',      color: '#ff3b3b', val: priorityCounts['HIGH']   || 0 },
    { id: 'spark-incidents', color: '#3b82f6', val: priorityCounts['MEDIUM'] || 0 },
    { id: 'spark-fp',        color: '#94a3b8', val: priorityCounts['LOW']    || 0 },
  ];

  sparkConfigs.forEach(({ id, color, val }) => {
    const canvas = document.getElementById(id);
    if (!canvas) return;
    const data = makeSparkData(val);
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
          backgroundColor: color.replace(')', ', 0.08)').replace('rgb', 'rgba').replace('#', '').length > 10
            ? color + '18'
            : hexToRgba(color, 0.08),
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: {
          x: { display: false },
          y: { display: false },
        },
        animation: false,
      },
    });
  });
}

function hexToRgba(hex, alpha) {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r},${g},${b},${alpha})`;
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
   "Load Sample Data" button on empty-state dashboard
   ========================================================= */
document.addEventListener('DOMContentLoaded', () => {
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


/* =========================================================
   Utility helpers
   ========================================================= */

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
