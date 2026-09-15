/**
 * upload.js — ThreatIntel Correlator
 * Handles: drag-and-drop file zone, file upload, sample data loader
 */

(function () {
  'use strict';

  const dropZone      = document.getElementById('drop-zone');
  const fileInput     = document.getElementById('file-input');
  const uploadProgress = document.getElementById('upload-progress');
  const progressFill  = document.getElementById('progress-fill');
  const progressLabel = document.getElementById('progress-label');
  const uploadResult  = document.getElementById('upload-result');
  const resultStats   = document.getElementById('result-stats');
  const uploadError   = document.getElementById('upload-error');
  const uploadErrorMsg = document.getElementById('upload-error-msg');
  const btnLoadSample = document.getElementById('btn-load-sample');

  if (!dropZone) return;  // not on upload page

  // =========================================================
  // Drag & Drop events
  // =========================================================
  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) handleFile(fileInput.files[0]);
  });


  // =========================================================
  // File validation & upload
  // =========================================================
  function handleFile(file) {
    const ext = file.name.toLowerCase().split('.').pop();
    if (ext !== 'csv' && ext !== 'json') {
      showError(`Unsupported file type ".${ext}". Please use .csv or .json`);
      return;
    }

    uploadFile(file);
  }

  function uploadFile(file) {
    hideError();
    hideResult();
    showProgress('Uploading…', 10);

    const formData = new FormData();
    formData.append('file', file);

    const xhr = new XMLHttpRequest();

    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 80);  // 0–80% during upload
        showProgress('Uploading…', pct);
      }
    });

    xhr.addEventListener('load', () => {
      let data;
      try {
        data = JSON.parse(xhr.responseText);
      } catch (_) {
        data = {};
      }

      if (xhr.status === 200) {
        showProgress('Processing pipeline…', 90);
        setTimeout(() => {
          hideProgress();
          showResult(data);
        }, 400);
      } else {
        hideProgress();
        showError(data.error || `Upload failed (HTTP ${xhr.status})`);
      }
    });

    xhr.addEventListener('error', () => {
      hideProgress();
      showError('Network error — check that the server is running.');
    });

    xhr.open('POST', '/api/v1/alerts/upload');
    xhr.send(formData);
  }


  // =========================================================
  // Load sample data
  // =========================================================
  if (btnLoadSample) {
    btnLoadSample.addEventListener('click', async () => {
      hideError();
      hideResult();
      showProgress('Loading sample data…', 20);
      btnLoadSample.disabled = true;

      try {
        const res  = await fetch('/api/v1/alerts/sample', { method: 'POST' });
        const data = await res.json().catch(() => ({}));

        if (res.ok) {
          showProgress('Running pipeline…', 80);
          setTimeout(() => {
            hideProgress();
            showResult(data);
          }, 400);
        } else {
          hideProgress();
          showError(data.error || 'Failed to load sample data');
        }
      } catch (e) {
        hideProgress();
        showError('Network error: ' + e.message);
      } finally {
        btnLoadSample.disabled = false;
      }
    });
  }


  // =========================================================
  // UI helpers
  // =========================================================
  function showProgress(label, pct) {
    if (!uploadProgress) return;
    uploadProgress.style.display = 'block';
    if (progressLabel) progressLabel.textContent = label;
    if (progressFill)  progressFill.style.width  = pct + '%';
  }

  function hideProgress() {
    if (uploadProgress) uploadProgress.style.display = 'none';
    if (progressFill)   progressFill.style.width = '0%';
  }

  function showResult(data) {
    if (!uploadResult || !resultStats) return;
    uploadResult.style.display = 'block';

    const stats = [
      { label: 'Alerts Ingested',    key: 'alerts_ingested',    fallback: data.total_alerts || 0 },
      { label: 'Incidents Created',  key: 'incidents_created',  fallback: data.incidents_created || 0 },
      { label: 'False Positives',    key: 'false_positives',    fallback: data.fp_count || 0 },
      { label: 'Already Existed',    key: 'duplicates_skipped', fallback: data.duplicates_skipped || 0 },
    ];

    resultStats.innerHTML = stats.map(s => `
      <div class="result-stat">
        <div class="stat-num">${data[s.key] !== undefined ? data[s.key] : s.fallback}</div>
        <div class="stat-label">${s.label}</div>
      </div>
    `).join('');
  }

  function hideResult() {
    if (uploadResult) uploadResult.style.display = 'none';
  }

  function showError(msg) {
    if (!uploadError || !uploadErrorMsg) return;
    uploadError.classList.remove('hidden');
    uploadErrorMsg.textContent = msg;
  }

  function hideError() {
    if (uploadError) uploadError.classList.add('hidden');
  }

})();
