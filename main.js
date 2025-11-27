// main.js - handles UI, API calls, charts, PDF export
let currentReport = null;
const apiPath = '/api/scan';

document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = document.getElementById('scanBtn');
  const sampleBtn = document.getElementById('sampleBtn');
  const exportBtn = document.getElementById('exportPDF');
  const copyBtn = document.getElementById('copyJSON');

  scanBtn.addEventListener('click', doScan);
  sampleBtn.addEventListener('click', loadSample);
  exportBtn.addEventListener('click', exportPDF);
  copyBtn.addEventListener('click', copyJSON);

  // init chart
  initChart();
});

function setStatus(txt){
  document.getElementById('status').innerText = txt;
}

async function doScan(){
  const url = document.getElementById('urlInput').value.trim();
  if(!url){ setStatus('Enter a URL'); return; }
  setStatus('Scanning (safe checks)...');
  try {
    const res = await fetch(apiPath, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({url})
    });
    const data = await res.json();
    if(res.ok){
      currentReport = data;
      renderReport(data);
      setStatus('Scan complete');
    } else {
      setStatus('Error: ' + (data.error || 'unknown'));
    }
  } catch (e) {
    setStatus('Error: ' + e.message);
  }
}

async function loadSample(){
  try {
    const res = await fetch('/sample');
    const data = await res.json();
    currentReport = data;
    renderReport(data);
    setStatus('Loaded sample report');
  } catch(e) {
    setStatus('Failed to load sample');
  }
}

function renderReport(r){
  document.getElementById('reportJSON').innerHTML = '<pre>' + JSON.stringify(r, null, 2) + '</pre>';
  document.getElementById('riskScore').innerText = (r.risk_score !== undefined) ? r.risk_score : '—';
  updateChart(r.header_coverage_percent || 0, (r.tls && r.tls.days_left) ? r.tls.days_left : null);
}

function copyJSON(){
  if(!currentReport){ setStatus('No report to copy'); return; }
  navigator.clipboard.writeText(JSON.stringify(currentReport, null, 2)).then(()=>{
    setStatus('JSON copied to clipboard');
  }).catch(()=> setStatus('Copy failed'));
}

// Chart.js: header coverage doughnut + tls days bar
let coverageChart;
function initChart(){
  const ctx = document.getElementById('coverageChart').getContext('2d');
  coverageChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Headers present', 'Missing'],
      datasets: [{
        label: 'Header coverage',
        data: [0, 100],
        backgroundColor: ['#10b981', '#ef4444'],
        hoverOffset: 6
      }]
    },
    options: {
      plugins: {
        legend: { position: 'bottom', labels: { color: '#cfe8ff' } }
      }
    }
  });
}

function updateChart(coverage, tlsDays){
  const present = coverage;
  const missing = Math.max(0, 100 - present);
  coverageChart.data.datasets[0].data = [present, missing];
  coverageChart.update();
  // optionally show TLS days tooltip by changing title
  coverageChart.options.plugins.title = {
    display: true,
    text: (tlsDays !== null && tlsDays !== undefined) ? `TLS days left: ${tlsDays}` : 'TLS days left: unknown',
    color: '#cfe8ff'
  };
  coverageChart.update();
}

async function exportPDF(){
  if(!currentReport){ setStatus('No report to export'); return; }
  setStatus('Exporting PDF...');
  try {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({
      orientation: 'portrait',
      unit: 'pt',
      format: 'a4'
    });
    const title = 'VulnLite Report';
    doc.setFontSize(18);
    doc.text(title, 40, 50);
    doc.setFontSize(11);
    doc.text(`Target: ${currentReport.target}`, 40, 80);
    doc.text(`Generated: ${currentReport.timestamp}`, 40, 100);
    doc.text(`Risk score: ${currentReport.risk_score}`, 40, 120);
    // add JSON snapshot
    const jsonStr = JSON.stringify(currentReport, null, 2);
    const lines = doc.splitTextToSize(jsonStr, 520);
    doc.setFontSize(9);
    doc.text(lines, 40, 150);
    doc.save('vulnlite-report.pdf');
    setStatus('PDF downloaded');
  } catch(e) {
    setStatus('PDF export failed: ' + e.message);
  }
}
