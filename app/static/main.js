// ==========================================================================
// Interaction Logic & Malware Diagnostic Pipeline
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const alertBox = document.getElementById('alert-box');
  const alertText = document.getElementById('alert-text');
  const loadingCard = document.getElementById('loading-card');
  const resultCard = document.getElementById('result-card');
  const btnRestart = document.getElementById('btn-restart');

  // Allowed Windows PE formats
  const ALLOWED_EXTENSIONS = ['.exe', '.dll'];

  // Handle Drag & Drop events
  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('drag-over');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('drag-over');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFileSelection(files[0]);
    }
  });

  dropzone.addEventListener('click', () => {
    fileInput.click();
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleFileSelection(e.target.files[0]);
    }
  });

  if (btnRestart) {
    btnRestart.addEventListener('click', resetInterface);
  }

  function showAlert(msg) {
    alertText.textContent = msg;
    alertBox.classList.add('visible');
    setTimeout(() => {
      alertBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 100);
  }

  function hideAlert() {
    alertBox.classList.remove('visible');
    alertText.textContent = '';
  }

  function resetInterface() {
    hideAlert();
    resultCard.classList.remove('visible');
    loadingCard.classList.remove('visible');
    dropzone.style.display = 'block';
    fileInput.value = '';
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  // Validate format and initiate upload
  function handleFileSelection(file) {
    hideAlert();
    const fileName = file.name;
    const ext = '.' + fileName.split('.').pop().toLowerCase();

    // STRICT CHECK: Reject anything that isn't .exe or .dll
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      showAlert(`ACCESS DENIED: Format '${ext}' is not supported. Please upload ONLY Windows PE binaries (.exe or .dll).`);
      fileInput.value = '';
      return;
    }

    uploadAndAnalyze(file);
  }

  async function uploadAndAnalyze(file) {
    // Show loading state
    dropzone.style.display = 'none';
    resultCard.classList.remove('visible');
    loadingCard.classList.add('visible');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        body: formData
      });

      const data = await response.json();

      // If status is 422 (unparseable / corrupted PE header like abc.exe), show Malware in red
      if (response.status === 422) {
        displayResults({
          filename: data.filename || file.name,
          file_size: file.size,
          file_type: 'Windows Binary (.exe/.dll)',
          is_malware: true,
          verdict: 'MALWARE',
          error_note: data.error || 'Corrupted or unprocessable PE file structure.',
          key_features: []
        });
        return;
      }

      if (!response.ok) {
        throw new Error(data.error || 'Server error during PE binary inspection.');
      }

      displayResults(data);
    } catch (err) {
      loadingCard.classList.remove('visible');
      dropzone.style.display = 'block';
      showAlert(`ANALYSIS FAILED: ${err.message}`);
    }
  }

  function displayResults(data) {
    loadingCard.classList.remove('visible');
    resultCard.classList.add('visible');

    const header = document.getElementById('res-header');
    const verdictIcon = document.getElementById('res-icon');
    const verdictText = document.getElementById('res-verdict');
    const filenameLabel = document.getElementById('res-filename');
    const typeLabel = document.getElementById('res-type');

    // Filename & Type
    filenameLabel.textContent = data.filename;
    typeLabel.textContent = `${data.file_type} — ${(data.file_size / 1024).toFixed(1)} KB`;

    // Verdict Styling: Safe in green, Malware in red
    if (data.is_malware) {
      header.className = 'result-header malware-header';
      verdictIcon.textContent = '✕';
      verdictText.textContent = 'MALWARE';
    } else {
      header.className = 'result-header safe-header';
      verdictIcon.textContent = '✓';
      verdictText.textContent = 'SAFE';
    }

    // Populate Key Extracted Features Table
    const featTbody = document.getElementById('features-tbody');
    featTbody.innerHTML = '';

    if (data.key_features && data.key_features.length > 0) {
      data.key_features.forEach(feat => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="mono"><strong>${feat.name}</strong></td>
          <td class="feature-val">${feat.value}</td>
          <td style="color: var(--text-secondary); font-size: 0.85rem;">${feat.desc}</td>
        `;
        featTbody.appendChild(tr);
      });
    } else {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td colspan="3" style="text-align: center; color: var(--accent-malware); padding: 1.5rem; font-family: var(--font-mono); font-size: 0.85rem;">
          ${data.error_note ? data.error_note : 'PE header attributes could not be extracted due to invalid binary structure. Flagged as suspicious / malware.'}
        </td>
      `;
      featTbody.appendChild(tr);
    }

    // Scroll into view
    setTimeout(() => {
      resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 150);
  }
});
