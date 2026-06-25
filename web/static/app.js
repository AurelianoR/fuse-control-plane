// Auto-submit filter form when any [data-autosubmit] element changes.
(function () {
  document.querySelectorAll('[data-autosubmit]').forEach(function (el) {
    el.addEventListener('change', function () {
      el.closest('form').submit();
    });
  });
})();

// Poll the run status endpoint until the run finishes, then reload.
(function () {
  const container = document.getElementById('run-status-container');
  if (!container) return;

  const pollUrl = container.dataset.pollUrl;
  if (!pollUrl) return;

  let interval = setInterval(async function () {
    try {
      const res = await fetch(pollUrl);
      if (!res.ok) return;
      const data = await res.json();
      if (data.status === 'success' || data.status === 'failed') {
        clearInterval(interval);
        window.location.reload();
      }
    } catch (e) {
      // Network error — keep polling
    }
  }, 3000);
})();
