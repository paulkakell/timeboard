(function () {
  function applySystemTheme() {
    const html = document.documentElement;
    const pref = html.getAttribute('data-theme-preference');
    if (pref !== 'system') return;

    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const set = () => {
      html.setAttribute('data-bs-theme', mq.matches ? 'dark' : 'light');
    };
    set();
    if (mq.addEventListener) {
      mq.addEventListener('change', set);
    } else if (mq.addListener) {
      mq.addListener(set);
    }
  }

  function initRecurrenceForm() {
    const typeSel = document.getElementById('recurrence_type');
    const intervalGroup = document.getElementById('recurrence_interval_group');
    const timesGroup = document.getElementById('recurrence_times_group');

    if (!typeSel || !intervalGroup || !timesGroup) return;

    const update = () => {
      const v = typeSel.value;
      const needsInterval = (v === 'post_completion' || v === 'fixed_clock');
      const needsTimes = (v === 'multi_slot_daily');

      intervalGroup.style.display = needsInterval ? '' : 'none';
      timesGroup.style.display = needsTimes ? '' : 'none';
    };

    typeSel.addEventListener('change', update);
    update();
  }

  function initCopyToClipboard() {
    const nodes = document.querySelectorAll('[data-copy-text]');
    if (!nodes || !nodes.length) return;

    const fallbackCopy = (text) => {
      const ta = document.createElement('textarea');
      ta.value = text;
      // Avoid scrolling to bottom
      ta.style.position = 'fixed';
      ta.style.top = '0';
      ta.style.left = '0';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      if (!ok) throw new Error('copy failed');
    };

    const copyText = (text) => {
      if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
      }
      return new Promise((resolve, reject) => {
        try {
          fallbackCopy(text);
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    };

    const showFeedback = (el) => {
      const id = el.getAttribute('data-copy-feedback');
      if (id) {
        const target = document.getElementById(id);
        if (target) {
          target.style.display = '';
          window.setTimeout(() => { target.style.display = 'none'; }, 1200);
          return;
        }
      }
      // Minimal fallback feedback
      const prevTitle = el.getAttribute('title') || '';
      el.setAttribute('title', 'Copied');
      window.setTimeout(() => { el.setAttribute('title', prevTitle); }, 1200);
    };

    nodes.forEach((el) => {
      el.addEventListener('click', () => {
        const text = (el.getAttribute('data-copy-text') || el.textContent || '').trim();
        if (!text) return;
        copyText(text).then(() => showFeedback(el)).catch(() => { /* ignore */ });
      });

      // Keyboard accessibility
      el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          el.click();
        }
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    applySystemTheme();
    initRecurrenceForm();
    initCopyToClipboard();

    // Browser notifications (best-effort): EventSource + Notification API.
    try {
      const enabled = document.body && document.body.getAttribute('data-browser-notifications-enabled') === '1';
      if (enabled && ('EventSource' in window)) {
        if ('Notification' in window && Notification.permission === 'default') {
          // Request once on page load when user explicitly enabled browser notifications.
          try {
            Notification.requestPermission();
          } catch (e) {
            // ignore
          }
        }

        const es = new EventSource('/notifications/stream');
        es.addEventListener('notification', function (ev) {
          try {
            const payload = JSON.parse(ev.data);
            if (!payload) return;

            if ('Notification' in window && Notification.permission === 'granted') {
              const n = new Notification(payload.title || 'Timeboard', {
                body: payload.message || ''
              });
              n.onclick = function () {
                try { window.focus(); } catch (e) {}
                if (payload.task_id) {
                  window.location.href = '/tasks/' + payload.task_id + '/edit';
                }
              };
            }
          } catch (e) {
            // ignore
          }
        });
      }
    } catch (e) {
      // ignore
    }
  });
})();
