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

  document.addEventListener('DOMContentLoaded', function () {
    applySystemTheme();
    initRecurrenceForm();
  });
})();
