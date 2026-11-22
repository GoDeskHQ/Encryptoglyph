(() => {
  'use strict';
  const preference = window.matchMedia('(prefers-color-scheme: dark)');
  let saved = null;
  try {
    const value = localStorage.getItem('encryptoglyph-theme');
    if (value === 'light' || value === 'dark') saved = value;
  } catch { /* System preference works when storage is unavailable. */ }
  function apply(theme) {
    document.documentElement.dataset.theme = theme;
    const toggle = document.getElementById('theme-toggle');
    if (toggle) {
      const dark = theme === 'dark';
      toggle.setAttribute('aria-label', `Switch to ${dark ? 'light' : 'dark'} mode`);
      document.getElementById('theme-label').textContent = dark ? 'Light mode' : 'Dark mode';
    }
  }
  apply(saved || (preference.matches ? 'dark' : 'light'));
  preference.addEventListener('change', () => {
    if (!saved) apply(preference.matches ? 'dark' : 'light');
  });
  document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('theme-toggle');
    toggle.hidden = false;
    apply(document.documentElement.dataset.theme);
    toggle.addEventListener('click', () => {
      saved = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      apply(saved);
      try { localStorage.setItem('encryptoglyph-theme', saved); } catch { /* Keep in-memory preference. */ }
    });
  });
})();
