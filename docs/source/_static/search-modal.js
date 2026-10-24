// Search-as-you-type modal, like the one Read the Docs adds to its hosted sites.
// Results come from the static Pagefind index built next to the HTML (see docs/Dockerfile).
// Opens with "/" or Ctrl+K, or from the sidebar search box; the search page stays as a fallback.
(() => {
  'use strict';

  const root = document.documentElement.dataset.content_root || './';
  const MAX_PAGES = 10;
  const MAX_SECTIONS = 3;

  let pagefind = null;
  let modal, input, results, status;
  let hits = [];
  let selected = -1;
  let seq = 0;

  // One shared load: keystrokes made while the index is still loading must not import and init it again.
  function loadPagefind() {
    if (!pagefind) {
      pagefind = (async () => {
        const pf = await import(new URL(root + 'pagefind/pagefind.js', location.href).href);
        await pf.options({ excerptLength: 24 });
        await pf.init();
        return pf;
      })();
      pagefind.catch(() => { pagefind = null; });
    }
    return pagefind;
  }

  const escape = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // Pagefind URLs start at the site root ("/ruletypes.html"); make them work from any page depth.
  const link = (url) => new URL(root + url.replace(/^\//, ''), location.href).href;

  function build() {
    if (modal) return;
    modal = document.createElement('div');
    modal.className = 'ps-overlay';
    modal.hidden = true;
    modal.innerHTML = `
      <div class="ps-dialog" role="dialog" aria-modal="true" aria-label="Search the documentation">
        <div class="ps-head">
          <span class="ps-icon fa fa-search" aria-hidden="true"></span>
          <input class="ps-input" type="search" placeholder="Search docs" autocomplete="off" spellcheck="false"
                 aria-label="Search docs" aria-controls="ps-results">
          <button class="ps-close" type="button" aria-label="Close">Esc</button>
        </div>
        <div class="ps-results" id="ps-results" role="listbox"></div>
        <div class="ps-foot">
          <span class="ps-status"></span>
          <span class="ps-keys"><kbd>&uarr;</kbd><kbd>&darr;</kbd> to navigate <kbd>Enter</kbd> to open <kbd>Esc</kbd> to close</span>
        </div>
      </div>`;
    document.body.appendChild(modal);
    input = modal.querySelector('.ps-input');
    results = modal.querySelector('.ps-results');
    status = modal.querySelector('.ps-status');

    modal.addEventListener('mousedown', (e) => { if (e.target === modal) close(); });
    modal.querySelector('.ps-close').addEventListener('click', close);
    input.addEventListener('input', search);
    input.addEventListener('keydown', onKey);
  }

  function open(query = '') {
    build();
    modal.hidden = false;
    document.body.classList.add('ps-open');
    if (query) input.value = query;
    input.focus();
    input.select();
    search();
    loadPagefind().catch(() => { status.textContent = 'Search index unavailable'; });
  }

  function close() {
    if (!modal || modal.hidden) return;
    modal.hidden = true;
    document.body.classList.remove('ps-open');
  }

  async function search() {
    const query = input.value.trim();
    const mine = ++seq;
    if (!query) {
      render([], query, 0);
      return;
    }
    let found;
    try {
      const pf = await loadPagefind();
      found = await pf.debouncedSearch(query, {}, 120);
    } catch (e) {
      status.textContent = 'Search index unavailable';
      return;
    }
    if (found === null || mine !== seq) return; // superseded by a newer keystroke
    const pages = await Promise.all(found.results.slice(0, MAX_PAGES).map((r) => r.data()));
    if (mine !== seq) return;
    render(pages, query, found.results.length);
  }

  function render(pages, query, total) {
    hits = [];
    selected = -1;
    if (!query) {
      results.innerHTML = '';
      status.textContent = '';
      return;
    }
    if (!pages.length) {
      results.innerHTML = `<p class="ps-empty">No results for <strong>${escape(query)}</strong></p>`;
      status.textContent = '';
      return;
    }
    results.innerHTML = pages.map((page) => {
      const sections = (page.sub_results || []).filter((s) => s.url.includes('#')).slice(0, MAX_SECTIONS);
      const title = escape(page.meta.title || page.url);
      const head = `<a class="ps-hit ps-page" href="${link(page.url)}">
          <span class="ps-title">${title}</span>
          ${sections.length ? '' : `<span class="ps-excerpt">${page.excerpt}</span>`}
        </a>`;
      const subs = sections.map((s) => `<a class="ps-hit ps-section" href="${link(s.url)}">
          <span class="ps-title">${escape(s.title)}</span>
          <span class="ps-excerpt">${s.excerpt}</span>
        </a>`).join('');
      return `<div class="ps-group">${head}${subs}</div>`;
    }).join('');
    hits = Array.from(results.querySelectorAll('.ps-hit'));
    hits.forEach((a, i) => a.addEventListener('mousemove', () => select(i, false)));
    results.scrollTop = 0;
    status.textContent = total > MAX_PAGES ? `${MAX_PAGES} of ${total} pages` : `${total} page${total > 1 ? 's' : ''}`;
    select(0, false);
  }

  function select(i, scroll = true) {
    if (!hits.length) return;
    if (selected >= 0) hits[selected].classList.remove('ps-selected');
    selected = (i + hits.length) % hits.length;
    hits[selected].classList.add('ps-selected');
    if (scroll) hits[selected].scrollIntoView({ block: 'nearest' });
  }

  function onKey(e) {
    if (e.key === 'ArrowDown') { e.preventDefault(); select(selected + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); select(selected - 1); }
    else if (e.key === 'Enter' && selected >= 0) { e.preventDefault(); location.href = hits[selected].href; close(); }
    else if (e.key === 'Escape') { e.preventDefault(); close(); }
  }

  function editing(el) {
    return el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') close();
    else if ((e.key === '/' && !editing(e.target)) || ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k')) {
      e.preventDefault();
      open();
    }
  });

  // The theme's sidebar search box opens the modal instead of going to search.html.
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('#rtd-search-form, form[role="search"]').forEach((form) => {
      const box = form.querySelector('input[name="q"]');
      if (!box) return;
      box.setAttribute('readonly', '');
      box.setAttribute('placeholder', 'Search docs  ( / )');
      const show = (e) => { e.preventDefault(); box.blur(); open(box.value); };
      box.addEventListener('focus', show);
      box.addEventListener('click', show);
      form.addEventListener('submit', show);
    });
  });
})();
