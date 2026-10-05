const menu = document.querySelector('.docs-menu');
if (menu) {
  const desktop = window.matchMedia('(min-width: 960px)');
  const updateMenu = () => { menu.open = desktop.matches; };
  desktop.addEventListener('change', updateMenu);
  updateMenu();
}

const copyIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V4a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h4"/></svg>';
const checkIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m5 12 4 4L19 6"/></svg>';

for (const code of document.querySelectorAll('pre > code')) {
  const pre = code.parentElement;
  const block = document.createElement('div');
  block.className = 'code-block';
  pre.before(block);
  block.append(pre);

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'copy-button';
  button.setAttribute('aria-label', 'Copy code to clipboard');
  button.title = 'Copy to clipboard';
  button.innerHTML = copyIcon;

  const status = document.createElement('span');
  status.className = 'copy-status';
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  block.append(button, status);

  let resetTimer;
  const reset = () => {
    button.innerHTML = copyIcon;
    button.classList.remove('copied');
    button.setAttribute('aria-label', 'Copy code to clipboard');
    button.title = 'Copy to clipboard';
    status.textContent = '';
  };
  button.addEventListener('click', async () => {
    clearTimeout(resetTimer);
    reset();
    if (!navigator.clipboard?.writeText) {
      status.textContent = 'Copy is unavailable. Select and copy the code instead.';
      return;
    }
    button.disabled = true;
    try {
      await navigator.clipboard.writeText(code.textContent.replace(/\n$/, ''));
      button.innerHTML = checkIcon;
      button.classList.add('copied');
      button.setAttribute('aria-label', 'Copied to clipboard');
      button.title = 'Copied!';
      status.textContent = 'Copied to clipboard.';
      resetTimer = setTimeout(reset, 2000);
    } catch (error) {
      console.error('Could not copy code to the clipboard:', error);
      status.textContent = 'Copy failed. Select and copy the code instead.';
    } finally {
      button.disabled = false;
    }
  });
}
