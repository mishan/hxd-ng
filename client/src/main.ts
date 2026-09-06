import './styles.css';
import { App } from './ui/app';
import { loadIcons } from './ui/icons';

async function boot(): Promise<void> {
  const root = document.getElementById('root');
  if (!root) throw new Error('no #root');
  // The sprite sheet is two files and both are needed before anything is
  // drawn, so wait for them rather than painting a roster of empty
  // squares that fills in a moment later.
  await loadIcons().catch((e: Error) => {
    root.textContent = `Could not load the icon sheet (${e.message}). Run "npm run icons".`;
    throw e;
  });
  new App(root).mount();
}

void boot();
