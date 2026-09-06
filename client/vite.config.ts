import { defineConfig } from 'vite';

// `base: './'` so a built `dist/` works from any path a static server
// happens to mount it at — including straight out of the repo with
// `python3 -m http.server`, which is how most people will run this.
export default defineConfig({
  base: './',
  build: {
    target: 'es2022',
    outDir: 'dist',
    assetsDir: 'assets',
    // No source map in the committed build: it is a large generated file
    // that would churn on every change, and anyone debugging the client
    // itself should be running `npm run dev` against real sources.
    sourcemap: false,
  },
  server: {
    port: 5701,
  },
});
