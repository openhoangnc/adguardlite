import { fileURLToPath } from 'node:url';

import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

/**
 * The three documents the server serves, and the chunk name each one's
 * bundle takes.
 *
 * The names are load-bearing.  `sift-api`'s `is_public_page` serves an asset
 * without a session only when its basename starts with `login.`, and
 * `is_install_page` refuses one starting with `install.` once the wizard has
 * run -- so the login form's own script must be `static/login.<hash>.js` and
 * nothing else.  That is also why every entry is built on its own: a single
 * multi-entry build would hoist React into a shared chunk under some third
 * name, which a signed-out browser is answered 401 for.
 */
const ENTRIES = {
    main: 'index.html',
    login: 'login.html',
    install: 'install.html',
} as const;

type Entry = keyof typeof ENTRIES;

const root = fileURLToPath(new URL('.', import.meta.url));

/** The backend a `npm run dev` session proxies its API calls to. */
const API = process.env.SIFT_API ?? 'http://127.0.0.1:3000';

export default defineConfig(() => {
    const only = process.env.SIFT_ENTRY as Entry | undefined;
    const names = only ? [only] : (Object.keys(ENTRIES) as Entry[]);
    const input = Object.fromEntries(names.map((n) => [n, root + ENTRIES[n]]));

    return {
        root,
        publicDir: root + 'public',
        base: '/',
        plugins: [react()],
        build: {
            outDir: root + '../build',
            // Only the first build clears the directory; the other two add to it.
            emptyOutDir: only === 'main' || only === undefined,
            assetsDir: 'static',
            target: 'es2022',
            sourcemap: false,
            reportCompressedSize: false,
            chunkSizeWarningLimit: 2048,
            rollupOptions: {
                input,
                output: {
                    // `static/` is what `ui.rs` treats as content-addressed and
                    // serves `immutable`; nothing else may carry a hash.
                    entryFileNames: 'static/[name].[hash].js',
                    chunkFileNames: 'static/[name].[hash].js',
                    assetFileNames: 'static/[name].[hash][extname]',
                },
            },
        },
        server: {
            port: 5173,
            strictPort: true,
            proxy: {
                '/control': { target: API, changeOrigin: false },
                '/apple': { target: API, changeOrigin: false },
                '/dns-query': { target: API, changeOrigin: false },
            },
        },
    };
});
