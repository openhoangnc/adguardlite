// Compresses the built web interface in place, for agl-api/src/ui.rs to embed.
//
// Every text asset becomes <name>.br and the original is removed, so the
// binary carries one copy rather than two.  Binary assets are left alone:
// a PNG is already compressed and brotli only makes it bigger.
//
// Run through scripts/build-frontend.sh, which passes the directory.

import { readdirSync, readFileSync, writeFileSync, statSync, unlinkSync } from 'node:fs';
import { join, extname } from 'node:path';
import { brotliCompressSync, constants } from 'node:zlib';

// The types worth compressing.  Anything else is stored as it came out of
// webpack.
const TEXT = new Set(['.js', '.css', '.html', '.svg', '.txt', '.json', '.map']);

const root = process.argv[2];
if (!root) {
    console.error('usage: brotli.mjs <dir>');
    process.exit(2);
}

function* walk(dir) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, entry.name);
        if (entry.isDirectory()) {
            yield* walk(p);
        } else if (entry.isFile()) {
            yield p;
        }
    }
}

let before = 0;
let after = 0;
let count = 0;

for (const path of walk(root)) {
    const size = statSync(path).size;
    before += size;

    if (!TEXT.has(extname(path))) {
        after += size;
        continue;
    }

    const raw = readFileSync(path);
    const compressed = brotliCompressSync(raw, {
        params: {
            // Quality 11 is the maximum.  This runs once per release, and
            // every byte it saves is a byte in the binary forever.
            [constants.BROTLI_PARAM_QUALITY]: constants.BROTLI_MAX_QUALITY,
            [constants.BROTLI_PARAM_MODE]: constants.BROTLI_MODE_TEXT,
            // A larger window compresses better and costs the decoder memory
            // it is required to have anyway.
            [constants.BROTLI_PARAM_LGWIN]: constants.BROTLI_MAX_WINDOW_BITS,
            [constants.BROTLI_PARAM_SIZE_HINT]: raw.length,
        },
    });

    writeFileSync(`${path}.br`, compressed);
    unlinkSync(path);

    after += compressed.length;
    count += 1;
}

const mb = (n) => `${(n / (1024 * 1024)).toFixed(1)} MB`;
console.log(`brotli: ${count} files, ${mb(before)} -> ${mb(after)}`);
