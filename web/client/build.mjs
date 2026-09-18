// Builds the three documents the server serves, one Vite build each.
//
// They are separate builds on purpose: with all three as inputs to one build,
// Rollup hoists what they share into a chunk of its own, and `sift-api` only
// serves `login.*` without a session -- so the login form would ask for a
// script it is answered 401 for.  See ENTRIES in vite.config.ts.
import { build } from 'vite';

for (const entry of ['main', 'login', 'install']) {
    process.env.SIFT_ENTRY = entry;
    await build();
}
