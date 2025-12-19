import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function repoRootFromHere() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  // scripts/ -> repo root
  return path.resolve(here, '..');
}

async function pathExists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  const root = repoRootFromHere();

  const src = path.resolve(root, 'dist');
  const dest = path.resolve(root, 'crates', 'beacon-worker', 'assets');

  if (!(await pathExists(src))) {
    throw new Error(
      `Frontend build output not found at '${src}'. Run 'pnpm build' first.`,
    );
  }

  // Replace destination to avoid stale assets.
  await fs.rm(dest, { recursive: true, force: true });
  await fs.mkdir(dest, { recursive: true });

  // Node 20+ supports fs.cp.
  await fs.cp(src, dest, { recursive: true });

  // Provide a stable marker for debugging deployments.
  await fs.writeFile(
    path.join(dest, '.synced-from-dist'),
    `Synced from ${src} at ${new Date().toISOString()}\n`,
    'utf8',
  );

  // eslint-disable-next-line no-console
  console.log(`Synced Worker assets: ${src} -> ${dest}`);
}

await main();
