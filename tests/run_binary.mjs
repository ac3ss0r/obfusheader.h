// Bounded test execution: a broken opaque condition must not fill the disk.
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';

const [binary, log, ...args] = process.argv.slice(2);
if (!binary || !log) throw new Error('Expected binary and output log paths');
const result = spawnSync(binary, args, {
  encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024, windowsHide: true,
});
writeFileSync(log, `${result.stdout ?? ''}${result.stderr ?? ''}${result.error ? `\n${result.error.message}\n` : ''}`);
if (result.error) throw result.error;
if (result.status !== 0) throw new Error(`Test exited with ${result.status}: ${binary}`);
