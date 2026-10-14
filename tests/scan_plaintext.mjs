// Usage: node scan_plaintext.mjs binary [runtime-output-log]
import { readFileSync } from 'node:fs';

const [binary, outputPath = `${binary}.run.log`] = process.argv.slice(2);
if (!binary) throw new Error('Expected a binary path');
const data = readFileSync(binary);
const output = readFileSync(outputPath, 'utf8');
for (const marker of ['LEAKPROBE_MARKER_ONE', 'LEAKPROBE MARKER TWO', 'WIDE_LEAKPROBE_MARKER']) {
  if (!output.includes(marker)) throw new Error(`Incorrect decryption: ${marker}`);
  const utf32 = Buffer.alloc(marker.length * 4);
  for (let i = 0; i < marker.length; ++i) utf32.writeUInt32LE(marker.charCodeAt(i), i * 4);
  for (const bytes of [Buffer.from(marker, 'ascii'), Buffer.from(marker, 'utf16le'), utf32]) {
    if (data.includes(bytes)) throw new Error(`Plaintext leak in ${binary}: ${marker}`);
  }
}
console.log(`Plaintext scan PASS: ${binary}`);
