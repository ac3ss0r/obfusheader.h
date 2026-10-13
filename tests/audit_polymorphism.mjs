// Usage: node audit_polymorphism.mjs path/to/objdump path/to/polymorphism-binary
// Measures compiler output diversity, not resistance to reverse engineering.
import { spawnSync } from 'node:child_process';

const [objdump, binary] = process.argv.slice(2);
if (!objdump || !binary) throw new Error('Expected objdump and binary paths');
const result = spawnSync(objdump, ['-d', '--no-show-raw-insn', binary], {
  encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
});
if (result.error) throw result.error;
if (result.status !== 0) throw new Error(result.stderr || 'objdump failed');
const signatures = [];
const padding = new Set(['nop', 'nopl', 'nopw', 'int3', 'data16', 'cs', 'xchg']);
for (let variant = 0; variant < 8; ++variant) {
  const body = result.stdout.match(new RegExp(
    `<_?poly_decode_${variant}>:\\r?\\n([\\s\\S]*?)(?=\\r?\\n[0-9a-f]+ <|$)`,
  ));
  if (!body) throw new Error(`Missing decoder symbol ${variant}`);
  const instructions = [];
  for (const line of body[1].split(/\r?\n/)) {
    const match = line.match(/^\s*[0-9a-f]+:\s+(\w+)/);
    if (!match || padding.has(match[1])) continue;
    instructions.push(match[1]);
    if (match[1].startsWith('ret')) break;
  }
  if (!instructions.length) throw new Error(`Empty decoder ${variant}`);
  signatures.push(instructions.join(' '));
  console.log(`family ${variant}: ${signatures[variant]}`);
}
const count = new Set(signatures).size;
console.log(`Distinct optimized opcode sequences: ${count}/8`);
if (count !== 8) throw new Error('Some decoder families have the same shape');
