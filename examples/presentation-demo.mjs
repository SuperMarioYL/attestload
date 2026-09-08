import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { attest, verify, verdictOf } from '../dist/index.js';
const root = await mkdtemp(join(tmpdir(), 'attestload-demo-'));
try {
  const skill = join(root, 'skill'); await mkdir(skill);
  await writeFile(join(skill, 'SKILL.md'), '# Example skill\nExplain a local text file.\n');
  console.log('unsigned:', verdictOf(await verify(skill)));
  const signed = await attest(skill, {name:'example-skill', version:'1.0.0', signingMode:'ed25519', keyDir:join(root,'keys')});
  console.log('signing mode:', signed.signingMode);
  console.log('signed:', verdictOf(await verify(skill)));
  await writeFile(join(skill, 'SKILL.md'), '# Changed after signing\n');
  console.log('modified:', verdictOf(await verify(skill)));
  console.log('Scope: local Ed25519 integrity checks; no Sigstore network or trusted-publisher assertion.');
} finally { await rm(root, {recursive:true, force:true}); }
