import { parse } from 'tldts';
import { createInterface } from 'node:readline';
// Mirrors the registry-domain boundary in DomScan, with a separately pinned
// IANA delegated-root check. Its private output is consumed only on-host.
for await (const line of createInterface({ input: process.stdin })) {
  const row = JSON.parse(line);
  const source = typeof row.domain === 'string' ? row.domain.toLowerCase().trim() : '';
  let domain = source;
  if (!/[@:/]/.test(source)) {
    try { domain = new URL('http://' + source).hostname; } catch {}
  }
  domain = domain.replace(/\.$/, '');
  const labels = domain.split('.');
  const valid = domain.length <= 253 && labels.length > 1 && labels.every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
  if (!valid) { console.log(JSON.stringify({ ...row, kind: 'invalid' })); continue; }
  const identity = parse(domain, { allowPrivateDomains: false, extractHostname: false, validateHostname: true });
  const root = labels.at(-1);
  const apex = identity.domain === domain && identity.subdomain === '';
  console.log(JSON.stringify({ ...row, domain, root, namespace: identity.publicSuffix || root, apex, kind: 'normalized' }));
}
