// Genera los archivos de reglas a partir del catálogo (una sola fuente de verdad).
//   atalaya-backend/ids/snort/local.rules            -> /etc/snort/rules/local.rules (ec2-backend)
//   atalaya-frontend/ids/suricata/atalaya-*.rules    -> /var/lib/suricata/rules/     (ec2-frontend)
// Uso: npm run rules:export
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { OBJECTIVES, RULES } from '../src/domain/catalog/detectionCatalog.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const frontendIds = resolve(root, '..', 'atalaya-frontend', 'ids', 'suricata');
const titleOf = (id) => OBJECTIVES.find((o) => o.id === id)?.title ?? id;

function render(rules, header) {
  const lines = [header, ''];
  let current = null;
  for (const r of rules) {
    if (r.objective !== current) {
      current = r.objective;
      lines.push(`# ===== ${titleOf(current)} =====`);
    }
    lines.push(`# Tráfico: ${r.trigger}`);
    lines.push(`# Por qué: ${r.reason}`);
    lines.push(r.text, '');
  }
  return lines.join('\n');
}

const byFile = new Map();
for (const r of RULES) {
  const key = `${r.sensor}/${r.file}`;
  byFile.set(key, [...(byFile.get(key) ?? []), r]);
}

for (const [key, rules] of byFile) {
  const [sensor, file] = key.split('/');
  const dir = sensor === 'snort' ? join(root, 'ids', 'snort') : frontendIds;
  if (sensor === 'suricata' && !existsSync(resolve(frontendIds, '..', '..'))) continue;
  mkdirSync(dir, { recursive: true });
  const header = sensor === 'snort'
    ? '# Atalaya · Reglas locales de Snort 2.9 (HIDS en ec2-backend)\n# Copiar a /etc/snort/rules/local.rules · SID locales: 1000001 a 1000099\n# Generado con npm run rules:export: edita src/domain/catalog/detectionCatalog.js'
    : `# Atalaya · Reglas de Suricata (NIDS en ec2-frontend) · ${file}\n# Copiar a /var/lib/suricata/rules/ y agregar en rule-files de suricata.yaml · SID 1100001 a 1100299\n# Generado con npm run rules:export: edita atalaya-backend/src/domain/catalog/detectionCatalog.js`;
  // order rules by objective order
  const order = Object.fromEntries(OBJECTIVES.map((o) => [o.id, o.order]));
  rules.sort((a, b) => order[a.objective] - order[b.objective] || a.sid - b.sid);
  writeFileSync(join(dir, file), render(rules, header));
  console.log(`Escrito ${join(dir, file)} (${rules.length} reglas)`);
}
