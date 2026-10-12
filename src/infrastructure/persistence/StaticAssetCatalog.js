import { AssetCatalog } from '../../domain/ports/AssetCatalog.js';

// Inventario de la propia arquitectura desplegada en AWS (prefijo /17).
const ASSETS = [
  { id: 'waf', name: 'atalaya-waf', type: 'AWS WAF', zone: 'Perímetro', address: 'Web ACL regional', exposure: 'Pública', controls: ['Managed Rules', 'SQLi', 'XSS', 'Rate limiting'] },
  { id: 'alb', name: 'atalaya-alb', type: 'Application Load Balancer', zone: 'Perímetro', address: '10.0.0.0/24 y 10.0.1.0/24', exposure: 'Pública', controls: ['HTTPS 443', 'Redirección 80 → 443', 'alb-sg'] },
  { id: 'vpc-front', name: 'vpc-frontend', type: 'VPC', zone: 'Frontend', address: '10.0.0.0/17', exposure: 'Segmentada', controls: ['Internet Gateway', 'rt-frontend'] },
  { id: 'ec2-front', name: 'ec2-frontend', type: 'EC2 Ubuntu 24.04', zone: 'Frontend', address: '10.0.0.10', exposure: 'Solo vía ALB', controls: ['Nginx', 'Certbot', 'UFW', 'Fail2Ban', 'Security Headers'] },
  { id: 'peering', name: 'peering-front-back', type: 'VPC Peering', zone: 'Red privada', address: '10.0.0.0/17 ↔ 10.0.128.0/17', exposure: 'Privada', controls: ['Rutas explícitas'] },
  { id: 'vpc-back', name: 'vpc-backend', type: 'VPC', zone: 'Backend', address: '10.0.128.0/17', exposure: 'Sin internet', controls: ['Sin Internet Gateway', 'rt-backend'] },
  { id: 'ec2-back', name: 'ec2-backend', type: 'EC2 Ubuntu 24.04', zone: 'Backend', address: '10.0.128.10', exposure: 'Privada', controls: ['API Node.js', 'JWT', 'UFW', 'Usuario sin privilegios'] },
  { id: 'sg-alb', name: 'alb-sg', type: 'Security Group', zone: 'Perímetro', address: '80, 443 ← 0.0.0.0/0', exposure: 'Pública', controls: ['Mínimo privilegio'] },
  { id: 'sg-front', name: 'frontend-sg', type: 'Security Group', zone: 'Frontend', address: '80, 443 ← alb-sg', exposure: 'Restringida', controls: ['SSH solo desde IP administrativa'] },
  { id: 'sg-back', name: 'backend-sg', type: 'Security Group', zone: 'Backend', address: '3000 ← 10.0.0.10/32', exposure: 'Restringida', controls: ['Salida solo hacia el frontend'] },
  { id: 'cw', name: 'CloudWatch', type: 'Monitoreo', zone: 'Auditoría', address: 'Métricas y logs de WAF', exposure: 'Interna', controls: ['Alarmas', 'aws-waf-logs-atalaya'] },
  { id: 'ct', name: 'CloudTrail', type: 'Auditoría', zone: 'Auditoría', address: 'Historial de eventos de la cuenta', exposure: 'Interna', controls: ['Registro de cambios'] },
];

export class StaticAssetCatalog extends AssetCatalog {
  async search(query = '') {
    const q = query.trim().toLowerCase();
    if (!q) return ASSETS;
    return ASSETS.filter((a) =>
      [a.name, a.type, a.zone, a.address, a.exposure, ...a.controls].some((f) => f.toLowerCase().includes(q)),
    );
  }
}
