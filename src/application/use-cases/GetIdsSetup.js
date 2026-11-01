import { OBJECTIVES, RULES } from '../../domain/catalog/detectionCatalog.js';

// Configuración que se muestra en "Sensores y reglas" y los datos que necesita la "Demo en vivo".
export class GetIdsSetup {
  constructor({ sensorsConfig, targets, storage }) {
    Object.assign(this, { sensorsConfig, targets, storage });
  }

  async execute() {
    return {
      storage: { engine: this.storage.engine, persistent: this.storage.persistent, ...(await this.storage.stats()) },
      sensors: Object.values(this.sensorsConfig),
      objectives: OBJECTIVES,
      rules: RULES,
      targets: this.targets,
    };
  }
}
