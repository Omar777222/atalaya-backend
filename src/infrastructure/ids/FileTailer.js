import { open, stat } from 'node:fs/promises';

// Sigue un archivo de log como "tail -f": cada cierto tiempo lee solo lo nuevo.
// Soporta rotación (logrotate crea un archivo nuevo) y truncado.
export class FileTailer {
  constructor({ path, intervalMs = 1000, backfillBytes = 256 * 1024, onLines, onState = () => {} }) {
    Object.assign(this, { path, intervalMs, backfillBytes, onLines, onState });
    this.offset = null;
    this.inode = null;
    this.remainder = '';
    this.timer = null;
    this.busy = false;
  }

  start() {
    this.tick();
    this.timer = setInterval(() => this.tick(), this.intervalMs);
    this.timer.unref?.();
  }

  stop() {
    clearInterval(this.timer);
  }

  async tick() {
    if (this.busy) return;
    this.busy = true;
    try {
      const info = await stat(this.path);
      const rotated = this.inode !== null && info.ino !== this.inode;
      if (this.offset === null) {
        // Primera lectura: tomar solo el final del archivo para no cargar meses de alertas
        this.offset = Math.max(0, info.size - this.backfillBytes);
      } else if (rotated || info.size < this.offset) {
        this.offset = 0;
        this.remainder = '';
      }
      this.inode = info.ino;

      if (info.size > this.offset) {
        const fh = await open(this.path, 'r');
        try {
          const length = info.size - this.offset;
          const buf = Buffer.alloc(length);
          await fh.read(buf, 0, length, this.offset);
          this.offset = info.size;
          const text = this.remainder + buf.toString('utf8');
          const lines = text.split('\n');
          this.remainder = lines.pop() ?? '';
          const complete = lines.filter((l) => l.trim());
          if (complete.length) await this.onLines(complete);
        } finally {
          await fh.close();
        }
      }
      this.onState({ ok: true, size: info.size, modifiedAt: info.mtime.toISOString() });
    } catch (err) {
      // ENOENT: Snort aún no crea el archivo · EACCES: el usuario de la API no tiene permiso de lectura
      this.onState({ ok: false, error: err.code ?? err.message });
    } finally {
      this.busy = false;
    }
  }
}
