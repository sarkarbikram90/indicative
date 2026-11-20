export interface HistogramBucket {
  count: number;
  sum: number;
  min: number;
  max: number;
}

export class MetricsRegistry {
  private readonly counters = new Map<string, number>();
  private readonly histograms = new Map<string, HistogramBucket>();
  private readonly gauges = new Map<string, number>();

  private key(name: string, labels?: Record<string, string>): string {
    if (!labels || Object.keys(labels).length === 0) return name;
    const sorted = Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${v}"`)
      .join(",");
    return `${name}{${sorted}}`;
  }

  inc(name: string, labels?: Record<string, string>, value = 1): void {
    const k = this.key(name, labels);
    this.counters.set(k, (this.counters.get(k) ?? 0) + value);
  }

  observe(name: string, value: number, labels?: Record<string, string>): void {
    const k = this.key(name, labels);
    const existing = this.histograms.get(k);
    if (!existing) {
      this.histograms.set(k, { count: 1, sum: value, min: value, max: value });
    } else {
      existing.count += 1;
      existing.sum += value;
      existing.min = Math.min(existing.min, value);
      existing.max = Math.max(existing.max, value);
    }
  }

  setGauge(name: string, value: number, labels?: Record<string, string>): void {
    const k = this.key(name, labels);
    this.gauges.set(k, value);
  }

  snapshot(): {
    counters: Record<string, number>;
    gauges: Record<string, number>;
    histograms: Record<string, HistogramBucket & { avg: number }>;
  } {
    const counters: Record<string, number> = {};
    for (const [k, v] of this.counters.entries()) counters[k] = v;

    const gauges: Record<string, number> = {};
    for (const [k, v] of this.gauges.entries()) gauges[k] = v;

    const histograms: Record<string, HistogramBucket & { avg: number }> = {};
    for (const [k, b] of this.histograms.entries()) {
      histograms[k] = {
        ...b,
        avg: b.count > 0 ? Math.round((b.sum / b.count) * 100) / 100 : 0
      };
    }

    return { counters, gauges, histograms };
  }

  toPrometheusText(): string {
    const lines: string[] = [];
    for (const [k, v] of this.counters.entries()) {
      lines.push(`${k} ${v}`);
    }
    for (const [k, v] of this.gauges.entries()) {
      lines.push(`${k} ${v}`);
    }
    for (const [k, b] of this.histograms.entries()) {
      const base = k.includes("{") ? k.slice(0, k.indexOf("{")) : k;
      const suffix = k.includes("{") ? k.slice(k.indexOf("{")) : "";
      lines.push(`${base}_count${suffix} ${b.count}`);
      lines.push(`${base}_sum${suffix} ${b.sum}`);
    }
    return `${lines.join("\n")}\n`;
  }
}

export const defaultMetrics = new MetricsRegistry();
