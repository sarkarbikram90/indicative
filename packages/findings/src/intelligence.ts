import type { VulnerabilityIntelligence } from "@indicative/contracts";

export interface VulnerabilityIntelligenceRecord {
  cveId: string;
  source: string;
  observedAt: string;
  kevListed?: boolean;
  kevDateAdded?: string;
  kevRequiredAction?: string;
  epssScore?: number;
  epssPercentile?: number;
  cweIds?: string[];
}

export interface VulnerabilityIntelligenceProvider {
  readonly name: string;
  readonly snapshotObservedAt?: string;
  lookup(cveId: string): VulnerabilityIntelligenceRecord | undefined;
}

/**
 * Offline, deterministic snapshot provider for CISA KEV and FIRST EPSS records.
 * - Preserves exact source provenance and observation timestamps.
 * - Never makes network calls during offline scanning.
 * - A missing record returns undefined and is NEVER interpreted as proof of safety.
 */
export class StaticVulnerabilityIntelligenceProvider
  implements VulnerabilityIntelligenceProvider
{
  public readonly name: string;
  public readonly snapshotObservedAt: string;
  private readonly records: Map<string, VulnerabilityIntelligenceRecord>;

  constructor(options: {
    name?: string;
    snapshotObservedAt: string;
    records: VulnerabilityIntelligenceRecord[];
  }) {
    this.name = options.name ?? "indicative-offline-vuln-intel";
    this.snapshotObservedAt = options.snapshotObservedAt;
    this.records = new Map(
      options.records.map((r) => [r.cveId.trim().toUpperCase(), r])
    );
  }

  lookup(cveId: string): VulnerabilityIntelligenceRecord | undefined {
    if (!cveId) return undefined;
    return this.records.get(cveId.trim().toUpperCase());
  }

  isStale(maxAgeDays = 30, nowMs = Date.now()): boolean {
    const observedMs = Date.parse(this.snapshotObservedAt);
    if (Number.isNaN(observedMs)) return true;
    return (nowMs - observedMs) / (1000 * 60 * 60 * 24) > maxAgeDays;
  }
}

/**
 * Built-in minimal curated offline reference snapshot of well-known CISA KEV / high-profile CVEs
 * for offline operation and deterministic regression testing.
 * Production deployments should periodically refresh snapshots from CISA KEV / FIRST EPSS / OSV
 * via out-of-band maintenance jobs while keeping scanners strictly offline.
 */
export const DEFAULT_OFFLINE_VULN_INTEL_RECORDS: VulnerabilityIntelligenceRecord[] = [
  {
    cveId: "CVE-2021-44228",
    source: "CISA-KEV+FIRST-EPSS-offline-snapshot",
    observedAt: "2026-11-23T00:00:00.000Z",
    kevListed: true,
    kevDateAdded: "2021-12-10",
    kevRequiredAction: "Apply mitigations per vendor instructions or discontinue use of Log4j < 2.17.1.",
    epssScore: 0.975,
    epssPercentile: 0.999,
    cweIds: ["CWE-502", "CWE-917"]
  },
  {
    cveId: "CVE-2021-23337",
    source: "FIRST-EPSS+NVD-offline-snapshot",
    observedAt: "2026-11-23T00:00:00.000Z",
    kevListed: false,
    epssScore: 0.52,
    epssPercentile: 0.976,
    cweIds: ["CWE-77"]
  },
  {
    cveId: "CVE-2020-8203",
    source: "FIRST-EPSS+NVD-offline-snapshot",
    observedAt: "2026-11-23T00:00:00.000Z",
    kevListed: false,
    epssScore: 0.41,
    epssPercentile: 0.971,
    cweIds: ["CWE-1321"]
  },
  {
    cveId: "CVE-2024-3094",
    source: "CISA-KEV+FIRST-EPSS-offline-snapshot",
    observedAt: "2026-11-23T00:00:00.000Z",
    kevListed: true,
    kevDateAdded: "2024-03-29",
    kevRequiredAction: "Downgrade xz-utils to an uncompromised version (e.g., 5.4.x).",
    epssScore: 0.94,
    epssPercentile: 0.996,
    cweIds: ["CWE-506"]
  }
];

export const defaultOfflineIntelligenceProvider =
  new StaticVulnerabilityIntelligenceProvider({
    name: "indicative-offline-vuln-intel-v1",
    snapshotObservedAt: "2026-11-23T00:00:00.000Z",
    records: DEFAULT_OFFLINE_VULN_INTEL_RECORDS
  });

/**
 * Safely enriches a CVE with vulnerability intelligence if available.
 * Never throws; never interprets a missing record as proof of safety.
 */
export function resolveVulnerabilityIntelligence(
  cveId: string | undefined,
  provider: VulnerabilityIntelligenceProvider = defaultOfflineIntelligenceProvider,
  evidenceBasis: VulnerabilityIntelligence["evidenceBasis"] = "SCANNER_MATCH"
): VulnerabilityIntelligence | undefined {
  if (!cveId) return undefined;
  try {
    const rec = provider.lookup(cveId);
    if (!rec) return undefined;
    return {
      source: rec.source,
      observedAt: rec.observedAt,
      kevListed: rec.kevListed,
      kevDateAdded: rec.kevDateAdded,
      kevRequiredAction: rec.kevRequiredAction,
      epssScore: rec.epssScore,
      epssPercentile: rec.epssPercentile,
      cweIds: rec.cweIds,
      reachabilityStatus: "UNKNOWN",
      exposureStatus: "UNKNOWN",
      evidenceBasis
    };
  } catch {
    // Enrichment outage or malformed provider must NEVER fail deterministic scanning
    return undefined;
  }
}
