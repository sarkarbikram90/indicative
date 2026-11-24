import type { ScannerAdapter, ScannerHealth } from "@indicative/contracts";
import { CicdGitHubActionsAdapter } from "@indicative/cicd-security";
import {
  GitleaksScannerAdapter,
  SemgrepScannerAdapter,
  TrivyScannerAdapter
} from "@indicative/scanners";

export interface ScannerRegistryConfig {
  semgrepBin: string;
  semgrepRulesDir: string;
  trivyBin: string;
  trivyCacheDir: string;
  trivyOfflineMode?: boolean;
  gitleaksBin: string;
}

export class ScannerAdapterRegistry {
  private readonly adapters = new Map<string, ScannerAdapter>();

  constructor(initialAdapters: ScannerAdapter[] = []) {
    for (const adapter of initialAdapters) {
      this.register(adapter);
    }
  }

  register(adapter: ScannerAdapter): void {
    this.adapters.set(adapter.name, adapter);
  }

  get(name: string): ScannerAdapter | undefined {
    return this.adapters.get(name);
  }

  listNames(): string[] {
    return [...this.adapters.keys()];
  }

  async checkAllHealth(): Promise<ScannerHealth[]> {
    return Promise.all([...this.adapters.values()].map((a) => a.healthCheck()));
  }
}

export function createDefaultScannerRegistry(
  config: ScannerRegistryConfig
): ScannerAdapterRegistry {
  return new ScannerAdapterRegistry([
    new SemgrepScannerAdapter({
      binaryPath: config.semgrepBin,
      rulesDir: config.semgrepRulesDir
    }),
    new TrivyScannerAdapter({
      binaryPath: config.trivyBin,
      cacheDir: config.trivyCacheDir,
      offlineMode: config.trivyOfflineMode ?? true
    }),
    new GitleaksScannerAdapter({
      binaryPath: config.gitleaksBin
    }),
    new CicdGitHubActionsAdapter()
  ]);
}
