import { redactObjectDeep, redactSecretsInText } from "./secrets.js";

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

export interface StructuredLogger {
  debug(msg: string, meta?: Record<string, unknown>): void;
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
  child(bindings: Record<string, unknown>): StructuredLogger;
}

export function createRedactingLogger(options: {
  service: string;
  level?: LogLevel;
  bindings?: Record<string, unknown>;
  sink?: (line: string) => void;
}): StructuredLogger {
  const minLevel = LEVEL_PRIORITY[options.level ?? "info"];
  const baseBindings = options.bindings ?? {};
  const sink = options.sink ?? ((line: string) => process.stdout.write(`${line}\n`));

  function emit(level: LogLevel, msg: string, meta?: Record<string, unknown>): void {
    if (LEVEL_PRIORITY[level] < minLevel) return;
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      service: options.service,
      message: redactSecretsInText(msg),
      ...redactObjectDeep(baseBindings),
      ...(meta ? redactObjectDeep(meta) : {})
    };
    sink(JSON.stringify(entry));
  }

  return {
    debug: (msg, meta) => emit("debug", msg, meta),
    info: (msg, meta) => emit("info", msg, meta),
    warn: (msg, meta) => emit("warn", msg, meta),
    error: (msg, meta) => emit("error", msg, meta),
    child: (bindings) =>
      createRedactingLogger({
        service: options.service,
        level: options.level,
        bindings: { ...baseBindings, ...bindings },
        sink
      })
  };
}
