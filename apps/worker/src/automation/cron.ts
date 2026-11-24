import type { ScheduleCadence } from "@indicative/contracts";

export const CADENCE_CRON_PRESETS: Record<Exclude<ScheduleCadence, "CUSTOM_CRON">, string> = {
  HOURLY: "0 * * * *",
  DAILY: "0 2 * * *",
  WEEKLY: "0 3 * * 1"
};

interface ParsedCronField {
  values: Set<number>;
  isWildcard: boolean;
}

interface ParsedCron {
  minute: ParsedCronField;
  hour: ParsedCronField;
  dayOfMonth: ParsedCronField;
  month: ParsedCronField;
  dayOfWeek: ParsedCronField;
}

function parseCronField(
  token: string,
  min: number,
  max: number,
  label: string
): ParsedCronField {
  const trimmed = token.trim();
  const values = new Set<number>();

  if (trimmed === "*") {
    for (let i = min; i <= max; i++) values.add(i);
    return { values, isWildcard: true };
  }

  const segments = trimmed.split(",");
  for (const segment of segments) {
    const [rangePart, stepPart] = segment.split("/");
    if (!rangePart) {
      throw new Error(`INVALID_CRON: Empty ${label} segment in "${token}".`);
    }

    const step = stepPart !== undefined ? Number(stepPart) : 1;
    if (!Number.isInteger(step) || step < 1 || step > max - min + 1) {
      throw new Error(`INVALID_CRON: Invalid step "${stepPart}" in ${label} "${token}".`);
    }

    let start = min;
    let end = max;
    if (rangePart === "*") {
      start = min;
      end = max;
    } else if (rangePart.includes("-")) {
      const [a, b] = rangePart.split("-");
      start = Number(a);
      end = Number(b);
      if (
        !Number.isInteger(start) ||
        !Number.isInteger(end) ||
        start < min ||
        end > max ||
        start > end
      ) {
        throw new Error(`INVALID_CRON: Invalid range "${rangePart}" in ${label}.`);
      }
    } else {
      const single = Number(rangePart);
      if (!Number.isInteger(single) || single < min || single > max) {
        throw new Error(`INVALID_CRON: Value "${rangePart}" out of bounds [${min}, ${max}] for ${label}.`);
      }
      start = single;
      end = stepPart !== undefined ? max : single;
    }

    for (let v = start; v <= end; v += step) {
      values.add(v);
    }
  }

  if (values.size === 0) {
    throw new Error(`INVALID_CRON: Field ${label} matched no values.`);
  }

  return { values, isWildcard: false };
}

export function parseCronExpression(expr: string): ParsedCron {
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) {
    throw new Error(
      `INVALID_CRON: Expected standard 5-field UTC cron expression ("min hour dom month dow"), got "${expr}".`
    );
  }
  const [minStr, hourStr, domStr, monStr, dowStr] = parts as [
    string,
    string,
    string,
    string,
    string
  ];

  // Normalize Sunday "7" to "0" in day-of-week
  const normalizedDow = dowStr.replace(/\b7\b/g, "0");

  return {
    minute: parseCronField(minStr, 0, 59, "minute"),
    hour: parseCronField(hourStr, 0, 23, "hour"),
    dayOfMonth: parseCronField(domStr, 1, 31, "day-of-month"),
    month: parseCronField(monStr, 1, 12, "month"),
    dayOfWeek: parseCronField(normalizedDow, 0, 6, "day-of-week")
  };
}

export function resolveCronExpression(
  cadence: ScheduleCadence,
  customCronExpression?: string
): string {
  if (cadence === "CUSTOM_CRON") {
    if (!customCronExpression) {
      throw new Error("INVALID_CRON: cronExpression is required when cadence is CUSTOM_CRON.");
    }
    parseCronExpression(customCronExpression);
    return customCronExpression.trim().replace(/\s+/g, " ");
  }
  if (customCronExpression && customCronExpression.trim().length > 0) {
    parseCronExpression(customCronExpression);
    return customCronExpression.trim().replace(/\s+/g, " ");
  }
  return CADENCE_CRON_PRESETS[cadence];
}

/**
 * Computes the next UTC Date strictly after `fromDate` matching the 5-field cron expression.
 * Searches up to 366 days ahead deterministically.
 */
export function computeNextCronRun(cronExpression: string, fromDate: Date = new Date()): Date {
  const parsed = parseCronExpression(cronExpression);
  const candidate = new Date(fromDate.getTime());
  candidate.setUTCSeconds(0, 0);
  candidate.setUTCMinutes(candidate.getUTCMinutes() + 1);

  const maxIterations = 366 * 24 * 60;
  for (let i = 0; i < maxIterations; i++) {
    const month = candidate.getUTCMonth() + 1;
    if (!parsed.month.values.has(month)) {
      candidate.setUTCMonth(candidate.getUTCMonth() + 1, 1);
      candidate.setUTCHours(0, 0, 0, 0);
      continue;
    }

    const dom = candidate.getUTCDate();
    const dow = candidate.getUTCDay();
    const dayMatches =
      parsed.dayOfMonth.isWildcard && parsed.dayOfWeek.isWildcard
        ? true
        : parsed.dayOfMonth.isWildcard
          ? parsed.dayOfWeek.values.has(dow)
          : parsed.dayOfWeek.isWildcard
            ? parsed.dayOfMonth.values.has(dom)
            : parsed.dayOfMonth.values.has(dom) || parsed.dayOfWeek.values.has(dow);

    if (!dayMatches) {
      candidate.setUTCDate(candidate.getUTCDate() + 1);
      candidate.setUTCHours(0, 0, 0, 0);
      continue;
    }

    const hour = candidate.getUTCHours();
    if (!parsed.hour.values.has(hour)) {
      candidate.setUTCHours(hour + 1, 0, 0, 0);
      continue;
    }

    const minute = candidate.getUTCMinutes();
    if (!parsed.minute.values.has(minute)) {
      candidate.setUTCMinutes(minute + 1, 0, 0);
      continue;
    }

    return candidate;
  }

  throw new Error(`INVALID_CRON: Could not find next execution within 366 days for "${cronExpression}".`);
}
