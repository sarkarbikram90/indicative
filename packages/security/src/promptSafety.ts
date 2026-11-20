import { redactSecretsInText } from "./secrets.js";

const PROMPT_INJECTION_INDICATORS: RegExp[] = [
  /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
  /disregard\s+(?:all\s+)?(?:previous|system)\s+(?:instructions|prompts)/i,
  /you\s+are\s+now\s+(?:a|an)\s+/i,
  /mark\s+this\s+finding\s+as\s+(?:false\s+positive|safe|resolved|info)/i,
  /suppress\s+(?:this|all)\s+finding/i,
  /execute\s+(?:shell|bash|command|curl|wget)/i,
  /reveal\s+(?:system\s+prompt|environment\s+variables|api\s+key|secrets)/i
];

export interface PromptSanitizationResult {
  sanitizedDataBlock: string;
  injectionSignalsDetected: string[];
  truncated: boolean;
}

/**
 * Prepares untrusted repository excerpts or scanner text for LLM prompts:
 * 1. Redacts all known and pattern-matched secrets.
 * 2. Strips delimiter-breakout attempts.
 * 3. Truncates to maxChars.
 * 4. Detects prompt-injection patterns for audit visibility.
 * 5. Wraps text in explicit untrusted-data XML fences.
 */
export function sanitizeUntrustedDataForLlm(
  rawText: string,
  maxChars: number,
  knownSecrets: string[] = []
): PromptSanitizationResult {
  const redacted = redactSecretsInText(rawText, knownSecrets);

  // Prevent breakout from our untrusted data fence tags
  const neutralized = redacted
    .replace(/<\/?UNTRUSTED_REPOSITORY_DATA>/gi, "[REMOVED_TAG]")
    .replace(/\0/g, "");

  const injectionSignalsDetected: string[] = [];
  for (const pattern of PROMPT_INJECTION_INDICATORS) {
    const match = neutralized.match(pattern);
    if (match) {
      injectionSignalsDetected.push(match[0].slice(0, 120));
    }
  }

  let truncated = false;
  let body = neutralized;
  if (body.length > maxChars) {
    body = `${body.slice(0, maxChars)}\n... [TRUNCATED AT ${maxChars} CHARS]`;
    truncated = true;
  }

  const sanitizedDataBlock = [
    "<UNTRUSTED_REPOSITORY_DATA>",
    body,
    "</UNTRUSTED_REPOSITORY_DATA>"
  ].join("\n");

  return {
    sanitizedDataBlock,
    injectionSignalsDetected,
    truncated
  };
}
