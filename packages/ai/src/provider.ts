export interface LlmMessage {
  role: "system" | "user";
  content: string;
}

export interface LlmCompletionRequest {
  messages: LlmMessage[];
  maxTokens: number;
  temperature?: number;
  jsonMode?: boolean;
}

export interface LlmCompletionResponse {
  content: string;
  model: string;
  provider: string;
  promptTokens?: number;
  completionTokens?: number;
  totalTokens?: number;
  latencyMs: number;
  refusal?: string;
}

export interface AiProvider {
  readonly name: string;
  readonly model: string;
  readonly enabled: boolean;
  complete(request: LlmCompletionRequest): Promise<LlmCompletionResponse>;
}

export class DisabledAiProvider implements AiProvider {
  public readonly name = "disabled";
  public readonly model = "none";
  public readonly enabled = false;

  async complete(): Promise<LlmCompletionResponse> {
    throw new Error(
      "AI_DISABLED: No LLM provider is configured. Set AI_PROVIDER=openai-compatible and AI_API_KEY to enable AI analysis."
    );
  }
}

export interface OpenAiCompatibleConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
  timeoutMs: number;
  maxRetries: number;
  fetchImpl?: typeof fetch;
}

interface OpenAiChatResponse {
  model?: string;
  choices?: Array<{
    message?: {
      content?: string | null;
      refusal?: string | null;
    };
    finish_reason?: string;
  }>;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
  error?: {
    message?: string;
    type?: string;
  };
}

export class OpenAiCompatibleProvider implements AiProvider {
  public readonly name = "openai-compatible";
  public readonly model: string;
  public readonly enabled = true;
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly fetchFn: typeof fetch;

  constructor(config: OpenAiCompatibleConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.apiKey = config.apiKey;
    this.model = config.model;
    this.timeoutMs = config.timeoutMs;
    this.maxRetries = config.maxRetries;
    this.fetchFn = config.fetchImpl ?? fetch;
  }

  async complete(request: LlmCompletionRequest): Promise<LlmCompletionResponse> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const start = Date.now();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const body: Record<string, unknown> = {
          model: this.model,
          messages: request.messages,
          max_tokens: request.maxTokens,
          temperature: request.temperature ?? 0.1
        };
        if (request.jsonMode) {
          body.response_format = { type: "json_object" };
        }

        const res = await this.fetchFn(`${this.baseUrl}/chat/completions`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${this.apiKey}`
          },
          body: JSON.stringify(body),
          signal: controller.signal
        });

        const latencyMs = Date.now() - start;

        if (res.status === 429 || res.status >= 500) {
          const errText = await res.text().catch(() => "");
          lastError = new Error(
            `AI_PROVIDER_TRANSIENT_ERROR (${res.status}): ${errText.slice(0, 300)}`
          );
          if (attempt < this.maxRetries) {
            await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
            continue;
          }
          throw lastError;
        }

        if (!res.ok) {
          const errText = await res.text().catch(() => "");
          throw new Error(
            `AI_PROVIDER_ERROR (${res.status}): ${errText.slice(0, 300)}`
          );
        }

        const data = (await res.json()) as OpenAiChatResponse;
        const choice = data.choices?.[0];
        if (!choice?.message) {
          throw new Error("AI_MALFORMED_RESPONSE: Provider returned no completion choice.");
        }

        if (choice.message.refusal) {
          return {
            content: "",
            refusal: choice.message.refusal,
            model: data.model ?? this.model,
            provider: this.name,
            promptTokens: data.usage?.prompt_tokens,
            completionTokens: data.usage?.completion_tokens,
            totalTokens: data.usage?.total_tokens,
            latencyMs
          };
        }

        const content = choice.message.content ?? "";
        if (!content.trim()) {
          throw new Error("AI_EMPTY_RESPONSE: Provider returned empty content.");
        }

        return {
          content,
          model: data.model ?? this.model,
          provider: this.name,
          promptTokens: data.usage?.prompt_tokens,
          completionTokens: data.usage?.completion_tokens,
          totalTokens: data.usage?.total_tokens,
          latencyMs
        };
      } catch (err) {
        if ((err as Error).name === "AbortError") {
          lastError = new Error(`AI_TIMEOUT: LLM request timed out after ${this.timeoutMs}ms.`);
        } else {
          lastError = err as Error;
        }
        if (attempt >= this.maxRetries) {
          throw lastError;
        }
      } finally {
        clearTimeout(timer);
      }
    }

    throw lastError ?? new Error("AI_PROVIDER_ERROR: Request failed.");
  }
}
