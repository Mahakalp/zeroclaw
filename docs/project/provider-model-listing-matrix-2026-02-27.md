# Provider Model-Listing Capability Matrix (Research)

Last verified: **2026-02-27**

Scope: AI model integrations currently present in `src/integrations/registry.rs`.

Capability classes:
- `LIST_SUPPORTED`: provider exposes a documented model-list endpoint suitable for API-driven discovery.
- `LIST_PARTIAL`: listing exists but is gateway/catalog-scoped, region-scoped, or requires provider-specific handling.
- `MANUAL_ONLY`: no reliable model-list endpoint confirmed from primary docs; manual model entry should remain available.

## Matrix

| Integration | Canonical provider(s) | Class | Endpoint pattern | Auth pattern | Notes | Sources |
|---|---|---|---|---|---|---|
| OpenAI | `openai` | LIST_SUPPORTED | `GET /v1/models` | `Authorization: Bearer <key>` | Standard OpenAI list response (`data[]`) | https://platform.openai.com/docs/api-reference/models/list |
| Anthropic | `anthropic` | LIST_SUPPORTED | `GET /v1/models` | `x-api-key` (+ `anthropic-version`) | Supports pagination (`after_id`, `before_id`, `limit`) | https://platform.claude.com/docs/en/api/models/list |
| Google (Gemini) | `gemini`, `google` | LIST_SUPPORTED | `GET /v1beta/models` | API key query param (`key=`) | Returns `models[]`; IDs often include `models/` prefix | https://ai.google.dev/api/models |
| OpenRouter | `openrouter` | LIST_SUPPORTED | `GET https://openrouter.ai/api/v1/models` | Bearer token | Rich metadata; OpenAI-compatible usage downstream | https://openrouter.ai/docs/api/api-reference/models/get-models |
| DeepSeek | `deepseek` | LIST_SUPPORTED | OpenAI-compatible model list (`/v1/models`) | Bearer token | Docs state OpenAI-compatible API; dedicated list-models docs page exists | https://api-docs.deepseek.com/ and https://api-docs.deepseek.com/api/list-models |
| xAI | `xai`, `x-ai` | LIST_SUPPORTED | `GET /v1/models` | Bearer token | Docs explicitly list model discovery endpoint | https://docs.x.ai/developers/rest-api-reference/inference/models |
| Mistral | `mistral` | LIST_SUPPORTED | `GET /v1/models` | Bearer token | Official docs expose list endpoint | https://docs.mistral.ai/api/endpoint/models |
| Ollama | `ollama` | LIST_PARTIAL | `GET /api/tags` (local daemon) | usually none (local) | Not OpenAI `/v1/models`; schema differs (`models[].name`) | https://github.com/ollama/ollama/blob/main/docs/api.md |
| Cohere | `cohere` | LIST_SUPPORTED | `GET /v1/models` | Bearer token | Supports endpoint filtering in list API | https://docs.cohere.com/reference/list-models |
| Groq | `groq` | LIST_SUPPORTED | `GET https://api.groq.com/openai/v1/models` | Bearer token | OpenAI-compatible list endpoint | https://console.groq.com/docs/models |
| Together AI | `together` | LIST_SUPPORTED | `GET /v1/models` | Bearer token | Official "List All Models" endpoint | https://docs.together.ai/reference/models |
| Fireworks AI | `fireworks` | LIST_SUPPORTED | `GET /v1/models` | Bearer token | Official list-models endpoint in REST docs | https://docs.fireworks.ai/api-reference/list-models |
| Perplexity | `perplexity` | LIST_PARTIAL | unclear public REST list endpoint | key auth for API calls | Public docs focus on model catalog/docs pages, not a clearly documented list endpoint in current snapshot | https://docs.perplexity.ai/docs/agent-api/models and https://docs.perplexity.ai/docs/getting-started/overview |
| Venice | `venice` | LIST_SUPPORTED | `GET /api/v1/models` | API key for account-scoped usage (listing docs available) | Docs explicitly expose list endpoint | https://docs.venice.ai/api-reference/endpoint/models/list |
| Vercel AI Gateway | `vercel` | LIST_PARTIAL | Gateway `GET /models` (OpenAI-compatible surface) | Gateway key | Catalog/gateway scoped; may not equal upstream-provider direct entitlements | https://vercel.com/docs/ai-gateway/sdks-and-apis/openai-compat |
| Cloudflare AI Gateway / Workers AI | `cloudflare` | LIST_PARTIAL | Cloudflare AI models APIs exist; gateway behavior differs by route/provider | Cloudflare account/gateway auth | Need product-specific split: Workers AI native catalog vs AI Gateway routed providers | https://developers.cloudflare.com/api/resources/ai/subresources/models/ and https://developers.cloudflare.com/ai-gateway/ |
| Moonshot (Kimi) | `moonshot`, `kimi` | LIST_SUPPORTED | `GET https://api.moonshot.ai/v1/models` | Bearer token | Official docs/search snippet explicitly references List Models URL; unauthenticated probe returns 401 while invalid endpoint returns 404 | https://platform.moonshot.ai/docs/api/chat |
| Z.AI / GLM | `zai`, `glm`, `zhipu*` aliases | MANUAL_ONLY | no model-list endpoint present in published OpenAPI index in this pass | provider-specific key/token | Z.AI docs/OpenAPI expose chat completion and tools APIs, but no dedicated models-list path discovered | https://docs.z.ai/llms.txt and https://docs.z.ai/openapi.json |
| MiniMax | `minimax` | MANUAL_ONLY | no reliable documented `/v1/models` found in this pass | provider-specific key/token | Community reports indicate missing standard model-list endpoint; verify against latest official OpenAPI before implementation | https://platform.minimax.io/docs/guides/models-intro and https://github.com/MiniMax-AI/MiniMax-M2/issues/60 |
| Qwen (DashScope) | `qwen`, `dashscope` aliases | LIST_SUPPORTED | `GET {base_url}/models` on OpenAI-compatible base URL (`.../compatible-mode/v1`) | Bearer token (`DASHSCOPE_API_KEY`) | Unauthenticated probe to `/compatible-mode/v1/models` returns 401 and invalid endpoint returns 404, indicating routed models endpoint in OpenAI-compatible surface | https://www.alibabacloud.com/help/en/model-studio/compatibility-of-openai-with-dashscope |
| Amazon Bedrock | `bedrock` | LIST_SUPPORTED | `ListFoundationModels` API | AWS SigV4 / IAM | Non-OpenAI schema; region/entitlement dependent | https://docs.aws.amazon.com/bedrock/latest/APIReference/API_ListFoundationModels.html |
| Qianfan (Baidu) | `qianfan` aliases | LIST_SUPPORTED | `GET https://qianfan.baidubce.com/v2/models` | `Authorization: Bearer <API Key>` | Official API reference includes request/response schema for model listing | https://cloud.baidu.com/doc/qianfan-api/s/Dmba8k71y |
| Synthetic | `synthetic` | MANUAL_ONLY | provider-specific / internal | provider-specific | No public model-list API reference confirmed | N/A (internal/provider-specific) |
| OpenCode Zen | `opencode` | MANUAL_ONLY | provider-specific / internal | provider-specific | No public model-list API reference confirmed | N/A (internal/provider-specific) |

## Parser Strategy by Response Shape

1. **OpenAI-compatible list** (`data[]` with `id`):
   - Use `id` as canonical model key.
   - Providers: OpenAI, OpenRouter, Groq, Together, Fireworks, often DeepSeek/xAI/Mistral-compatible.

2. **Google Gemini list** (`models[]` with `name` like `models/gemini-...`):
   - Normalize by stripping `models/` prefix for display and storage aliases.

3. **Anthropic list** (`data[]` with `id`, cursor paging):
   - Consume paging fields (`has_more`, `last_id`) when available.

4. **Ollama local tags** (`models[]` with `name`):
   - Treat as local daemon catalog, separate from hosted provider semantics.

5. **Bedrock list** (`modelSummaries[]` via AWS API):
   - Map to normalized internal shape; preserve `modelId` and modality/provider metadata.

6. **Gateway providers (Vercel/Cloudflare)**:
   - Treat as gateway catalogs with potentially different visibility than native provider APIs.

## Open Questions (for `zeroclaw-c46.1` follow-up)

- Verify whether MiniMax has introduced an official model-list endpoint after current docs snapshot.
- Verify whether Z.AI/GLM adds a dedicated model-list route in future API revisions (current OpenAPI snapshot shows none).
- Decide whether `LIST_PARTIAL` providers should default to live-fetch, static fallback, or manual-only in v1 UX.
