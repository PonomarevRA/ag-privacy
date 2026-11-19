using System.Security.Cryptography;
using System.Text;
namespace AgPrivacy;

/// <summary>IDs come from the trusted product session, never from page text or agent arguments.</summary>
public sealed record PrivacyContext(string ProductId, string ChatId, string TaskId);
public enum HumanConsentAction { WarningConfirmation, ExplicitHumanReply, ExplicitPreserveInstruction }
/// <summary>Common bounded trusted context contract for full and per-field approvals.</summary>
public static class PrivacyContextRules
{
    public static void Validate(PrivacyContext context)
    {
        if (string.IsNullOrWhiteSpace(context.ProductId) || context.ProductId.Length > 128 || string.IsNullOrWhiteSpace(context.ChatId) || context.ChatId.Length > 128 || string.IsNullOrWhiteSpace(context.TaskId) || context.TaskId.Length > 128) throw new ArgumentException("invalid-privacy-context");
    }
}
public enum ConsentScope { Task, Chat, ProductSession }
/// <summary>UI request contains no page values. RequestId is private to the product, not an agent capability.</summary>
public sealed record PrivacyConsentPrompt(string RequestId, ConsentScope Scope, string Warning);
/// <summary>Agent-visible result: no original mappings, approval tokens or diagnostic excerpts.</summary>
public sealed record AgentPrivacyResponse(bool Allowed, string ProtectionMode, bool MaskingApplied,
    bool MustDiscloseMasking, string Notice, string? Text, System.Text.Json.Nodes.JsonNode? Data);

/// <summary>
/// Trusted product control plane. Do not register any methods of this class as agent/MCP tools.
/// Library cannot distinguish a human from its host: host must authenticate an actual UI action.
/// Agent-facing interface contains only sanitized reads and instructions to find human settings.
/// </summary>
public sealed class PrivacyConsentController(PrivacyEngine engine, string policyVersion, TimeProvider? time = null)
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly object sync = new();
    private bool exhausted;
    private readonly TimeProvider clock = time ?? TimeProvider.System;
    private readonly Dictionary<string, Request> requests = new(StringComparer.Ordinal);
    private readonly HashSet<string> endedChats = new(StringComparer.Ordinal);
    private readonly HashSet<PrivacyContext> endedTasks = [];
    public const string MaskingNotice = "Часть данных скрыта ag-privacy. Исходные значения агенту недоступны.";
    public const string AgentSettingsHelp = "Для работы с оригиналами откройте настройки приватности продукта, выберите задачу или чат и подтвердите предупреждение. Агент не может выключить ag-privacy.";

    /// <summary>Create a bounded prompt to display in trusted UI. Pending prompt never changes data access.</summary>
    public PrivacyConsentPrompt RequestUserDecision(PrivacyContext context, ConsentScope scope, string purpose, TimeSpan lifetime)
    {
        PrivacyContextRules.Validate(context);
        if (!Enum.IsDefined(scope) || purpose.Length is 0 or > 256 || lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromHours(1)) throw new ArgumentException("invalid-consent-request");
        lock (sync)
        {
            PruneExpired();
            if (requests.Count >= 256 || IsEnded(context)) throw new InvalidOperationException("consent-request-unavailable");
            string id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            requests.Add(id, new(context, scope, policyVersion, clock.GetTimestamp(), clock.GetUtcNow().Add(lifetime), lifetime));
            string area = scope switch { ConsentScope.Task => "этой задачи", ConsentScope.Chat => "этого чата", _ => "текущего сеанса продукта" };
            string warning = $"Выключить ag-privacy для {area}? Агент получит оригинальные персональные данные и токены доступа; они могут попасть к провайдеру модели и в историю чата. Цель: {purpose}. Разрешение действует до {lifetime.TotalMinutes:0.#} мин. или окончания области действия. Отмена оставляет защиту включённой. Включить её снова можно в настройках.";
            return new(id, scope, warning);
        }
    }

    /// <summary>Call only on actual human warning confirmation/cancel in UI. Agent text is never confirmation.</summary>
    public bool ResolveFromHumanAction(string requestId, PrivacyContext current, bool confirmed, HumanConsentAction action = HumanConsentAction.WarningConfirmation)
    {
        PrivacyContextRules.Validate(current);
        lock (sync)
        {
            if (!Enum.IsDefined(action) || !requests.TryGetValue(requestId, out var request) || request.Resolved || request.Context != current || !Current(request)) return false;
            request.Resolved = true; request.Approved = confirmed;
            return true;
        }
    }

    /// <summary>Reads are atomic with consent resolution/revocation; unknown, denied or wrong-scope requests stay protected.</summary>
    public AgentPrivacyResponse Read(PrivacyContext current, string input, bool json = false)
    {
        PrivacyContextRules.Validate(current);
        lock (sync)
        {
            if (IsEnded(current)) return new(false, "blocked", false, false, "Область задачи или чата завершена.", null, null);
            if (!ValidInput(input)) return new(false, "blocked", false, false, "Превышен лимит ag-privacy.", null, null);
            foreach (var request in requests.Values)
            {
                if (!request.Approved || !Current(request) || !ScopeMatches(request, current)) continue;
                // Raw text remains an opaque string even if JSON: no second parse/error path can echo rejected input.
                string area = request.Scope switch { ConsentScope.Task => "задачи", ConsentScope.Chat => "чата", _ => "сеанса продукта" };
                return new(true, "disabled-by-user", false, false, $"ag-privacy выключен пользователем для {area}. Агент получает оригинальные данные.", input, null);
            }
            PrivacyResult result = json ? engine.SanitizeJson(input, current) : engine.SanitizeText(input);
            if (!result.Allowed || !result.SafeForAgent) return new(false, "blocked", false, false, "Выдача данных заблокирована ag-privacy.", null, null);
            string notice = result.AgentNotice ?? "ag-privacy включён.";
            bool fieldException = result.DisclosedFields.Length > 0;
            if (fieldException) notice += " Пользователь разрешил отдельные оригинальные значения для текущей задачи.";
            string mode = fieldException ? "enabled-with-human-field-exception" : "enabled";
            return new(true, mode, result.OriginalReplaced, result.MustDiscloseMasking, notice, result.Text, result.Data);
        }
    }

    /// <summary>Human re-enable control revokes matching approvals and pending prompts; it never attempts to erase earlier model context.</summary>
    public void EnableFromUserInterface(PrivacyContext current)
    {
        PrivacyContextRules.Validate(current);
        lock (sync)
        {
            engine.RevokeDisclosure();
            foreach (string id in requests.Keys.ToArray()) if (ScopeMatches(requests[id], current)) requests.Remove(id);
        }
    }

    /// <summary>Trusted product lifecycle end revokes the task grant; chat grants intentionally survive another task in the same live chat.</summary>
    public void EndTask(PrivacyContext current)
    {
        PrivacyContextRules.Validate(current);
        lock (sync) { if (endedTasks.Count >= 4096) exhausted = true; else endedTasks.Add(current); foreach (string id in requests.Keys.ToArray()) if (requests[id].Scope == ConsentScope.Task && requests[id].Context == current) requests.Remove(id); }
    }
    /// <summary>End a chat permanently within this controller; products must create fresh unique chat IDs for a new chat.</summary>
    public void EndChat(PrivacyContext current)
    {
        PrivacyContextRules.Validate(current);
        lock (sync) { if (endedChats.Count >= 4096) exhausted = true; else endedChats.Add(ChatKey(current)); foreach (string id in requests.Keys.ToArray()) if (ChatKey(requests[id].Context) == ChatKey(current)) requests.Remove(id); }
    }

    private bool Current(Request request) => request.Policy == policyVersion && !exhausted && ScopeLive(request) && clock.GetUtcNow() < request.Expires && clock.GetElapsedTime(request.Started) < request.Lifetime;
    private bool ScopeLive(Request request) => request.Scope switch
    {
        ConsentScope.Task => !IsEnded(request.Context),
        ConsentScope.Chat => !endedChats.Contains(ChatKey(request.Context)),
        _ => true
    };
    private static bool ValidInput(string input)
    {
        try { return StrictUtf8.GetByteCount(input) <= PrivacyLimits.InputBytes; }
        catch (EncoderFallbackException) { return false; }
    }
    private bool IsEnded(PrivacyContext context) => exhausted || endedChats.Contains(ChatKey(context)) || endedTasks.Contains(context);
    private static string ChatKey(PrivacyContext context) => context.ProductId.Length + ":" + context.ProductId + context.ChatId;
    private static bool ScopeMatches(Request request, PrivacyContext current) => request.Context.ProductId == current.ProductId && (request.Scope == ConsentScope.ProductSession || (request.Context.ChatId == current.ChatId && (request.Scope == ConsentScope.Chat || request.Context.TaskId == current.TaskId)));
    private void PruneExpired() { foreach (string id in requests.Keys.ToArray()) if (!Current(requests[id])) requests.Remove(id); }
    private sealed class Request(PrivacyContext context, ConsentScope scope, string policy, long started, DateTimeOffset expires, TimeSpan lifetime)
    {
        public PrivacyContext Context { get; } = context;
        public ConsentScope Scope { get; } = scope;
        public string Policy { get; } = policy;
        public long Started { get; } = started;
        public DateTimeOffset Expires { get; } = expires;
        public TimeSpan Lifetime { get; } = lifetime;
        public bool Resolved;
        public bool Approved;
    }
}
