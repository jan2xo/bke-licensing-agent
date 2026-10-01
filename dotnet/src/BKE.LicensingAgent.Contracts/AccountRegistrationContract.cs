using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record AccountRegistrationPreflightRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record AccountRegistrationLegalDocument(
    [property: JsonPropertyName("document_type")] string DocumentType,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("slug")] string Slug,
    [property: JsonPropertyName("version_id")] string VersionId,
    [property: JsonPropertyName("version_number")] int VersionNumber,
    [property: JsonPropertyName("effective_at")] string? EffectiveAt,
    [property: JsonPropertyName("content_markdown")] string ContentMarkdown);

public sealed record AccountRegistrationPreflightResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("legal_documents")] IReadOnlyList<AccountRegistrationLegalDocument> LegalDocuments,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountRegistrationError? Error);

public sealed record AccountRegistrationRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("password")] string Password,
    [property: JsonPropertyName("legal_version_ids")] IReadOnlyList<string> LegalVersionIds);

public sealed record AccountRegistrationVerifyEmailRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("code")] string Code);

public sealed record AccountRegistrationResendRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("email")] string Email);

public sealed record AccountRegistrationResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountRegistrationError? Error);

public sealed record AccountRegistrationError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
