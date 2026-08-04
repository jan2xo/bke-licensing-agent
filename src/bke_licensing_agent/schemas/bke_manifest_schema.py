schema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://example.com/schemas/bke-manifest.schema.json",
    "title": "BKE Product Manifest",
    "type": "object",
    "required": [
        "schemaVersion",
        "productId",
        "displayName",
        "version",
        "entryPoint",
        "updateChannel",
        "minimumAgentVersion",
        "platform",
        "architecture"
    ],
    "additionalProperties": False,
    "properties": {
        "schemaVersion": {
            "type": "integer",
            "const": 1
        },
        "productId": {
            "type": "string",
            "pattern": "^[a-z0-9-]+$"
        },
        "displayName": {
            "type": "string",
            "minLength": 1
        },
        "publisher": {
            "type": "string",
            "minLength": 1
        },
        "version": {
            "type": "string",
            "pattern": "^\\d+\\.\\d+\\.\\d+(?:[-+].*)?$"
        },
        "entryPoint": {
            "type": "string",
            "minLength": 1
        },
        "icon": {
            "type": "string",
            "minLength": 1
        },
        "updateChannel": {
            "type": "string",
            "enum": ["stable", "beta", "alpha"]
        },
        "minimumAgentVersion": {
            "type": "string",
            "pattern": "^\\d+\\.\\d+\\.\\d+(?:[-+].*)?$"
        },
        "platform": {
            "type": "string",
            "enum": ["windows", "macos", "linux"]
        },
        "architecture": {
            "type": "string",
            "enum": ["x86", "x64", "arm64"]
        }
    }
}
