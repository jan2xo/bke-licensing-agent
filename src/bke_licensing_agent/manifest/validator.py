from jsonschema import Draft202012Validator
from pydantic import ValidationError

from bke_licensing_agent.manifest.models import Manifest
from bke_licensing_agent.schemas.bke_manifest_schema import schema


def validate_manifest(manifest: dict) -> Manifest:
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(manifest), key=lambda err: err.path)
    if errors:
        message = "; ".join([f"{'.'.join(map(str, error.path))}: {error.message}" for error in errors])
        raise ValueError(message)

    try:
        return Manifest(**manifest)
    except ValidationError as exc:
        raise ValueError(exc) from exc
