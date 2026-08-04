# License entitlement

`LicensingService` uses the authenticated Phase 4 session and Phase 3 HTTPS
client to retrieve product entitlement. Server status is authoritative. Unknown
or ineligible states fail closed; local manifest and SQLite state never grant
entitlement.
