# Generation 1 Python Licensing Agent

The current Python implementation remains in its existing repository paths (`src/bke_licensing_agent`, packaging, certification, and existing workflows) so released behavior and packaging are not disturbed during the .NET 10 migration.

It is the behavioral/reference implementation for migration work until the corresponding .NET 10 capability is independently certified and explicitly promoted.

## Do not

- move the Python package merely to make the repository look cleaner;
- delete existing tests or packaging while .NET coverage is incomplete;
- change product-facing loopback contracts as part of language migration;
- make products understand whether the provider is Python or .NET;
- bypass Agent trust/update authority during migration.

## Replacement rule

Migrate one owned capability at a time. When a .NET capability is proven compatible and green, composition may switch that capability behind the same contract. Generation 1 remains recoverable until the replacement wave is certified.
