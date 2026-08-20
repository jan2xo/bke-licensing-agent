# Product integration contract

A product joins the universal updater by shipping only a trusted local
bke.manifest.json:

- schema: bke.product.v1
- product_id
- version
- platform
- architecture
- executable relative to install_root
- install_root
- update_channel
- optional local health-check identity

The product talks only to the Agent localhost authorization interface. It does
not contain update download, signature, rollback, licensing, or Digital
Solutions code.

Authorization mapping:

- UP_TO_DATE and UPDATE_AVAILABLE: ALLOW
- UPDATE_REQUIRED: continue only while the Agent's explicit offline policy permits; otherwise DENY
- UNSUPPORTED or unverifiable policy: DENY

AirStack, RenderDock, Scraper, WeatherWatch desktop components, WPF/.NET
applications, and Python applications use the same contract. Their package
layout and artifact data differ; updater source does not.
