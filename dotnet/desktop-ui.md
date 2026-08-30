# BKE Licensing Agent Desktop UI (.NET 10)

The long-term Licensing Agent desktop experience is a real cross-platform .NET desktop application built with Avalonia, not a browser surface or Electron shell.

## Ownership

### WHAT I NEED

- `AgentDesktopSnapshot`
- typed presentation actions through `IAgentDesktopViewSource`

### WHAT I DO

- render Agent status, managed products, update state, trust posture and activity
- translate user intent into presentation actions

### WHAT I GIVE

- a native desktop application experience for Windows, macOS and Linux
- no licensing authority, update authority, signing material, trusted paths or persistence ownership

## Replaceable UI boundary

`BKE.LicensingAgent.Presentation` is the stable UI-facing contract. The Avalonia implementation is one adapter.

```text
Agent capabilities
      ↓
AgentDesktopSnapshot
      ↓
BKE.LicensingAgent.Desktop (Avalonia)
```

A future desktop implementation may replace Avalonia if it satisfies the same presentation contract. Agent business capabilities must not depend on Avalonia types.

## Preview mode

The desktop shell does not invent live product state while the .NET providers are still being migrated.

Normal launch shows a fail-closed unconnected state.

For UI development only:

```text
BKE_AGENT_UI_PREVIEW=1
```

This enables clearly labelled preview data so the presentation can be developed and certified without Licensing, Digital Solutions, updater execution or production state.

## Framework

- Target: `net10.0`
- UI: Avalonia 12.1.1
- Desktop targets: Windows, macOS, Linux

Platform-specific privileged execution remains outside the presentation layer.
