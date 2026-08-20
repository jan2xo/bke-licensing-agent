# Universal updater certification fixtures

Product A is a disposable executable fixture with versions 1.0.0, 1.1.0, and intentionally broken 1.2.0. It contains no updater code.

Product B represents a compiled/WPF-style installation: it only supplies a manifest and executable identity. It does not import Python updater code.

The fixtures are inputs for the Agent/updater-core certification harness. They are not production packages and do not prove end-to-end success until the harness is executed with a local Digital Solutions stack.
