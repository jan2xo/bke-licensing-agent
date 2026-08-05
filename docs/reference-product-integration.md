# Reference Product Integration

Products provide a validated manifest and declared entry point. The shared agent
owns licensing, authorization, integrity checks, execution, recovery, and update preparation.

The Demo Product calls a supplied `AuthorizationDecision` provider and exits
non-zero on denial; it does not hardcode authorization or implement licensing.
