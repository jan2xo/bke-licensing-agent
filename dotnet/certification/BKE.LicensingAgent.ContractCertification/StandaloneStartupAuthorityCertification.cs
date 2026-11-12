using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

/// <summary>
/// Hermetic Agent-owned process/credential decision matrix. This is NOT a
/// customer executable test or a substitute for an installed signed registry.
/// </summary>
internal static class StandaloneStartupAuthorityCertification
{
    public static async Task RunAsync()
    {
        int passed = 0;
        async Task Case(
            string description,
            Action<Fixture> arrange,
            bool allow,
            string? credential = null,
            Action<Fixture>? inspect = null)
        {
            var f = new Fixture();
            arrange(f);
            var result = await f.Service().AuthorizeConnectedPeerAsync(
                CancellationToken.None);
            if (result.Authorized != allow ||
                (allow && result.Credential != credential) ||
                (!allow && result.Credential is not null))
                throw new InvalidOperationException(
                    $"FAIL standalone startup {description}: {result}");
            inspect?.Invoke(f);
            passed++;
            Console.WriteLine($"PASS standalone startup: {description}");
        }

        await Case("ACCOUNT requires authenticated catalog and fresh JWS",
            f => { f.SetMode("ACCOUNT"); f.Account.Allow = true; }, true,
            "ACCOUNT", f => {
                Must(f.Account.Calls == 1 && f.Key.Calls == 0 &&
                    f.Audit.Calls == 1 && f.Peer.RecheckCalls == 1,
                    "account proof gate ordering");
            });

        await Case("LICENSE_KEY works independently without account/Google",
            f => {
                f.SetMode("LICENSE_KEY");
                f.Key.Allow = true;
                f.Catalog.Response = f.Catalog.Response with {
                    Status = "AUTH_REQUIRED", Items = []
                };
            }, true, "LICENSE_KEY", f => {
                Must(f.Catalog.Calls == 0 && f.Account.Calls == 0 &&
                    f.Key.Calls == 1, "key path consulted account authority");
            });

        await Case("explicit EITHER accepts the fresh account proof",
            f => { f.SetMode("EITHER"); f.Account.Allow = true; },
            true, "ACCOUNT", f => {
                Must(f.Key.Calls == 0, "EITHER borrowed the key route");
            });

        await Case("explicit EITHER accepts signed key with offline account",
            f => {
                f.SetMode("EITHER");
                f.Catalog.Response = f.Catalog.Response with {
                    Status = "AUTH_REQUIRED", Items = []
                };
                f.Key.Allow = true;
            }, true, "LICENSE_KEY");

        await Case("LICENSE_KEY never accepts an account entitlement/JWS",
            f => { f.SetMode("LICENSE_KEY"); f.Account.Allow = true; },
            false, inspect: f => {
                Must(f.Account.Calls == 0 && f.Key.Calls == 1,
                    "key-only accepted account credential");
            });

        await Case("ACCOUNT never borrows a commercial signed key",
            f => { f.SetMode("ACCOUNT"); f.Key.Allow = true; },
            false, inspect: f => Must(f.Key.Calls == 0,
                "account-only attempted key fallback"));

        await Case("ACCOUNT unavailable JWS fails closed",
            f => f.Mode.Mode = "ACCOUNT", false);
        await Case("unknown mode never becomes EITHER",
            f => { f.SetMode("UNKNOWN"); f.Key.Allow = true; f.Account.Allow = true; },
            false, inspect: f => Must(f.Key.Calls == 0 && f.Account.Calls == 0,
                "unknown mode reached credentials"));
        await Case("missing mode never becomes EITHER",
            f => { f.Mode.PolicyMissing = true; f.Key.Allow = true; }, false);
        await Case("policy wrong product denies",
            f => { f.Mode.PolicyProduct = "another-product"; f.Key.Allow = true; },
            false);
        await Case("policy wrong version denies",
            f => { f.Mode.PolicyVersion = "9.9.9"; f.Key.Allow = true; }, false);
        await Case("unsigned/unavailable registry denies",
            f => { f.Registry.Missing = true; f.Key.Allow = true; }, false);
        await Case("untrusted image SHA denies",
            f => { f.Registry.ExpectedHash = new string('b', 64); f.Key.Allow = true; },
            false);
        await Case("wrong Windows user SID denies",
            f => { f.Registry.ExpectedSid = "S-1-5-21-888"; f.Key.Allow = true; },
            false);
        await Case("invalid installation identity denies",
            f => { f.Registry.InstallationId = "product-asserted-id"; f.Key.Allow = true; },
            false);
        await Case("unknown OS process identity denies",
            f => { f.Peer.Evidence = f.Peer.Evidence with {
                WindowsKernelObserved = false
            }; f.Key.Allow = true; }, false);
        await Case("missing process ID denies",
            f => { f.Peer.Evidence = f.Peer.Evidence with {
                ProcessId = 0
            }; f.Key.Allow = true; }, false);
        await Case("old process cannot replay startup admission",
            f => { f.Peer.Evidence = f.Peer.Evidence with {
                StartedUtcTicks = DateTime.UtcNow.AddMinutes(-5).Ticks
            }; f.Key.Allow = true; }, false);
        await Case("stale peer observation denies",
            f => { f.Peer.Evidence = f.Peer.Evidence with {
                ObservedAt = DateTimeOffset.UtcNow.AddMinutes(-5)
            }; f.Key.Allow = true; }, false);
        await Case("peer substitution after signing denies",
            f => { f.SetMode("ACCOUNT"); f.Account.Allow = true; f.Peer.Live = false; },
            false, inspect: f => Must(f.Audit.Calls == 0,
                "changed process reached audit"));
        await Case("audit failure blocks key credential",
            f => { f.SetMode("LICENSE_KEY"); f.Key.Allow = true; f.Audit.Allow = false; },
            false);
        await Case("audit failure blocks account credential",
            f => { f.SetMode("ACCOUNT"); f.Account.Allow = true; f.Audit.Allow = false; },
            false);
        await Case("catalog entitlement false denies ACCOUNT despite JWS",
            f => {
                f.SetMode("ACCOUNT"); f.Account.Allow = true;
                f.Catalog.Response = Fixture.Ready(f.Catalog.Response.Items[0] with {
                    Entitled = false, State = "INSTALLED_NOT_ENTITLED"
                });
            }, false, inspect: f => Must(f.Account.Calls == 0,
                "unentitled account reached signer"));
        await Case("catalog version mismatch denies ACCOUNT",
            f => {
                f.SetMode("ACCOUNT"); f.Account.Allow = true;
                f.Catalog.Response = Fixture.Ready(f.Catalog.Response.Items[0] with {
                    InstalledVersion = "1.0.2"
                });
            }, false);
        await Case("catalog activation-mode mismatch denies ACCOUNT",
            f => {
                f.SetMode("ACCOUNT"); f.Account.Allow = true;
                f.Catalog.Response = Fixture.Ready(f.Catalog.Response.Items[0] with {
                    ActivationMode = "LICENSE_KEY"
                });
            }, false);
        await Case("duplicate catalog identity denies",
            f => {
                f.SetMode("ACCOUNT"); f.Account.Allow = true;
                f.Catalog.Response = f.Catalog.Response with {
                    Items = [f.Catalog.Response.Items[0], f.Catalog.Response.Items[0]]
                };
            }, false);
        await Case("plugin execution never grants standalone startup",
            f => {
                f.SetMode("ACCOUNT"); f.Account.Allow = true;
                f.Catalog.Response = Fixture.Ready(f.Catalog.Response.Items[0] with {
                    ExecutionType = "LAUNCHER_PLUGIN"
                });
            }, false);
        await Case("commercial signature/lease denial fails closed",
            f => f.Mode.Mode = "LICENSE_KEY", false);
        await Case("Agent commercial authority exception fails closed",
            f => { f.SetMode("LICENSE_KEY"); f.Key.Throw = true; }, false);
        await Case("Agent account authority exception fails closed",
            f => { f.SetMode("ACCOUNT"); f.Account.Throw = true; }, false);
        await Case("trusted mode authority exception fails closed",
            f => { f.Mode.Throw = true; f.Key.Allow = true; }, false);
        await Case("production environment cannot start the new gate",
            f => { f.Environment = "production"; f.Key.Allow = true; },
            false, inspect: f => Must(f.Peer.Calls == 0,
                "production inspected a peer"));
        await Case("unapproved environment cannot start the gate",
            f => { f.Environment = "staging"; f.Key.Allow = true; },
            false, inspect: f => Must(f.Peer.Calls == 0,
                "unapproved env inspected a peer"));

        var replay = new Fixture();
        replay.SetMode("LICENSE_KEY");
        replay.Key.Allow = true;
        var service = replay.Service();
        var one = await service.AuthorizeConnectedPeerAsync(CancellationToken.None);
        var two = await service.AuthorizeConnectedPeerAsync(CancellationToken.None);
        Must(one.Authorized && !two.Authorized &&
            two.Reason == "startup_replay" && replay.Audit.Calls == 1,
            "kernel process admission replay");
        passed++;
        Console.WriteLine("PASS standalone startup: same process cannot redeem twice");

        var host = File.ReadAllText(Path.Combine(
            "dotnet", "src", "BKE.LicensingAgent.Host", "Program.cs"));
        Must(!host.Contains("StandaloneStartupAuthorizationService",
                StringComparison.Ordinal) &&
            !host.Contains("WindowsNamedPipeStandaloneStartupPeerAttestor",
                StringComparison.Ordinal),
            "unproven production Host startup grant exposed");
        passed++;
        Console.WriteLine("PASS standalone startup: no incomplete Host grant endpoint");

        if (passed != 35)
            throw new InvalidOperationException(
                $"Incomplete standalone startup matrix: {passed}/35.");
        Console.WriteLine($"Standalone startup authority certification: {passed}/35 PASS");
    }

    private static void Must(bool condition, string text)
    {
        if (!condition) throw new InvalidOperationException("FAIL: " + text);
    }

    private sealed class Fixture
    {
        internal readonly FakePeer Peer = new();
        internal readonly FakeRegistry Registry = new();
        internal readonly FakePolicy Mode = new();
        internal readonly FakeCatalog Catalog = new();
        internal readonly FakeAccount Account = new();
        internal readonly FakeKey Key = new();
        internal readonly FakeAudit Audit = new();
        internal string Environment = "certification";

        internal void SetMode(string mode)
        {
            Mode.Mode = mode;
            Catalog.Response = Catalog.Response with {
                Items = Catalog.Response.Items.Select(item => item with {
                    ActivationMode = mode
                }).ToArray()
            };
        }

        internal StandaloneStartupAuthorizationService Service() => new(
            Peer, Registry, Mode, Catalog, Key, Account, Audit, Environment);

        internal static SoftwareCatalogResponse Ready(SoftwareCatalogItem item) =>
            new(LocalAgentContract.SoftwareCatalogCapabilityId,
                LocalAgentContract.SoftwareCatalogContractVersion,
                "READY", [item], null);
    }

    private sealed class FakePeer : IStandaloneStartupPeerAttestor
    {
        internal StandaloneStartupProcessEvidence Evidence = new(
            4501, DateTime.UtcNow.AddSeconds(-2).Ticks,
            @"C:\Program Files\BKE Digital Solutions\Render Dock\RENDER DOCK.exe",
            new string('a', 64), "S-1-5-21-777",
            DateTimeOffset.UtcNow, WindowsKernelObserved: true);
        internal bool Live = true;
        internal int Calls;
        internal int RecheckCalls;

        public Task<StandaloneStartupProcessEvidence?> ObserveConnectedPeerAsync(
            CancellationToken ct)
        {
            Calls++;
            return Task.FromResult<StandaloneStartupProcessEvidence?>(Evidence);
        }

        public Task<bool> IsSameLivePeerAsync(
            StandaloneStartupProcessEvidence original, CancellationToken ct)
        {
            RecheckCalls++;
            return Task.FromResult(Live &&
                original.ProcessId == Evidence.ProcessId &&
                original.StartedUtcTicks == Evidence.StartedUtcTicks);
        }
    }

    private sealed class FakeRegistry : ITrustedStandaloneStartupRegistry
    {
        internal bool Missing;
        internal string ExpectedHash = new string('a', 64);
        internal string ExpectedSid = "S-1-5-21-777";
        internal string InstallationId = "00000000-0000-0000-0000-000000000001";

        public Task<TrustedStandaloneStartupInstallation?> ResolveVerifiedAsync(
            StandaloneStartupProcessEvidence peer, CancellationToken ct) =>
            Task.FromResult<TrustedStandaloneStartupInstallation?>(
                Missing ? null : new(
                    "bke-render-dock", "1.0.3", InstallationId,
                    peer.ImagePath, ExpectedHash, ExpectedSid));
    }

    private sealed class FakePolicy : ITrustedStandaloneStartupPolicySource
    {
        internal string Mode = "EITHER";
        internal string PolicyProduct = "bke-render-dock";
        internal string PolicyVersion = "1.0.3";
        internal bool PolicyMissing;
        internal bool Throw;

        public Task<TrustedStandaloneStartupPolicy?> ReadVerifiedAsync(
            string productId, string version, CancellationToken ct)
        {
            if (Throw) throw new InvalidDataException("untrusted policy");
            return Task.FromResult<TrustedStandaloneStartupPolicy?>(
                PolicyMissing ? null : new(PolicyProduct, PolicyVersion, Mode));
        }
    }

    private sealed class FakeCatalog : ISoftwareCatalogService
    {
        internal int Calls;
        internal SoftwareCatalogResponse Response = Fixture.Ready(new(
            "bke-render-dock", "Render Dock", "Video output", "STANDALONE",
            true, true, "INSTALLED", "1.0.3", "1.0.3", "EITHER"));
        public Task<SoftwareCatalogResponse> GetAsync(
            SoftwareCatalogRequest request, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(Response);
        }
    }

    private sealed class FakeAccount : IAccountProductOpenLeaseGate
    {
        internal bool Allow;
        internal bool Throw;
        internal int Calls;
        public Task<bool> VerifyFreshOpenAsync(
            string productId, CancellationToken ct)
        {
            Calls++;
            if (Throw) throw new InvalidOperationException("offline JWS signer");
            return Task.FromResult(Allow);
        }
    }

    private sealed class FakeKey : IAuthorizationService
    {
        internal bool Allow;
        internal bool Throw;
        internal int Calls;
        public Task<AuthorizationResponse> AuthorizeAsync(
            AuthorizeRequest request, CancellationToken ct)
        {
            Calls++;
            if (Throw) throw new InvalidOperationException("invalid lease");
            return Task.FromResult(new AuthorizationResponse(
                Allow, Allow ? "authorized" : "unverifiable_signed_lease"));
        }
    }

    private sealed class FakeAudit : IStandaloneStartupAudit
    {
        internal bool Allow = true;
        internal int Calls;
        public Task<bool> CommitGrantAsync(
            TrustedStandaloneStartupInstallation installation,
            StandaloneStartupProcessEvidence peer,
            string credential, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(Allow);
        }
    }
}
