# systemd deployment for interceptor witnesses

`interceptor-witness.timer` (every 5 min) checkpoints the live journal and
ships the witness off-host. `interceptor-verify.timer` (every 15 min) verifies
the chain, checks every shipped witness stays covered, and audits for
`needs_reconciliation` / `failed` invocations. Any non-zero exit should page.

```sh
sudo cp deploy/systemd/interceptor-*.service deploy/systemd/interceptor-*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now interceptor-witness.timer interceptor-verify.timer
systemctl list-timers 'interceptor-*'
journalctl -u interceptor-witness.service -u interceptor-verify.service -f
```

Configure:

- `systemctl edit interceptor-witness.service` to set `INTERCEPTOR_JOURNAL`,
  `INTERCEPTOR_WITNESS_DIR`, and optionally `INTERCEPTOR_COUNTER_KEY`
  (`--counter-key` countersigns each witness with the external key).
- The witness dir must live where the journal cannot reach (separate mount,
  second host, WORM bucket). See `docs/DEPLOYMENT.md` for the S3 ObjectLock
  recipe and for pairing this with `WitnessFreshnessProvider`
  (`max_age_seconds` ≈ 2× the witness interval) so stale witnesses deny
  high-risk actions in-process instead of only paging afterwards.
- `OnFailure=` paging is yours: add `OnFailure=pager.service` to both
  `.service` units.
