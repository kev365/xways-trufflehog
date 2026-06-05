# custom-detectors

Community-contributed TruffleHog YAML detector packs for forensic relevance — secrets that the upstream TruffleHog detectors miss because they're forensic-specific (credential-cache artifacts from specific apps, telecom session tokens recovered from MFT slack, vendor-specific token formats, etc.).

## How it works

TruffleHog's `--config=<file>` flag loads a YAML pattern pack **on top of** the ~800 built-in detectors. The xways-trufflehog X-Tension surfaces this as the optional cfg key `custom_config_path=`:

```ini
custom_config_path=C:\xways\xtensions\xways-trufflehog\custom-detectors\mypatterns.yml
```

The X-Tension extracts per-pattern names from the `ExtraData.name` field on each hit, so custom findings land in granular `trufflehog: custom:<name>` Report Tables instead of a single `CustomRegex` bucket.

Full YAML schema + worked examples: <https://docs.trufflesecurity.com/custom-detectors>.

## Quick start

1. Copy [`example.yml`](example.yml) to `mypatterns.yml`.
2. Edit the regex / keywords / `verify` block for your pattern.
3. Set `custom_config_path=<full path>` in your `xways-trufflehog.cfg`.
4. Run — hits appear under `trufflehog: custom:<your-pattern-name>` in the Report Tables.

## Contributing

PRs welcome — one YAML file per contribution under [`contributed/`](contributed/).

Conventions:

- **Filename:** `<author>-<name>.yml` (e.g. `kev365-windows-credman.yml`).
- **Attribution:** preserve a `# author: <github-handle>` comment at the top.
- **Test string:** include at least one positive test snippet in a comment block so reviewers can verify the regex without running on real data.
- **Forensic relevance:** pattern should be useful in incident-response / triage contexts — not just duplicating a built-in TruffleHog detector.
- **No live secrets:** use synthetic / clearly-fake values in test snippets. Real secrets get scrubbed by maintainers + the PR rejected.

Drive-by drops in [Discussions](https://github.com/kev365/xways-trufflehog/discussions) are welcome too — maintainers will package good ones into PRs.
