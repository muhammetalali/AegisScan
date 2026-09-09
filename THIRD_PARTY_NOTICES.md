# Third-Party Notices

## HexStrike AI

AegisScan includes a pinned upstream source integration of HexStrike AI for authorized security-validation capability discovery and adaptation.

- Upstream repository: `https://github.com/0x4m4/hexstrike-ai.git`
- Upstream ref: `master`
- Pinned commit: `d689933ff579d839c676c82b231f8e98326c5f04`
- Integrated path: `third_party/hexstrike-ai`
- License: MIT License
- Upstream copyright: Copyright (c) 2026 Muhammad Osama (0x4m4) <contact@0x4m4.com>

The complete upstream license text remains available at `third_party/hexstrike-ai/LICENSE` when the pinned submodule is initialized. AegisScan-specific orchestration, authorization, evidence, governance, adapters, contracts and user experience remain implemented in the AegisScan codebase rather than modifying the upstream trust boundary.

The upstream source is pinned by Git object identity. Updating it requires changing the gitlink commit and passing the HexStrike Native Integration contract gate.
