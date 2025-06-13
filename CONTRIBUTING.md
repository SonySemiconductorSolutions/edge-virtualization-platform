<!--
SPDX-FileCopyrightText: 2025 Sony Semiconductor Solutions Corporation

SPDX-License-Identifier: Apache-2.0
-->

# Contributing Guidelines

We gratefully accept contributions from the community. Please take a moment to review this document, our [Code of Conduct](CODE_OF_CONDUCT.md), and our [Privacy Policy](PrivacyPolicy.md) in order to make the contribution process efficient and pleasant for everyone involved.

## Bug Reports

If you think you have found a bug, first make sure that you are testing against the latest version, in case your issue has already been fixed. Search our issues list on GitHub to see if a similar or related problem has already been reported.

When creating a new issue, or updating an existing one, please provide as much contextual information as you can. What environment, device and OS do you use? What is your build configuration? With what version of dependencies and with which compiler and toolchain did you build?

In addition it will be very helpful if you can provide a unit test, system test, or step by step instructions to reproduce the bug. It makes it much easier to find the problem and fix it.

## Feature Requests

If you find yourself wishing for a feature that doesn't exist, you are probably not alone. There are bound to be others with similar needs. Open an issue on our issues list on GitHub, detailing:
- The feature you would like to see
- Why it is important
- How it should work
- How you will use it

## Security Vulnerabilities

> [!WARNING]
> Do not use public issues to report security vulnerabilities: contact us directly instead.

If you think that you have identified a security vulnerability in Edge Virtualization Platform(EVP), please send us your report with as much context as possible via [our contact form](https://support.aitrios.sony-semicon.com/hc/en-us/requests/new).

## Contributing Code, Tests, and Documentation

Send us your pull requests! For those just getting started, GitHub has a [how to](https://help.github.com/articles/using-pull-requests/).

In order to maintain proper traceability of contributions, we require that you agree to the four clauses of the [Developer's Certificate of Origin](https://developercertificate.org/). Particularly, commits should be signed off by their respective authors. This repository enforces this by means of the [DCO GitHub app](https://github.com/apps/dco).

### Submit a Pull Request (PR)

- Check for open issues or PRs related to your change.
- Before writing any code, consider creating a new issue for any major change and enhancement that you wish to make. It may be that somebody is already working on it, or that there are particular complexities that you should know about.
- Fork the repository on GitHub to start making your changes. As a general rule, you should use the "main" branch as a basis.
- Include unit tests when you contribute new features, as they help to prove that your code works correctly and guard against future breaking changes.
- Bug fixes also generally require unit tests, because the presence of bugs usually indicates insufficient test coverage.
- Keep API compatibility in mind when you change code in core functionality. Any non-backward-compatible public API changes, i.e. breaking changes to header files in the `edge-virtualization-platform/src/` folder, will require a major version increment.
- Include a license header at the top of all new files.
- Please avoid including unrelated commits and changes in your PR branch.
- Before submitting a PR, test locally. Run formatting checks and unit tests on your development machine. See [the build instructions](docs/README.md) for details.
- Send a PR and work with us until it is merged. Contributions may need some modifications, so a few rounds of review and fixing may be necessary.
- For quick merging, the contribution should be short, and concentrated on a single feature or topic. The larger the contribution is, the longer it takes to review and merge.
- Include as much context as possible: What problem does your PR solve, how does it solve it, and why is it important?

Our team members will review your PR, and once it is approved and passes continuous integration checks it will be ready to merge.

Bear in mind that when you contribute a new feature, the maintenance burden is transferred to the edge-virtualization-platform team. This means that the benefit of the contribution must be compared against the cost of maintaining the feature.

> [!WARNING]
> By submitting a PR, you agree to license your work under the same license as that used by the project.

## License and Copyright

Contributors accept that their contributions are made under the Apache-2.0 license. All new files should include the Apache-2.0 standard license header where possible. See the [LICENSE](LICENSE) file for the full text of this license.
