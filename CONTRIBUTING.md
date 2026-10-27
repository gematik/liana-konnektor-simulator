# Welcome to the gematik contributing guide <!-- omit in toc -->

Thank you for investing your time in contributing to LIANA!

Read our [Code of Conduct](./CODE_OF_CONDUCT.md) to keep our community approachable and respectable.

In this guide you will get an overview how you can contribute to this project by opening an issue, creating,
reviewing and merging a pull request.

## Reporting a security vulnerability

Please check [SECURITY.md](./SECURITY.md) for information on how to report a security vulnerability.

## New contributor guide

To get an overview of the project, read the [README](./README.md). The detailed manual (German) is in
[docs/handbuch.md](./docs/handbuch.md), the architecture in [docs/architektur.md](./docs/architektur.md).

## Getting started

### Issues

#### Create a new issue

If you spot a problem, search if an issue already exists.
If a related issue doesn't exist, you can open a new issue.

Behavior that differs from the gematik specifications is the most valuable kind of report. Please name the
specification, its version and the requirement (AFO) or section, and attach the request and response if you have
them.

#### Solve an issue

Scan through our existing issues to find one that interests you. If you find an issue to work on, you are
welcome to open a PR with a fix.

### Coding Style

gematik projects follow the [google style guide](https://github.com/google/styleguide) conventions. Please
follow them when working on your contributions.

### Build and tests

- Java 21 for LIANA itself, Java 17 for the client modules (`liana-contract`, `konnektor-client`,
  `liana-control-client`)
- `./mvnw verify` runs the unit tests, the kartos integration tests and the trace tests
- `./mvnw verify -Dnative` additionally builds and tests the native image (slow)
- Some tests run against traces and signatures recorded from connector vendor products. This data is not
  published, so these tests (JUnit tag `vendor-data`) are skipped automatically in a public checkout
- Java sources are formatted with [Google Java Format](https://github.com/google/google-java-format); the build
  checks the formatting (Spotless) and fails otherwise. `./mvnw spotless:apply` reformats all modules
- Every source file starts with the license header from [license.header.txt](./license.header.txt); the build
  fails otherwise. `./mvnw com.mycila:license-maven-plugin:format` adds it to new files
- `./mvnw -Powasp verify -DskipTests` runs the OWASP Dependency Check; it fails on critical findings. It needs an
  NVD API key (https://nvd.nist.gov/developers/request-an-api-key), passed with `-DnvdApiKey=…`
- New runtime dependencies of the client modules and of `liana-app` must use a license from the allowlist of the
  `license-maven-plugin` in [pom.xml](./pom.xml); the build fails otherwise

### Commit your update

Commit the changes once you are happy with them.

### Pull Request Process

- When you're finished with the changes, create a pull request, also known as a PR.
- To open a PR
  please [fork the repository](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request-from-a-fork).
  When you are making changes, it is recommended that you create
  a [new branch](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-and-deleting-branches-within-your-repository)
  for this purpose, based off of the main branch. After your changes are pushed back to your forked
  repository, you can then create a pull request from there.
- Don't forget to [link the PR to the issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue)
  if you are solving one.
- Update the [README.md](./README.md), the documentation and the [ReleaseNotes.md](./ReleaseNotes.md) with all
  details to document the changes made by this PR.
- Once you submit your PR, a project team member will review your proposal. We may ask questions or request
  additional information.
- We may ask for changes to be made before a PR can be merged, either
  using [suggested changes](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/incorporating-feedback-in-your-pull-request)
  or pull request comments. You can apply suggested changes directly through the UI. You can make any other
  changes in your fork, then commit them to your branch.
- As you update your PR and apply changes, mark each conversation
  as [resolved](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/commenting-on-a-pull-request#resolving-conversations).

### Your PR is merged!

Congratulations :tada::tada: The gematik team thanks you :sparkles:.

Once your PR is merged, your contributions will be publicly visible on the [gematik github page](https://github.com/gematik/).
