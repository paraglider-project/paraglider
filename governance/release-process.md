# Release Management

[Release manager(s)](roles.md) of stable releases are
responsible for approving and merging backports, tagging stable releases, and
sending announcements about them.

# Release Process
This section describes the release processes for tracking, preparing, and
creating new Paraglider releases. This includes information around the release cycles
and guides for developers responsible for preparing upcoming stable releases.

## Active Development

Active development is happening on the `main` branch and the target is to
release a new version approximately every 6 months.

## Release Tracking

Feature work for upcoming releases is tracked through
[GitHub Issues](https://github.com/paraglider-project/paraglider/issues).

## Steps to Create a New Release (TODO: Review this more closely)
1. Bump the version number ([Semantic Versioning 2.0](https://semver.org/))
  for the following files:
  * [version.mk](../build/version.mk)
2. Create a new pull request for the version number changes.
3. Ensure that the artifacts are built and all checks pass.
4. Merge the PR upon successful review.
5. Clone the repo, and add a tag to the commit with the version number changes
  (e.g., "git tag v1.0.0", "git push --tags")
6. This will initiate a release.
7. Navigate to "Releases" to view the release.
8. Edit the "Release title" and click on "Generate release notes" button to pull
  in all the PR changes since the last tagged release
9. All binaries/artefacts should already be attached to the release.
10. Click the "Publish release" button to post the
  release

## Stable Releases

Stable releases of Paraglider include:

* Maintenance window (any version released in the last 6 to 12 months).
* Stability fixes backported from the `main` branch (anything that can result in
  a crash).
* Bug fixes deemed worthwhile by the maintainers.

## Backports

The process of backporting can consist of the following steps:

- Changes nominated by the change author and/or members of the Paraglider community
  are evaluated for backporting on a case-by-case basis
- These changes require approval from both the release manager of the stable
  release and from the relevant code owners.
- Once approved, these fixes can be backported from the `main` branch to an
  existing or previous stable branch by the branch's release manager.
