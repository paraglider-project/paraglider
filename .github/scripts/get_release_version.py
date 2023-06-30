# This script parses release version from Git references and set the parsed version to
# environment variables, REL_VERSION and REL_CHANNEL.

# We set the environment variable REL_CHANNEL based on the kind of build. This is used for
# versioning of our assets.
#
# REL_CHANNEL is:
# 'latest': for most builds
# 'latest': for PR builds
# '1.0.0-rc1' (the full version): for a tagged prerelease
# '1.0' (major.minor): for a tagged release

# You can test this script manually by setting some environment variables and running it:
#  touch env.txt summary.txt
#  export GITHUB_ENV="$(pwd)/env.txt"
#  export GITHUB_STEP_SUMMARY="$(pwd)/summary.txt"
#  export GITHUB_REF=<the value you want to test>
#
# Example pre-release tag:
#  export GITHUB_REF=refs/tags/v1.0.0-rc1
# Example release tag:
#  export GITHUB_REF=refs/tags/v1.0.0
# Example pull-request:
#  export GITHUB_REF=refs/pull/42/head
#
# Running the script will write the environment variables to env.txt and the summary to summary.txt

from enum import Enum
import os
import re

class BuildType(Enum):
    UNKNOWN = 1
    PULL_REQUEST = 2
    NORMAL = 3
    PRERELEASE = 4
    RELEASE = 5

# From https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
# Group 'version' returns the whole version other named groups return the components:
# major, minor, patch, prerelease, buildmetadata
tag_ref_regex = r"^refs/tags/v(?P<version>0|(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)$"
pull_ref_regex = r"^refs/pull/(.*)/(.*)$"

github_ref = os.getenv("GITHUB_REF")

def decide_versions() -> tuple[BuildType, str, str]: 
    if github_ref is None:
        return (BuildType.UNKNOWN, "latest", "latest")
    
    match = re.search(pull_ref_regex, github_ref)
    if match is not None:
        return (BuildType.PULL_REQUEST, "pr-{}".format(match.group(1)), "latest")

    match = re.search(tag_ref_regex, github_ref)
    if match is not None and match.group("prerelease") is not None:
        return (BuildType.PRERELEASE, match.group("version"), match.group("version"))
    elif match is not None:
        return (BuildType.RELEASE, match.group("version"), "{}.{}".format(match.group("major"), match.group("minor")))

    # We end up here for a build of any other branch (eg: a build of main).
    return (BuildType.NORMAL, "latest", "latest")

build_type, version, channel = decide_versions()
with open(os.getenv("GITHUB_ENV"), "a") as github_env, open(os.getenv("GITHUB_STEP_SUMMARY"), "a") as github_step_summary:
    # Set environment variables for the build to use
    github_env.write("REL_VERSION={}\n".format(version))
    github_env.write("REL_CHANNEL={}\n".format(channel))

    summary = """This is a {} build based on ref '{}'. Setting:

    - REL_VERSION={}
    - REL_CHANNEL={}""".format(build_type, github_ref, version, channel)

    # Print description for debugging
    print(summary)
    github_step_summary.write(summary)