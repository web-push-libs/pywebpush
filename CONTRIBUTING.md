# Contribution Guidelines

Anyone is welcome to contribute to this project. Feel free to get in touch with
other community members on IRC, the mailing list or through issues here on
GitHub.

[See the README](/README.md) for contact information.

## Bug Reports

You can file issues here on GitHub. Please try to include as much information as
you can and under what conditions you saw the issue.

## Sending Pull Requests

Patches should be submitted as pull requests (PR).

Before submitting a PR:
- Your code must run and pass all the automated tests before you submit your PR
  for review. "Work in progress" pull requests are allowed to be submitted, but
  should be clearly labeled as such and should not be merged until all tests
  pass and the code has been reviewed. NOTE: LLM generated patches are
  NOT accepted. See LLM section below.
- Your patch should include new tests that cover your changes. It is
  your and your reviewer's responsibility to ensure your patch includes adequate tests.

When submitting a PR:
- **[Sign all your git commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#ssh-commit-verification)**.
  We cannot accept any PR that does not have all commits signed. This is a policy
  put in place by our Security Operations team and is enforced by our CI processes.
- You agree to license your code under the project's open source license
  ([MPL 2.0](/LICENSE)).
- Base your branch off the current `main`.
- Add both your code and new tests if relevant.
- Run the test suite to make sure your code passes linting and tests.
- Ensure your changes do not reduce code coverage of the test suite.
- Please do not include merge commits in pull requests; include only commits
  with the new relevant code.

## Code Review

This project is subject to the Mozilla [engineering practices and
quality
standards](https://developer.mozilla.org/en-US/docs/Mozilla/Developer_guide/Committing_Rules_and_Responsibilities).
Every patch must be peer reviewed.

## Git Commit Guidelines

We loosely follow the [Angular commit guidelines](https://github.com/angular/angular.js/blob/master/CONTRIBUTING.md#type)
of `<type>: <subject>` where `type` must be one of:

* **feat**: A new feature
* **fix**: A bug fix
* **bug**: alias for fix; A bug fix
* **docs**: Documentation only changes
* **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing
  semi-colons, etc)
* **refactor**: A code change that neither fixes a bug or adds a feature
* **perf**: A code change that improves performance
* **test**: Adding missing tests
* **chore**: Changes to the build process or auxiliary tools and libraries such as documentation
  generation
* **breaks**: Contains a **BREAKING_CHANGE** to the existing execution environment.

### Subject

The subject contains succinct description of the change:

* use the imperative, present tense: "change" not "changed" nor "changes"
* don't capitalize first letter
* no dot (.) at the end

### Body

In order to maintain a reference to the context of the commit, add
`Closes #<issue_number>` if it closes a related issue or `Issue #<issue_number>`
if it's a partial fix.

You can also write a detailed description of the commit: Just as in the
**subject**, use the imperative, present tense: "change" not "changed" nor
"changes" It should include the motivation for the change and contrast this with
previous behavior.

### Footer

The footer should contain any information about **Breaking Changes** and is also
the place to reference GitHub issues that this commit **Closes**.

### Example

A properly formatted commit message should look like:

```
feat: give the developers a delicious cookie

Properly formatted commit messages provide understandable history and
documentation. This patch will provide a delicious cookie when all tests have
passed and the commit message is properly formatted.

BREAKING CHANGE: This patch requires developer to lower expectations about
    what "delicious" and "cookie" may mean. Some sadness may result.

Closes #314, #975
```

## LLM generated content

United States copyright and case law has determined that [content
created by non-humans is not
copyrightable](https://www.congress.gov/crs_external_products/LSB/PDF/LSB10922/LSB10922.8.pdf).
This includes LLMs. If non-human generated code is introduced and not
very explicitly noted, there is unsettled case law indicating that the
entire work may not qualify as copyrightable.

While you are certainly free to take the output of what an LLM may
generate and modify it (significantly) in order to take full, personal
ownership of the patch, you must be able to explain and detail the
changes, answer questions about the impact, and be knowledgeable about
the method of this codes production. I will, in good faith, accept
that your patch is human created and verified and that you will affix
your profile identity to this change. You acknowledge that if, at any
point, your code is determined to have been geneated by non-human
mechanisms, your submission will be immediately removed and your
contributions with be exised as soon as possible solely at the
discression of the main author of this repo.

