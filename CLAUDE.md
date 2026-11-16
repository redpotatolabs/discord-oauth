# discord-oauth

Discord OAuth for the Red Potato Labs sites: the authorize URL, the code
exchange, token refresh, and reading the signed-in user, their servers and
their roles in one server. gohttp-scaffold's `auth` package builds on it.

## Branches and CI

This is a public library and deploys nothing, so there is no `test` branch and
no test site. Work goes on a branch from `main` straight to a pull request.
`main` only takes squash-merged pull requests whose `checks` job passes.

`checks` (`.github/workflows/ci.yml`) runs on a GitHub-hosted runner with a
read-only token and no secrets, because pull requests from forks run it. Never
move it to the self-hosted runners, add secrets, or switch it to
`pull_request_target`.

## Always verify locally

Before pushing, run `go vet ./...` and `go test -race ./...` and report what they
said. gohttp-scaffold, the schedule and the apps on the scaffold pin this
module, so check they still build against a change before they update.

## Linear

Project Productionize. Org-wide work, so tickets carry only an Initiative label.
Name a ticket in a pull request title only when the PR finishes it: merging
closes every ticket named there.
