# Release checklist

How a RemotePower release gets from the test branch to production. Work top to
bottom — later steps assume the earlier ones passed.

Two branches, both called `main`: one on the test remote, one on production.
All development lands on test. A release is a signed tag on `main`, and
production is promoted by fast-forwarding it to that tag. There are no release
branches.

---

## 1. Before you begin

- [ ] Every item you meant to ship is merged and the working tree is clean.
- [ ] `git log` on test contains the production commit — production must be an
      ancestor, or the fast-forward promotion will not work:
      `git merge-base --is-ancestor <prod>/main origin/main`
- [ ] No open pull requests you wanted in this release, on **either** remote.
      Land community and dependency PRs on test first. Merging one straight to
      production while test is ahead splits the two branches apart.
- [ ] You know the version number and the codename before you start editing.

## 2. Bump the version

Eleven places, and the build checks most of them for you.

- [ ] `SERVER_VERSION` in the API.
- [ ] `VERSION` in all three agents — Linux, Windows, macOS.
- [ ] Copy the Linux agent to its extensionless twin so the two match.
- [ ] `CACHE_NAME` in the service worker.
- [ ] Every `?v=` in the served HTML pages. There are six such pages, not one.
      A stale marker on any of them pins returning browsers to old assets,
      because static files are cached for a year.
- [ ] The version badge in `README.md`.

`CACHE_NAME` and every `?v=` must carry the same value. A test enforces this,
and it also applies mid-cycle: change any client asset and the marker moves,
even when the version number does not.

## 3. Write it down

- [ ] New entry at the top of `CHANGELOG.md`.
- [ ] New `docs/<version>.md`, and delete anything older than the last three.
      Removing a version doc has knock-on effects: the in-app "What's new"
      card links to it and `docs/README.md` indexes it, so trim both in the
      same commit, then search the repo for links that now point nowhere.
- [ ] Trim the "Recent releases" list in `README.md` to five.
- [ ] Update the in-app Documentation page, including its "What's new" card.
      The card carries a hidden list of search keywords — update those too, or
      searching for the new codename will not find the card.
- [ ] Add a new test file pinning this version, and relax the previous one's
      exact pins to patterns.
- [ ] Read the version doc and the "What's new" card against the changelog.
      Both are written when the version opens and headline features land after,
      so they go stale inside a single cycle.

## 4. Check the whole product, not just the diff

Run these across the project, not only over recent commits.

- [ ] **Every signal an agent collects lands somewhere a person can see it** —
      the device drawer, the pages, search, alerts, reports, the AI context.
      A signal that is collected and displayed nowhere is the most common gap.
- [ ] **Security review.** Nothing critical, high or medium ships, and nothing
      exploitable at any severity. Pay attention to tenant boundaries: an
      administrator of one customer passes an administrator check, so a gate
      that only asks "are you an admin?" lets them through. Publish a public
      write-up of the pass under `docs/`.
- [ ] **Bug hunt with the tools, not by reading.** Static analysis, the
      structural test gates, property tests, and a browser walk of the running
      product. Reading source answers a different question from measuring the
      thing an operator sees.
- [ ] **Click the seeded demo instance.** Walk every page, open every dialog,
      and record failed network calls as well as console errors. A page whose
      data call fails still renders its shell, so "the page loads" is not the
      same as "the page works".
- [ ] **Layout.** Every list or table with a variable number of rows caps its
      height and scrolls. One heading size, one body size. Icon-to-label gaps
      and button padding match across the app.
- [ ] **Translations.** New interface text exists in all supported languages.
      Text the server sends, rather than markup, is invisible to the
      translation checks — audit those by hand.
- [ ] **Documentation matches the code as it is now.** Check the numbers you
      quote by measuring them; counts drift every cycle and are almost always
      understated. Remove anything describing a limitation you have since
      fixed. Give every non-obvious page and settings section a link to its
      guide, and write the guide if it is missing.
- [ ] **The demo seeder fills every current feature**, with the right version.
      The visual and accessibility checks all measure the seeded instance, so a
      seeder that misses a feature hides it from every one of them.
- [ ] **Vendored components are current.**

## 5. The gate

- [ ] `make pre-release`

One command, and it is the bar for production. It runs the full suite on both
default storage backends, then the third one, then the same suite again against
the packaged release tree, then a build matching the continuous-integration
environment, then static analysis and the code-scanning pass that production
runs. On success it records the commit it checked.

Points worth knowing:

- Run it **once, at the end**, when nothing is left on your list. It takes a
  while, and a run you have to abandon buys nothing.
- The tree must be clean. Editing during a run makes the results untrustworthy
  and the commit record is skipped.
- Read the real verdict line in the output. A wrapper can exit successfully
  while the suite underneath it failed.
- A browser and a database server must be present. Where they are missing the
  affected checks fail rather than skipping, because a check that skips proves
  nothing.

## 6. Tag and publish

- [ ] Change the changelog heading from "unreleased" to the release date, and
      fix any earlier entry still marked unreleased. Do this **before** the
      tag so the tagged tree carries the right date.
- [ ] Create the signed tag. Signing needs a person at the keyboard; everything
      afterwards can run unattended for a while, so sign first and continue
      promptly.
- [ ] Push the tag to production **before** any fetch. A fetch can remove a
      local tag part-way through.
- [ ] Fast-forward production to the tagged commit, and keep test level with
      it.
- [ ] Build the release archive with its checksum and signature, and publish
      the release with all three files attached.
- [ ] Title the release `vX.Y.Z — "Codename"`, matching the changelog heading
      without its date. No product-name prefix, no colon.
- [ ] Keep the five most recent releases on both remotes and remove older
      release pages. Keep the tags — the promotion model and older checkouts
      depend on them.

Publishing the release starts the container image build on its own.

## 7. Packages and sites

- [ ] Update both distribution packages and confirm they went live by querying
      the package index, not by reading your own files. A push that fails
      quietly leaves the previous version in place while everything in the repo
      still looks correct.
- [ ] Refresh the marketing site: version badge, footer, the "New in" section,
      and screenshots. Leave the logo and icon files untouched.
- [ ] Regenerate the wiki from `docs/`. The generator version-stamps the home
      page and sidebar, but the topic list in the sidebar is hand-curated — a
      new guide appears as a page and stays invisible in the navigation until
      you add it. The generator prints which pages are unlinked; act on that
      list.
- [ ] Update the codename where the wiki generator hard-codes it.

## 8. After it ships

- [ ] Continuous integration is green on the release commit.
- [ ] The published archive contains nothing private: no planning notes,
      internal runbooks, deployment configuration, editor or agent settings,
      credentials, or version-control metadata. The archive packs the working
      tree, so files ignored by version control still ship unless the build
      excludes them by name.
- [ ] Container images are published and public.
- [ ] The site and wiki serve the new version.
- [ ] Triage new code-scanning alerts. Dismiss the reviewed false-positive
      classes with a reason, and record the triage.

---

## If something fails

Fix the cause and run the gate again. Two habits save the most time:

**A failure in an unrelated-looking place is usually real.** A formatting
complaint can stop the gate before it reaches the checks that matter, so one
cosmetic failure can hide a serious one for days.

**Trust the measurement over the reasoning.** When a check disagrees with your
reading of the code, measure the running product before deciding the check is
wrong. It usually is not.

---

← [Back to docs index](README.md)
