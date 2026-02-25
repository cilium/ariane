# Ariane

GitHub App for triggering workflows based on trigger phrases found in PR comments, and marking desired workflows successful in merge groups, to be used for Cilium CI.

## How does it work

### Issue Comments

A GitHub App watches comments on pull requests for specific trigger phrases, and manually runs workflows using `workflow_dispatch` events. If configured only allowed team members can trigger the tests. If there are no new changes, no new commit, no force push, issue comment trigger phrases only re-run failed tests.
The triggers themselves, which workflow to run and allowed teams are configured in the repository via `.github/ariane-config.yaml` (basic example available [here](./example/ariane-config.yaml)).

### Pull Request

Pull request handler works similarly to Issue Comments handler, but automatically triggers workflows that have `/default` set as their trigger phrase when a new PR is opened, reopened, synchronized or marked as ready for review. This allows to automatically run a set of default tests on every PR without requiring manual intervention while being able to control workflow execution via ariane instead of relying on GHA triggers.

### Merge Group

A GitHub App watches `merge_group` events. When a PR is added to the merge queue the app gets all the required checks for the target branch, and marks the status of the required check as completed with success if its check source is configured as `any source`.

### Workflow Run

A GitHub App watches `workflow_run` events and handles them based on the workflow conclusion. **Note**: This handler only processes PRs created by bot users with username prefix matching the repository organization name and suffix `[bot]` (e.g., for organization `isovalent`: `isovalent-renovate[bot]`, `isovalent-release[bot]`).

1. **Success (Staged Runner)**: When a workflow run completes successfully, the app checks if the workflow is configured in the repository via `.github/ariane-config.yaml` (basic example available [here](./example/ariane-config.yaml)). If the workflow is configured in the stages section, the app runs the configured command on the PR to trigger the next stage.

2. **Failure (Rerun Failed Jobs)**: When a workflow run completes with a failure, the app can automatically re-run only the failed jobs. The app tracks the run attempt number and will only rerun up to the configured maximum. This helps recover from transient failures without re-running successful jobs, while preventing infinite retry loops.

   **Configuration**: Add the `rerun-failed:N` label to your PR (where N is 1-9) to enable automatic reruns. Optionally configure limits in `.github/ariane-config.yaml`:
   ```yaml
   rerun:
     max-retries: 3  # Optional: enforce upper limit on label values
     workflows:      # Optional: limit to specific workflows
       - conformance-e2e.yaml
       - integration-test.yaml
   ```

   **Configuration Priority**:
   - If config `max-retries` exists: enforces upper limit (uses minimum of label and config)
   - If `workflows` list is empty or omitted, no workflows are eligible for reruns

### Deployments

Below table describes the triggers and the environment where this tool is deployed.

| Trigger | Environment | Service | GCP Project | Artifact Registry | Github Repository |
| ------- | ----------- | ------- | ----------- | ----------------- | ------------------- |
| `workflow_dispatch` | `isovalent` | `default` | `isovalent-pr` | `gcr.io/isovalent-pr/ariane` | `isovalent/cilium` |
| `push` | `staging` | `staging` | `isovalent-dev` | `gcr.io/isovalent-dev/ariane` | `NA` |
| `pull_request` | `testing` | `staging` | `isovalent-dev` | `gcr.io/isovalent-dev/ariane` | `NA` |


Github workflow builds a docker image and pushes it to Google Artifact Registry (repo-path) is listed in the table above.

## Local development

### One-time setup

- Copy `server-config.yaml.tmpl` to `server-config.yaml` and adjust `address` / `port` to your liking.
- Register a personal GitHub App at https://github.com/settings/apps, which you'll use for development.
- Fill-in `github.app` properties in `server-config.yaml`:
  - `integration_id`: the GitHub App ID
  - `webhook_secret`: a webhook secret of your choice (needs to be set up on the GitHub App).
  - `private_key`: a private key generated from the GitHub App.
- Set up permissions & events for the GitHub App:
  - Repository permissions:
    - Actions: Read and write
    - Administration: Read-only
    - Checks: Read and write
    - Commit statuses: Read and write
    - Contents: Read-only
    - Issues: Read-only
    - Merge queues: Read-only
    - Pull requests: Read and write
  - Organization permissions:
    - Members: Read-only
  - Subscribe to events:
    - Issue comment
    - Merge group
- Install the app to your account and give it access to your test repository (e.g. your fork of Cilium).

### Testing

- Make sure to expose the config's `address` / `port` to the internet (e.g. `ngrok http 8080`).
- Make sure the GitHub App webhook points to `/api/github/hook` on your exposed host (e.g. `https://{ngrok_forward_host}/api/github/hook`).
- Run the app: `go run .`
- In order to register a GitHub workflow, you might need to add `pull_request: {}` to it. This makes the workflow accessible to Ariane. Later on, you can remove the condition, so that it can be started by a trigger phrase.
- Try to comment something in a PR targeting your repository :)

## Production

One instances of the GitHub App is deployed on GCP via App Engine, in order to supervise the main repository `cilium/cilium`.
To update the instances, run the release workflow in GitHub Actions.
