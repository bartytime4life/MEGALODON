# Review-gate canary

This file exists only for a controlled repository-review gate canary.

It contains no runtime, dependency, workflow, data, policy, firewall, scheduler, service, release, or deployment change. The associated pull request must remain unmerged and be closed after the ruleset's missing-approval behavior has been read back.

The canary's purpose is to verify that a green, non-draft pull request with zero qualifying approvals is blocked specifically by the required independent-review rule.