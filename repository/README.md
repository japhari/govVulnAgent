# Vulnerable Test Repositories

This folder contains intentionally vulnerable mini-repositories for local testing of `GovVulnAgent`.

## Repositories

- `vuln-node-api` (JavaScript / Express style patterns)
- `vuln-java-spring` (Java / Spring MVC style patterns)
- `vuln-ts-service` (TypeScript / Nest-like patterns)

## Scan examples

From `govVulnAgent` root:

```bash
# Scan all vulnerable repos
python cli.py scan ./repository

# Scan one repo
python cli.py scan ./repository/vuln-node-api
python cli.py scan ./repository/vuln-java-spring
python cli.py scan ./repository/vuln-ts-service
```

These projects are not for production use.
