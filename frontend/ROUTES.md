# Route Map

Source of truth: `src/routes.ts`.

| Path                                      | Page                                   |
|-------------------------------------------|----------------------------------------|
| `/`                                       | Dashboard (Metrics)                    |
| `/sbom`                                   | SBOM (TablePackages)                   |
| `/vulnerabilities`                        | Vulnerabilities                        |
| `/scans`                                  | Scans (ScanHistory)                    |
| `/review`                                 | Review                                 |
| `/ai-context`                             | AI Context                             |
| `/export`                                 | Export                                 |
| `/settings`                               | Settings (general)                     |
| `/settings/transfer`                      | Settings: Transfer Assessments         |
| `/settings/custom-export`                 | Settings: Custom reports & assets      |
| `/settings/projects/:projectId`           | Settings: project management           |
| `/settings/projects/:projectId/:variantId`| Settings: variant management           |
| `/settings/*` (unknown)                   | Not Found (404), also for unknown ids  |
| `*` (unknown)                             | Not Found (404) page                   |

Settings sub-paths are built and parsed by `SETTINGS_PATHS`,
`settingsProjectPath`, `settingsVariantPath` and `parseSettingsPath`;
project and variant ids are URI-encoded.

The dependency explorer opens in a popup from the SBOM table's **Dependency** column,
using the table's project/variant selection and comparison operations. It has no separate route.
