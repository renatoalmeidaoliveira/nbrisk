# CLAUDE.md

This file provides guidance to Claude (claude.ai) and other AI assistants when working with code in this repository.

## Project

`nbrisk` is a [NetBox](https://github.com/netbox-community/netbox) plugin that implements NIST 800-30 Risk Management. It provides Threat Sources, Threat Events, Vulnerabilities, Vulnerability Assignments, Risks, and Controls. It also includes CVE enrichment via NVD, CISA KEV, and EPSS, plus a Device CVE tab that queries NVD using verified CPE Mappings.

The plugin is distributed as a GitHub-installable package and installs as a Django app named `nb_risk`. The NetBox ↔ plugin version pairing is strict (declared in `nb_risk/__init__.py` via `min_version`/`max_version` and summarised in `COMPATIBILITY.md`). The current branch (`main`) targets NetBox 4.5.x. Changing the NetBox version range almost always requires migration and import changes.

## Development Workflow

The `develop/` directory contains a full Docker Compose stack (NetBox + worker + Postgres + Redis). The plugin source is bind-mounted, so edits take effect after a container restart. The `Makefile` wraps everything — prefer it over raw `docker compose`.

Common commands:

- `make cbuild` — build the dev image
- `make debug` / `make start` / `make stop` — foreground / detached / stop
- `make destroy` — stop the stack and drop the Postgres volume
- `make migrations` — generate Django migrations after `models.py` changes
- `make test` — run the test suite
- `make nbshell` — open a NetBox shell
- `make adduser` — create a superuser

The version string lives in one place: `nb_risk/version.py`.

## Architecture

Standard NetBox plugin. `nb_risk/__init__.py` exposes a `PluginConfig` subclass. All models inherit from `netbox.models.NetBoxModel`.

### Key modules

| Module | Purpose |
|---|---|
| `models.py` | All data models |
| `views.py` | Generic CRUD views using `netbox.views.generic` |
| `forms.py` | Edit, filter, and import forms |
| `filtersets.py` | django-filter FilterSets (UI + API) |
| `tables.py` | django-tables2 tables |
| `navigation.py` | Plugin menu definition |
| `urls.py` | URL patterns using `get_model_urls()` |
| `template_content.py` | PluginTemplateExtension for asset buttons |
| `cve.py` | NVD API integration, CPE building, Device CVE tab view |
| `kev.py` | CISA KEV catalog fetch, sync, and enrichment |
| `epss.py` | FIRST.org EPSS score fetch, sync, and enrichment |
| `cpe_lookup.py` | NVD CPE dictionary search view |
| `api/` | DRF serializers, viewsets, router |
| `management/commands/` | `sync_kev`, `sync_epss` management commands |
| `migrations/` | Django migrations — always generate via `make migrations` |

### Models overview

- **ThreatSource** — who/what poses a threat (capability, intent, targeting)
- **ThreatEvent** — what a threat source could do (linked to ThreatSource)
- **Vulnerability** — a CVE or custom vulnerability with CVSS, KEV, and EPSS fields
- **VulnerabilityAssignment** — links a Vulnerability to any supported asset (GFK)
- **Risk** — combines a ThreatEvent with likelihood/impact scores
- **Control** — mitigating action linked to Risks
- **CPEMapping** — maps a Platform or DeviceType to a verified NVD CPE 2.3 string

### CVE Enrichment Pipeline

NVD results flow through:
1. `cve._parse_cvss()` — extract CVSSv2/v3/v4 scores
2. `kev.enrich_cve_results()` — tag with CISA KEV status (Redis cached 6h)
3. `epss.enrich_cve_results()` — add EPSS scores (Redis cached 24h per CVE)

### Device CVE Tab

Registered via `@register_model_view(Device, name='device_cve')` with a `ViewTab`. Lookup order:

1. Check for `CPEMapping` records for the device's `device_type` (preferred) or `platform`
2. If found → build exact CPE strings using `mapping.build_cpe(version)`
3. If not found → fall back to heuristic `_build_device_cpes()` (normalized manufacturer + platform/model)
4. Run all CPE queries in parallel via `ThreadPoolExecutor`
5. Cache results in Redis for 6 hours

### CPE Mapping

`CPEMapping.build_cpe(version)` assembles: `cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:{target_sw}:*:*`

The `target_sw` field (8th component) scopes results to a platform family (e.g. `nexus_9000_series`).

## Coding Standards

- Follow existing patterns — all views use `netbox.views.generic`, all models inherit `NetBoxModel`
- Use `@register_model_view` for tabs, not `PluginTemplateExtension.tabs()`
- `PluginTemplateExtension` is for injecting buttons/content into existing templates only
- `PluginTemplateExtension.models` must be a list (not singular `model`) — required since NetBox 4.3
- All ViewSet querysets must have `.order_by()` — required since NetBox 4.3.5
- Import `ContentType` from `django.contrib.contenttypes.models`, not `core.models`
- Import `ObjectType` from `core.models` when needed for NetBox-aware GFK fields
- Use `GFKSerializerField` from `netbox.api.gfk_fields` for GFK API serialization
- Redis caching via `django.core.cache.cache` — never write to disk
- External API calls must always include a timeout parameter
- Parallel NVD queries use `concurrent.futures.ThreadPoolExecutor`

## Plugin Config Defaults

Defined in `nb_risk/__init__.py`:

| Key | Default | Description |
|---|---|---|
| `nvd_api_key` | `None` | NIST NVD API key (free, raises rate limit to 50 req/30s) |
| `supported_assets` | `[dcim.device, ...]` | Models that get the Assign Vulnerability button |
| `additional_assets` | `[]` | Extra models to support |
| `proxies` | `{}` | Deprecated — use `HTTP_PROXIES` in configuration.py |

## External APIs

| API | Auth | Rate Limit | Cache TTL |
|---|---|---|---|
| NVD CVE | Optional API key header | 5/30s (no key), 50/30s (with key) | 6 hours (per device) |
| NVD CPE | Optional API key header | Same as above | None |
| CISA KEV | None | None | 6 hours (set keyed) |
| FIRST.org EPSS | None | None | 24 hours (per CVE) |

## Migration Conventions

- Never hand-write migrations for model changes — always use `make migrations`
- Hand-written migrations are acceptable for data-only operations
- Migration dependencies must reference the previous `nb_risk` migration
- Check `dcim` dependency is listed when referencing `Platform` or `DeviceType`

## Version Numbering

Follows `{netbox_major}{netbox_minor}.{plugin_minor}.{plugin_patch}`:
- `45.x.x` = targets NetBox 4.5.x
- `45.5.0` = fifth plugin minor version for the 4.5 series

Version lives in `nb_risk/version.py` only. `__init__.py` reads it via `get_version()`.
