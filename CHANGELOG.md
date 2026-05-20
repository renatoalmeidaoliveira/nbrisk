# Changelog

## 45.3.0 (20/05/2026)

* Add **CPEMapping model** — maps a NetBox Platform or DeviceType to a verified NVD CPE 2.3 string for precise, vendor-agnostic CVE matching
* Add **CPE Lookup Assistant** — search the NVD CPE dictionary by keyword and create mappings directly from results
* Device CVE tab now uses CPEMapping records when available; falls back to heuristic CPE generation when no mapping exists
* Device CVE tab shows a warning with direct links to CPE Lookup and Add Mapping when no mapping is configured
* Add CPE Mappings section to the Risk Assessment navigation menu with Lookup shortcut button
* Add full CRUD views, bulk delete, and CSV import for CPEMapping
* Add CPEMapping REST API endpoint at `/api/plugins/nb_risk/cpemapping/`
* Add migration `0009_cpemapping`

## 45.2.0 (15/05/2026)

* Add **Device CVE tab** — queries NVD for CVEs matching the device's running software via the `software_version` custom field (populated by `netbox_software_tracker`)
* CPE strings are built automatically from the device's manufacturer, platform (preferred), and device type model, querying both `o` (OS/firmware) and `a` (application) part types
* CPE component normalization: lowercased, spaces/hyphens replaced with underscores for NVD compatibility
* Tab shows colour-coded CVSS scores (Critical/High/Medium/Low), NVD links, and one-click Import button per CVE
* Tab renders informative empty states when no software version is set or no CVEs are found
* CPE Queries panel shows exactly what was sent to NVD for transparency and debugging
* Use NetBox `HTTP_PROXIES` setting for all NVD API requests instead of plugin-level proxy config

## 45.1.0 (15/05/2026)

* Add `nvd_api_key` to plugin config — passed as `apiKey` header to raise NVD rate limit from 5 to 50 requests/30s
* Fix CPE search — `/cpes/2.0` returns products, not CVEs; now performs follow-up CVE lookup per CPE result
* Fix device type search — now queries `/cves/2.0?cpeName=...` directly instead of the CPE registry
* Add CVSSv3.1, CVSSv3.0, and CVSSv4.0 fallback score parsing; previously only CVSSv2 was read
* Add `CVSS Version` and `Base Score` columns to CVE search results table
* Import button now correctly pre-populates all CVSS fields regardless of score version
* Add 15-second timeout to all NVD API requests
* Update CI release workflow to trigger on published release instead of tag push (prevents overwriting release notes)
* Update README with full `PLUGINS_CONFIG` example and NVD API key documentation

## 45.0.0 (15/05/2026)

> Maintained by [@droolingtaz](https://github.com/droolingtaz). The original upstream repository is no longer actively maintained. This release adds full compatibility with NetBox 4.5.x and Python 3.12+.

* Bump `min_version`/`max_version` to `4.5.0`/`4.5.99`
* Fix shadowed `ContentType` import in `views.py` — `ObjectType as ContentType` was clobbering Django's `ContentType`
* Replace deprecated singular `model` attribute with `models = [model_name]` list on `PluginTemplateExtension` (required since NetBox 4.3); remove unused `packaging` import from `template_content.py`
* Replace legacy `actions` dict on `VulnerabilityAssignmentListView` with new `ObjectAction` tuple (`BulkImport`, `BulkExport`, `BulkDelete`) required by NetBox 4.5
* Add `.order_by()` to all API ViewSet querysets to prevent `QuerySetNotOrdered` exceptions on paginated API calls (NetBox 4.3.5+)
* Switch `ContentTypeField` in serializers to use `core.models.ObjectType`; migrate GFK serialization to `GFKSerializerField` from `netbox.api.gfk_fields` (NetBox 4.5+)
* Add `Meta.ordering = ('name',)` to all models for deterministic API pagination
* Add migration `0008_alter_ordering` for `Meta.ordering` changes
* Add `python_requires >= 3.12` and update Python classifiers in `setup.py`
* Update README with fork notice, compatibility table, and corrected installation instructions

## 35.1.0 (18/08/2023)

* Add case sensitive name constrain to Vulnerability model
* Change the import path of get_plugin_config() to extras.plugins.utils [13368](https://github.com/netbox-community/netbox/commit/f5a1f83f9fa9d98c945d21eb0f7ccb8cd37fbf59)