# Changelog

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