from typing import Iterable


from django.urls import reverse
from django.urls.exceptions import NoReverseMatch
from django.utils.http import url_has_allowed_host_and_scheme
from netbox.plugins import PluginConfig


class GetReturnURLMixin:
    """
    Provides logic for determining where a user should be redirected after processing a form.
    """
    default_return_url = None

    def get_return_url(self, request, obj=None):

        # First, see if `return_url` was specified as a query parameter or form data. Use this URL only if it's
        # considered safe.
        return_url = request.GET.get('return_url') or request.POST.get('return_url')
        if return_url and url_has_allowed_host_and_scheme(return_url, allowed_hosts=None):
            return return_url

        # Next, check if the object being modified (if any) has an absolute URL.
        if obj is not None and obj.pk and hasattr(obj, 'get_absolute_url'):
            return obj.get_absolute_url()

        # Fall back to the default URL (if specified) for the view.
        if self.default_return_url is not None:
            return reverse(self.default_return_url)

        # Attempt to dynamically resolve the list view for the object
        if hasattr(self, 'queryset'):
            is_plugin = isinstance(self.queryset.model._meta.app_config, PluginConfig)
            model_opts = self.queryset.model._meta
            try:
                if is_plugin:
                    return reverse(f'plugins:{model_opts.app_label}:{model_opts.model_name}_list')
                else:
                    return reverse(f'{model_opts.app_label}:{model_opts.model_name}_list')
            except NoReverseMatch:
                pass

        # If all else fails, return home. Ideally this should never happen.
        return reverse('home')
