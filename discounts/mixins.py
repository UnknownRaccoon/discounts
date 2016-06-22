from django.views.decorators.csrf import csrf_exempt


class CSRFTokenNotRequiredMixin(object):
    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super(CSRFTokenNotRequiredMixin, self).dispatch(request, *args, **kwargs)
