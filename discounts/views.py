from discounts.forms import SignUpForm
from discounts.helpers import user_important_data
from discounts.models import Card, Company
from django.contrib.auth.models import User
from django.forms.utils import ErrorDict
from django.http.response import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from jwt_auth.mixins import JSONWebTokenAuthMixin


class SignUpView(View):
    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super(SignUpView, self).dispatch(request, *args, **kwargs)

    # "role" field value definitions:
    # 0: user
    # 1: company
    def post(self, request, *args, **kwargs):
        user_data = SignUpForm(request.POST)
        try:
            role = int(user_data.data.get('role'))
        except ValueError:
            return JsonResponse({'error': 'Role field must be specified and valid'}, status=406)

        if user_data.is_valid() and role in (0, 1):
            created_user = user_data.save()
            if role == 0:
                return JsonResponse(user_important_data(created_user))
            if role == 1:
                created_company = Company.objects.create(user=created_user)
                return JsonResponse(created_company.important_data())
        errors = user_data.errors
        return JsonResponse(errors, status=406)


class CardsIndexView(JSONWebTokenAuthMixin, View):
    def get(self, request, *args, **kwargs):
        return JsonResponse(Card.objects.filter(user=request.user))
