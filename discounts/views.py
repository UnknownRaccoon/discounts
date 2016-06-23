from discounts.forms import SignUpForm, CardForm
from discounts.helpers import user_important_data, user_is_company, prepare_request
from discounts.mixins import CSRFTokenNotRequiredMixin
from discounts.models import Card, Company
from django.contrib.auth.models import User
from django.forms.models import model_to_dict
from django.http.response import JsonResponse
from django.views.generic import View
from jwt_auth.mixins import JSONWebTokenAuthMixin


class SignUpView(CSRFTokenNotRequiredMixin, View):
    # "role" field value definitions:
    # 0: user
    # 1: company
    def post(self, request, *args, **kwargs):
        user_data = SignUpForm(request.POST)
        try:
            role = int(user_data.data.get('role'))
            if role not in (0, 1):
                raise ValueError
        except(ValueError, TypeError):
            return JsonResponse({'error': 'Role field must be specified and valid'}, status=406)
        if user_data.is_valid():
            created_user = User.objects.create_user(user_data.cleaned_data['username'],
                                                    '',
                                                    user_data.cleaned_data['password'])
            if role == 0:
                return JsonResponse(user_important_data(created_user), status=201)
            if role == 1:
                created_company = Company.objects.create(user=created_user)
                return JsonResponse(created_company.important_data(), status=201)
        errors = user_data.errors
        return JsonResponse(errors, status=406)


class CardsIndexView(CSRFTokenNotRequiredMixin, JSONWebTokenAuthMixin, View):
    def get(self, request, *args, **kwargs):
        if user_is_company(request.user):
            cards = Card.objects.filter(company=request.user.company)
        else:
            cards = Card.objects.filter(user=request.user)
        data = {'cards': [item.important_data() for item in cards]}
        return JsonResponse(data)

    def post(self, request, *args, **kwargs):
        request.POST = request.POST.copy()
        if user_is_company(request.user):
            return JsonResponse({'error': 'Companies cannot manipulate cards'}, status=403)
        request.POST['user'] = request.user.id
        card_data = CardForm(request.POST)
        if card_data.is_valid():
            created_card = card_data.save()
            return JsonResponse(created_card.important_data(), status=201)
        return JsonResponse(card_data.errors, status=406)


class CardItemView(CSRFTokenNotRequiredMixin, JSONWebTokenAuthMixin, View):
    def get(self, request, *args, **kwargs):
        try:
            card = Card.objects.get(pk=kwargs['card_id'])
        except(Card.DoesNotExist):
            return JsonResponse({'error': 'Card with given id does not exist'}, status=404)
        if user_is_company(request.user):
            if card.company != request.user.company:
                return JsonResponse({'error': 'Access denied'}, status=403)
        elif card.user != request.user:
            return JsonResponse({'error': 'Access denied'}, status=403)
        return JsonResponse(model_to_dict(card))

    def put(self, request, *args, **kwargs):
        request.PUT = prepare_request(request, 'PUT')
        card = Card.objects.get(pk=kwargs['card_id'])
        access_errors = card.get_access_errors(request.user)
        if access_errors is not None:
            return JsonResponse({'error': access_errors}, status=403)
        request.PUT = request.PUT.copy()
        request.PUT = {k: v[0] for k, v in request.PUT.items()}
        request.PUT['user'] = request.user.id
        values = model_to_dict(card)
        values.update(request.PUT)
        card_data = CardForm(values)
        if card_data.is_valid():
            created_card = card_data.save(commit=False)
            created_card.id = card.id
            card = created_card
            card.save()
            return JsonResponse({}, status=204)
        return JsonResponse(card_data.errors, status=406)

    def delete(self, request, *args, **kwargs):
        request.DELETE = prepare_request(request, 'DELETE')
        card = Card.objects.get(pk=kwargs['card_id'])
        access_errors = card.get_access_errors(request.user)
        if access_errors is not None:
            return JsonResponse({'error': access_errors}, status=403)
        Card.objects.get(pk=kwargs['card_id']).delete()
        return JsonResponse({}, status=204)
