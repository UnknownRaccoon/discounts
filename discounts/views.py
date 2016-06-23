from discounts.forms import SignUpForm, CardForm, CompanyForm
from discounts.helpers import user_important_data, user_is_company, prepare_request
from discounts.mixins import CSRFTokenNotRequiredMixin
from discounts.models import Card, Company, PasswordReset
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.forms.models import model_to_dict
from django.http.response import JsonResponse
from django.utils.crypto import get_random_string
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
            if role > 1:
                raise ValueError
        except(ValueError, TypeError):
            return JsonResponse({'error': 'Role field must be specified and valid'}, status=406)
        if user_data.is_valid():
            created_user = User.objects.create_user(user_data.cleaned_data['username'],
                                                    user_data.cleaned_data['email'],
                                                    user_data.cleaned_data['password'])
            if role == 0:
                return JsonResponse(user_important_data(created_user), status=201)
            if role == 1:
                created_company = Company.objects.create(user=created_user)
                return JsonResponse(created_company.important_data(), status=201)
        errors = user_data.errors
        return JsonResponse(errors, status=406)


class UserItemView(JSONWebTokenAuthMixin, View):
    def get(self, request, *args, **kwargs):
        try:
            user = User.objects.get(pk=kwargs['user_id'])
        except(User.DoesNotExist):
            return JsonResponse({'error': 'User does not exist'}, status=404)
        if user_is_company(user):
            return JsonResponse(user.company.important_data())
        elif user_is_company(request.user) and\
                        user not in User.objects.filter(card__company=request.user.company).distinct() or\
                                user != request.user and not user_is_company(request.user):
                return JsonResponse({'error': 'Access denied'}, status=403)
        return JsonResponse(user_important_data(user))

    def put(self, request, *args, **kwargs):
        request.PUT = prepare_request(request, 'PUT')
        user = User.objects.get(pk=kwargs['user_id'])
        if user != request.user:
            return JsonResponse({'error': 'Access denied'}, status=403)
        request.PUT = request.PUT.copy()
        request.PUT['user'] = request.user.id
        values = model_to_dict(user)
        values.update(request.PUT)
        for k, v in values.items():
            if k in request.PUT:
                values[k] = v[0]
        user_data = SignUpForm(values, files=request.FILES, instance=user)
        if user_data.is_valid():
            user_data.save()
            if user_is_company(user):
                company_data = CompanyForm(values, files=request.FILES, instance=user.company)
                if company_data.is_valid():
                    company_data.save()
            return JsonResponse({}, status=204)
        return JsonResponse({'errors': user_data.errors})


class UsersIndexView(JSONWebTokenAuthMixin, View):
    def get(self, request, *args, **kwargs):
        if not user_is_company(request.user):
            return JsonResponse({'error:' 'Access denied'})
        else:
            users = [user_important_data(item) for item in User.objects.filter(card__company=request.user.company).distinct()]
            return JsonResponse({'users': users})


class CardsIndexView(JSONWebTokenAuthMixin, View):
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


class CardItemView(JSONWebTokenAuthMixin, View):
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


class ResetPasswordView(CSRFTokenNotRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        email = request.POST['email']
        user = User.objects.filter(email=email).first()
        if user is None:
            return JsonResponse({'error': 'No such email found'}, status=404)
        token = PasswordReset.objects.create(user=user, token=get_random_string(length=64))
        send_mail('Password reset', 'Your password reset token: ' + token.token, 'intersog.labs@gmail.com', [user.email])
        return JsonResponse({}, status=204)


class NewPasswordView(CSRFTokenNotRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        token = request.POST.get('token')
        new_password = request.POST.get('password')
        if token is None or new_password is None or len(new_password) < 4:
            return JsonResponse({'error': 'Both reset token and new password are required'}, status=406)
        password_reset = PasswordReset.objects.filter(token=token, used=False).first()
        if password_reset is None:
            return JsonResponse({'error': 'Specified token does not match any of the active ones'}, status=404)
        password_reset.user.set_password(new_password)
        password_reset.user.save()
        password_reset.used = True
        password_reset.save()
        return JsonResponse({}, status=204)
