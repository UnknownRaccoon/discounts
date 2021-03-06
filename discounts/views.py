import re
from discounts.forms import SignUpForm, CardForm, CompanyForm, AddressForm
from discounts.helpers import user_important_data, user_is_company, prepare_request
from discounts.mixins import CSRFTokenNotRequiredMixin
from discounts.models import Card, Company, PasswordReset, Address
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
            if not re.match(r'\+\d{9,15}', user_data.cleaned_data['username']) and role == 0:
                return JsonResponse({'error': 'Username must be valid phone number'}, status=406)
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
            user = User.objects.get(pk=kwargs['user_id'], company__isnull=True)
        except(User.DoesNotExist):
            return JsonResponse({'error': 'User does not exist'}, status=404)
        if user_is_company(request.user) and\
                        user not in User.objects.filter(card__company=request.user.company).distinct() or\
                                user != request.user and not user_is_company(request.user):
                return JsonResponse({'error': 'Access denied'}, status=403)
        return JsonResponse(user_important_data(user))


class AccountControlView(JSONWebTokenAuthMixin, View):
    def get(self, request, *args, **kwargs):
        return JsonResponse(user_important_data(request.user))

    def put(self, request, *args, **kwargs):
        request.PUT = prepare_request(request, 'PUT')
        values = model_to_dict(request.user)
        values.update({key: value for key, value in request.PUT.items()})
        user_data = SignUpForm(values, files=request.FILES, instance=request.user)
        if user_data.is_valid():
            if not re.match(r'\+\d{9,15}', user_data.cleaned_data['username']) and user_is_company(request.user):
                return JsonResponse({'error': 'Username must be valid phone number'}, status=406)
            user_data.save()
            if user_is_company(request.user):
                company_data = CompanyForm(values, files=request.FILES, instance=request.user.company)
                if company_data.is_valid():
                    company_data.save()
                    return JsonResponse({}, status=204)
                user_data.errors.update(company_data.errors)
            else:
                return JsonResponse({}, status=204)
        return JsonResponse({'errors': user_data.errors}, status=406)


class UsersIndexView(JSONWebTokenAuthMixin, View):
    def get(self, request, *args, **kwargs):
        if not user_is_company(request.user):
            return JsonResponse({'error': 'Access denied'}, status=403)
        else:
            users = [user_important_data(user) for user in User.objects.filter(card__company=request.user.company).distinct()]
            return JsonResponse({'users': users})


class CardsIndexView(JSONWebTokenAuthMixin, View):
    def get(self, request, *args, **kwargs):
        if user_is_company(request.user):
            cards = Card.objects.filter(company=request.user.company)
        else:
            cards = Card.objects.filter(user=request.user)
        cards = [item.important_data() for item in cards]
        return JsonResponse({'cards': cards})

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
        try:
            card = Card.objects.get(pk=kwargs['card_id'])
        except Card.DoesNotExist:
            return JsonResponse({'error': 'Card with given id does not exist'}, status=404)
        access_errors = card.get_access_errors(request.user)
        if access_errors is not None:
            return JsonResponse({'error': access_errors}, status=403)
        request.PUT = prepare_request(request, 'PUT')
        request.PUT = request.PUT.copy()
        request.PUT['user'] = request.user.id
        values = model_to_dict(card)
        values.update({key: value for key, value in request.PUT.items()})
        card_data = CardForm(values, instance=card)
        if card_data.is_valid():
            card_data.save()
            return JsonResponse({}, status=204)
        return JsonResponse(card_data.errors, status=406)

    def delete(self, request, *args, **kwargs):
        try:
            card = Card.objects.get(pk=kwargs['card_id'])
        except Card.DoesNotExist:
            return JsonResponse({'error': 'Card with given id does not exist'}, status=404)
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


class AddressItemView(JSONWebTokenAuthMixin, View):
    def get(self, request, *args, **kwargs):
        try:
            address = Address.objects.get(pk=kwargs['address_id'])
        except(Address.DoesNotExist):
            return JsonResponse({'error': 'Address with given id does not exist'}, status=404)
        return JsonResponse(model_to_dict(address))

    def put(self, request, *args, **kwargs):
        try:
            address = Address.objects.get(pk=kwargs['address_id'])
        except Address.DoesNotExist:
            return JsonResponse({'error': 'Address with given id does not exist'}, status=404)
        if not user_is_company(request.user) or address not in request.user.company.address_set.all():
            return JsonResponse({'error': 'Access denied'}, status=403)
        request.PUT = prepare_request(request, 'PUT')
        request.PUT = request.PUT.copy()
        request.PUT['company'] = request.user.company.id
        values = model_to_dict(address)
        values.update({key: value for key, value in request.PUT.items()})
        address_data = AddressForm(values, instance=address)
        if address_data.is_valid():
            address_data.save()
            return JsonResponse({}, status=204)
        return JsonResponse(address_data.errors, status=406)

    def delete(self, request, *args, **kwargs):
        try:
            address = Address.objects.get(pk=kwargs['address_id'])
        except Address.DoesNotExist:
            return JsonResponse({'error': 'Address with given id does not exist'}, status=404)
        if not user_is_company(request.user) or address not in request.user.company.address_set.all():
            return JsonResponse({'error': 'Access denied'}, status=403)
        address.delete()
        return JsonResponse({}, status=204)


class AddressIndexView(JSONWebTokenAuthMixin, View):
    def get(self, request, *args, **kwargs):
        addresses = Address.objects.filter(company_id=kwargs['company_id'])
        data = {'addresses': [model_to_dict(address) for address in addresses]}
        return JsonResponse(data)

    def post(self, request, *args, **kwargs):
        if not user_is_company(request.user) or str(request.user.company.id) != kwargs['company_id']:
            return JsonResponse({'error': 'Access denied'}, status=403)
        request.POST = request.POST.copy()
        request.POST['company'] = request.user.company.id
        address_data = AddressForm(request.POST)
        if address_data.is_valid():
            created_address = address_data.save()
            return JsonResponse(model_to_dict(created_address), status=201)
        return JsonResponse(address_data.errors, status=406)


class CompaniesIndexView(JSONWebTokenAuthMixin, View):
    def get(self, request, *args, **kwargs):
        companies = [company.important_data() for company in Company.objects.all()]
        return JsonResponse({'companies': companies})


class CompanyItemView(JSONWebTokenAuthMixin, View):
    def get(self, request, *args, **kwargs):
        try:
            company = Company.objects.get(pk=kwargs['company_id'])
            return JsonResponse({'company': company.important_data()})
        except Company.DoesNotExist:
            return JsonResponse({'error': 'Company with given id does not exist'}, status=404)
