from discounts.models import Card, Company, Address
from django.contrib.auth.models import User
from django.forms.models import ModelForm


class SignUpForm(ModelForm):
    class Meta:
        model = User
        fields = ['username', 'password', 'email', 'first_name', 'last_name']


class CardForm(ModelForm):
    class Meta:
        model = Card
        fields = '__all__'


class CompanyForm(ModelForm):
    class Meta:
        model = Company
        fields = ['logo']


class AddressForm(ModelForm):
    class Meta:
        model = Address
        fields = '__all__'
