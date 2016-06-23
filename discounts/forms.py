from discounts.models import Card, Company
from django.contrib.auth.models import User
from django.forms.models import ModelForm


class SignUpForm(ModelForm):
    class Meta:
        model = User
        fields = ['username', 'password', 'email']


class CardForm(ModelForm):
    class Meta:
        model = Card
        fields = '__all__'


class CompanyForm(ModelForm):
    class Meta:
        model = Company
        fields = '__all__'
