from discounts.models import Card
from django.contrib.auth.models import User
from django.forms.models import ModelForm


class SignUpForm(ModelForm):
    class Meta:
        model = User
        fields = ['username', 'password']


class CardForm(ModelForm):
    class Meta:
        model = Card
        fields = '__all__'
