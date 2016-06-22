from discounts.helpers import user_is_company
from discounts.models import Card, Company
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.forms.models import ModelForm


class SignUpForm(ModelForm):
    class Meta:
        model = User
        fields = ['username', 'password']


class CardForm(ModelForm):
    class Meta:
        model = Card
        fields = '__all__'

    def clean_company(self):
        try:
            company = self.cleaned_data['company']
            if not user_is_company(company.user):
                raise ValidationError('Wrong company id')
        except Company.DoesNotExist:
            raise ValidationError('Wrong company id')
        return self.cleaned_data['company']
