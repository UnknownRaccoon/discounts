from django.contrib.auth.models import User
from django.db.models.fields import PositiveSmallIntegerField
from django.forms.models import ModelForm


class SignUpForm(ModelForm):
    role = PositiveSmallIntegerField(blank=False, null=False)

    class Meta:
        model = User
        fields = ['username', 'password']