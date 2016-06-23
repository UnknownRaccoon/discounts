from discounts.helpers import user_is_company
from django.db import models
from django.contrib.auth.models import User


class Company(models.Model):
    user = models.OneToOneField(User)
    logo = models.ImageField(blank=True, null=True)

    def __str__(self):
        return self.user.username

    def important_data(self):
        return {'id': self.id,
                'name': self.user.username.encode(),
                'email': self.user.email,
                'logo': self.logo or None
                }


class Address(models.Model):
    address = models.CharField(max_length=100)
    company = models.ForeignKey(Company, on_delete=models.CASCADE)


class Card(models.Model):
    DISCOUNT = 0
    CUMULATIVE = 1
    TYPE_CHOICES = (
        (DISCOUNT, 'Discount'),
        (CUMULATIVE, 'Cumulative'),
    )
    user = models.ForeignKey(User)
    company = models.ForeignKey(Company)
    number = models.CharField(max_length=50)
    type = models.SmallIntegerField(choices=TYPE_CHOICES)

    def important_data(self):
        return {'id': self.id,
                'number': self.number,
                'user': self.user.id,
                'company': self.company.id,
                'type': self.type,
                }
    def get_access_errors(self, user):
        if user_is_company(user):
            return 'Companies cannot manipulate cards'
        elif user != self.user:
            return 'Access denied'
        else:
            return None