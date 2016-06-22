from discounts.views import CardsIndexView, SignUpView
from django.conf.urls import url

urlpatterns = [
    url('^cards$', CardsIndexView.as_view(), name='cards_index'),
    url('^signup$', SignUpView.as_view(), name='signup'),
]
