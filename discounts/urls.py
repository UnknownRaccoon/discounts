from discounts.views import CardsIndexView, SignUpView
from django.conf.urls import url
from jwt_auth.views import obtain_jwt_token

urlpatterns = [
    url('^cards$', CardsIndexView.as_view(), name='cards_index'),
    url('^signup$', SignUpView.as_view(), name='signup'),
    url('^login$', obtain_jwt_token, name='signin')
]
