from discounts.views import CardsIndexView, UsersIndexView, CardItemView, ResetPasswordView, NewPasswordView,\
    AccountControlView, SignUpView, UserItemView, AddressIndexView, AddressItemView, CompaniesIndexView, CompanyItemView
from django.conf.urls import url
from jwt_auth.views import obtain_jwt_token

urlpatterns = [
    url(r'^cards/$', CardsIndexView.as_view(), name='cards_index'),
    url(r'^cards/(?P<card_id>[0-9]+)/$', CardItemView.as_view(), name='card'),
    url(r'^login/$', obtain_jwt_token, name='signin'),
    url(r'^users/$', UsersIndexView.as_view(), name='users'),
    url(r'^users/(?P<user_id>[0-9]+)/$', UserItemView.as_view(), name='user'),
    url(r'^companies/$', CompaniesIndexView.as_view(), name='users'),
    url(r'^companies/(?P<company_id>[0-9]+)/$', CompanyItemView.as_view(), name='user'),
    url(r'^reset/$', ResetPasswordView.as_view(), name='reset_start'),
    url(r'^reset-complete/$', NewPasswordView.as_view(), name='reset_complete'),
    url(r'^companies/(?P<company_id>[0-9]+)/addresses/$', AddressIndexView.as_view(), name='addresses'),
    url(r'^companies/(?P<company_id>[0-9]+)/addresses/(?P<address_id>[0-9]+)/$', AddressItemView.as_view(), name='address'),
    url(r'^account/create/$', SignUpView.as_view(), name='signup'),
    url(r'^account/$', AccountControlView.as_view(), name='account'),
]
