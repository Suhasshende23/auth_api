from django.urls import path
from apiauth.authapp.views import EmailOTPLoginView, VerifyOTPView

urlpatterns = [
    path("login/", EmailOTPLoginView.as_view(), name="rest_login"),  # replaces default
    path("verify-otp/", VerifyOTPView.as_view(), name="verify_otp"),
]
