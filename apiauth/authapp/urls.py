from django.urls import path
# from apiauth.authapp.views import EmailOTPLoginView, VerifyOTPView


from apiauth.authapp.google_auth_views import VerifyTOTPView, EnableTOTPView, DisableTOTPView
urlpatterns = [
    # path("login/", EmailOTPLoginView.as_view(), name="rest_login"),  # replaces default
    # path("verify-otp/", VerifyOTPView.as_view(), name="verify_otp"),



    path("verify-otp/", VerifyTOTPView.as_view(), name="verify-otp"),
    path("enable/", EnableTOTPView.as_view(), name="enable-totp"),
    path("disable/", DisableTOTPView.as_view(), name="disable-totp"),    

    
]
