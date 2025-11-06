# twofactor/views.py
import os
import base64, qrcode
from io import BytesIO
from django.conf import settings
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework import status
from rest_framework.response import Response
from dj_rest_auth.views import LoginView
from rest_framework.authtoken.models import Token as TokenModel
from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiParameter, OpenApiResponse

from django.contrib.auth import get_user_model
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated




class LoginGoogleTwoFAView(LoginView):
    """
    1) Login with username and password.
    If user has 2FA enabled, require OTP verification.
    """

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        user = getattr(self, "user", None)
        if not user:
            return response

        # Asking TOTP OTP if user enabled the 2FA for authentication 
        if TOTPDevice.objects.filter(user=user, name="default").exists():
            # Remove issued token until OTP verified
            TokenModel.objects.filter(user=user).delete()
            return Response(
                {
                    "detail": "TOTP verification required.",
                    "requires_otp": True,
                    "user_id": user.pk,
                },
                status=status.HTTP_202_ACCEPTED,
            )

        # If user dont have 2FA return token
        return response








User = get_user_model()


@extend_schema(

    request={
        "application/json": {
            "example": {
                "user_id": 3,
                "otp": "428719"
            }
        }
    }

)
class VerifyTOTPView(APIView):
    """
    2) Verify TOTP for a logged-in user in response it gives token 
    """

    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.data.get("user_id")
        otp = request.data.get("otp")


        try:
            user = User.objects.get(pk=user_id)
            device = TOTPDevice.objects.get(user=user, name="default")
        except (User.DoesNotExist, TOTPDevice.DoesNotExist):
            return Response({"detail": "Invalid user or device."}, status=400)

        if device.verify_token(otp):
            token, _ = TokenModel.objects.get_or_create(user=user)
            return Response(
                {"detail": "OTP verified successfully.", "token": token.key},
                status=200,
            )
        return Response({"detail": "Invalid or expired OTP."}, status=400)












class EnableTOTPView(APIView):
    """
    Enable Two-Factor Authentication (TOTP) for an authenticated user.
    - Generates a new TOTP device.
    - Saves a QR code image in /media/totp_qr/.
    - Returns both QR code URL and base64 image.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        # If already enabled
        if TOTPDevice.objects.filter(user=user, name="default").exists():
            return Response({"detail": "2FA already enabled."}, status=status.HTTP_400_BAD_REQUEST)

        # Creating TOTP device for user
        device = TOTPDevice.objects.create(user=user, name="default")
        otpauth_url = device.config_url

        qr = qrcode.make(otpauth_url)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")

        qr_dir = os.path.join(settings.MEDIA_ROOT, "totp_qr")
        os.makedirs(qr_dir, exist_ok=True)

        qr_filename = f"totp_{user.username}.png"
        qr_path = os.path.join(qr_dir, qr_filename)
        with open(qr_path, "wb") as f:
            f.write(buffer.getvalue())

        qr_url = f"{settings.MEDIA_URL}totp_qr/{qr_filename}"

       
        qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

        return Response(
            {
                "detail": "TOTP enabled. Scan this QR in Google Authenticator.",
                "qr_image_url": qr_url,
                "qr_code_base64": qr_base64,
            },
            status=status.HTTP_201_CREATED,
        )

class DisableTOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        deleted, _ = TOTPDevice.objects.filter(user=user, name="default").delete()
        if deleted:
            return Response({"detail": "2FA disabled."}, status=200)
        return Response({"detail": "No 2FA found."}, status=400)
