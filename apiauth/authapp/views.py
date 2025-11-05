from django.contrib.auth import get_user_model
from dj_rest_auth.views import LoginView
from django_otp.plugins.otp_email.models import EmailDevice
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiParameter, OpenApiResponse
User = get_user_model()


class EmailOTPLoginView(LoginView):
    """
    1) Verify credentials and send OTP via email
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

   
        device, _ = EmailDevice.objects.get_or_create(user=user, name="default")
        device.generate_challenge()  

        return Response(
            {
                "detail": "OTP sent to your registered email.",
                "user_id": user.pk
            },
            status=status.HTTP_202_ACCEPTED,
        )





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








class VerifyOTPView(APIView):
    """
    2) Verify the OTP and return token
    """
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.data.get("user_id")
        otp = request.data.get("otp")

        if not user_id or not otp:
            return Response(
                {"detail": "Both user_id and otp are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(pk=user_id)
            device = EmailDevice.objects.get(user=user, name="default")
        except (User.DoesNotExist, EmailDevice.DoesNotExist):
            return Response(
                {"detail": "Invalid user or no OTP device found."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if device.verify_token(otp):
            token, _ = Token.objects.get_or_create(user=user)
            return Response(
                {"token": token.key},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"detail": "Invalid or expired OTP."},
                status=status.HTTP_400_BAD_REQUEST,
            )
