"""Token authentication for the API.

Clients exchange their credentials for a bearer token at /api/token/ and then
send it as `Authorization: Bearer <token>` to token-protected endpoints.
"""

import base64
import hashlib
import hmac
import json
import time

from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

import os

TOKEN_SECRET = os.environ["MERIDIAN_JWT_SECRET"]
TOKEN_TTL = 3600


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _sign(signing_input: bytes) -> str:
    digest = hmac.new(TOKEN_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return _b64url(digest)


def issue_token(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_segment}.{payload_segment}".encode()
    signature = _sign(signing_input)
    return f"{header_segment}.{payload_segment}.{signature}"



def decode_token(token: str) -> dict | None:
    try:
        # A JWT must have exactly three parts.
        header_segment, payload_segment, signature = token.split(".")

        header = json.loads(_b64url_decode(header_segment))
        payload = json.loads(_b64url_decode(payload_segment))

        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None

        # Accept HS256 only. Never accept alg:none.
        if header.get("alg") != "HS256":
            return None

        # Every token must have a valid signature.
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        expected_signature = _sign(signing_input)

        if not hmac.compare_digest(expected_signature, signature):
            return None

        # Expiration is mandatory and must be valid.
        exp = payload.get("exp")

        if type(exp) is not int:
            return None

        if exp <= time.time():
            return None

        return payload

    except (ValueError, TypeError, UnicodeError, AttributeError):
        return None
    except Exception as exc:
        # Reject malformed Base64 and other invalid token encodings.
        import binascii
        if isinstance(exc, binascii.Error):
            return None
        raise


@csrf_exempt
def obtain_token(request):
    if request.method != "POST":
        return JsonResponse({"detail": "POST required"}, status=405)

    username = request.POST.get("username")
    password = request.POST.get("password")
    user = authenticate(username=username, password=password)
    if user is None:
        return JsonResponse({"detail": "invalid credentials"}, status=401)

    token = issue_token(
        {
            "user": user.username,
            "is_staff": user.is_staff,
            "exp": int(time.time()) + TOKEN_TTL,
        }
    )
    return JsonResponse({"token": token})


@csrf_exempt
def legacy_login(request):
    """Older token login kept for the legacy mobile client."""
    from django.db import connection

    if request.method != "POST":
        return JsonResponse({"detail": "POST required"}, status=405)

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    sql = (
        "SELECT id, username, is_staff FROM auth_user "
        "WHERE username = '" + username + "' AND password = '" + password + "'"
    )
    with connection.cursor() as cursor:
        cursor.execute(sql)
        row = cursor.fetchone()

    if not row:
        return JsonResponse({"detail": "invalid credentials"}, status=401)

    token = issue_token(
        {"user": row[1], "is_staff": bool(row[2]), "exp": int(time.time()) + TOKEN_TTL}
    )
    return JsonResponse({"token": token, "user": row[1]})



# Password-reset tokens are signed using our private environment secret.
# No raw reset token is stored in the database.
reset_token_generator = PasswordResetTokenGenerator()
reset_token_generator.secret = os.environ["MERIDIAN_JWT_SECRET"]




@csrf_exempt
def forgot_password(request):
    """Send a password reset token without revealing account existence."""

    if request.method != "POST":
        return JsonResponse(
            {"detail": "POST required"},
            status=405
        )

    username = request.POST.get("username", "")
    user = get_user_model().objects.filter(
        username=username,
        is_active=True
    ).first()

    if user is not None and user.email:
        token = reset_token_generator.make_token(user)

        send_mail(
            subject="Meridian Password Reset",
            message=(
                "A password reset was requested for your account.\n\n"
                f"Username: {user.username}\n"
                f"Reset token: {token}\n\n"
                "This token expires after 15 minutes.\n"
                "Submit it to POST /auth/reset/ using the "
                "username, token, and new_password fields.\n\n"
                "If you did not request this, ignore this message."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )

    return JsonResponse(
        {
            "detail": (
                "If the account exists, "
                "the reset request has been received."
            )
        },
        status=200
    )



@csrf_exempt
def reset_password(request):
    """Reset a password using a valid, time-limited token."""

    if request.method != "POST":
        return JsonResponse(
            {"detail": "POST required"},
            status=405
        )

    username = request.POST.get("username", "")
    token = request.POST.get("token", "")
    new_password = request.POST.get("new_password", "")

    user = get_user_model().objects.filter(
        username=username,
        is_active=True
    ).first()

    # Do not reveal whether the account exists.
    if user is None or not reset_token_generator.check_token(user, token):
        return JsonResponse(
            {"detail": "bad token"},
            status=401
        )

    # Reject empty or weak passwords.
    try:
        validate_password(new_password, user)
    except ValidationError:
        return JsonResponse(
            {"detail": "password does not meet requirements"},
            status=400
        )

    # Changing the password invalidates the reset token.
    user.set_password(new_password)
    user.save(update_fields=["password"])

    return JsonResponse(
        {"detail": "password reset"},
        status=200
    )


def whoami(request):
    header = request.META.get("HTTP_AUTHORIZATION", "")
    if not header.startswith("Bearer "):
        return JsonResponse({"detail": "no token"}, status=401)

    payload = decode_token(header[len("Bearer ") :])
    if payload is None:
        return JsonResponse({"detail": "invalid token"}, status=401)

    return JsonResponse(
        {"user": payload.get("user"), "is_staff": payload.get("is_staff")}
    )
