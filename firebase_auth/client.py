import json
from dataclasses import asdict
from typing import Self

import httpx

from .requests import (
    ConfirmPasswordResetRequest,
    SendPasswordResetEmailRequest,
    SignInWithEmailAndPasswordRequest,
    SignUpWithEmailAndPasswordRequest,
    VerifyPasswordResetCodeRequest,
)
from .responses import (
    ConfirmPasswordResetResponse,
    FirebaseErrorItem,
    FirebaseErrorMetadata,
    FirebaseResponseError,
    SendPasswordResetEmailResponse,
    SignInWithEmailAndPasswordResponse,
    SignUpWithEmailAndPasswordResponse,
    VerifyPasswordResetCodeResponse,
)


class FirebaseAuthClient:
    """Http Client instance to run various Firebase Auth methods. Requires an API key."""

    _api_key: str

    def __init__(self: Self, api_key: str) -> None:
        self._api_key = api_key

    def _post_request(self: Self, url: str, request_body: dict) -> dict:
        """runs an http POST request.

        Args:
            self (Self): instance of the FirebaseAuthClient.
            url (str): endpoint url
            request_body (dict): request payload

        Returns:
            dict: json response
        """
        with httpx.Client() as client:
            r = client.post(
                url,
                headers={
                    "Content-Type": "application/json",
                },
                json=json.dumps(request_body),
            )
            return r.json()

    def _parse_response(
        self: Self,
        response_data: dict,
    ) -> FirebaseResponseError | None:
        """Checks to see if the response body conforms to a custom error class.
        If not, it tells us we can instead conform it to an OK response dataclass.

        Args:
            self (Self): instance of the FirebaseAuthClient.
            response_data (dict): json response body

        Returns:
            FirebaseResponseError | None: error class
        """

        if "error" not in response_data:
            return None

        error_metadata = FirebaseErrorMetadata(
            errors=[
                FirebaseErrorItem(**item)
                for item in response_data["error"].get("errors", [])
            ],
            code=response_data["error"]["code"],
            message=response_data["error"]["message"],
        )

        return FirebaseResponseError(error=error_metadata)

    def sign_up_with_email_and_password(
        self: Self,
        req: SignUpWithEmailAndPasswordRequest,
    ) -> SignUpWithEmailAndPasswordResponse | FirebaseResponseError:
        """You can create a new email and password user by issuing an HTTP `POST`
        request to the Auth `signupNewUser` endpoint.

        Reference: https://firebase.google.com/docs/reference/rest/auth/#section-create-email-password

        Args:
            self (Self): instance of the FirebaseAuthClient.
            req (SignUpWithEmailAndPasswordRequest): request body payload

        Returns:
            SignUpWithEmailAndPasswordResponse | FirebaseResponseError: response body
        """

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self._api_key}"
        response_body = self._post_request(url, request_body=asdict(req))
        err = self._parse_response(response_body)
        if err is not None:
            return err
        return SignUpWithEmailAndPasswordResponse(**response_body)

    def sign_in_with_email_and_password(
        self: Self,
        req: SignInWithEmailAndPasswordRequest,
    ) -> SignInWithEmailAndPasswordResponse | FirebaseResponseError:
        """You can sign in a user with an email and password by issuing an HTTP POST
        request to the Auth verifyPassword endpoint.

        Reference: https://firebase.google.com/docs/reference/rest/auth/#section-sign-in-email-password

        Args:
            self (Self): instance of the FirebaseAuthClient.
            email (str): The email the user is signing in with.
            password (str): The password for the account.

        Returns:
            SignInWithEmailAndPasswordResponse | FirebaseResponseError: response body
        """

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={self._api_key}"
        response_body = self._post_request(url, request_body=asdict(req))
        err = self._parse_response(response_body)
        if err is not None:
            return err
        return SignInWithEmailAndPasswordResponse(**response_body)

    def send_password_reset_email(
        self: Self,
        req: SendPasswordResetEmailRequest,
    ) -> SendPasswordResetEmailResponse | FirebaseResponseError:
        """You can send a password reset email by issuing an HTTP POST request to the
        Auth getOobConfirmationCode endpoint.

        Reference: https://firebase.google.com/docs/reference/rest/auth/#section-send-password-reset-email

        Args:
            self (Self): instance of the FirebaseAuthClient
            email (str): User's email address.

        Returns:
            SendPasswordResetEmailResponse | FirebaseResponseError: response body
        """

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={self._api_key}"
        response_body = self._post_request(url, request_body=asdict(req))
        err = self._parse_response(response_body)
        if err is not None:
            return err
        return SendPasswordResetEmailResponse(**response_body)

    def verify_password_reset_code(
        self: Self,
        req: VerifyPasswordResetCodeRequest,
    ) -> VerifyPasswordResetCodeResponse | FirebaseResponseError:
        """You can verify a password reset code by issuing an HTTP `POST` request to
        the Auth `resetPassword` endpoint.

        Args:
            self (Self): instance of the FirebaseAuthClient
            oob_code (str): The email action code sent to the user's email for
            resetting the password.

        Returns:
            VerifyPasswordResetCodeResponse | FirebaseResponseError: response body
        """

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key={self._api_key}"
        response_body = self._post_request(url, request_body=asdict(req))
        err = self._parse_response(response_body)
        if err is not None:
            return err
        return VerifyPasswordResetCodeResponse(**response_body)

    def confirm_password_reset(
        self: Self,
        req: ConfirmPasswordResetRequest,
    ) -> ConfirmPasswordResetResponse | FirebaseResponseError:
        """You can apply a password reset change by issuing an HTTP `POST` request to
        the Auth `resetPassword` endpoint.

        Args:
            self (Self): insance of the FirebaseAuthClient
            oob_code (str): The email action code sent to the user's email for resetting
            the password.
            new_password (str): The user's new password.

        Returns:
            ConfirmPasswordResetResponse | FirebaseResponseError: response body
        """

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key={self._api_key}"
        response_body = self._post_request(url, request_body=asdict(req))
        err = self._parse_response(response_body)
        if err is not None:
            return err
        return ConfirmPasswordResetResponse(**response_body)
