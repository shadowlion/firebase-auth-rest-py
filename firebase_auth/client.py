import json
from typing import Self

import httpx

from firebase_auth.responses import (
    FirebaseErrorItem,
    FirebaseErrorMetadata,
    FirebaseResponseError,
    SignInWithEmailAndPasswordResponse,
    SignUpWithEmailAndPasswordResponse,
)


class FirebaseAuthClient:
    """Http Client instance to run various Firebase Auth methods. Requires an API key."""

    _api_key: str

    def __init__(self: Self, api_key: str) -> None:
        self._api_key = api_key

    def _post_request(self: Self, url: str, request_body: dict) -> dict:
        headers = {"Content-Type": "application/json"}
        with httpx.Client() as client:
            r = client.post(url, headers=headers, data=json.dumps(request_body))
            return r.json()

    def _parse_firebase_response(
        self: Self,
        response_data: dict,
    ) -> FirebaseResponseError | None:
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
        email: str,
        password: str,
    ) -> SignUpWithEmailAndPasswordResponse | FirebaseResponseError:
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self._api_key}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True,
        }

        response_body = self._post_request(url, request_body=payload)
        err = self._parse_firebase_response(response_body)
        if err is not None:
            return err
        return SignUpWithEmailAndPasswordResponse(**response_body)

    def sign_in_with_email_and_password(
        self: Self,
        email: str,
        password: str,
    ) -> SignInWithEmailAndPasswordResponse | FirebaseResponseError:
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={self._api_key}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True,
        }
        response_body = self._post_request(url, request_body=payload)
        err = self._parse_firebase_response(response_body)
        if err is not None:
            return err
        return SignInWithEmailAndPasswordResponse(**response_body)
