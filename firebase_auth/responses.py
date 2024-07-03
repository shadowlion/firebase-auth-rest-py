from dataclasses import dataclass


@dataclass
class FirebaseErrorItem:
    domain: str
    reason: str
    message: str


@dataclass
class FirebaseErrorMetadata:
    errors: list[FirebaseErrorItem]
    code: int
    message: str


@dataclass
class FirebaseResponseError:
    error: FirebaseErrorMetadata


@dataclass
class SignUpWithEmailAndPasswordResponse:
    idToken: str
    email: str
    refreshToken: str
    expiresIn: str
    localId: str


@dataclass
class SignInWithEmailAndPasswordResponse:
    displayName: str
    email: str
    expiresIn: str
    idToken: str
    kind: str
    localId: str
    refreshToken: str
    registered: bool
