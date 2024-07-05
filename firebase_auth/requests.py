from dataclasses import dataclass, field


@dataclass
class SignUpWithEmailAndPasswordRequest:
    email: str
    password: str
    return_secure_token: bool = field(metadata={"json_key": "returnSecureToken"})


@dataclass
class SignInWithEmailAndPasswordRequest:
    email: str
    password: str
    return_secure_token: bool = field(metadata={"json_key": "returnSecureToken"})


@dataclass
class SendPasswordResetEmailRequest:
    email: str


@dataclass
class VerifyPasswordResetCodeRequest:
    oob_code: str = field(metadata={"json_key": "oobCode"})


@dataclass
class ConfirmPasswordResetRequest:
    oob_code: str = field(metadata={"json_key": "oobCode"})
    new_password: str = field(metadata={"json_key": "newPassword"})
