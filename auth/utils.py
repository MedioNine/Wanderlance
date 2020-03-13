from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
import six
import time


class TokenGenerator(PasswordResetTokenGenerator):
    pass


activation_token = TokenGenerator()


def encode_id(id):
    return urlsafe_base64_encode(force_bytes(id))


def decode_id(id):
    return force_text(urlsafe_base64_decode(id))


def send_email_activation(user):
    mail_subject = 'Wanderlance Confirm Registration'
    token = activation_token.make_token(user=user)

    message = render_to_string('email.html', {
        'user': user,
        'domain': 'auth/',
        'uid': encode_id(user.id),
        'token': token})

    to_email = user.email
    email = EmailMessage(mail_subject, message, to=[to_email])
    email.send()

def send_email_reset_password(user):
    mail_subject = 'Wanderlance Password Reset'

    token = activation_token.make_token(user=user)

    message = render_to_string('reset_password.html', {
        'user': user,
        'domain': 'auth/',
        'uid': encode_id(user.id),
        'token': token})

    to_email = user.email
    email = EmailMessage(mail_subject, message, to=[to_email])
    email.send()
