from __future__ import absolute_import, division, print_function, unicode_literals

from binascii import unhexlify
import logging
import time

from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils.encoding import force_text

from django_otp.models import Device
from django_otp.oath import TOTP
from django_otp.util import hex_validator, random_hex
import messagebird

from .conf import settings


logger = logging.getLogger(__name__)


def default_key():
    return force_text(random_hex(20))


def key_validator(value):
    return hex_validator(20)(value)


class MessageBirdSMSDevice(Device):
    """
    A :class:`~django_otp.models.Device` that delivers codes via the MessageBird SMS
    service. This uses TOTP to generate temporary tokens, which are valid for
    :setting:`OTP_MESSAGEBIRD_TOKEN_VALIDITY` seconds. Once a given token has been
    accepted, it is no longer valid, nor is any other token generated at an
    earlier time.

    .. attribute:: number

        *CharField*: The mobile phone number to deliver to. This module requires
        using the `E.164 <http://en.wikipedia.org/wiki/E.164>`_ format. For US numbers,
        this would look like '+15555555555'.

    .. attribute:: key

        *CharField*: The secret key used to generate TOTP tokens.

    .. attribute:: last_t

        *BigIntegerField*: The t value of the latest verified token.

    """

    number = models.CharField(
        max_length=30, help_text="The mobile number to deliver tokens to (E.164)."
    )

    key = models.CharField(
        max_length=40,
        validators=[key_validator],
        default=default_key,
        help_text="A random key used to generate tokens (hex-encoded).",
    )

    last_t = models.BigIntegerField(
        default=-1,
        help_text="The t value of the latest verified token. The next token must be at a higher time step.",
    )

    class Meta(Device.Meta):
        verbose_name = "MessageBird SMS Device"

    @property
    def bin_key(self):
        return unhexlify(self.key.encode())

    def generate_challenge(self):
        """
        Sends the current TOTP token to ``self.number``.

        :returns: :setting:`OTP_MESSAGEBIRD_CHALLENGE_MESSAGE` on success.
        :raises: Exception if delivery fails.

        """
        totp = self.totp_obj()
        token = format(totp.token(), "06d")
        token_template = getattr(settings, "OTP_MESSAGEBIRD_TOKEN_TEMPLATE", None)
        if callable(token_template):
            token_template = token_template(self)
        message = token_template.format(token=token)

        if settings.OTP_MESSAGEBIRD_NO_DELIVERY:
            logger.info(message)
        else:
            self._deliver_token(message)

        challenge_message = getattr(settings, "OTP_MESSAGEBIRD_CHALLENGE_MESSAGE", None)
        if callable(challenge_message):
            challenge_message = challenge_message(self)
        challenge = challenge_message.format(token=token)

        return challenge

    def _deliver_token(self, token):
        self._validate_config()

        client = messagebird.Client(settings.OTP_MESSAGEBIRD_ACCESS_KEY)
        try:
            client.message_create(
                originator=settings.OTP_MESSAGEBIRD_FROM,
                recipients=self.number.replace("+", ""),
                body=str(token),
            )
        except messagebird.client.ErrorException as e:
            logger.exception("Error sending token by MessageBird SMS: {0}".format(e))
            raise

    def _validate_config(self):
        if settings.OTP_MESSAGEBIRD_ACCESS_KEY is None:
            raise ImproperlyConfigured(
                "OTP_MESSAGEBIRD_ACCESS_KEY must be set to your MessageBird access key"
            )

        if settings.OTP_MESSAGEBIRD_FROM is None:
            raise ImproperlyConfigured(
                "OTP_MESSAGEBIRD_FROM must be set to one of your MessageBird phone numbers or a string"
            )

    def verify_token(self, token):
        try:
            token = int(token)
        except Exception:
            verified = False
        else:
            totp = self.totp_obj()
            tolerance = settings.OTP_MESSAGEBIRD_TOKEN_VALIDITY

            for offset in range(-tolerance, 1):
                totp.drift = offset
                if (totp.t() > self.last_t) and (totp.token() == token):
                    self.last_t = totp.t()
                    self.save()

                    verified = True
                    break
            else:
                verified = False

        return verified

    def totp_obj(self):
        totp = TOTP(self.bin_key, step=1)
        totp.time = time.time()

        return totp
