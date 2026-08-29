from django.db.models.signals import pre_save
from django.dispatch import receiver
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

from .models import User


@receiver(pre_save, sender=User)
def revoke_user_tokens_on_security_change(sender, instance: User, **kwargs):
    if not instance.pk:
        return

    previous = sender.objects.filter(pk=instance.pk).values(
        'password', 'is_active', 'two_factor_enabled', 'session_version'
    ).first()
    if not previous:
        return

    password_changed = previous['password'] != instance.password
    account_deactivated = previous['is_active'] and not instance.is_active
    two_factor_disabled = previous['two_factor_enabled'] and not instance.two_factor_enabled

    if not (password_changed or account_deactivated or two_factor_disabled):
        return

    instance.session_version = previous['session_version'] + 1

    outstanding = OutstandingToken.objects.filter(user_id=instance.pk)
    for token in outstanding.iterator():
        BlacklistedToken.objects.get_or_create(token=token)
