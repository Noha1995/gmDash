import logging

from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.conf import settings
from .agent import SKEY_AGENT


@receiver(user_logged_in)
def sig_user_logged_in(sender, user, request, **kwargs):
    request.session[SKEY_AGENT] = None
    log = logging.getLogger('django')
    log.info("user logged in: %s at %s" % (user, request.META['REMOTE_ADDR']))


@receiver(user_logged_out)
def sig_user_logged_out(sender, user, request, **kwargs):
    request.session[SKEY_AGENT] = None
    request.session['selected_email'] = None

    log = logging.getLogger('django')
    log.info("user logged out: %s at %s" % (user, request.META['REMOTE_ADDR']))
