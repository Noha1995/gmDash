import os

import oauth2client
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.db.models import Q
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, permission_required
from django.urls import reverse
from django.views.decorators.http import require_http_methods
from googleapiclient.errors import HttpError
import logging

from dashboard.gapi import GapiUsersMessages
from dashboard.models import MailAccount, MailAccountUser, MailUserCredential, CustomerMailData
from dashboard.agent import GROUP_ADMIN, GROUP_USERA, GROUP_USERB, SKEY_AGENT
from .forms import MailAccountForm, FilterActionForm, FilterCriteriaForm, MailAccountMultipleForm, \
    MailUserCredentialForm, CustomerMailDataForm
from dashboard import gapi
import time
import math
import datetime
from .agent import Agent

from django.contrib import messages
from django.conf import settings
import json, csv
import pandas as pd

log = logging.getLogger('django')


# logging.basicConfig(filename='applog.log',
#                             filemode='a',
#                             format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
#                             datefmt='%H:%M:%S',
#                             level=logging.DEBUG)

@login_required
def index(request):
    return redirect('mail_accounts')
    # return HttpResponse("Hello, world. You're at the index.")


@login_required
def accounts(request):
    return render(request, "dashboard.html")


@login_required
def mail_accounts(request):
    """
    Show the gmail accounts list.

    :param request:
    :return:
    """
    # Search keyword
    search = request.session.get('search')
    user_id = request.session.get('user_name')

    if not search:
        search = {}
    if not user_id:
        user_id = {}

    if request.method == 'POST':
        if request.POST.get('search[keyword]'):
            search['keyword'] = request.POST.get('search[keyword]')
        else:
            search['keyword'] = None
        request.session['search'] = search
        if request.POST.get('user_name'):
            user_id['keyword'] = request.POST.get('user_name')
        else:
            user_id['keyword'] = None
        request.session['user_name'] = user_id

        return redirect('mail_accounts')

    # Querying the mail_account table by user's role and search keyword.
    accounts_qs = MailAccount.objects.all()
    if not Agent.is_site_superuser(request):
        accounts_qs = accounts_qs.filter(mailaccountuser__user_id=Agent.dashboard_user(request).id).all()

    if search.get('keyword'):
        accounts_qs = accounts_qs.filter(email__contains=search.get('keyword'))
    if user_id.get('keyword') and user_id.get('keyword') != '0':
        accounts_qs = accounts_qs.filter(mailaccountuser__user_id=user_id.get('keyword'))
    users = User.objects.all()
    return render(request, "mail_accounts.html", {
        'accounts': accounts_qs,
        'search': search,
        'user_name': int(user_id.get('keyword') or 0),
        'users': users
    })


@login_required
def mail_account_add(request):
    """
    Add the bulk gmail accounts line by line.

    :param request:
    :return:
    """
    if not Agent.is_site_superuser(request):
        messages.error(request, 'Invalid permission')
        return redirect('mail_accounts')

    mail_form = MailAccountMultipleForm()

    if request.method == 'POST':
        mail_form = MailAccountMultipleForm(request.POST)
        if mail_form.is_valid():
            emails = mail_form.cleaned_data.get('emails')
            user = mail_form.cleaned_data.get('user')

            if emails:
                cnt = 0
                for email in emails:
                    mail_account, created = MailAccount.objects.get_or_create(email=email)
                    if created:
                        mail_account.email = email
                        mail_account.save()

                    mail_account_user = MailAccountUser.objects.filter(mail_account_id=mail_account.id).first()
                    if not mail_account_user:
                        mail_account_user = MailAccountUser()

                        mail_account_user.mail_account_id = mail_account.id
                        mail_account_user.user_id = user
                        mail_account_user.save()
                        cnt += 1
                    else:
                        messages.info(request, "'%s' already exists." % email)
                if cnt > 0:
                    messages.success(request, "Added %s email(s) successfully." % cnt)
                return redirect('mail_accounts')

            messages.error(request, "No emails specified.")
        else:
            messages.error(request, mail_form.errors)

    return render(request, "mail_account_add.html", {'form': mail_form})


@login_required
def mail_account_delete(request, id):
    """
    Delete the registered gmail account by primary key 'id'

    :param request:
    :param id:
    :return:
    """
    if not Agent.is_site_superuser(request):
        messages.error(request, 'Invalid permission')
        return redirect('mail_accounts')

    account = MailAccount.objects.filter(id=id).first()

    if account:
        account.delete()
        messages.success(request, "Deleted '%s' successfully." % account.email)
    else:
        messages.error(request, "There is no account with ID '%s'." % id)
    return redirect('mail_accounts')


@login_required
def mail_filters(request):
    """
    Show the gmail filters list for the selected email.

    :param request:
    :return:
    """
    selected_email = ''
    if request.method == 'POST':
        request.session['selected_email'] = request.POST['selected_email']
        return redirect('mail_filters')

    # get the selected email address in session
    selected_email = request.session.get('selected_email', '')
    accounts = MailAccount.get_active_mail_accounts(Agent.dashboard_user(request))

    account = MailAccount.objects.filter(email=selected_email).first()
    filters = []
    if account:
        if account.user_id:
            credentials = gapi.get_stored_credentials(account.user_id)
            if credentials and credentials.refresh_token is not None:
                try:
                    result = gapi.GapiFilters.get_filters(credentials)
                    if result and 'filter' in result:
                        filters += result['filter']
                except HttpError as e:
                    resp_str = e.content.decode(encoding="utf-8")
                    error = json.loads(resp_str)
                    error = error.get('error')
                    if error and error.get('errors'):
                        errors = error.get('errors')
                        if errors:
                            messages.error(request, "Failed to create filter on " + account.email + "." + errors[0].get('message'))
                            log.error('[Filter Create]\t %s' % (errors[0].get('message'),))
                except oauth2client.client.HttpAccessTokenRefreshError as e1:
                    log.error("[Add Filter]Failed to add filer on %s. Details: %s" % (account.email, str(e1)))
                    show_invalid_access_token(request, account.email, account.id)

            else:
                log.info('no credential for %s' % account.email)
                show_no_credential_msg(request, account.email, account.id)
        else:
            log.info('no credential for %s' % account.email)
            show_no_credential_msg(request, account.email, account.id)

            # redirect to get the authentication
            # url = gapi.get_authorization_url(account.email, 'state_code')
            # return HttpResponseRedirect(url)

    return render(request,
                  "mail_filters.html", {
                      'filters': filters,
                      'accounts': accounts,
                      'selected_email': selected_email
                  })


@login_required
def mail_filter_add(request):
    """
    Add a filter for the multiple accounts.
    User can select the emails to apply a filter.
    User can use the existed filter to create a new filter.

    :param request:
    :return:
    """
    accounts = MailAccount.get_active_mail_accounts(Agent.dashboard_user(request))
    context = {
        'filter_emails': ''
    }
    # Forms
    action = FilterActionForm()
    criteria = FilterCriteriaForm()

    # we add a filter
    if request.method == 'POST':
        filter_by_email = request.POST.get('filter_by_email')
        if filter_by_email == '1':
            context['filter_emails'] = request.POST.get('filter_emails').strip()
            if request.POST.get('filter_emails').strip() != '':
                emails = request.POST.get('filter_emails').strip().splitlines()
                accounts = MailAccount.get_active_mail_accounts(Agent.dashboard_user(request)).filter(email__in=emails).all()
        else:
            emails_applied = request.POST.getlist('emails_applied[]')
            action = FilterActionForm(request.POST)
            criteria = FilterCriteriaForm(request.POST)

            success_cnt = 0
            fail_cnt = 0

            if emails_applied and action.is_valid() and criteria.is_valid():
                for email in emails_applied:
                    account = MailAccount.objects.filter(email=email).first()
                    if account and account.user_id:
                        credentials = gapi.get_stored_credentials(account.user_id)
                        if credentials and credentials.refresh_token is not None:
                            filter = {
                                'criteria': criteria.get_google_data(),
                                'action': action.get_google_data()
                            }

                            try:
                                result = gapi.GapiFilters.create_filter(credentials, filter)
                                if result.get('id'):
                                    success_cnt += 1
                                    # messages.success(request,
                                    #                  "Created the filter '%s' on %s successfully." % (
                                    #                      result.get('id'), email))
                                    log.info("[Filter Create]\tSuccess on %s." % email)
                                else:
                                    fail_cnt += 1
                                    log.error("[Filter Create]\tFailed to create the filter on %s." % email)
                            except HttpError as e:
                                fail_cnt += 1
                                resp_str = e.content.decode(encoding="utf-8")
                                error = json.loads(resp_str)
                                error = error.get('error')
                                if error and error.get('errors'):
                                    errors = error.get('errors')
                                    if errors:
                                        messages.error(request, "Failed to create filter on " + account.email + "." + errors[0].get('message'))
                                        log.error('[Add Filter]\t %s' % (errors[0].get('message'),))
                            except oauth2client.client.HttpAccessTokenRefreshError as e1:
                                log.error("[Add Filter]Failed to create filer on %s. Details: %s" % (account.email, str(e1)))
                                show_invalid_access_token(request, account.email, account.id)
                        else:
                            fail_cnt += 1
                            messages.error(request, "Failed to create the filter on %s.  There is no credential information. <br /> \
                                    <a href='get_gmail_auth/%s' class=''>Refresh Auth please.</a>" % (email, account.id))
                            log.error("Failed to create the filter on %s.  There is no credential information. <br /> \
                                    <a href='get_gmail_auth/%s' class=''>Refresh Auth please.</a>" % (email, account.id))
                    else:
                        fail_cnt += 1
                        log.error("Failed to create the filter on %s.  <br />There is no credential or account information. <br /> \
                                                        <a href='get_gmail_auth/%s' class=''>Refresh Auth please.</a>" % (email, account.id))
                        messages.error(request, "Failed to create the filter on %s.  <br />There is no credential or account information. <br /> \
                                                        <a href='get_gmail_auth/%s' class=''>Refresh Auth please.</a>" % (email, account.id))

                if success_cnt > 0:
                    messages.success(request, 'Added a filter on %s emails successfully.' % success_cnt)

                if fail_cnt > 0:
                    messages.error(request, 'Failed to add a filter on %s emails.' % fail_cnt)
                    log.error('Failed to add a filter on %s emails.' % fail_cnt)

                return redirect('mail_filters')
            else:
                log.error("Please select the emails to apply filters.")
                messages.error(request, "Please select the emails to apply filters.")

    if request.session.get('copied_email'):
        copied_email = request.session.get('copied_email')
        copied_filter = request.session.get('copied_filter')

        criteria.set_google_data(copied_filter.get('criteria'))
        action.set_google_data(copied_filter.get('action'))

        request.session['copied_email'] = None
        request.session['copied_filter'] = None

    context['accounts'] = accounts
    context['action'] = action
    context['criteria'] = criteria

    return render(request, "mail_filter_add.html", context)


@login_required
def mail_filter_copy(request):
    """
    To make creating a filter easy, user can copy the filter from filters list page.

    :param request:
    :return:
    """
    copied_email = request.POST.get('copied_email')
    copied_filter = request.POST.get('copied_filter')
    copied_filter = copied_filter.replace("\'", "\"")
    copied_filter = json.loads(copied_filter)

    request.session['copied_email'] = copied_email
    request.session['copied_filter'] = copied_filter

    return redirect("mail_filter_add")


@login_required
def mail_filter_delete(request, filter_id):
    """
    Remove the gmail filter by filter_id

    :param request:
    :param filter_id:
    :return:
    """

    selected_email = request.session.get('selected_email', '')
    account = MailAccount.objects.filter(email=selected_email).first()
    if account and account.user_id:
        credentials = gapi.get_stored_credentials(account.user_id)
        if credentials and credentials.refresh_token is not None:
            try:
                result = gapi.GapiFilters.delete_filter(credentials, filter_id)
                if not result:
                    messages.success(request, "Removed the filter successfully.")
                    log.info("Success: Removed the filter successfully.")
                else:
                    messages.error(request, "Failed to remove the filter. Try again later.")
                    log.error("Error: Failed to remove the filter. Try again later.")
            except HttpError as e:
                resp_str = e.content.decode(encoding="utf-8")
                error = json.loads(resp_str)
                error = error.get('error')
                if error and error.get('errors'):
                    errors = error.get('errors')
                    if errors:
                        messages.error(request, "Failed to delete filter on " + account.email + "." + errors[0].get('message'))
                        log.error('[Delete Filter]\t %s' % (errors[0].get('message'),))
            except oauth2client.client.HttpAccessTokenRefreshError as e1:
                log.error("[Delete Filter]Failed to delete filer on %s. Details: %s" % (account.email, str(e1)))
                show_invalid_access_token(request, account.email, account.id)
        else:
            messages.error(request, "Credential no exists or expired. Need to redirect to get the authorization.")
            log.error("Error: Credential no exists or expired. Need to redirect to get the authorization.")
    else:
        messages.error(request, "Invalid parameters to delete the filter.")
        log.error("Invalid parameters to delete the filter.")

    return redirect('mail_filters')


@login_required
@require_http_methods(["POST"])
def mail_filter_delete_all(request):
    """
    Remove the bulk filters on current gmail account.
    If user is super user, he can delete all. Other users can only delete their gmail accounts.

    :param request:
    :return:
    """

    selected_email = request.session.get('selected_email', '')

    account = MailAccount.objects.filter(email=selected_email).first()
    if account and account.user_id:
        credentials = gapi.get_stored_credentials(account.user_id)
        if credentials and credentials.refresh_token is not None:

            success_cnt = 0
            fail_cnt = 0
            filter_ids = request.POST.getlist('filter_ids[]')

            for filter_id in filter_ids:
                try:
                    result = gapi.GapiFilters.delete_filter(credentials, filter_id)
                    if not result:
                        success_cnt += 1
                        log.info("Success: Removed the filter successfully.")
                    else:
                        fail_cnt += 1
                        log.error("Error: Failed to remove the filter. Try again later.")
                except HttpError as e:
                    fail_cnt += 1
                    resp_str = e.content.decode(encoding="utf-8")
                    error = json.loads(resp_str)
                    error = error.get('error')
                    if error and error.get('errors'):
                        errors = error.get('errors')
                        if errors:
                            messages.error(request, "Failed to batch delete filter on " + account.email + "." + errors[0].get('message'))
                            log.error('[Batch Delete Filter]\t %s' % (errors[0].get('message'),))
                except oauth2client.client.HttpAccessTokenRefreshError as e1:
                    log.error("[Batch Delete Filter]Failed to batch delete filer on %s. Details: %s" % (account.email, str(e1)))
                    show_invalid_access_token(request, account.email, account.id)
                    break

            if success_cnt > 0:
                messages.success(request, 'Deleted %s filter(s) on %s email successfully.' % (success_cnt, selected_email))
            if fail_cnt > 0:
                messages.error(request, 'Failed to delete %s filter(s) on %s emails.' % (fail_cnt, selected_email))

        else:
            messages.error(request, "Credential no exists or expired. Need to redirect to get the authorization.")
            log.error("Error: Credential no exists or expired. Need to redirect to get the authorization.")
    else:
        messages.error(request, "Invalid parameters to delete the filter.")
        log.error("Invalid parameters to delete the filter.")

    return redirect('mail_filters')


@login_required
@require_http_methods(["GET"])
def mail_filter_delete_all_on_accounts(request):
    """
    Remove the bulk filters on all gmail accounts.
    If user is super user, he can delete all. Other users can only delete their gmail accounts.

    :param request:
    :return:
    """

    accounts = MailAccount.get_active_mail_accounts(Agent.dashboard_user(request))
    success_cnt = 0
    fail_cnt = 0

    for account in accounts:
        if account.user_id:
            credentials = gapi.get_stored_credentials(account.user_id)
            if credentials and credentials.refresh_token is not None:
                result = gapi.GapiFilters.get_filters(credentials)
                if result and 'filter' in result:
                    filters = result['filter']

                    for filter in filters:
                        filter_id = filter.get('id')
                        try:
                            result = gapi.GapiFilters.delete_filter(credentials, filter_id)
                            if not result:
                                # success_cnt += 1
                                log.info("Success: Removed the filter successfully.")
                            else:
                                # fail_cnt += 1
                                log.error("[Batch Filter Delete]: Failed to delete the filter. Try again later.")
                        except HttpError as e:
                            fail_cnt += 1
                            resp_str = e.content.decode(encoding="utf-8")
                            error = json.loads(resp_str)
                            error = error.get('error')
                            if error and error.get('errors'):
                                errors = error.get('errors')
                                if errors:
                                    messages.error(request, "Failed to batch delete filter on " + account.email + "." + errors[0].get('message'))
                                    log.error('[Batch Filter Delete]\t %s' % (errors[0].get('message'),))
                        except oauth2client.client.HttpAccessTokenRefreshError as e1:
                            log.error("[Batch Filter Delete]Failed to add filer on %s. Details: %s" % (account.email, str(e1)))
                            show_invalid_access_token(request, account.email, account.id)
                            break

                    success_cnt += 1
                else:
                    fail_cnt += 1
            else:
                fail_cnt += 1
                # messages.error(request, "Credential no exists or expired for %s. Need to redirect to get the authorization." % account.email)
                log.error("[Filter Delete] Credential no exists or expired for %s. Need to redirect to get the authorization." % account.email)

    if success_cnt > 0:
        messages.success(request, 'Deleted all filters on %s emails successfully.' % (success_cnt,))
    if fail_cnt > 0:
        messages.error(request, 'Failed to delete all filters on %s emails.' % (fail_cnt,))
        log.error('[Filter Delete] Failed to delete all filters on %s emails.' % (fail_cnt,))

    return redirect('mail_filters')


@login_required
@require_http_methods(["POST"])
def inbox_delete_all_on_accounts(request):
    """
    Remove the bulk emails on all gmail accounts.
    If user is super user, he can delete all. Other users can only delete their gmail accounts.

    :param request:
    :return:
    """
    ids = request.POST.getlist('ids[]')
    delete_type = request.POST.get('delete_type')
    if len(ids) < 1:
        messages.error(request, "Please select an email account at least.")
        return redirect('mail_accounts')

    accounts = MailAccount.objects.exclude(Q(user_id__isnull=True) | Q(user_id__exact='')).filter(pk__in=ids).all()
    if not Agent.is_site_superuser(request):
        accounts = accounts.filter(mailaccountuser__user_id=Agent.dashboard_user(request).id)

    if delete_type == "1":
        MailAccount.objects.filter(pk__in=ids).delete()
        messages.success(request, 'Deleted the selected messages successfully.')
        return redirect('mail_accounts')

    success_cnt = 0
    fail_cnt = 0
    success_msg_cnt = 0
    fail_msg_cnt = 0

    for account in accounts:
        success_msg_cnt = 0
        fail_msg_cnt = 0
        if account.user_id:
            credentials = gapi.get_stored_credentials(account.user_id)
            if credentials and credentials.refresh_token is not None:
                try:
                    gapi.GapiWrap.set_credential(credentials)
                    result = gapi.GapiUsersMessages.delete_all('me', 100, ['INBOX'])

                    if not result['error']:
                        fail_msg_cnt = result['data']['deleted']
                        success_msg_cnt = result['data']['cnt']
                        success_cnt += 1

                        log.info('Deleted %s/%s messages from %s' % (success_msg_cnt, success_msg_cnt + fail_msg_cnt, account.email))
                    else:
                        log.error("[Inbox Delete]: %s" % result['error'])
                        messages.error(request, 'Failed to delete all messages from %s' % account.email)
                        fail_cnt += 1
                except HttpError as e:
                    fail_cnt += 1
                    resp_str = e.content.decode(encoding="utf-8")
                    error = json.loads(resp_str)
                    error = error.get('error')
                    if error and error.get('errors'):
                        errors = error.get('errors')
                        if errors:
                            messages.error(request, "Failed to delete messages on " + account.email + "." + errors[0].get('message'))
                            log.error('[Filter Create]\t %s' % (errors[0].get('message'),))
                except oauth2client.client.HttpAccessTokenRefreshError as e1:
                    log.error("[Delete inbox]Failed to delete messages on %s. Details: %s" % (account.email, str(e1)))
                    show_invalid_access_token(request, account.email, account.id)
            else:
                fail_cnt += 1
                log.error("[Inbox Delete]: Credential no exists or expired for %s. Need to redirect to get the authorization." % account.email)

    if success_cnt > 0:
        messages.success(request, 'Deleted all messages on %s emails successfully.' % (success_cnt,))
    if fail_cnt > 0:
        log.error('[Inbox Delete]: Failed to delete all messages on %s emails.' % (fail_cnt,))
        messages.error(request, 'Failed to delete all messages on %s emails.' % (fail_cnt,))

    return redirect('mail_accounts')


@login_required
def mail_vacation_settings(request):
    selected_email = None
    if request.method == 'POST':
        request.session['selected_email'] = request.POST['selected_email']
        return redirect('mail_vacation_settings')

    # get the selected email address in session
    selected_email = request.session.get('selected_email', '')
    accounts = MailAccount.get_active_mail_accounts(Agent.dashboard_user(request))
    account = MailAccount.objects.filter(email=selected_email).first()
    vacation = None

    if account:
        if account.user_id:
            credentials = gapi.get_stored_credentials(account.user_id)
            if credentials and credentials.refresh_token is not None:
                try:
                    result = gapi.GapiVacations.get_vacation_settings(credentials)

                    if 'startTime' in result:
                        result['startTime'] = datetime.datetime.fromtimestamp(int(result['startTime']) / 1000).strftime(
                            "%Y-%m-%d")

                    if 'endTime' in result:
                        result['endTime'] = datetime.datetime.fromtimestamp(int(result['endTime']) / 1000).strftime(
                            "%Y-%m-%d")
                    vacation = result
                except HttpError as e:
                    resp_str = e.content.decode(encoding="utf-8")
                    error = json.loads(resp_str)
                    error = error.get('error')
                    if error and error.get('errors'):
                        errors = error.get('errors')
                        if errors:
                            messages.error(request, "Failed to update vacation setting on " + account.email + "." + errors[0].get('message'))
                            log.error('[Vacation Setting]\t %s' % (errors[0].get('message'),))
                except oauth2client.client.HttpAccessTokenRefreshError as e1:
                    log.error("[Vacation Setting]Failed to update vacation setting on %s. Details: %s" % (account.email, str(e1)))
                    show_invalid_access_token(request, account.email, account.id)

            else:
                show_no_credential_msg(account.email, account.id)
                print('no credential')
                # url = gapi.get_authorization_url(account.email, 'state_code')
                # return HttpResponseRedirect(url)
        else:
            show_no_credential_msg(account.email, account.id)
            print('no credential')
            # redirect to get the authentication
            # url = gapi.get_authorization_url(account.email, 'state_code')
            # return HttpResponseRedirect(url)

    context = {
        'accounts': accounts,
        'vacation': vacation,
        'selected_email': selected_email
    }
    return render(request, "mail_vacation_settings.html", context)


@login_required
def mail_vacation_multi_settings(request):
    """
    View page to show the vacation setting form.

    :param request:
    :return:
    """

    selected_email = None
    # get the selected email address in session
    selected_email = request.session.get('selected_email', '')
    accounts = MailAccount.get_active_mail_accounts(Agent.dashboard_user(request))
    account = MailAccount.objects.filter(email=selected_email).first()
    vacation = None
    context = {
        'accounts': accounts,
        'vacation': vacation,
        'selected_email': selected_email
    }
    if account:
        if account.user_id:
            credentials = gapi.get_stored_credentials(account.user_id)
            if credentials and credentials.refresh_token is not None:
                try:
                    result = gapi.GapiVacations.get_vacation_settings(credentials)

                    if 'startTime' in result:
                        result['startTime'] = datetime.datetime.fromtimestamp(int(result['startTime']) / 1000).strftime("%Y-%m-%d")

                    if 'endTime' in result:
                        result['endTime'] = datetime.datetime.fromtimestamp(int(result['endTime']) / 1000).strftime("%Y-%m-%d")

                    vacation = result
                except HttpError as e:
                    resp_str = e.content.decode(encoding="utf-8")
                    error = json.loads(resp_str)
                    error = error.get('error')
                    if error and error.get('errors'):
                        errors = error.get('errors')
                        if errors:
                            messages.error(request, "Failed to create filter on " + account.email + "." + errors[0].get('message'))
                            log.error('[Filter Create]\t %s' % (errors[0].get('message'),))
                except oauth2client.client.HttpAccessTokenRefreshError as e1:
                    log.error("[Vacation Multi Setting]Failed to set batch vacation setting on %s. Details: %s" % (account.email, str(e1)))
                    show_invalid_access_token(request, account.email, account.id)
            else:
                show_no_credential_msg(account.email, account.id)
                print('no credential')
                # url = gapi.get_authorization_url(account.email, 'state_code')
                # return HttpResponseRedirect(url)
        else:
            show_no_credential_msg(account.email, account.id)
            print('no credential')
            # redirect to get the authentication
            # url = gapi.get_authorization_url(account.email, 'state_code')
            # return HttpResponseRedirect(url)
    if request.method == 'POST':
        filter_by_email = request.POST.get('filter_by_email')
        if filter_by_email == '1':
            context['filter_emails'] = request.POST.get('filter_emails').strip()
            if request.POST.get('filter_emails').strip() != '':
                emails = request.POST.get('filter_emails').strip().splitlines()
                accounts = MailAccount.get_active_mail_accounts(Agent.dashboard_user(request)).filter(
                    email__in=emails).all()

    context['accounts'] = accounts
    context['vacation'] = vacation
    context['selected_email'] = selected_email

    return render(request, "mail_vacation_multi_settings.html", context)


@login_required
def mail_vacation_settings_update(request):
    """
    Set the vacation setting on the selected gmail account.

    :param request:
    :return:
    """

    selected_email = request.POST['selected_email']
    post_data = request.POST
    settings = dict(post_data.dict())

    del settings['csrfmiddlewaretoken']
    del settings['selected_email']
    settings['startTime'] = int(
        time.mktime(datetime.datetime.strptime(settings['startTime'], "%Y-%m-%d").timetuple()) * 1000)
    if settings['endTime'] and settings['endTime'] != '':
        settings['endTime'] = int(
            time.mktime(datetime.datetime.strptime(settings['endTime'], "%Y-%m-%d").timetuple()) * 1000)
    else:
        del settings['endTime']

    if settings.get('restrictToContacts') == 'on':
        settings['restrictToContacts'] = True

    # get the selected email address in session
    account = MailAccount.objects.filter(email=selected_email).first()

    if account:
        if account.user_id:
            credentials = gapi.get_stored_credentials(account.user_id)
            if credentials and credentials.refresh_token is not None:
                try:
                    result = gapi.GapiVacations.update_vacation_settings(credentials, settings)
                    print('vacation settings update ok')
                    messages.success(request, 'Updated vacation setting successfully.')
                except HttpError as e:
                    resp_str = e.content.decode(encoding="utf-8")
                    error = json.loads(resp_str)
                    error = error.get('error')
                    if error and error.get('errors'):
                        errors = error.get('errors')
                        if errors:
                            messages.error(request, "Failed to update vacation setting on " + account.email + "." + errors[0].get('message'))
                except oauth2client.client.HttpAccessTokenRefreshError as e1:
                    log.error("Failed to update vacation setting on %s. Details: %s" % (account.email, str(e1)))
                    show_invalid_access_token(request, account.email, account.id)
            else:
                print('no credential')
                show_no_credential_msg(account.email, account.id)
                # url = gapi.get_authorization_url(account.email, 'state_code')
                # return HttpResponseRedirect(url)
        else:
            show_no_credential_msg(account.email, account.id)
            print('no credential')

    return redirect('mail_vacation_settings')


@login_required
@require_http_methods(["POST"])
def mail_vacation_multi_settings_update(request):
    """
    Set the vacation setting for the multiple gmail accounts.

    :param request:
    :return:
    """

    post_data = request.POST
    settings = dict(post_data.dict())

    del settings['csrfmiddlewaretoken']

    settings['startTime'] = int(time.mktime(datetime.datetime.strptime(settings['startTime'], "%Y-%m-%d").timetuple()) * 1000)
    if settings['endTime'] and settings['endTime'] != '':
        settings['endTime'] = int(time.mktime(datetime.datetime.strptime(settings['endTime'], "%Y-%m-%d").timetuple()) * 1000)
    else:
        del settings['endTime']

    if settings.get('restrictToContacts') == 'on':
        settings['restrictToContacts'] = True

    # get the selected email address in session
    emails_applied = request.POST.getlist('emails_applied[]')

    if emails_applied:
        success_cnt = 0
        fail_cnt = 0
        for email in emails_applied:
            account = MailAccount.objects.filter(email=email).first()
            if account and account.user_id:
                credentials = gapi.get_stored_credentials(account.user_id)
                if credentials and credentials.refresh_token is not None:
                    try:
                        result = gapi.GapiVacations.update_vacation_settings(credentials, settings)
                        success_cnt += 1
                        print('vacation settings update ok')
                    except HttpError as e:
                        print(e)
                        fail_cnt += 1
                        resp_str = e.content.decode(encoding="utf-8")
                        error = json.loads(resp_str)
                        error = error.get('error')
                        if error and error.get('errors'):
                            errors = error.get('errors')
                            if errors:
                                messages.error(request, "Failed to update vacation setting(batch mode) on " + account.email + "." + errors[0].get('message'))
                    except oauth2client.client.HttpAccessTokenRefreshError as e1:
                        log.error("Failed to update vacation setting on %s. Details: %s" % (account.email, str(e1)))
                        show_invalid_access_token(request, account.email, account.id)
                else:
                    print('no credential')
                    show_no_credential_msg(request, account.email, account.id)
            else:
                show_no_credential_msg(request, account.email, account.id)
                print('no credential')

        if success_cnt > 0:
            messages.success(request, 'Updated vacation setting on %s emails successfully.' % success_cnt)
        if fail_cnt > 0:
            messages.error(request, 'Failed to update vacation setting on %s emails.' % fail_cnt)

    return redirect('mail_vacation_multi_settings')


""" 
    =========================================================================================================
    Authentication and Authorization
    =========================================================================================================
"""


@login_required
def gmail_auth_callback(request):
    """
    Callback page from Google.
    authorization code should be included.
    Using this auth code, we will get the refresh Token and access token for the future API calls.
    access token information will be stored in mail_account table on gapi.get_credentials() function.

    :param request:
    :return:
    """
    auth_code = request.GET['code']

    log.info('-' * 30)
    log.info("Auth Code:" + auth_code)

    try:
        success = set_api_setting(request)
        if not success:
            return redirect('api_credential')

        credentials = gapi.get_credentials(auth_code, 'state_code')
        log.info('-' * 30)
        log.info('Access Token:', credentials.access_token)
        log.info('Refresh Token:', credentials.refresh_token)

    except Exception as error:
        messages.error(request, error)
        log.error(error)
        return redirect('index')

    messages.success(request, 'Authorized successfully. Now you can manage the google mail settings.')
    return redirect('mail_accounts')


@login_required
def get_gmail_auth(request, id):
    """
    Called to get the authorization code from the gmail user for further managing gmail account through Gmail API.
    See Google oAuth2.0.
    After user takes several actions, page will be redirected to our callback page which is implemented above(gmail_auth_callback).

    :param request:
    :param id:      Number: ID in mail_account table
    :return:
    """

    try:
        account = MailAccount.objects.get(id=id)
    except MailAccount.DoesNotExist:
        messages.error(request, "Invalid request. There is no account with id '%s'." % id)
        log.error("[Gmail Auth error]: Invalid request. There is no account with id '%s'." % id)
        return redirect('mail_accounts')

    """ Gmail authorization """
    try:
        success = set_api_setting(request)
        if not success:
            return redirect('api_credential')
        url = gapi.get_authorization_url(account.email, 'state_code')
    except Exception as e:
        log.error("[Gmail Auth error]: %s" % e)
        messages.error(request, e)
        return redirect('mail_accounts')

    return HttpResponseRedirect(url)


""" 
    =========================================================================================================
    End of Authentication and Authorization
    =========================================================================================================
"""


@login_required
def mail_set_alias(request):
    """
    Set the SendAs Name for all gmail accounts.
    If logged in user has a Super User role, he can set SendAs Name on all of gmail accounts.
    If logged in user has a general user, he can only set it on his gmail accounts.

    :param request:
    :return:
    """

    accounts = MailAccount.get_active_mail_accounts(Agent.dashboard_user(request))
    context = {
        'filter_emails': ''
    }
    if request.method == 'POST':
        filter_by_email = request.POST.get('filter_by_email')
        if filter_by_email == '1':
            context['filter_emails'] = request.POST.get('filter_emails').strip()
            if request.POST.get('filter_emails').strip() != '':
                emails = request.POST.get('filter_emails').strip().splitlines()
                print(emails)
                accounts = MailAccount.get_active_mail_accounts(Agent.dashboard_user(request)).filter(
                    email__in=emails).all()
        else:
            emails_applied = request.POST.getlist('emails_applied[]')
            if len(emails_applied) < 1:
                messages.error(request, "Please select an email account at least.")
            else:
                full_name = request.POST.get('name').strip()

                success_cnt = 0
                fail_cnt = 0
                for email in emails_applied:
                    account = MailAccount.objects.filter(email=email).first()
                    if account and account.user_id:
                        credentials = gapi.get_stored_credentials(account.user_id)
                        if credentials and credentials.refresh_token is not None:
                            try:
                                result = gapi.GapiSetting.set_alias(credentials, full_name, '')
                                if result and result.get('displayName'):
                                    account.sender_name = result.get('displayName')
                                    success_cnt += 1
                                else:
                                    account.sender_name = '-'
                                    fail_cnt += 1
                                account.save()
                            except HttpError as e:
                                log.error(e.__str__())
                                fail_cnt += 1
                                resp_str = e.content.decode(encoding="utf-8")
                                error = json.loads(resp_str)
                                error = error.get('error')
                                if error and error.get('errors'):
                                    errors = error.get('errors')
                                    if errors:
                                        log.error("Failed to set Alias on " + account.email + "." + errors[0].get('message'))
                                        messages.error(request, "Failed to set Alias on " + account.email + "." + errors[0].get('message'))
                            except oauth2client.client.HttpAccessTokenRefreshError as e1:
                                log.error("Failed to set Alias on %s. Details: %s" % (account.email, str(e1)))
                                show_invalid_access_token(request, account.email, account.id)
                        else:
                            fail_cnt += 1
                            show_no_credential_msg(account.email, account.id)
                            log.error('no credential for %s' % account.email)
                    else:
                        fail_cnt += 1
                        show_no_credential_msg(account.email, account.id)
                        log.error('no credential for %s' % account.email)

                if success_cnt > 0:
                    messages.success(request, 'Updated sendAs setting \'%s\' on %s emails successfully.' % (full_name, success_cnt))

                if fail_cnt > 0:
                    messages.error(request, 'Failed to update sendAs setting on %s emails.' % fail_cnt)

                #return redirect('mail_accounts')

    context['accounts'] = accounts
    return render(request, "mail_set_alias.html", context)

@login_required
def mail_send(request):
    """
    Send messages from the registered emails to the customers.
    Args:
        request: Client Page Request
    Returns:
    """
    accounts = MailAccount.get_active_mail_accounts(Agent.dashboard_user(request))
    customer_data = CustomerMailData.objects.all()
    context = {
        'filter_emails': ''
    }
    if request.method == 'POST':
        filter_by_email = request.POST.get('filter_by_email')
        if filter_by_email == '1':
            context['filter_emails'] = request.POST.get('filter_emails').strip()
            if request.POST.get('filter_emails').strip() != '':
                emails = request.POST.get('filter_emails').strip().splitlines()
                accounts = MailAccount.get_active_mail_accounts(Agent.dashboard_user(request)).filter(
                    sender_name__in=emails).all()
        else:
            emails_applied = request.POST.getlist('emails_applied[]')
            email_data_id = request.POST.get('to_email')
            print(email_data_id)
            email_data = CustomerMailData.objects.filter(id=email_data_id).first()
            to_emails = []
            if email_data.email_data.name.endswith('.xlsx'):
                df = pd.read_excel(os.path.join(settings.EMAILDATA_BASE_PATH, str(email_data.id)+'_'+email_data.email_data.name), sheet_name=0, header=None)
                file_data = df.to_dict()[0]
                to_emails = [file_data[item] for item in file_data]

            elif email_data.email_data.name.endswith('.xls'):
                df = pd.read_excel(os.path.join(settings.EMAILDATA_BASE_PATH, str(email_data.id)+'_'+email_data.email_data.name), sheet_name=0, header=None)
                file_data = df.to_dict()[0]
                to_emails = [file_data[item] for item in file_data]

            elif email_data.email_data.name.endswith('.csv'):
                df = pd.read_csv(os.path.join(settings.EMAILDATA_BASE_PATH, str(email_data.id)+'_'+email_data.email_data.name), header=None)
                file_data = df.to_dict()[0]
                to_emails = [file_data[item] for item in file_data]

            elif email_data.email_data.name.endswith('.txt'):
                df = pd.read_csv(os.path.join(settings.EMAILDATA_BASE_PATH, str(email_data.id)+'_'+email_data.email_data.name), header=None)
                file_data = df.to_dict()[0]
                to_emails = [file_data[item] for item in file_data]

            # to_emails = to_emails.strip().splitlines()
            subject = request.POST.get('subject')
            message = request.POST.get('message')
            frequency = int(request.POST.get('frequency'))
            recipient_emails = request.POST.get('recipient_emails')
            recipient_emails = recipient_emails.strip().split(',')

            if len(emails_applied) < 1 or subject == '' or len(to_emails) < 1\
                or message == '' or len(recipient_emails) < 1:
                if len(emails_applied) < 1:
                    messages.error(request, "Please select an email account at least.")
                if len(to_emails) < 1:
                    messages.error(request, "Please input the receiver emails.")
                if subject == '':
                    messages.error(request, "Please input subject.")
                if message == '':
                    messages.error(request, "Please input message.")
                if len(recipient_emails) < 1:
                    messages.error(request, "Please input recipient emails.")
            elif len(emails_applied)*settings.MAIL_SEND_LIMIT_PER_DAY < (len(to_emails) + math.ceil((len(to_emails)*len(recipient_emails))/frequency)):
                messages.error(request, "The emails can\'t be sent by the selected emails.")
            else:
                mail_num = 0
                success_cnt = 0
                fail_cnt = 0
                sender_pos = 0
                for i in range(len(to_emails)):
                    if mail_num != 0 and mail_num % settings.MAIL_SEND_LIMIT_PER_DAY == 0:
                        sender_pos += 1
                    account = MailAccount.objects.filter(email=emails_applied[sender_pos]).first()
                    if account and account.user_id:
                        credentials = gapi.get_stored_credentials(account.user_id)
                        if credentials and credentials.refresh_token is not None:
                            try:
                                result = gapi.GapiUsersMessages.send(request, credentials, emails_applied[sender_pos], to_emails[i], subject, message)
                                if result and result.get('id'):
                                    messages.success(request, 'Sent message to %s successfully. Num: %s' %
                                                     (to_emails[i], i+1))
                                    log.info('Sent message to %s successfully. Num: %s' %
                                             (to_emails[i], i+1))
                                    success_cnt += 1
                                else:
                                    fail_cnt += 1
                                    messages.error(request, 'Failed to Send message to %s. Num: %s' %
                                                   (to_emails[i], i+1))
                                    log.error('Failed to Send message to %s. Num: %s' %
                                              (to_emails[i], i+1))
                            except HttpError as e:
                                log.error(e.__str__())
                                resp_str = e.content.decode(encoding="utf-8")
                                error = json.loads(resp_str)
                                error = error.get('error')
                                if error and error.get('errors'):
                                    errors = error.get('errors')
                                    if errors:
                                        log.error(
                                            "Failed to send message on " + account.email + "." + errors[0].get('message'))
                                        messages.error(request,
                                                       "Failed to send message on " + account.email + "." + errors[0].get(
                                                           'message'))
                                fail_cnt += 1
                                messages.error(request, 'Failed to Send message to %s' %
                                               to_emails[i])
                                log.error('Failed to Send message to %s. Num: %s' %
                                          (to_emails[i], i+1))
                                print('An error occurred on %s: %s' % (to_emails[i], e))

                            except oauth2client.client.HttpAccessTokenRefreshError as e1:
                                log.error("Failed to send message on %s. Details: %s" % (account.email, str(e1)))
                                show_invalid_access_token(request, account.email, account.id)
                            mail_num += 1

                            print(emails_applied[sender_pos], to_emails[i], i, frequency, (i+1)%frequency)
                            if (i+1) % frequency == 0:
                                for recipient in recipient_emails:
                                    if mail_num != 0 and mail_num % settings.MAIL_SEND_LIMIT_PER_DAY == 0:
                                        sender_pos += 1
                                    account = MailAccount.objects.filter(email=emails_applied[sender_pos]).first()
                                    if account and account.user_id:
                                        credentials = gapi.get_stored_credentials(account.user_id)
                                        if credentials and credentials.refresh_token is not None:
                                            try:
                                                result = gapi.GapiUsersMessages.send(request, credentials,
                                                                                     emails_applied[sender_pos],
                                                                                     recipient.strip(), 'Sending Process',
                                                                                     'Checking frequency: %s' % frequency)
                                                if result and result.get('id'):
                                                    messages.info(request,
                                                                     'Sent the check message to %s successfully.' %
                                                                     recipient.strip())
                                                    log.info('Sent the check message to %s successfully.' %
                                                             recipient.strip())
                                                else:
                                                    messages.warning(request, 'Failed to Send the check message to %s.' %
                                                                   recipient)
                                                    log.error('Failed to Send message to %s.' %
                                                              recipient)
                                            except HttpError as e:
                                                log.error(e.__str__())
                                                resp_str = e.content.decode(encoding="utf-8")
                                                error = json.loads(resp_str)
                                                error = error.get('error')
                                                if error and error.get('errors'):
                                                    errors = error.get('errors')
                                                    if errors:
                                                        log.error(
                                                            "Failed to send message on " + account.email + "." + errors[
                                                                0].get('message'))
                                                        messages.warning(request,
                                                                       "Failed to send message on " + account.email + "." +
                                                                       errors[0].get(
                                                                           'message'))
                                                messages.warning(request, 'Failed to Send the check message to %s' %
                                                               recipient)
                                                log.error('Failed to Send the check message to %s. ' %
                                                          recipient)
                                                print('An error occurred on %s: %s' % (to_emails[i], e))

                                            except oauth2client.client.HttpAccessTokenRefreshError as e1:
                                                    log.error("Failed to send message on %s. Details: %s" % (
                                                    account.email, str(e1)))
                                                    show_invalid_access_token(request, account.email, account.id)
                                            mail_num += 1
                                        else:
                                            show_no_credential_msg(account.email, account.id)
                                            log.error('no credential for %s' % account.email)
                                    else:
                                        show_no_credential_msg(account.email, account.id)
                                        log.error('no credential for %s' % account.email)

                        else:
                            show_no_credential_msg(account.email, account.id)
                            log.error('no credential for %s' % account.email)
                    else:
                        show_no_credential_msg(account.email, account.id)
                        log.error('no credential for %s' % account.email)

    context['accounts'] = accounts
    context['customer_data'] = customer_data

    return render(request, "mail_send.html", context)

@login_required
def api_credential(request):
    """
    To manage the multiple gmail accounts, uploade the Gmail API credential on server.
    Credential file is a JSON file, which can be downloaded from Google API console.
    Note: the credential JSON file should include the REDIRECT_URI.

    :param request:
    :return:
    """
    user = Agent.dashboard_user(request)
    cred, created = MailUserCredential.objects.get_or_create(user=user)

    if request.method == 'POST':
        form = MailUserCredentialForm(request.POST, request.FILES)

        if form.is_valid():

            if 'credential' in request.FILES:
                folder = settings.CLIENTSECRETS_BASE_PATH
                uploaded_filename = user.username + "_" + request.FILES['credential'].name

                # create the folder if it doesn't exist.
                try:
                    # Checking the old file and remove it.
                    if not os.path.exists(os.path.join(settings.BASE_DIR, folder)):
                        os.mkdir(os.path.join(settings.BASE_DIR, folder))
                except Exception as e:
                    messages.error(request, e)
                    log.error("[API Credential] %s" % e)

                # save the uploaded file inside that folder.
                full_filename = os.path.join(settings.BASE_DIR, folder, uploaded_filename)
                log.info('full_filename: ' + full_filename)

                try:
                    # Checking the old file and remove it.
                    if os.path.exists(full_filename):
                        os.remove(full_filename)

                    fout = open(full_filename, 'wb+')

                    file_content = ContentFile(request.FILES['credential'].read())

                    # Iterate through the chunks.
                    cred.credential_detail = ''
                    for chunk in file_content.chunks():
                        fout.write(chunk)
                        cred.credential_detail += chunk.decode(encoding="utf-8")
                    fout.close()
                    cred.credential = uploaded_filename
                    messages.success(request, "Uploaded the file successfully.")
                except Exception as e:
                    log.error("[API Credential] %s" % e)
                    messages.error(request, e)

            cred.user = user
            cred.project_id = form.cleaned_data.get('project_id')
            cred.client_id = form.cleaned_data.get('client_id')
            cred.client_secret = form.cleaned_data.get('client_secret')
            cred.save()
        else:
            messages.error(request, form.errors)

    form = MailUserCredentialForm(instance=cred)

    context = {
        'form': form,
        'cred': cred,
        'redirect_uri': request.build_absolute_uri(reverse("gmail_auth_callback", kwargs={}))
    }
    return render(request, "api_credential.html", context)


@login_required
def api_credential_remove(request):
    """
    Remove the uploaded Gmail API credential information(JSON file)

    :param request:
    :return:
    """
    user = Agent.dashboard_user(request)
    cred = MailUserCredential.objects.filter(user=user).first()
    if not cred:
        messages.error(request, "Credential doesn't exist.")
        return redirect('api_credential')

    folder = settings.CLIENTSECRETS_BASE_PATH
    full_path = os.path.join(settings.BASE_DIR, folder, cred.credential.__str__())

    try:
        if os.path.exists(full_path):
            os.remove(full_path)

        cred.credential = ''
        cred.credential_detail = ''
        cred.save()
        messages.success(request, 'Removed the API credential successfully.')
    except Exception as e:
        print(e)
        messages.error(request, 'Failed to remove the API credential.' + e.__str__())

    return redirect('api_credential')


def show_no_credential_msg(request, email, account_id):
    """
    If email account is not authorized by Gamil API credential, will show the error message.
    In this case, user should get the authorization by clicking 'Refresh Auth' in Filters list page.

    :param request:
    :param email:       email address in mail_accounts table.
    :param account_id:  ID in mail_accounts table.
    :return:
    """
    messages.error(request, "There is no credential information for '%s'. <br /> \
                                    <a href='get_gmail_auth/%s' class=''>Refresh linking to get the authorization please.</a>" % (email, account_id))


def show_invalid_access_token(request, email, account_id):
    messages.error(request, "Token has been expired or revoked on '%s'. <br /> \
                                        <a href='get_gmail_auth/%s' class=''>Refresh linking to get the authorization please.</a>" % (email, account_id))


def set_api_setting(request):
    """
    Set 2 setting values for Gapi module.
    If all values are available, will return True, otherwise False.

    :param request:
    :return: Boolean
    """
    user = Agent.dashboard_user(request)
    cred = MailUserCredential.objects.filter(user=user).first()

    if cred:
        gapi.CLIENT_ID = None
        gapi.CLIENT_SECRET = None
        gapi.REDIRECT_URI = request.build_absolute_uri(reverse("gmail_auth_callback"))

        if cred.client_id and cred.client_secret:
            gapi.CLIENT_ID = cred.client_id
            gapi.CLIENT_SECRET = cred.client_secret
        else:
            gapi.CLIENTSECRETS_LOCATION = os.path.join(settings.BASE_DIR, settings.CLIENTSECRETS_BASE_PATH, cred.credential.__str__())
            if not cred.credential.__str__() or not os.path.exists(gapi.CLIENTSECRETS_LOCATION):
                messages.error(request, 'Gmail API Credential doesn\'t exist. Please upload it.')
                return False
    return True


@login_required
def agent_users(request):
    """
    Show the users list for the agent login

    :param request:
    :return: Boolean
    """
    if Agent.has_agent_permission(request):
        print('Has permission')
    else:
        return redirect('index')
    users = User.objects.filter(groups__name=GROUP_USERB, is_active=True).all()
    context = {
        'users': users
    }
    return render(request, 'agent_users.html', context)


@login_required
def agent_login(request, username):
    if not Agent.has_agent_permission(request):
        return redirect('index')

    agent = User.objects.filter(username=username).first()
    if not agent:
        messages.info(request, "User '%' doesn't exist" % username)
        return redirect('agent_users')

    messages.success(request, "You logged in as '%s (%s %s)'" % (agent.username, agent.first_name, agent.last_name))

    Agent.store_agent_in_session(request, agent)
    request.session['selected_email'] = None
    return redirect('index')


@login_required
def agent_logout(request):
    if not Agent.has_agent_permission(request):
        return redirect('index')

    request.session[SKEY_AGENT] = None
    request.session['selected_email'] = None
    messages.success(request, "You logged out from agent user")
    return redirect('index')

@login_required
def mail_data_add(request):
    """Add the customer email address file.
    Every emails are separated by linebreak in the file.
    The user can select the file on 'Send Email' page.

    Args:
    Returns:
    """
    user = Agent.dashboard_user(request)

    if request.method == 'POST':
        form = CustomerMailDataForm(request.POST, request.FILES)

        if form.is_valid():
            if 'email_data' in request.FILES:
                customer_data = CustomerMailData.objects.create(user=user, email_data=request.FILES['email_data'].name,
                                                                data_name=form.cleaned_data.get('data_name'))
                folder = settings.EMAILDATA_BASE_PATH
                uploaded_filename = str(customer_data.id) + "_" + request.FILES['email_data'].name

                # create the folder if it doesn't exist.
                try:
                    # Checking the old file and remove it.
                    if not os.path.exists(os.path.join(settings.BASE_DIR, folder)):
                        os.mkdir(os.path.join(settings.BASE_DIR, folder))
                except Exception as e:
                    messages.error(request, e)
                    log.error("[Email Data] %s" % e)

                # save the uploaded file inside that folder.
                full_filename = os.path.join(settings.BASE_DIR, folder, uploaded_filename)
                log.info('full_filename: ' + full_filename)

                try:
                    # Checking the old file and remove it.
                    if os.path.exists(full_filename):
                        os.remove(full_filename)

                    fout = open(full_filename, 'wb+')

                    file_content = ContentFile(request.FILES['email_data'].read())

                    # Iterate through the chunks.

                    for chunk in file_content.chunks():
                        fout.write(chunk)
                    fout.close()

                    #Email Numbers
                    #request.FILES['email_data'].name
                    if request.FILES['email_data'].name.endswith('.xlsx'):
                        df = pd.read_excel(os.path.join(settings.EMAILDATA_BASE_PATH, full_filename),
                                           sheet_name=0, header=None)
                        file_data = df.to_dict()[0]
                        to_emails = [file_data[item] for item in file_data]
                        customer_data.data_num = len(to_emails)
                        customer_data.save()

                    elif request.FILES['email_data'].name.endswith('.xls'):
                        df = pd.read_excel(os.path.join(settings.EMAILDATA_BASE_PATH, full_filename),
                                           sheet_name=0, header=None)
                        file_data = df.to_dict()[0]
                        to_emails = [file_data[item] for item in file_data]
                        customer_data.data_num = len(to_emails)
                        customer_data.save()

                    elif request.FILES['email_data'].name.endswith('.csv'):
                        df = pd.read_csv(os.path.join(settings.EMAILDATA_BASE_PATH, full_filename),
                                         header=None)
                        file_data = df.to_dict()[0]
                        to_emails = [file_data[item] for item in file_data]
                        customer_data.data_num = len(to_emails)
                        customer_data.save()

                    elif request.FILES['email_data'].name.endswith('.txt'):
                        df = pd.read_csv(os.path.join(settings.EMAILDATA_BASE_PATH, full_filename),
                                         header=None)
                        file_data = df.to_dict()[0]
                        to_emails = [file_data[item] for item in file_data]
                        customer_data.data_num = len(to_emails)
                        customer_data.save()

                    messages.success(request, "Uploaded the file successfully: %s" % request.FILES['email_data'].name)
                except Exception as e:
                    log.error("[Email Data] %s" % e)
                    messages.error(request, e)

        else:
            messages.error(request, form.errors)

    form = CustomerMailDataForm()

    context = {
        'form': form,
    }
    return render(request, "mail_data_add.html", context)

@login_required
def mail_data_list(request):
    """View the email data set list.

    Args:
    Returns:
    """
    # Search keyword
    search = request.session.get('search')
    user_id = request.session.get('user_name')

    if not search:
        search = {}
    if not user_id:
        user_id = {}
    email_datas = CustomerMailData.objects.all()

    if request.method == 'POST':
        print(request.POST)
        if 'edit' in request.POST:
            email_data = CustomerMailData.objects.filter(id=request.POST.get('id')).first()
            if request.POST.get('data_name') != '':
                email_data.data_name = request.POST.get('data_name')
                email_data.save()
                email_data = CustomerMailData.objects.all()
            else:
                messages.error(request, 'The data name can\'t be the empty.')
            return redirect('mail_data_list')
        else:
            if request.POST.get('search[keyword]'):
                search['keyword'] = request.POST.get('search[keyword]')
            else:
                search['keyword'] = None
            request.session['search'] = search
            if request.POST.get('user_name'):
                user_id['keyword'] = request.POST.get('user_name')
            else:
                user_id['keyword'] = None
            request.session['user_name'] = user_id

            return redirect('mail_data_list')

    if search.get('keyword'):
        email_datas = email_datas.filter(data_name__contains=search.get('keyword'))
    if user_id.get('keyword') and user_id.get('keyword') != '0':
        email_datas = email_datas.filter(user_id=user_id.get('keyword'))

    users = User.objects.all()
    context = {
        'search': search,
        'users': users,
        'email_data': email_datas,
        'user_name': int(user_id.get('keyword') or 0),
    }

    return render(request, "mail_data_list.html", context)

@login_required
def mail_data_delete(request, id):
    """Delete the mail data set by id

    Args
        id: id of mail data set
    Returns
    """

    if id == 0:
        data_list = CustomerMailData.objects.all()
        for file in data_list:
            filepath = os.path.join(settings.EMAILDATA_BASE_PATH, str(file.id) + '_' + file.email_data.name)

            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
                CustomerMailData.objects.filter(id=file.id).delete()
                messages.success(request, 'The file: %s were deleted successfully.' % file.email_data.name)
            except Exception as e:
                print(e)
                messages.success(request, 'Failed to delete the file: %s.' % file.email_data.name)

        return redirect('mail_data_list')
    mail_data = CustomerMailData.objects.filter(id=id).first()
    data_name = mail_data.data_name
    try:
        filepath = os.path.join(settings.EMAILDATA_BASE_PATH, str(mail_data.id) + '_' + mail_data.email_data.name)
        if os.path.exists(filepath):
            os.remove(filepath)
        mail_data.delete()
        messages.success(request, 'The mail data: %s was deleted successfully.' % data_name)
    except Exception as e:
        print(e)
        messages.error(request, 'Failed to delete the mail data: %s.' % data_name)

    return redirect('mail_data_list')