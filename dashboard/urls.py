from django.urls import path
from django.views.generic.base import TemplateView
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('mail_accounts', views.mail_accounts, name='mail_accounts'),
    path('mail_account_add', views.mail_account_add, name='mail_account_add'),
    path('mail_account_delete/<int:id>', views.mail_account_delete),
    path('api_credential', views.api_credential, name='api_credential'),
    path('api_credential_remove', views.api_credential_remove, name='api_credential_remove'),

    path('mail_set_alias', views.mail_set_alias, name='mail_set_alias'),

    path('mail_filters', views.mail_filters, name='mail_filters'),
    path('mail_filter_add', views.mail_filter_add, name='mail_filter_add'),
    path('mail_filter_delete/<filter_id>', views.mail_filter_delete),
    path('mail_filter_delete_all', views.mail_filter_delete_all, name='mail_filter_delete_all'),
    path('mail_filter_delete_all_on_accounts', views.mail_filter_delete_all_on_accounts, name='mail_filter_delete_all_on_accounts'),
    path('mail_filter_copy', views.mail_filter_copy, name='mail_filter_copy'),

    path('mail_vacation_settings', views.mail_vacation_settings, name='mail_vacation_settings'),
    path('mail_vacation_settings_update', views.mail_vacation_settings_update, name='mail_vacation_settings_update'),
    path('mail_vacation_multi_settings', views.mail_vacation_multi_settings, name='mail_vacation_multi_settings'),
    path('mail_vacation_multi_settings_update', views.mail_vacation_multi_settings_update, name='mail_vacation_multi_settings_update'),

    path('inbox_delete_all_on_accounts', views.inbox_delete_all_on_accounts, name='inbox_delete_all_on_accounts'),


    # ============= User Agent Function
    path('agent_users', views.agent_users, name='agent_users'),
    path('agent_login/<username>', views.agent_login),
    path('agent_logout', views.agent_logout, name='agent_logout'),

    path('get_gmail_auth/<int:id>', views.get_gmail_auth),
    path('gmail_auth_callback', views.gmail_auth_callback, name='gmail_auth_callback'),
]