from django.contrib import admin, messages
from django.http import HttpResponseRedirect
from django.shortcuts import render

from .forms import MailAccountMultipleForm
from .models import MailAccount, FakeModel, MailAccountUser

admin.site.site_header = 'Google Mail API Administration'


class MailAccountAdmin(admin.ModelAdmin):
    list_display = ['email', 'user_id', 'created_at', 'updated_at']


class MailAccountsByUserAdmin(admin.ModelAdmin):
    list_display = ['user',
                    'get_email',
                    'get_user_id',
                    'get_created_at',
                    'get_updated_at'
                    ]

    list_filter = ['user']
    list_display_links = None

    def get_email(self, obj):
        return obj.mail_account.email

    get_email.admin_order_field = 'email'  # Allows column order sorting
    get_email.short_description = 'Email'  # Renames column head

    def get_user_id(self, obj):
        return obj.mail_account.user_id

    get_user_id.admin_order_field = 'user_id'  # Allows column order sorting
    get_user_id.short_description = 'Google User Id'  # Renames column head

    def get_created_at(self, obj):
        return obj.mail_account.created_at

    get_created_at.admin_order_field = 'created_at'  # Allows column order sorting
    get_created_at.short_description = 'Created At'  # Renames column head

    def get_updated_at(self, obj):
        return obj.mail_account.updated_at

    get_updated_at.admin_order_field = 'updated_at'  # Allows column order sorting
    get_updated_at.short_description = 'Updated At'  # Renames column head

    def changelist_view(self, request, extra_context=None):
        extra_context = {'title': 'Emails assigned to users'}
        return super(MailAccountsByUserAdmin, self).changelist_view(request, extra_context=extra_context)


class MailAccountMultipleAdmin(admin.ModelAdmin):
    """
        This is a funky way to register a regular view with the Django Admin.
        """

    list_display = ['email', 'user_id', 'created_at', 'updated_at']
    list_display_links = None
    list_editable = ['email']

    def has_add_permission(*args, **kwargs):
        return True

    def has_change_permission(*args, **kwargs):
        return False

    def has_delete_permission(*args, **kwargs):
        return True

    def change_view(self, request, object_id, extra_context=None):
        self.exclude = ('access_token', 'user_id', 'detail',)
        return super(MailAccountMultipleAdmin, self).change_view(request, object_id, extra_context)

    # def changelist_view(self, request):
    #     context = {'title': 'My Custom AdminForm'}
    #     if request.method == 'POST':
    #         form = MailAccountMultipleForm(request.POST)
    #         if form.is_valid():
    #             # Do your magic with the completed form data.
    #
    #             # Let the user know that form was submitted.
    #             messages.success(request, 'Congrats, form submitted!')
    #             return HttpResponseRedirect('')
    #         else:
    #             messages.error(
    #                 request, 'Please correct the error below'
    #             )
    #
    #     else:
    #         form = MailAccountMultipleForm()
    #
    #     context['form'] = form
    #     return render(request, 'admin/change_form.html', context)


admin.site.register([MailAccount], MailAccountMultipleAdmin)
admin.site.register(MailAccountUser, MailAccountsByUserAdmin)
