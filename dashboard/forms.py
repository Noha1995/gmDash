from django import forms
from django.core.validators import validate_email
from django.contrib.auth.models import User

from .models import MailAccount, MailUserCredential, CustomerMailData


class MailAccountForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        cls = {
            'class': 'form-control'
        }
        self.fields['email'].widget.attrs.update(cls)
        # self.fields['comment'].widget.attrs.update(cls)

    class Meta:
        model = MailAccount
        fields = {
            'email',
            'detail',
        }


class MailUserCredentialForm(forms.ModelForm):

    # skip_inbox = forms.BooleanField(label='Skip the Inbox (Archive it)', required=False)
    # mark_as_read = forms.BooleanField(label='Mark as read', required=False)
    # star_it = forms.BooleanField(label='Star it', required=False)
    # no_spam = forms.BooleanField(label='Never send it to Spam', required=False)
    # mark_as_important = forms.BooleanField(label='Always mark it as important', required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        cls = {
            'class': 'form-control'
        }
        for field_name in self.fields:
            self.fields[field_name].widget.attrs.update(cls)

    def credential_link(self):
        if self.credential:
            return "<a href='%s'>download</a>" % (self.credential.url,)
        else:
            return "No attachment"
    credential_link.allow_tags = True
    
    class Meta:
        model = MailUserCredential
        widgets = {
            'project_id': forms.TextInput(),
            'client_id': forms.TextInput(),
            'client_secret': forms.TextInput(),
        }
        fields = {
            'credential',
            'project_id',
            'client_id',
            'client_secret',
        }


class CustomerMailDataForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        cls = {
            'class': 'form-control'
        }
        for field_name in self.fields:
            self.fields[field_name].widget.attrs.update(cls)

    def clean(self):
        clean_data = super(CustomerMailDataForm, self).clean()
        file = clean_data.get('email_data')
        if file:
            filename = file.name
            if not filename.endswith('.xlsx') and not filename.endswith('.xls') \
               and not filename.endswith('.csv') and not filename.endswith('.txt'):
                self.add_error('email_data', 'The file format must be one of xlsx, xls, csv, txt.')

    def email_data_link(self):
        if self.credential:
            return "<a href='%s'>download</a>" % (self.email_data.url,)
        else:
            return "No attachment"

    email_data_link.allow_tags = True

    class Meta:
        model = CustomerMailData
        widgets = {
            'data_name': forms.TextInput(),

        }
        fields = {
            'email_data',
            'data_name',
        }


class MultiEmailField(forms.Field):
    def to_python(self, value):
        """Normalize data to a list of strings."""
        # Return an empty list if no input was given.
        if not value:
            return []
        result = [x.strip() for x in value.split('\n')]
        return result

    def validate(self, value):
        """Check if value consists only of valid emails."""
        # Use the parent's handling of required fields, etc.
        super().validate(value)
        for email in value:
            validate_email(email)


class MailAccountMultipleForm(forms.Form):
    emails = MultiEmailField(label='Email Addresses', required=True, widget=forms.Textarea,
                             help_text='Please specify the comma separated emails.')
    user = forms.ChoiceField(label='User', required=True, widget=forms.Select)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        cls = {
            'class': 'form-control',
            'rows': 6,
        }
        self.fields['emails'].widget.attrs.update(cls)

        users = [(user.pk, "%s" % (user.username,)) for user in User.objects.filter(is_active=True)]
        self.fields['user'].choices = users

    class Meta:
        fields = ('emails', 'user',)
        # widgets = {'users': forms.Select}

    # def save(self, commit=True):
    #     emails = self.cleaned_data.get('emails', None)
    # 
    #     for email in emails:
    #         obj = MailAccount()
    #         obj.email = email
    #         obj.save()
    # 
    #     # return super(MailAccount, self).save(commit=commit)
    #     return self


class FilterCriteriaForm(forms.Form):
    from_field = forms.CharField(label='From', required=False)
    to = forms.CharField(label='To', required=False)
    subject = forms.CharField(label='Subject', required=False)
    query = forms.CharField(label='Includes Words', required=False)
    negatedQuery = forms.CharField(label='Don\'t have', required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        cls = {
            'class': 'form-control'
        }
        for field_name in self.fields:
            self.fields[field_name].widget.attrs.update(cls)

    def get_google_data(self):
        form = self
        g_criteria = {
            'from': form.cleaned_data.get('from_field'),
            'to': form.cleaned_data.get('to'),
            'subject': form.cleaned_data.get('subject'),
            'query': form.cleaned_data.get('query'),
            'negatedQuery': form.cleaned_data.get('negatedQuery')
        }

        return g_criteria

    def set_google_data(self, criteria):
        if criteria.get('from'):
            self.fields['from_field'].initial = criteria.get('from')
        if criteria.get('to'):
            self.fields['to'].initial = criteria.get('to')
        if criteria.get('subject'):
            self.fields['subject'].initial = criteria.get('subject')
        if criteria.get('query'):
            self.fields['query'].initial = criteria.get('query')
        if criteria.get('query'):
            self.fields['negatedQuery'].initial = criteria.get('negatedQuery')


class FilterActionForm(forms.Form):
    skip_inbox = forms.BooleanField(label='Skip the Inbox (Archive it)', required=False)
    mark_as_read = forms.BooleanField(label='Mark as read', required=False)
    star_it = forms.BooleanField(label='Star it', required=False)
    no_spam = forms.BooleanField(label='Never send it to Spam', required=False)
    mark_as_important = forms.BooleanField(label='Always mark it as important', required=False)

    # apply_in_matching = forms.BooleanField(label='Apply to exists')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        cls = {
            'class': 'form-control fc-check ml-3'
        }
        for field_name in self.fields:
            self.fields[field_name].widget.attrs.update(cls)

    def get_google_data(self):
        form = self
        g_action = {
            'removeLabelIds': [],
            'addLabelIds': [],
        }

        if form.cleaned_data.get('skip_inbox'):
            g_action['removeLabelIds'] += ['INBOX']
        if form.cleaned_data.get('mark_as_read'):
            g_action['removeLabelIds'] += ['UNREAD']
        if form.cleaned_data.get('no_spam'):
            g_action['removeLabelIds'] += ['SPAM']

        if form.cleaned_data.get('star_it'):
            g_action['addLabelIds'] += ['STARRED']
        if form.cleaned_data.get('mark_as_important'):
            g_action['addLabelIds'] += ['IMPORTANT']

        return g_action

    def set_google_data(self, action):
        if not action:
            action = {}
        removeLabelIds = action.get('removeLabelIds')
        addLabelIds = action.get('addLabelIds')

        if removeLabelIds:
            for item in removeLabelIds:
                if item == 'UNREAD':
                    self.fields['mark_as_read'].initial = True
                if item == 'INBOX':
                    self.fields['skip_inbox'].initial = True
                if item == 'SPAM':
                    self.fields['no_spam'].initial = True

        if addLabelIds:
            for item in addLabelIds:
                if item == 'STARRED':
                    self.fields['star_it'].initial = True
                if item == 'IMPORTANT':
                    self.fields['mark_as_important'].initial = True
