from django.conf import settings

import logging
import httplib2
from oauth2client.client import flow_from_clientsecrets, OAuth2WebServerFlow

from oauth2client.client import FlowExchangeError, Credentials

from googleapiclient.discovery import build

from googleapiclient import errors

from .models import MailAccount

import base64
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import mimetypes
import os
import time
from apiclient import errors
from django.contrib import messages
log = logging.getLogger('django')

# Path to client_secrets.json which should contain a JSON document such as:
#   {
#     "web": {
#       "client_id": "[[YOUR_CLIENT_ID]]",
#       "client_secret": "[[YOUR_CLIENT_SECRET]]",
#       "redirect_uris": [],
#       "auth_uri": "https://accounts.google.com/o/oauth2/auth",
#       "token_uri": "https://accounts.google.com/o/oauth2/token"
#     }
#   }
CLIENTSECRETS_LOCATION = settings.CLIENTSECRETS_LOCATION
REDIRECT_URI = settings.GAPI_REDIRECT_URL
SCOPES = [
    'https://mail.google.com/',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/gmail.settings.basic',
    'https://www.googleapis.com/auth/gmail.settings.sharing',
    'https://www.googleapis.com/auth/gmail.compose',
    'https://www.googleapis.com/auth/gmail.send'
]
CLIENT_ID = None
CLIENT_SECRET = None


class GetCredentialsException(Exception):
    """Error raised when an error occurred while retrieving credentials.

    Attributes:
      authorization_url: Authorization URL to redirect the user to in order to
                         request offline access.
    """

    def __init__(self, authorization_url):
        """Construct a GetCredentialsException."""
        self.authorization_url = authorization_url


class CodeExchangeException(GetCredentialsException):
    """Error raised when a code exchange has failed."""


class NoRefreshTokenException(GetCredentialsException):
    """Error raised when no refresh token has been found."""


class NoUserIdException(Exception):
    """Error raised when no user ID could be retrieved."""


def get_stored_credentials(user_id):
    """Retrieved stored credentials for the provided user ID.

    Args:
      user_id: User's ID.
    Returns:
      Stored oauth2client.client.OAuth2Credentials if found, None otherwise.
    Raises:
      NotImplemented: This function has not been implemented.
    """

    account = MailAccount.objects.filter(user_id=user_id).first()
    credentials = None
    if account:
        credentials = account.detail
        credentials = Credentials.new_from_json(credentials)

    return credentials


def store_credentials(user_id, credentials, email):
    """Store OAuth 2.0 credentials in the application's database.

    This function stores the provided OAuth 2.0 credentials using the user ID as
    key.

    Args:
      user_id: User's ID.
      credentials: OAuth 2.0 credentials to store.
    """

    account = MailAccount.objects.filter(email=email).first()

    if account:
        account.detail = credentials.to_json()
        account.user_id = user_id
        account.save()

    # raise NotImplementedError()


def exchange_code(authorization_code):
    """Exchange an authorization code for OAuth 2.0 credentials.

    Args:
      authorization_code: Authorization code to exchange for OAuth 2.0
                          credentials.
    Returns:
      oauth2client.client.OAuth2Credentials instance.
    Raises:
      CodeExchangeException: an error occurred.
    """
    # flow = flow_from_clientsecrets(CLIENTSECRETS_LOCATION, ' '.join(SCOPES))
    flow = make_flow()

    flow.redirect_uri = REDIRECT_URI
    try:
        credentials = flow.step2_exchange(authorization_code)
        return credentials
    except FlowExchangeError as error:
        log.error('[exchange_code] %s', error)
        raise CodeExchangeException(None)


def get_user_info(credentials):
    """Send a request to the UserInfo API to retrieve the user's information.

    Args:
      credentials: oauth2client.client.OAuth2Credentials instance to authorize the
                   request.
    Returns:
      User information as a dict.
    """
    user_info_service = build(
        serviceName='oauth2', version='v2',
        http=credentials.authorize(httplib2.Http()))
    user_info = None
    try:
        user_info = user_info_service.userinfo().get().execute()
    except errors.HttpError as e:
        log.error('[GetUserInfo]: %s', e)
    if user_info and user_info.get('id'):
        return user_info
    else:
        log.error('[GetUserInfo]: No user exists. %s', e)
        raise NoUserIdException()


def make_flow(email_address=None, state=None):
    if CLIENT_ID and CLIENT_SECRET:
        print(CLIENT_ID)
        print(CLIENT_SECRET)
        flow = OAuth2WebServerFlow(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scope=SCOPES
        )
    else:
        flow = flow_from_clientsecrets(CLIENTSECRETS_LOCATION, ' '.join(SCOPES))

    return flow


def get_authorization_url(email_address, state):
    """Retrieve the authorization URL.

    Args:
      email_address: User's e-mail address.
      state: State for the authorization URL.
    Returns:
      Authorization URL to redirect the user to.
    """
    flow = make_flow(email_address, state)

    flow.params['access_type'] = 'offline'
    flow.params['approval_prompt'] = 'force'
    flow.params['user_id'] = email_address
    flow.params['state'] = state
    return flow.step1_get_authorize_url(REDIRECT_URI)


def get_credentials(authorization_code, state):
    """Retrieve credentials using the provided authorization code.

    This function exchanges the authorization code for an access token and queries
    the UserInfo API to retrieve the user's e-mail address.
    If a refresh token has been retrieved along with an access token, it is stored
    in the application database using the user's e-mail address as key.
    If no refresh token has been retrieved, the function checks in the application
    database for one and returns it if found or raises a NoRefreshTokenException
    with the authorization URL to redirect the user to.

    Args:
      authorization_code: Authorization code to use to retrieve an access token.
      state: State to set to the authorization URL in case of error.
    Returns:
      oauth2client.client.OAuth2Credentials instance containing an access and
      refresh token.
    Raises:
      CodeExchangeError: Could not exchange the authorization code.
      NoRefreshTokenException: No refresh token could be retrieved from the
                               available sources.
    """
    email_address = ''
    try:
        credentials = exchange_code(authorization_code)
        user_info = get_user_info(credentials)
        email_address = user_info.get('email')
        user_id = user_info.get('id')

        if credentials.refresh_token is not None:
            store_credentials(user_id, credentials, email_address)
            return credentials
        else:
            credentials = get_stored_credentials(user_id)
            if credentials and credentials.refresh_token is not None:
                return credentials
    except CodeExchangeException as error:
        log.error('[Error Get Email Credential]: %s' % error)
        # Drive apps should try to retrieve the user and credentials for the current
        # session.
        # If none is available, redirect the user to the authorization URL.
        error.authorization_url = get_authorization_url(email_address, state)
        raise error
    except NoUserIdException:
        log.error('[Error Get Email Credential]: No user ID could be retrieved.')
    # No refresh token has been retrieved.
    authorization_url = get_authorization_url(email_address, state)

    raise NoRefreshTokenException(authorization_url)


def get_labels(credentials):
    service = build_service(credentials)
    results = service.users().labels().list(userId='me').execute()
    labels = results.get('labels', [])

    if not labels:
        log.error('No labels found.')
    else:
        for label in labels:
            print(label['name'])


def build_service(credentials):
    """Build a Gmail service object.

    Args:
      credentials: OAuth 2.0 credentials.

    Returns:
      Gmail service object.
    """
    http = httplib2.Http()
    http = credentials.authorize(http)
    return build('gmail', 'v1', http=http)


def ListMessages(service, user, query=''):
    """Gets a list of messages.

    Args:
      service: Authorized Gmail API service instance.
      user: The email address of the account.
      query: String used to filter messages returned.
             Eg.- 'label:UNREAD' for unread Messages only.

    Returns:
      List of messages that match the criteria of the query. Note that the
      returned list contains Message IDs, you must use get with the
      appropriate id to get the details of a Message.
    """
    try:
        response = service.users().messages().list(userId=user, q=query).execute()
        messages = response['messages']

        while 'nextPageToken' in response:
            page_token = response['nextPageToken']
            response = service.users().messages().list(userId=user, q=query,
                                                       pageToken=page_token).execute()
            messages.extend(response['messages'])

        return messages
    except errors.HttpError as error:
        print
        'An error occurred: %s' % error
        if error.resp.status == 401:
            # Credentials have been revoked.
            raise NotImplementedError()


class GapiFilters:

    @staticmethod
    def get_filters(credentials):
        gmail_service = build_service(credentials)
        result = gmail_service.users().settings().filters().list(userId='me').execute()
        return result

    @staticmethod
    def delete_filter(credentials, filter_id):
        gmail_service = build_service(credentials)
        result = gmail_service.users().settings().filters().delete(userId='me', id=filter_id).execute()
        return result

    @staticmethod
    def create_filter(credentials, filter):
        gmail_service = build_service(credentials)
        result = gmail_service.users().settings().filters().create(userId='me', body=filter).execute()
        return result


class GapiVacations:

    @staticmethod
    def get_vacation_settings(credentials):
        gmail_service = build_service(credentials)
        result = gmail_service.users().settings().getVacation(userId='me').execute()
        return result

    @staticmethod
    def update_vacation_settings(credentials, vacation_settings):
        gmail_service = build_service(credentials)
        result = gmail_service.users().settings().updateVacation(userId='me', body=vacation_settings).execute()
        return result


class GapiSetting:
    @staticmethod
    def set_alias(credentials, full_name, signature):
        gmail_service = build_service(credentials)
        primary_alias = None
        aliases = gmail_service.users().settings().sendAs().list(userId='me').execute()
        sendAsConfiguration = {
            'displayName': full_name
        }
        for alias in aliases.get('sendAs'):
            if alias.get('isPrimary'):
                primary_alias = alias
                break

        result = gmail_service.users().settings().sendAs().update(
            userId='me',
            sendAsEmail=primary_alias.get('sendAsEmail'),
            body=sendAsConfiguration).execute()

        return result


class GapiWrap:
    credential = None
    gmail_service = None

    @staticmethod
    def set_credential(credential):
        GapiWrap.credential = credential
        GapiWrap.gmail_service = build_service(GapiWrap.credential)


class GapiUsersMessages(GapiWrap):

    @staticmethod
    def create_message(sender, to, subject, message_text):
        """Create a message for an email.

        Args:
          sender: Email address of the sender.
          to: Email address of the receiver.
          subject: The subject of the email message.
          message_text: The text of the email message.

        Returns:
          An object containing a base64url encoded email object.
        """
        print(message_text)
        message = MIMEText(message_text, 'html')
        print(message)
        message['to'] = to
        message['from'] = sender
        message['subject'] = subject

        return {'raw': base64.urlsafe_b64encode(message.as_string().encode('utf-8')).decode('utf-8')}

    @staticmethod
    def create_message_with_attachment(sender, to, subject, message_text, file_dir,
                                    filename):
        """Create a message for an email.

        Args:
          sender: Email address of the sender.
          to: Email address of the receiver.
          subject: The subject of the email message.
          message_text: The text of the email message.
          file_dir: The directory containing the file to be attached.
          filename: The name of the file to be attached.

        Returns:
          An object containing a base64url encoded email object.
        """
        message = MIMEMultipart()
        message['to'] = to
        message['from'] = sender
        message['subject'] = subject

        msg = MIMEText(message_text)
        message.attach(msg)

        path = os.path.join(file_dir, filename)
        content_type, encoding = mimetypes.guess_type(path)

        if content_type is None or encoding is not None:
            content_type = 'application/octet-stream'
        main_type, sub_type = content_type.split('/', 1)
        if main_type == 'text':
            fp = open(path, 'rb')
            msg = MIMEText(fp.read(), _subtype=sub_type)
            fp.close()
        elif main_type == 'image':
            fp = open(path, 'rb')
            msg = MIMEImage(fp.read(), _subtype=sub_type)
            fp.close()
        elif main_type == 'audio':
            fp = open(path, 'rb')
            msg = MIMEAudio(fp.read(), _subtype=sub_type)
            fp.close()
        else:
            fp = open(path, 'rb')
            msg = MIMEBase(main_type, sub_type)
            msg.set_payload(fp.read())
            fp.close()

        msg.add_header('Content-Disposition', 'attachment', filename=filename)
        message.attach(msg)

        return {'raw': base64.urlsafe_b64encode(message.as_string())}

    @staticmethod
    def send(request, credentials, sender, user_id, subject, message_data):
        """Send an email message.

        Args:
          service: Authorized Gmail API service instance.
          user_id: User's email address. The special value "me"
          can be used to indicate the authenticated user.
          message: Message to be sent.

        Returns:
          Sent Message.
        """
        gmail_service = build_service(credentials)
        message_text = GapiUsersMessages.create_message(sender, user_id.strip(), subject, message_data)
        message = (gmail_service.users().messages().send(userId=sender, body=message_text)
                   .execute())

        print('Message Id: %s' % message['id'])
        return message

    @staticmethod
    def list():
        result = GapiUsersMessages.gmail_service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
        return result

    @staticmethod
    def threads():
        result = GapiUsersMessages.gmail_service.users().threads().list(userId='me', labelIds=['INBOX'], maxResults=10).execute()
        return result

    @staticmethod
    def labels_get(labelId='INBOX'):
        result = GapiUsersMessages.gmail_service.users().labels().get(userId='me', id=labelId).execute()
        return result

    def delete_all(userId, maxResults=1, labelIds=['INBOX']):
        """

        :param maxResults:
        :param labelIds:
        :return:
        """
        ret = {
            'error': None,
            'data': {
                'cnt': 0,
                'deleted': 0
            }
        }

        try:
            gmail_service = GapiWrap.gmail_service
            response = gmail_service.users().messages().list(userId=userId,
                                                             labelIds=labelIds,
                                                             maxResults=maxResults).execute()

            exist_first_data = False
            items = []
            if 'messages' in response:
                items.extend(response['messages'])
                exist_first_data = True

            # limit = 0
            while exist_first_data or 'nextPageToken' in response:  # and limit < 1:

                if 'nextPageToken' in response:
                    page_token = response['nextPageToken']
                    response = gmail_service.users().messages().list(userId=userId,
                                                                     labelIds=labelIds,
                                                                     maxResults=maxResults,
                                                                     pageToken=page_token).execute()

                    if 'messages' in response:
                        items.extend(response['messages'])
                else:
                    if not exist_first_data:
                        break

                exist_first_data = False
                # limit += 1

                if len(items) > 0:
                    ret['data']['cnt'] += len(items)

                    # Remove the threads.
                    ids = [message['id'] for message in items]
                    result = gmail_service.users().messages().batchDelete(userId=userId, body={'ids': ids}).execute()

                    ret['data']['deleted'] += len(items)
                    log.info("Deleted: %s" % ret['data']['deleted'])
                    items.clear()

            return ret
        except errors.HttpError as error:
            ret['error'] = "%s" % error
            log.error("Delete Messages: " + ret['error'])

        return ret


class GapiUsersThreads(GapiWrap):

    @staticmethod
    def list(labelIds=['INBOX']):
        result = GapiUsersMessages.gmail_service.users().threads().list(userId='me', labelIds=labelIds, maxResults=10).execute()
        return result
