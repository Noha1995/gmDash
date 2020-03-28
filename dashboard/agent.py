from django.contrib.auth.models import User

GROUP_ADMIN = 'ADMIN'
GROUP_USERA = 'USERA'
GROUP_USERB = 'USERB'

# session key
SKEY_AGENT = 'agent'


class Agent:
    agent_mode = False

    @staticmethod
    def has_agent_permission(request):
        """
        Check if the current user can login as an agent.

        :param request:
        :return:
        """
        user = request.user
        if not user:
            return False
        return user.is_superuser or user.groups.filter(name__in=(GROUP_ADMIN, GROUP_USERA)).exists()

    @staticmethod
    def store_agent_in_session(request, agent):
        """
        Store the agent user's info dictionary in session

        :param request:
        :param agent:
        :return:
        """
        request.session[SKEY_AGENT] = {
            'id': agent.id,
            'username': agent.username,
            'first_name': agent.first_name,
            'last_name': agent.last_name,
            'email': agent.email,
        }

    @staticmethod
    def get_logged_agent(request):
        """
        Get the agent user from session.
        Note: This may be called in request context. Don't use in views as much as possible.

        :param request:
        :return:
        """
        agent = request.session.get(SKEY_AGENT)
        if not agent:
            return {
                'agent_user': None
            }
        return {
            'agent_user': agent
        }

    @staticmethod
    def get_agent(request):
        """
        Get the agent user object from session and database.

        :param request:
        :return:
        """
        agent = request.session.get(SKEY_AGENT)
        if not agent:
            return None
        return User.objects.filter(id=agent['id']).first()

    @staticmethod
    def dashboard_user(request):
        """
        Get the dashboard user: Agent User or Current User

        :param request:
        :return:
        """
        agent = Agent.get_agent(request)
        if agent:
            return agent
        else:
            return request.user

    @staticmethod
    def is_site_superuser(request):
        """
        Check if the current user is a super administrator

        :param request:
        :return:
        """
        if not request.user:
            return False

        agent = Agent.get_agent(request)
        if agent:
            return False

        return request.user.is_superuser

    @staticmethod
    def is_dashboard_admin(request):
        """
        Check if this user( or agent user) is a dashboard administrator.
        Note: This is a quite different with django administrator.

        :param request:
        :return:
        """
        if not request.user:
            return False
        agent = Agent.get_agent(request)
        if agent:
            return agent.is_superuser or agent.groups.filter(name__in=(GROUP_ADMIN, GROUP_USERA)).exists()

        return request.user.is_superuser or request.user.groups.filter(name__in=(GROUP_ADMIN, GROUP_USERA)).exists()


def agent_user(request):
    """
    Get the agent user in the request context(Django template)

    :param request:
    :return:
    """
    return Agent.get_logged_agent(request)


def dashboard_user(request):
    """
    Get the dashboard user( or agent) in the request context(Django template)
    Note: In the django template, we can use the variable "is_dashboard_admin" and "dashboard" user.

    :param request:
    :return:
    """
    is_dashboard_admin = False

    user = Agent.get_agent(request)
    if user:
        return {
            'dashboard_user': user,
            'is_dashboard_admin': is_dashboard_admin,
            'is_site_superuser': user.is_superuser
        }

    user = request.user
    if user:
        is_dashboard_admin = request.user.is_superuser or request.user.groups.filter(name__in=(GROUP_ADMIN, GROUP_USERA)).exists()
    return {
        'dashboard_user': user,
        'is_dashboard_admin': is_dashboard_admin,
        'is_site_superuser': Agent.is_site_superuser(request)
    }
