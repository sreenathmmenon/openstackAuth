from django.http import HttpResponse
from django.template import RequestContext, loader
from openstack_dashboard.views import get_user_home,callKeystoneForTotp
from django import shortcuts
from horizon import exceptions
import logging

LOG = logging.getLogger(__name__)

def index(request):
    """
    Function to show the TOTP page.
    @param : request
    @return : HTTP response
    """

    LOG.info('enterrrring')
    request.session['totp_invalid'] = False
    if not request.user.is_authenticated():
        LOG.info("User not autenticated-2. Please check! ")
        raise exceptions.NotAuthenticated()
     
    LOG.info('5555555555555555555555555555')
    template = loader.get_template('auth/twofactor.html')
    context = RequestContext(request, {
        'totpVal': "test",
    })

    LOG.info('6666666666666666666666666666')
    LOG.info('returning the response-index function - twofactor/views.py')
    return HttpResponse(template.render(context))

def totpSubmit(request) :
	"""
	TOTP submit call. This will get the submitted TOTP from request and call keystone for TOTP validation.
	@param : request object
	"""
        LOG.info('totpSubmit function') 
	res = callKeystoneForTotp(request)
        LOG.info(request)
	if res :
                LOG.info('Will be redirected to dashboard page')
		response = shortcuts.redirect(get_user_home(request.user))
		return response
	else :
                LOG.info('Will be redirected to totp page itself')
		LOG.info('777777777777777777777')
		response = shortcuts.redirect('/dashboard/twofactor')
                return response

def backToLogin(request):
	"""
	Function to destroy session and move back to login screen.
	"""
	request.session.flush()
	return shortcuts.redirect("/auth/login")
