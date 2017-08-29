from django.http import HttpResponse
from django.template import RequestContext, loader

def index(request):
    template = loader.get_template('otp/index.html')
    context = RequestContext(request, {
        'otpVal': "test",
    })
    return HttpResponse(template.render(context))
