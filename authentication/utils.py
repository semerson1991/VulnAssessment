import uuid

from django.contrib.auth.models import User
from django.core.serializers.json import DjangoJSONEncoder

from authentication.models import ActiveScans
from authentication.serializers import VulnerabilitySerializer


def jsonDefault(object):
    return object.__dict__

def get_user(request):
    email = request.POST['email']
    user = User.objects.get(email=email)
    return user

def get_active_scan(request):
    scanid = request.POST['scanid']
    active_scan = ActiveScans.objects.get(scan_id=scanid)
    return active_scan

def create_uuid():
    id = uuid.uuid4()
    return id