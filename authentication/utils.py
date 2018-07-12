import uuid

from django.contrib.auth.models import User
from django.core.serializers.json import DjangoJSONEncoder
from authentication.serializers import VulnerabilitySerializer


def jsonDefault(object):
    return object.__dict__

def get_user(request):
    email = request.POST['email']
    user = User.objects.get(email=email)
    return user

def create_uuid():
    id = uuid.uuid4()
    return id