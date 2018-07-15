import uuid
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.template.loader import get_template
from django.core.serializers.json import DjangoJSONEncoder
from authentication.serializers import VulnerabilitySerializer
from networkassessment import settings


def jsonDefault(object):
    return object.__dict__


def get_user(request):
    email = request.POST['email']
    user = User.objects.get(email=email)
    return user


def create_uuid():
    id = uuid.uuid4()
    return id


def sendEmail(username, action, adminEmails):
    content = ""
    subject = ""

    if action == "create-user":
        subject = "New user registration request"
    elif action == "perform-scan":
        subject = "New scan request"

    id = uuid.uuid4()
    template = get_template('email_template.html')
    context = {
        'username': username,
        'request_id': id,
    }
    content = template.render(context)

    email = EmailMultiAlternatives(
        "Security Box " + subject,
        "",
        settings.EMAIL_HOST_USER,
        [adminEmails],
    )
    email.attach_alternative(content, "text/html")

    ret = email.send()
    if ret == 1:
        print('email sent')
    else:
        print('error sending email')
    return id