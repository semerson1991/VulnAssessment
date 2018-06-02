import uuid

from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, mixins, generics
from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response #Wrapper, the correct data is handled rather than having to manually do it ourself
from rest_framework.views import APIView

from automated_scans import vulnerability_assessment
from authentication.models import NetworkType, UserNetworkConfig, NetworkDevice, ActiveScans
from authentication.serializers import UserSerializer, NetworkTypeSerializer
from authentication import utils
from rest_framework.decorators import api_view
from rest_framework import status
from automated_scans import vulnerability_assessment
import json
# Create your views here.
from authentication.utils import jsonDefault
from automated_scans.openvas.openvas_results import OpenVasResults
from automated_scans.vulnerability_assessment import VulnerabilityAssessment

vulnerability_assessment = VulnerabilityAssessment()

@csrf_exempt # because we want to be able to POST to this view from clients that won't have a CSRF token we need to mark the view as csrf_exempt
def register_network(request):
   # users = User.objects.all() #need to loop through emails and usernames to make sure they're unique
    if request.method == 'POST':
        net_type = request.POST['network_type']
        network = NetworkType(network_type=net_type)
        network.save()
        return Response(status=status.HTTP_200_OK)
    return Response(status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt # because we want to be able to POST to this view from clients that won't have a CSRF token we need to mark the view as csrf_exempt
@api_view(['GET', 'POST', ])
def get_network_type(request, pk):
    try:
        network_type = NetworkType.objects.get(pk=pk)
    except NetworkType.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST) # Working = HttpResponse(status=404)
#REMEMBER TO PASS IN THE CONTENT TYPE YOU WANT RETURNED WHEN USING Response() Wrapper
    if request.method == 'POST':
        the_network_type = NetworkTypeSerializer(network_type)
        return Response(the_network_type.data, status=status.HTTP_200_OK) #working = return JsonResponse(the_network_type.data)


@csrf_exempt # because we want to be able to POST to this view from clients that won't have a CSRF token we need to mark the view as csrf_exempt
@api_view(['GET', 'POST', ])
def update_network_type(request, pk):
    try:
        the_network_type = NetworkType.objects.get(pk=pk)
    except NetworkType.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)  # Working = HttpResponse(status=404)

    if request.method == 'POST':
        net_type = request.POST['network_type']
        the_network_type.network_type = net_type
        the_network_type.save()
        return Response(status=status.HTTP_200_OK)


@csrf_exempt # because we want to be able to POST to this view from clients that won't have a CSRF token we need to mark the view as csrf_exempt
@api_view(['GET', 'POST', ])
def delete_network_type(request, pk):
    try:
        the_network_type = NetworkType.objects.get(pk=pk)
    except NetworkType.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)  # Working = HttpResponse(status=404)

    if request.method == 'POST':
        net_type = request.POST['network_type']
        the_network_type.network_type = net_type
        the_network_type.delete()
        return Response(status=status.HTTP_200_OK)


@api_view(['GET', 'POST']) #This is good to have a browsable view of the API
def network_type_list(request, format=None):
    """
    List all network devices.
    """
    network_types = NetworkType.objects.all()
    network_types_serialized = NetworkTypeSerializer(network_types, many=True)
    return Response(network_types_serialized.data)


@api_view(['GET', 'POST']) #This is good to have a browsable view of the API
def network_type_detail(request, pk, format=None):
    """
    List all network devices.
    """
    try:
        the_network_type = NetworkType.objects.get(pk=pk)
    except NetworkType.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)  # Working = HttpResponse(status=404)

    network_type_detail_serialized = NetworkTypeSerializer(the_network_type)
    return Response(network_type_detail_serialized.data)


class NetworkTypeList(APIView):#Class Based View. The function based view is def network_type_list
    def post(self, request, format=None):
        network_types = NetworkType.objects.all()
        network_types_serialized = NetworkTypeSerializer(network_types, many=True)
        return Response(network_types_serialized.data)


#Class base allow the use of reusable behaviour by using Mixins. Common behaviour can be seperated as shown below.
class NetworkTypeListMixing(generics.ListCreateAPIView):
    queryset = NetworkType.objects.all()
    serializer_class = NetworkTypeSerializer

@csrf_exempt
def register_network(request):


    users = User.objects.all()
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']

        config_name = request.POST['config-name']
        network_type = request.POST['network-type']
        password = request.POST['password']

        #check is user exists (by username
        #compare passwords

@csrf_exempt
@api_view(['GET', 'POST', ])
def register_user(request):
    if request.method == 'POST':
        email = request.POST.get('email', -1)
        password = request.POST.get('password', -1)

        if User.objects.filter(email=email).exists():
            data = {'success': 'false'}
            #json = JSONRenderer().render(data)
            #print(json)
            return Response(data=data, status=status.HTTP_409_CONFLICT)
            print("not returned")
           # return Response(status=status.HTTP_409_CONFLICT)
        if email != -1 and password != -1:
            User.objects.create(  # Check serializers for the bcrypt hashing
                email=email,
                password=password,
                username=email,
            )
            data = {'success': 'true'}
            return Response(data=data, status=status.HTTP_200_OK)
        data = {'success': 'false'}
        return Response(data=data, status=status.HTTP_204_NO_CONTENT)


@csrf_exempt
@api_view(['GET', 'POST', ])
def login_user(request):
    data = {'success': 'false'}
    if request.method == 'POST':
        email = request.POST.get('email', "")
        the_password = request.POST.get('password', "")

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            if user.password == the_password:
                data = {'success': 'true'}
                return Response(data=data, status=status.HTTP_200_OK)

        return Response(data=data, status=status.HTTP_401_UNAUTHORIZED)
    return Response(data=data, status=status.HTTP_401_UNAUTHORIZED)


@csrf_exempt
@api_view(['GET', 'POST', ])
def register_network_config(request):
    network_device = NetworkDevice.objects.get(pk=1)

    if request.method == 'POST':
        password = request.POST['password'] #device password
        net_type = request.POST['network_type']
        conf_name = request.POST['config_name']

        email = request.POST['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            if NetworkType.objects.filter(network_type=net_type).exists():
                network_type = NetworkType.objects.get(network_type=net_type)
                if password == network_device.password:
                    UserNetworkConfig.objects.create(
                        config_name=conf_name,
                        user=user,
                        network_type=network_type,
                    )
                    return Response(status=status.HTTP_200_OK)
            return Response(status=status.HTTP_403_FORBIDDEN)

    return Response(status=status.HTTP_403_FORBIDDEN)

@csrf_exempt
@api_view(['GET', 'POST', ])
def run_scan(request):
        vulnerability_assessment.run_all()
        scan_id = vulnerability_assessment.scan_results[-1].scan_id
        scanid_as_string = str(scan_id)
        data = {'scan-started' : 'true', 'scan-id' : scanid_as_string}
        print(scan_id)
        jsonResponse = json.dumps(data, default=jsonDefault)
        return HttpResponse(jsonResponse, content_type="application/json")

@csrf_exempt
@api_view(['GET', 'POST', ])
def check_scan_status(request):
    data = {'scan-finished': 'false'}
    #if request.method == 'POST':
        #scanID = request.POST['scan-id']
    scan_id = vulnerability_assessment.scan_results[-1].scan_id #TODO NEED TO CHANGE THIS - The user will send the Scan ID

    for scan_result in vulnerability_assessment.scan_results:
        if scan_result.scan_id == scan_id:
            if scan_result.results_collected is True:
                data = {'scan-finished': 'true'}
                json_response = json.dumps(data, default=jsonDefault)
                scan_result.results_collected = False
                return HttpResponse(json_response, content_type="application/json")
    json_response = json.dumps(data, default=jsonDefault)
    return HttpResponse(json_response, content_type="application/json")


@csrf_exempt
@api_view(['GET', 'POST', ])
def get_results(request):
    #if request.method == 'POST':
        #scanID = request.POST['scan-id']
    scan_id = vulnerability_assessment.scan_results[-1].scan_id #TODO Need to change this - The usr will send the scan ID

    for scan_result in vulnerability_assessment.scan_results:
        if scan_result.scan_id == scan_id:
            json_response = json.dumps(scan_result, default=jsonDefault)
            #vulnerability_assessment.scan_results.remove(scan_result)
            return HttpResponse(json_response, content_type="application/json")
            #return JsonResponse(scan_result.openvas_result.data, status=200)
    data = {'error': 'unable to retrieve'}
    json_response = json.dumps(data, default=jsonDefault)
    return HttpResponse(json_response, content_type="application/json")






        #data = JSONRenderer.render(nmap_results)

       # return JsonResponse({'status':'false', 'data':data}, status=500)




       # return Response(status=status.HTTP_200_OK, data=nmap_results)

'''
    config_name = models.CharField(max_length=256)
    device=models.ForeignKey(NetworkDevice, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    network_type = models.ForeignKey(NetworkType, on_delete=models.CASCADE)
    
    
    
    @csrf_exempt  # because we want to be able to POST to this view from clients that won't have a CSRF token we need to mark the view as csrf_exempt
    @api_view(['GET', 'POST', ])
    def update_network_type(request, pk):
        try:
            the_network_type = NetworkType.objects.get(pk=pk)
        except NetworkType.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)  # Working = HttpResponse(status=404)

        if request.method == 'POST':
            net_type = request.POST['network_type']
            the_network_type.network_type = net_type
            the_network_type.save()
            return Response(status=status.HTTP_200_OK)


def createUser(request):


    if request.method == 'POST':
        net_type = request.POST['network_type']
        network = NetworkType(network_type=net_type)
        network.save()
        return Response(status=status.HTTP_200_OK)
    return Response(status=status.HTTP_400_BAD_REQUEST)


    return


    class UserNetworkConfig(models.Model):
        config_name = models.CharField(max_length=256)
        device = models.ForeignKey(NetworkDevice, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        network_type = models.ForeignKey(NetworkType, on_delete=models.CASCADE)

        @csrf_exempt  # because we want to be able to POST to this view from clients that won't have a CSRF token we need to mark the view as csrf_exempt
        def register_network(request):
            # users = User.objects.all() #need to loop through emails and usernames to make sure they're unique
            if request.method == 'POST':
                net_type = request.POST['network_type']
                network = NetworkType(network_type=net_type)
                network.save()
                return Response(status=status.HTTP_200_OK)
            return Response(status=status.HTTP_400_BAD_REQUEST)
'''