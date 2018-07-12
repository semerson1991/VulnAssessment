import threading
import uuid

from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, mixins, generics
from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer
from rest_framework.response import \
    Response  # Wrapper, the correct data is handled rather than having to manually do it ourself
from rest_framework.views import APIView

from automated_scans import vulnerability_assessment
from authentication.models import NetworkType, UserNetworkConfig, NetworkDevice, AdminUsers
from authentication.serializers import UserSerializer, NetworkTypeSerializer
from authentication import utils
from rest_framework.decorators import api_view
from rest_framework import status
from automated_scans import vulnerability_assessment
import json
# Create your views here.
from authentication.utils import jsonDefault
from automated_scans.nmap.nmap_scan_config import NmapScanConfig
from automated_scans.nmap.nmap_results import NmapResult
from automated_scans.openvas.openvas_results import OpenVasResults
from automated_scans.results.scan_results import ScanResults
from automated_scans.vulnerability_assessment import VulnerabilityAssessment
from automated_scans.security import cryptography
from threading import Thread

vulnerability_assessment = VulnerabilityAssessment()


@csrf_exempt  # because we want to be able to POST to this view from clients that won't have a CSRF token we need to mark the view as csrf_exempt
def register_network(request):
    # users = User.objects.all() #need to loop through emails and usernames to make sure they're unique
    if request.method == 'POST':
        net_type = request.POST['network_type']
        network = NetworkType(network_type=net_type)
        network.save()
        return Response(status=status.HTTP_200_OK)
    return Response(status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt  # because we want to be able to POST to this view from clients that won't have a CSRF token we need to mark the view as csrf_exempt
@api_view(['GET', 'POST', ])
def get_network_type(request, pk):
    try:
        network_type = NetworkType.objects.get(pk=pk)
    except NetworkType.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)  # Working = HttpResponse(status=404)
    # REMEMBER TO PASS IN THE CONTENT TYPE YOU WANT RETURNED WHEN USING Response() Wrapper
    if request.method == 'POST':
        the_network_type = NetworkTypeSerializer(network_type)
        return Response(the_network_type.data,
                        status=status.HTTP_200_OK)  # working = return JsonResponse(the_network_type.data)


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


@csrf_exempt  # because we want to be able to POST to this view from clients that won't have a CSRF token we need to mark the view as csrf_exempt
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


@api_view(['GET', 'POST'])  # This is good to have a browsable view of the API
def network_type_list(request, format=None):
    """
    List all network devices.
    """
    network_types = NetworkType.objects.all()
    network_types_serialized = NetworkTypeSerializer(network_types, many=True)
    return Response(network_types_serialized.data)

@csrf_exempt
@api_view(['GET', 'POST', ])
def register_network_config(request):
    users = User.objects.all()
    if request.method == 'POST':
        username = request.POST['username']
        config_name = request.POST['config-name']
        network_type = request.POST['network-type']
        password = request.POST['password']

        network_device = NetworkDevice.objects.first()

        print (username + ' ' + config_name + ' ' + network_type + ' ' + password)

        if network_device.password == password:
            if User.objects.filter(username=username).exists():
                user = User.objects.get(username=username)
                net_type = NetworkType.objects.get(network_type=network_type)
                UserNetworkConfig.objects.create(
                    network_name=config_name,
                    user=user,
                    network_type=net_type,
                )
                data = {'success': 'true'}
                return Response(data=data, status=status.HTTP_200_OK)
        data = {'success': 'false', 'reason':'incorrect_password'}
        return Response(data=data, status=status.HTTP_401_UNAUTHORIZED)
    data = {'success': 'false', 'reason': 'incorrect_password'}
    return Response(data=data, status=status.HTTP_401_UNAUTHORIZED)

        # check is user exists (by username
        # compare passwords


@csrf_exempt
@api_view(['GET', 'POST', ])
def register_user(request):
    if request.method == 'POST':
        email = request.POST.get('email', "")
        password = request.POST.get('password', "")
        alias = request.POST.get('nickname', "")
        app_admin = request.POST.get('app-admin', "")

        admin_users = AdminUsers.objects.all()
        #if len(admin_users) > 0:
         #   print('Admins exist. Requesting permission for newuser')
          #  for user in admin_users.iterator():
           #     user = User.objects.get(id=user.id)
            #    print(user.email)
            # data = {'success': 'false', 'reason': 'admin-approval-required'}
            # return Response(data=data, status=status.HTTP_200_OK)
        if User.objects.filter(email=email).exists():
            print('user exists')
            data = {'success': 'false', 'reason' : 'user-exists'}
            # json = JSONRenderer().render(data)
            # print(json)
            return Response(data=data, status=status.HTTP_409_CONFLICT)
        if email != -1 and password != -1:
            print('creating user')
            User.objects.create(
                email=email,
                password=password,
                username=alias,
            )
            if app_admin == "True":
                print('Requested user as an admin')
                AdminUsers.objects.create(
                    user=User.objects.get(email=email)
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
                data = {'success': 'true', 'nickname' : user.username}
                return Response(data=data, status=status.HTTP_200_OK)
        return Response(data=data, status=status.HTTP_401_UNAUTHORIZED)
    return Response(data=data, status=status.HTTP_401_UNAUTHORIZED)


@csrf_exempt
@api_view(['GET', 'POST', ])
def run_vulnerability_scan(request):
    print('Request to perform openvas')
    scan_results = ScanResults()
    hosts = []
    key = ""
    if request.method == 'POST':
        hosts = request.POST['hosts']
        scan_type = request.POST['vulnerability-scan-type']
        key = '1234567890123456'.encode('utf-8')  # Add user key
        print('Hosts to scan: ' +hosts)

    t1 = threading.Thread(target=vulnerability_assessment.run_openvas_scan, args=(scan_results, hosts, key, scan_type))
    t1.start()

    data = {'scan-started': 'true', 'scan-id': scan_results.scan_id, 'action': 'openvas_scan_started'}
    jsonResponse = json.dumps(data, default=jsonDefault)
    return HttpResponse(jsonResponse, content_type="application/json")


@csrf_exempt
@api_view(['GET', 'POST', ])
def run_nmap_scan(request):
    print('Request to perform nmap scan')
    key = ""
    nmapScanConfig = NmapScanConfig()
    if request.method == 'POST':
        nmapScanConfig.scan_technique = request.POST['network-scan-technique']
        nmapScanConfig.scanType = request.POST['network-scan-type']
        nmapScanConfig.port_range = request.POST['port-range']
        nmapScanConfig.hosts = request.POST['network-scan-hosts']
        nmapScanConfig.detections_ops = request.POST['network-detection-ops']
        nmapScanConfig.custom_args = request.POST['network-scan-custom-args']

        key = '1234567890123456'.encode('utf-8')  # Add user key

    scan_results = ScanResults()
    t1 = threading.Thread(target=vulnerability_assessment.run_nmap_scan, args=(scan_results, key, nmapScanConfig))
    t1.start()

    data = {'scan-started': 'true', 'scan-id': scan_results.scan_id, 'action': 'nmap_scan_started'}
    jsonResponse = json.dumps(data, default=jsonDefault)
    return HttpResponse(jsonResponse, content_type="application/json", status=200)

@csrf_exempt
@api_view(['GET', 'POST', ])
def check_scan_status(request):
    data = {'action' : 'scan-status', 'scan-finished': 'false'}
    if request.method == 'POST':
        scan_id = request.POST['scan-id']
    if vulnerability_assessment.scan_results:
        for scan_result in vulnerability_assessment.scan_results:
            if str(scan_result.scan_id) == scan_id:
                if scan_result.error != '':
                    data = {'action': 'scan-status', 'scan-finished': 'true', 'error' : scan_result.error}
                    json_response = json.dumps(data, default=jsonDefault)
                    return HttpResponse(json_response, content_type="application/json", status=status.HTTP_404_NOT_FOUND)
                if scan_result.results_collected is True:
                    data = {'action' : 'scan-status', 'scan-finished': 'true'}
                    json_response = json.dumps(data, default=jsonDefault)
                    return HttpResponse(json_response, content_type="application/json", status=status.HTTP_200_OK)
    json_response = json.dumps(data, default=jsonDefault)
    return HttpResponse(json_response, content_type="application/json", status=status.HTTP_404_NOT_FOUND)


@csrf_exempt
@api_view(['GET', 'POST', ])
def get_pending_results(request):
    if request.method == 'POST':
        scan_id = request.POST['scan-id']
        results_type = request.POST['result-type']
        key = '1234567890123456'.encode('utf-8')  # Add user key

        for scan_result in vulnerability_assessment.scan_results:
            if str(scan_result.scan_id) == scan_id:
                if results_type == 'openvas-results':
                    print("Retrieving OpenVas result")
                    openvas_result = OpenVasResults()
                    openvas_report = openvas_result.get_results(scan_result.vuln_assessment_path, key)
                    scan_result.openvas_result.append(openvas_report)
                if results_type == 'nmap-results':
                    print("Retrieving Network Mapping Results")
                    nmap_result = NmapResult()
                    nmap_result.get_results(scan_result.network_discovery_path, key)
                    scan_result.nmap_result = nmap_result

                json_response = json.dumps(scan_result, default=jsonDefault)
                if results_type == 'openvas-results':
                    scan_result.openvas_result.remove(openvas_report)
                if results_type == 'nmap-scan':
                    scan_result.nmap_result = None
                return HttpResponse(json_response, content_type="application/json", status=status.HTTP_200_OK)

    data = {'error': 'Unable to retrieve results'}
    json_response = json.dumps(data, default=jsonDefault)
    return HttpResponse(json_response, content_type="application/json")

@csrf_exempt
@api_view(['GET', 'POST', ])
def get_stored_results(request):
    if request.method == 'POST':
        scan_id = request.POST['scan-id']
        results_type = request.POST['result-type']
        key = '1234567890123456'.encode('utf-8')  # Add user key

        scan_result = ScanResults()
        path = "/root/Desktop/FinalYearProjectRESTAPI/automated_scans/reports/"
        path_prefix = ".xml"

        if results_type == 'openvas-results':
            print("Retrieving OpenVas result")
            openvas_result = OpenVasResults()
            openvas_report = openvas_result.get_results(path+ str(scan_id) + path_prefix, key)
            scan_result.openvas_result.append(openvas_report)
        if results_type == 'nmap-results':
            print("Retrieving Network Mapping Results")
            nmap_result = NmapResult()
            nmap_result.get_results(path+ str(scan_id) + path_prefix, key)
            scan_result.nmap_result = nmap_result

        json_response = json.dumps(scan_result, default=jsonDefault)
        if results_type == 'openvas-results':
            scan_result.openvas_result.remove(openvas_report)
        if results_type == 'nmap-scan':
            scan_result.nmap_result = None
        return HttpResponse(json_response, content_type="application/json", status=status.HTTP_200_OK)

    data = {'error': 'Unable to retrieve results'}
    json_response = json.dumps(data, default=jsonDefault)
    return HttpResponse(json_response, content_type="application/json")
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
