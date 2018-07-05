from openvas_lib import report_parser

from authentication.models import Vulnerability, VulnerabilityURL, Url, VulnerabilityFamily, MitigationType, ThreatLevel
from authentication.serializers import VulnerabilitySerializer, UrlInfoSerializer
import os

from automated_scans.security.cryptography import Encryptor


class OpenVasResults:
    def __init__(self):
        pass

    def get_report(self, openvas_results_encrypted_xml, key):
        print('Getting report')
        encryptor = Encryptor(key)
        encryptor.decrypt_file(openvas_results_encrypted_xml+'.enc')
        report = report_parser(openvas_results_encrypted_xml) #-4 to remove .enc extensions
        os.remove(openvas_results_encrypted_xml)
        vulnResult = None
        scanResults = []
        for result in report:
            if Vulnerability.objects.filter(vulnerabilityId=result.nvt.oid).exists():
                vulnResult = Vulnerability.objects.get(vulnerabilityId=result.nvt.oid)

                serializedResult = VulnerabilitySerializer(vulnResult)

                scanResult = {}
                #This is for setting values from the object returned from the scan, and getting values from Foreign Key fields
                for key, value  in serializedResult.data.items():
                    if (key is not 'host' or key is not 'port' or key is not 'protocol'):
                        scanResult[key] = value;
                    if key == 'host':
                        scanResult[key] = result.host
                    if key == 'port':
                        scanResult[key] = result.port.port_name
                    if key == 'protocol':
                        scanResult[key] = result.port.proto
                    if key == 'family':
                        vulnFamilyModel = VulnerabilityFamily.objects.get(id=value)
                        scanResult[key] = vulnFamilyModel.family
                    if key == 'solution_type':
                        vulnSolutionModel = MitigationType.objects.get(id=value)
                        scanResult[key] = vulnSolutionModel.mitigationtype
                        scanResult[key+'_technical'] = vulnSolutionModel.mitigationtypeTechnical
                    if key == 'threatRating':
                        vulnThreatModel = ThreatLevel.objects.get(id=value)
                        scanResult[key] = vulnThreatModel.threatLevel
                tags = result.nvt.tags


                urls = VulnerabilityURL.objects.filter(vulnerability=vulnResult)
                serializedUrls = []
                for url in urls:
                    print('url name: ' + url.url.urlName + 'vuln name: '+ vulnResult.name)
                    try:
                        urlInfo = Url.objects.get(id=url.url.id)
                        serializedUrl = UrlInfoSerializer(urlInfo)
                        serializedUrls.append(serializedUrl.data)
                    except Url.DoesNotExist:
                        print('id ' + str(url.id) + ' does not exist')



                if serializedUrls:
                    count = 0
                    scanResult['urlCount'] = len(serializedUrls)
                    for url in serializedUrls:
                        key = 'url' + str(count)
                        scanResult[key] = url
                        count += 1
                scanResults.append(scanResult)

        return scanResults




