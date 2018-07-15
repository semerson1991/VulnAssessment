from django.db import models

# Create your models here.
from django.db import models
import bcrypt
from django.contrib.auth.models import User


class AdminUser(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.user.username)


class NetworkDevice(models.Model):
    name = models.CharField(max_length=200, default='Home Network Device')
    password = models.CharField(max_length=256)

    def verify_password(self, raw_password):
        return bcrypt.checkpw(raw_password.encode('utf8'), self.password)

    def __str__(self):
        return str(self.id) + " " +self.name


class NetworkType(models.Model):
    network_type = models.CharField(max_length=250)

    def __str__(self):
        return str(self.id) + " " +self.network_type


class UserNetworkConfig(models.Model):
    network_name = models.CharField(max_length=256)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    network_type = models.ForeignKey(NetworkType, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.id) + " " +self.network_name

class VulnerabilityFamily(models.Model):
    family = models.CharField(max_length=32, blank=True, null=True)

    def __str__(self):
        return str(self.id) + " " +self.family


class ThreatLevel(models.Model):
    threatLevel = models.CharField(max_length=32, blank=True, null=True)

    def __str__(self):
        return str(self.id) + " " +self.threatLevel


class MitigationType(models.Model):
    mitigationtype = models.CharField(max_length=64, blank=True, null=True)
    mitigationtypeTechnical = models.CharField(max_length=64, blank=True, null=True)

    def __str__(self):
        return str(self.id) + " " +self.mitigationtype


class Vulnerability(models.Model):
    vulnerabilityId = models.CharField(max_length=64)
    host = models.GenericIPAddressField(blank=True, null=True)
    port = models.IntegerField(blank=True, null=True)
    protocol = models.CharField(max_length=64, blank=True, null=True)
    name = models.CharField(max_length=256, blank=True, null=True)
    technicalname = models.CharField(max_length=256, blank=True, null=True)
    baseScore = models.IntegerField(blank=True, null=True)
    baseVector= models.CharField(max_length=64, blank=True, null=True)
    family = models.ForeignKey(VulnerabilityFamily, on_delete=models.CASCADE, blank=True, null=True)
    summary = models.TextField(max_length=512,blank=True, null=True)
    impact = models.TextField(max_length=512, blank=True, null=True)
    solution = models.TextField(max_length=512, blank=True, null=True)
    solution_type = models.ForeignKey(MitigationType, on_delete=models.CASCADE, blank=True, null=True)
    technicalDetails = models.TextField(max_length=512, blank=True, null=True, )
    threatRating = models.ForeignKey(ThreatLevel, on_delete=models.CASCADE, blank=True, null=True)
    date = models.DateField()

    def __str__(self):
        return str(self.id) + " " +self.vulnerabilityId + " " + self.name


class Url(models.Model):
    urlName = models.CharField(max_length=256)
    urlDescription = models.CharField(max_length=256)

    def __str__(self):
        return str(self.id)+ " " +self.urlName


class VulnerabilityURL(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    url = models.ForeignKey(Url, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.id) + " " + self.vulnerability.name + "-" + self.url.urlName



