from django.contrib import admin

from .models import NetworkType, NetworkDevice, UserNetworkConfig, Vulnerability, VulnerabilityURL, Url, \
    VulnerabilityFamily, ThreatLevel, MitigationType, AdminUser

# Register your models here.

admin.site.register(NetworkType)
admin.site.register(NetworkDevice)
admin.site.register(UserNetworkConfig)
admin.site.register(Vulnerability)
admin.site.register(VulnerabilityURL)
admin.site.register(AdminUser)
admin.site.register(Url)
admin.site.register(VulnerabilityFamily)
admin.site.register(ThreatLevel)
admin.site.register(MitigationType)