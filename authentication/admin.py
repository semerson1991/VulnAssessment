from django.contrib import admin

from .models import NetworkType, NetworkDevice, UserNetworkConfig, Vulnerability, VulnerabilityURL, Url, \
    VulnerabilityFamily, ThreatLevel, MitigationType, AdminUsers

# Register your models here.

admin.site.register(NetworkType)
admin.site.register(NetworkDevice)
admin.site.register(UserNetworkConfig)
admin.site.register(Vulnerability)
admin.site.register(VulnerabilityURL)
admin.site.register(AdminUsers)
admin.site.register(Url)
admin.site.register(VulnerabilityFamily)
admin.site.register(ThreatLevel)
admin.site.register(MitigationType)