from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns

from authentication import views

urlpatterns = [

    url(r'^register-user/$', views.register_user),
    url(r'^login-user/$', views.login_user),
    url(r'^register-network-config/$', views.register_network_config),

    url(r'^register/$', views.register_network),
    url(r'^retrieve-network-type/(?P<pk>[0-9]+)/$', views.get_network_type),
    url(r'^update-network-type/(?P<pk>[0-9]+)/$', views.update_network_type),
    url(r'^delete-network-type/(?P<pk>[0-9]+)/$', views.delete_network_type),

    #Function, Class, and Mixins
    url(r'^view-network-types/$', views.network_type_list), #network_type_detail
    url(r'^view-network-types_class/$', views.NetworkTypeList.as_view()), #network_type_detail
    url(r'^view-network-types_class_mixins/$', views.NetworkTypeListMixing.as_view()),  # network_type_detail

    url(r'^run-vulnerability-scan/$', views.run_vulnerability_scan),
    url(r'^run-nmap-scan/$', views.run_nmap_scan),

    url(r'^check-scan-status/$', views.check_scan_status),
    url(r'^get-results/$', views.get_stored_results),
   # url(r'^get-stored-results/$', views.get_stored_results),

    url(r'^view-network-type-details/(?P<pk>[0-9]+)/$', views.network_type_detail),
    #url(r'^authentication/(?P<pk>[0-9]+)/$', views.snippet_detail),
]

urlpatterns = format_suffix_patterns(urlpatterns) #Allows for url file appendings e.g. append .json or .api (or use Accept.json)