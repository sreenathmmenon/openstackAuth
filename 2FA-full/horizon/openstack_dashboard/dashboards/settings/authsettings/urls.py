# Copyright 2012 Nebula, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from django.conf.urls import patterns
from django.conf.urls import url

from openstack_dashboard.dashboards.settings.authsettings import views


urlpatterns = patterns(
    '',
    url(r'^$', views.Manage2FAView.as_view(), name='index'),
    url(r'^$', views.Manage2FAView.as_view(), name='twofactor'),
    #url(r'^$', views.ManageTwoFactorView.as_view(), name='twofactor'),
    #url(r'^twofactor/$', views.ManageTwoFactorView.as_view(), name='twofactor'),
    url(r'^twofactor/newkey/$', views.Manage2FAKeyView.as_view(), name='newkey'),
    url(r'^twofactor/disable/$', views.Disable2FAView.as_view(), name='twofactor_disable'),
    url(r'^ajax/validate_code/$', views.validate_code, name='validate_code'),
)

