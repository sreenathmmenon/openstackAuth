from django.utils.translation import ugettext_lazy as _

from horizon import exceptions
from horizon import tabs

from openstack_dashboard import api
from openstack_dashboard.dashboards.settings.multisettings import tables

class MFATab(tabs.TableTab):
    name = _("MFA Tab")
    slug = "mfa_tag"
    table_classes = (tables.MFATable,)
    template_name = ("horizon/common/_detail_table.html")
    preload = False
  
    #def has_more_data(self, table):
    #return self._has_more

    def get_mfa_data(self):
	#list1 = ['physics', 'chemistry', 1997, 2000];
	list1 = {'id':'1','name':'ball'}
        return list1

class MFApanelTabs(tabs.TabGroup):
    slug = "mfapanel_tabs"
    tabs = (MFATab,)
    sticky = True
