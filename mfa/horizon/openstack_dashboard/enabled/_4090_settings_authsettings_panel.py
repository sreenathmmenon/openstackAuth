#The name of the PANEL to be added to the HORIZON_CONFIG.
PANEL = 'authsettings'

#The name of the dashboard the PANEL is associated with.
PANEL_DASHBOARD = 'settings'

#Python Panel class of the PANEL to be added
ADD_PANEL = 'openstack_dashboard.dashboards.settings.authsettings.panel.TwoFactorPanel'

#If set to True, the PANEL will be removed from PANEL_DASHBOARD/PANEL_GROUP.
#Set the below option to TRUE if Two factor authentication management shouldn't be displayed
REMOVE_PANEL = False
