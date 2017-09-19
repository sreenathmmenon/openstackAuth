from django.utils.translation import ugettext_lazy as _
from horizon import tables
from django.core.urlresolvers import reverse, reverse_lazy

class MFAFilterAction(tables.FilterAction):
    name = "mfafilter"

class MFATable(tables.DataTable):
    name         = tables.Column('name', \
                                 verbose_name=_("Method"))
    description  = tables.Column('description', \
                                 verbose_name=_("Description"))
	
    class Meta(object):
        name = "mfa"
        verbose_name = _("MFA")
        table_actions = (MFAFilterAction,)


