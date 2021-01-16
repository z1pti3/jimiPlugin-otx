from core import plugin, model

class _otx(plugin._plugin):
    version = 0.2

    def install(self):
        # Register models
        model.registerModel("otxUpdate","_otxUpdate","_action","plugins.otx.models.action")
        model.registerModel("otxLookup","_otxLookup","_action","plugins.otx.models.action")
        model.registerModel("otxLookupIPv4","_otxLookupIPv4","_action","plugins.otx.models.action")
        model.registerModel("otxLookupIPv6","_otxLookupIPv6","_action","plugins.otx.models.action")
        model.registerModel("otxLookupDomain","_otxLookupDomain","_action","plugins.otx.models.action")
        model.registerModel("otxLookupHostname","_otxLookupHostname","_action","plugins.otx.models.action")
        model.registerModel("otxLookupUrl","_otxLookupUrl","_action","plugins.otx.models.action")
        model.registerModel("otxLookupCve","_otxLookupCve","_action","plugins.otx.models.action")
        model.registerModel("otxLookupFileHash","_otxLookupFileHash","_action","plugins.otx.models.action")
        return True

    def uninstall(self):
        # deregister models
        model.deregisterModel("otxUpdate","_otxUpdate","_action","plugins.otx.models.action")
        model.deregisterModel("otxLookup","_otxLookup","_action","plugins.otx.models.action")
        model.deregisterModel("otxLookupIPv4","_otxLookupIPv4","_action","plugins.otx.models.action")
        model.deregisterModel("otxLookupIPv6","_otxLookupIPv6","_action","plugins.otx.models.action")
        model.deregisterModel("otxLookupDomain","_otxLookupDomain","_action","plugins.otx.models.action")
        model.deregisterModel("otxLookupHostname","_otxLookupHostname","_action","plugins.otx.models.action")
        model.deregisterModel("otxLookupUrl","_otxLookupUrl","_action","plugins.otx.models.action")
        model.deregisterModel("otxLookupCve","_otxLookupCve","_action","plugins.otx.models.action")
        model.deregisterModel("otxLookupFileHash","_otxLookupFileHash","_action","plugins.otx.models.action")
        return True
    
    def upgrade(self,LatestPluginVersion):
        if self.version < 0.2:
            model.registerModel("otxLookupIPv4","_otxLookupIPv4","_action","plugins.otx.models.action")
            model.registerModel("otxLookupIPv6","_otxLookupIPv6","_action","plugins.otx.models.action")
            model.registerModel("otxLookupDomain","_otxLookupDomain","_action","plugins.otx.models.action")
            model.registerModel("otxLookupHostname","_otxLookupHostname","_action","plugins.otx.models.action")
            model.registerModel("otxLookupUrl","_otxLookupUrl","_action","plugins.otx.models.action")
            model.registerModel("otxLookupCve","_otxLookupCve","_action","plugins.otx.models.action")
            model.registerModel("otxLookupFileHash","_otxLookupFileHash","_action","plugins.otx.models.action")
