from core import plugin, model

class _otx(plugin._plugin):
    version = 0.1

    def install(self):
        # Register models
        model.registerModel("otxUpdate","_otxUpdate","_action","plugins.otx.models.action")
        model.registerModel("otxLookup","_otxLookup","_action","plugins.otx.models.action")
        return True

    def uninstall(self):
        # deregister models
        model.deregisterModel("otxUpdate","_otxUpdate","_action","plugins.otx.models.action")
        model.deregisterModel("otxLookup","_otxLookup","_action","plugins.otx.models.action")
        return True
    