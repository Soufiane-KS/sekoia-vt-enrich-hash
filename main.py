from vtenrichhash_modules.action_vt_enrich_hash import VTEnrichHashAction
from vtenrichhash_modules import VtenrichhashModule

if __name__ == "__main__":
    module = VtenrichhashModule()
    module.register(VTEnrichHashAction, "vt_enrich_hash")
    module.run()
