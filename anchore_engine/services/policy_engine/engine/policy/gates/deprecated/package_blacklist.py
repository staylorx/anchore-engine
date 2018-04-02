from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.policy.params import NameVersionStringListParameter, CommaDelimitedStringListParameter
from anchore_engine.db import ImagePackage
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.policy.gates.util import deprecated_operation

log = get_logger()


class FullMatchTrigger(BaseTrigger):
    __trigger_name__ = 'pkgfullmatch'
    __description__ = 'triggers if the evaluated image has a package installed that matches one in the list given as a param (package_name|vers)'
    fullmatch_blacklist = NameVersionStringListParameter(name='blacklist_fullmatch', description='List of package name|version pairs for exact match')

    def evaluate(self, image_obj, context):
        pkgs = self.fullmatch_blacklist.value() if self.fullmatch_blacklist.value() else []

        for pkg, vers in pkgs.items():
            try:
                matches = image_obj.packages.filter(ImagePackage.name == pkg, ImagePackage.version == vers)
                for m in matches:
                    self._fire(msg='PKGFULLMATCH Package is blacklisted: ' + m.name + "-" + m.version)
            except Exception as e:
                log.exception('Error filtering packages for full match')
                pass


class NameMatchTrigger(BaseTrigger):
    __trigger_name__ = 'pkgnamematch'
    __description__ = 'triggers if the evaluated image has a package installed that matches one in the list given as a param (package_name)'
    namematch_blacklist = CommaDelimitedStringListParameter(name='blacklist_namematch', description='List of package names to be blacklisted')

    def evaluate(self, image_obj, context):
        pkg_names = self.namematch_blacklist.value() if self.namematch_blacklist.value() else []

        for pval in pkg_names:
            try:
                for pkg in image_obj.packages.filter(ImagePackage.name == pval):
                    self._fire(msg='PKGNAMEMATCH Package is blacklisted: ' + pkg.name)
            except Exception as e:
                log.exception('Error searching packages for blacklisted names')
                pass

@deprecated_operation(superceded_by='packages')
class PackageBlacklistGate(Gate):
    __gate_name__ = 'pkgblacklist'
    __description__ = 'Distro Package Blacklists'
    __triggers__ = [
        FullMatchTrigger,
        NameMatchTrigger
    ]