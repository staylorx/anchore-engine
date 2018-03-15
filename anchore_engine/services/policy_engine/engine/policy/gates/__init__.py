# Import all valid gates

from .dockerfile import DockerfileGate
from .files import FileCheckGate
from .etc_passwd_content import FileparsePasswordGate
from .packages import PackagesCheckGate
from .anchoresec import AnchoreSecGate
from .licenses import LicensesGate
from .gem_check import GemCheckGate
from .npm_check import NpmCheckGate
from .secret_check import SecretCheckGate
from .image_metadata import ImageMetadataGate
from .always import AlwaysGate
