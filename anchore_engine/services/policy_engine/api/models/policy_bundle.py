# coding: utf-8

from __future__ import absolute_import
from .image_selection_rule import ImageSelectionRule
from .mapping_rule import MappingRule
from .policy import Policy
from .whitelist import Whitelist
from .base_model_ import Model
from datetime import date, datetime
from typing import List, Dict
from ..util import deserialize_model


class PolicyBundle(Model):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self, id=None, name=None, comment=None, version=None, whitelists=None, policies=None, mappings=None, whitelisted_images=None, blacklisted_images=None):
        """
        PolicyBundle - a model defined in Swagger

        :param id: The id of this PolicyBundle.
        :type id: str
        :param name: The name of this PolicyBundle.
        :type name: str
        :param comment: The comment of this PolicyBundle.
        :type comment: str
        :param version: The version of this PolicyBundle.
        :type version: str
        :param whitelists: The whitelists of this PolicyBundle.
        :type whitelists: List[Whitelist]
        :param policies: The policies of this PolicyBundle.
        :type policies: List[Policy]
        :param mappings: The mappings of this PolicyBundle.
        :type mappings: List[MappingRule]
        :param whitelisted_images: The whitelisted_images of this PolicyBundle.
        :type whitelisted_images: List[ImageSelectionRule]
        :param blacklisted_images: The blacklisted_images of this PolicyBundle.
        :type blacklisted_images: List[ImageSelectionRule]
        """
        self.swagger_types = {
            'id': str,
            'name': str,
            'comment': str,
            'version': str,
            'whitelists': List[Whitelist],
            'policies': List[Policy],
            'mappings': List[MappingRule],
            'whitelisted_images': List[ImageSelectionRule],
            'blacklisted_images': List[ImageSelectionRule]
        }

        self.attribute_map = {
            'id': 'id',
            'name': 'name',
            'comment': 'comment',
            'version': 'version',
            'whitelists': 'whitelists',
            'policies': 'policies',
            'mappings': 'mappings',
            'whitelisted_images': 'whitelisted_images',
            'blacklisted_images': 'blacklisted_images'
        }

        self._id = id
        self._name = name
        self._comment = comment
        self._version = version
        self._whitelists = whitelists
        self._policies = policies
        self._mappings = mappings
        self._whitelisted_images = whitelisted_images
        self._blacklisted_images = blacklisted_images

    @classmethod
    def from_dict(cls, dikt):
        """
        Returns the dict as a model

        :param dikt: A dict.
        :type: dict
        :return: The PolicyBundle of this PolicyBundle.
        :rtype: PolicyBundle
        """
        return deserialize_model(dikt, cls)

    @property
    def id(self):
        """
        Gets the id of this PolicyBundle.
        Id of the bundle

        :return: The id of this PolicyBundle.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this PolicyBundle.
        Id of the bundle

        :param id: The id of this PolicyBundle.
        :type id: str
        """
        if id is None:
            raise ValueError("Invalid value for `id`, must not be `None`")

        self._id = id

    @property
    def name(self):
        """
        Gets the name of this PolicyBundle.

        :return: The name of this PolicyBundle.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this PolicyBundle.

        :param name: The name of this PolicyBundle.
        :type name: str
        """

        self._name = name

    @property
    def comment(self):
        """
        Gets the comment of this PolicyBundle.

        :return: The comment of this PolicyBundle.
        :rtype: str
        """
        return self._comment

    @comment.setter
    def comment(self, comment):
        """
        Sets the comment of this PolicyBundle.

        :param comment: The comment of this PolicyBundle.
        :type comment: str
        """

        self._comment = comment

    @property
    def version(self):
        """
        Gets the version of this PolicyBundle.

        :return: The version of this PolicyBundle.
        :rtype: str
        """
        return self._version

    @version.setter
    def version(self, version):
        """
        Sets the version of this PolicyBundle.

        :param version: The version of this PolicyBundle.
        :type version: str
        """
        if version is None:
            raise ValueError("Invalid value for `version`, must not be `None`")

        self._version = version

    @property
    def whitelists(self):
        """
        Gets the whitelists of this PolicyBundle.

        :return: The whitelists of this PolicyBundle.
        :rtype: List[Whitelist]
        """
        return self._whitelists

    @whitelists.setter
    def whitelists(self, whitelists):
        """
        Sets the whitelists of this PolicyBundle.

        :param whitelists: The whitelists of this PolicyBundle.
        :type whitelists: List[Whitelist]
        """

        self._whitelists = whitelists

    @property
    def policies(self):
        """
        Gets the policies of this PolicyBundle.

        :return: The policies of this PolicyBundle.
        :rtype: List[Policy]
        """
        return self._policies

    @policies.setter
    def policies(self, policies):
        """
        Sets the policies of this PolicyBundle.

        :param policies: The policies of this PolicyBundle.
        :type policies: List[Policy]
        """

        self._policies = policies

    @property
    def mappings(self):
        """
        Gets the mappings of this PolicyBundle.

        :return: The mappings of this PolicyBundle.
        :rtype: List[MappingRule]
        """
        return self._mappings

    @mappings.setter
    def mappings(self, mappings):
        """
        Sets the mappings of this PolicyBundle.

        :param mappings: The mappings of this PolicyBundle.
        :type mappings: List[MappingRule]
        """

        self._mappings = mappings

    @property
    def whitelisted_images(self):
        """
        Gets the whitelisted_images of this PolicyBundle.
        List of mapping rules that define which images should always be passed (unless also on the blacklist), regardless of policy result.

        :return: The whitelisted_images of this PolicyBundle.
        :rtype: List[ImageSelectionRule]
        """
        return self._whitelisted_images

    @whitelisted_images.setter
    def whitelisted_images(self, whitelisted_images):
        """
        Sets the whitelisted_images of this PolicyBundle.
        List of mapping rules that define which images should always be passed (unless also on the blacklist), regardless of policy result.

        :param whitelisted_images: The whitelisted_images of this PolicyBundle.
        :type whitelisted_images: List[ImageSelectionRule]
        """

        self._whitelisted_images = whitelisted_images

    @property
    def blacklisted_images(self):
        """
        Gets the blacklisted_images of this PolicyBundle.
        List of mapping rules that define which images should always result in a STOP/FAIL policy result regardless of policy content or presence in whitelisted_images

        :return: The blacklisted_images of this PolicyBundle.
        :rtype: List[ImageSelectionRule]
        """
        return self._blacklisted_images

    @blacklisted_images.setter
    def blacklisted_images(self, blacklisted_images):
        """
        Sets the blacklisted_images of this PolicyBundle.
        List of mapping rules that define which images should always result in a STOP/FAIL policy result regardless of policy content or presence in whitelisted_images

        :param blacklisted_images: The blacklisted_images of this PolicyBundle.
        :type blacklisted_images: List[ImageSelectionRule]
        """

        self._blacklisted_images = blacklisted_images

