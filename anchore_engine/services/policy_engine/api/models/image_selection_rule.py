# coding: utf-8

from __future__ import absolute_import
from anchore_engine.services.policy_engine.api.models.image_ref import ImageRef
from .base_model_ import Model
from datetime import date, datetime
from typing import List, Dict
from ..util import deserialize_model


class ImageSelectionRule(Model):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self, id=None, name=None, registry=None, repository=None, image=None):
        """
        ImageSelectionRule - a model defined in Swagger

        :param id: The id of this ImageSelectionRule.
        :type id: str
        :param name: The name of this ImageSelectionRule.
        :type name: str
        :param registry: The registry of this ImageSelectionRule.
        :type registry: str
        :param repository: The repository of this ImageSelectionRule.
        :type repository: str
        :param image: The image of this ImageSelectionRule.
        :type image: ImageRef
        """
        self.swagger_types = {
            'id': str,
            'name': str,
            'registry': str,
            'repository': str,
            'image': ImageRef
        }

        self.attribute_map = {
            'id': 'id',
            'name': 'name',
            'registry': 'registry',
            'repository': 'repository',
            'image': 'image'
        }

        self._id = id
        self._name = name
        self._registry = registry
        self._repository = repository
        self._image = image

    @classmethod
    def from_dict(cls, dikt):
        """
        Returns the dict as a model

        :param dikt: A dict.
        :type: dict
        :return: The ImageSelectionRule of this ImageSelectionRule.
        :rtype: ImageSelectionRule
        """
        return deserialize_model(dikt, cls)

    @property
    def id(self):
        """
        Gets the id of this ImageSelectionRule.

        :return: The id of this ImageSelectionRule.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this ImageSelectionRule.

        :param id: The id of this ImageSelectionRule.
        :type id: str
        """

        self._id = id

    @property
    def name(self):
        """
        Gets the name of this ImageSelectionRule.

        :return: The name of this ImageSelectionRule.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this ImageSelectionRule.

        :param name: The name of this ImageSelectionRule.
        :type name: str
        """
        if name is None:
            raise ValueError("Invalid value for `name`, must not be `None`")

        self._name = name

    @property
    def registry(self):
        """
        Gets the registry of this ImageSelectionRule.

        :return: The registry of this ImageSelectionRule.
        :rtype: str
        """
        return self._registry

    @registry.setter
    def registry(self, registry):
        """
        Sets the registry of this ImageSelectionRule.

        :param registry: The registry of this ImageSelectionRule.
        :type registry: str
        """
        if registry is None:
            raise ValueError("Invalid value for `registry`, must not be `None`")

        self._registry = registry

    @property
    def repository(self):
        """
        Gets the repository of this ImageSelectionRule.

        :return: The repository of this ImageSelectionRule.
        :rtype: str
        """
        return self._repository

    @repository.setter
    def repository(self, repository):
        """
        Sets the repository of this ImageSelectionRule.

        :param repository: The repository of this ImageSelectionRule.
        :type repository: str
        """
        if repository is None:
            raise ValueError("Invalid value for `repository`, must not be `None`")

        self._repository = repository

    @property
    def image(self):
        """
        Gets the image of this ImageSelectionRule.

        :return: The image of this ImageSelectionRule.
        :rtype: ImageRef
        """
        return self._image

    @image.setter
    def image(self, image):
        """
        Sets the image of this ImageSelectionRule.

        :param image: The image of this ImageSelectionRule.
        :type image: ImageRef
        """
        if image is None:
            raise ValueError("Invalid value for `image`, must not be `None`")

        self._image = image

