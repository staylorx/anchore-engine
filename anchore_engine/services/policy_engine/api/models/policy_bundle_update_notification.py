# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from anchore_engine.services.policy_engine.api.models.base_model_ import Model
from anchore_engine.services.policy_engine.api import util


class PolicyBundleUpdateNotification(Model):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    def __init__(self, bundle_id=None, event_timestamp=None):  # noqa: E501
        """PolicyBundleUpdateNotification - a model defined in Swagger

        :param bundle_id: The bundle_id of this PolicyBundleUpdateNotification.  # noqa: E501
        :type bundle_id: str
        :param event_timestamp: The event_timestamp of this PolicyBundleUpdateNotification.  # noqa: E501
        :type event_timestamp: datetime
        """
        self.swagger_types = {
            'bundle_id': str,
            'event_timestamp': datetime
        }

        self.attribute_map = {
            'bundle_id': 'bundle_id',
            'event_timestamp': 'event_timestamp'
        }

        self._bundle_id = bundle_id
        self._event_timestamp = event_timestamp

    @classmethod
    def from_dict(cls, dikt):
        """Returns the dict as a model

        :param dikt: A dict.
        :type: dict
        :return: The PolicyBundleUpdateNotification of this PolicyBundleUpdateNotification.  # noqa: E501
        :rtype: PolicyBundleUpdateNotification
        """
        return util.deserialize_model(dikt, cls)

    @property
    def bundle_id(self):
        """Gets the bundle_id of this PolicyBundleUpdateNotification.


        :return: The bundle_id of this PolicyBundleUpdateNotification.
        :rtype: str
        """
        return self._bundle_id

    @bundle_id.setter
    def bundle_id(self, bundle_id):
        """Sets the bundle_id of this PolicyBundleUpdateNotification.


        :param bundle_id: The bundle_id of this PolicyBundleUpdateNotification.
        :type bundle_id: str
        """

        self._bundle_id = bundle_id

    @property
    def event_timestamp(self):
        """Gets the event_timestamp of this PolicyBundleUpdateNotification.

        The time of the external event. Should be set to when the event occurred, to the delivery time  # noqa: E501

        :return: The event_timestamp of this PolicyBundleUpdateNotification.
        :rtype: datetime
        """
        return self._event_timestamp

    @event_timestamp.setter
    def event_timestamp(self, event_timestamp):
        """Sets the event_timestamp of this PolicyBundleUpdateNotification.

        The time of the external event. Should be set to when the event occurred, to the delivery time  # noqa: E501

        :param event_timestamp: The event_timestamp of this PolicyBundleUpdateNotification.
        :type event_timestamp: datetime
        """

        self._event_timestamp = event_timestamp
