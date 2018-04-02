from collections import OrderedDict, namedtuple
import enum
import copy
import re
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, TriggerMatch
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.util.docker import parse_dockerimage_string
from anchore_engine.services.policy_engine.engine.util.matcher import regexify, is_match
from anchore_engine.services.policy_engine.engine.policy.formatting import policy_json_to_txt, whitelist_json_to_txt
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger

from anchore_engine.services.policy_engine.engine.policy.exceptions import TriggerNotAvailableError, \
    TriggerEvaluationError, \
    TriggerNotFoundError, \
    GateEvaluationError, \
    DeprecatedGateWarning, \
    GateNotFoundError, \
    ParameterValueInvalidError, \
    InvalidParameterError, \
    InvalidGateAction, \
    PolicyEvaluationError, \
    UnsupportedVersionError, \
    PolicyError, \
    InitializationError, \
    ValidationError, \
    BundleTargetTagMismatchError, PolicyRuleValidationErrorCollection, DuplicateIdentifierFoundError, ReferencedObjectNotFoundError

# Load all the gate classes to ensure the registry is populated. This may appear unused but is necessary for proper lookup
from anchore_engine.services.policy_engine.engine.policy.gates import *

log = get_logger()


class VersionedEntityMixin(object):
    __supported_versions__ = ['1_0']

    def verify_version(self, json_obj):
        found_version = json_obj.get('version')
        if not found_version or found_version not in self.__supported_versions__:
            raise UnsupportedVersionError(got_version=found_version, supported_versions=self.__supported_versions__, message='Version not supported')


class GateAction(enum.IntEnum):
    """
    The outcome of a policy rule evaluation against a gate trigger
    """

    stop = -1
    warn = 0
    go = 1


class SimpleMemoryBundleCache(object):
    def __init__(self):
        self._bundles = {}

    def get(self, user_id, bundle_id):
        return self._bundles.get((user_id, bundle_id))

    def cache(self, user_id, bundle):
        self._bundles[(user_id, bundle.id)] = bundle

    def flush(self):
        self._bundles = {}


class WhitelistAwarePolicyDecider(object):
    @classmethod
    def decide(cls, decisions):
        candidate_actions = map(lambda x: x.action,
                                filter(lambda d: not getattr(d, 'is_whitelisted', False), decisions))
        if candidate_actions:
            return min(candidate_actions)
        else:
            return GateAction.go  # No matches or everything is whitelisted


class AlwaysStopDecider(object):
    @classmethod
    def decide(cls, decisions):
        return GateAction.stop


class AlwaysGoDecider(object):
    @classmethod
    def decide(cls, decisions):
        return GateAction.go


class PolicyRuleDecision(object):
    """
    A policy decision is a combination of a TriggerMatch and an 'action' as defined by a policy.
    """

    def __init__(self, trigger_match, policy_rule):
        self.match = trigger_match
        self.policy_rule = policy_rule

    @property
    def action(self):
        """
        Returns the evaluated action from the trigger and mapped policy_rule
        :return: a rule evaluation's GateAction result
        """
        if self.match and not (hasattr(self.match, 'is_whitelisted') and self.match.is_whitelisted):
            return self.policy_rule.action
        else:
            return GateAction.go

    def json(self):
        return {
            'match': self.match.json(),
            'rule': self.policy_rule.json(),
            'action': self.action.name
        }


class ErrorMatch(TriggerMatch):
    """
    An instance of a fired trigger
    """

    class EmptyGate(object):
        __gate_name__ = 'gate_not_found'
        __description__ = 'Placeholder for executions where policy includes a gate not found in the server'

    class EmptyTrigger(BaseTrigger):
        __trigger_name__ = 'empty'
        __description__ = 'Empty trigger definition for handling errors like trigger-not-found'

        def __init__(self, parent_gate_cls, msg=None):
            self.gate_cls = parent_gate_cls if parent_gate_cls else ErrorMatch.EmptyGate
            self.msg = 'Trigger implementation not found, this is placeholder' if not msg else msg

    def __init__(self, trigger, match_instance_id=None, msg=None):
        self.trigger = trigger if trigger else ErrorMatch.EmptyTrigger(ErrorMatch.EmptyGate)
        self.id = match_instance_id if match_instance_id else 'evaluation_error'
        self.msg = msg

    def json(self):
        return {
            'trigger': self.trigger.__trigger_name__,
            'trigger_id': self.id,
            'message': self.msg
        }


class PolicyRuleFailure(PolicyRuleDecision):
    """
    A failure indicator that the rule could not be evaluated.
    """

    def __init__(self, trigger_match, policy_rule, failure_msg, failure_cause):
        """
        A failure to execute. Failure-cause should be an exception, with addition info in the failure_msg

        :param trigger_match:
        :param policy_rule:
        :param failure_msg:
        :param failure_cause:
        """
        self.match = trigger_match if trigger_match else ErrorMatch(None, msg=failure_msg)
        self.policy_rule = policy_rule
        self.msg = failure_msg
        self.cause = failure_cause

    @property
    def action(self):
        """
        Since this is a failure indicator, it simply emits WARN actions that can be mapped to warnings

        :return: GateAction.warn
        """
        return GateAction.warn

    def json(self):
        return {
            'match': self.match.json(),
            'rule': self.policy_rule.json(),
            'action': self.action.name,
            'failed': True,
            'error_message': self.msg,
            'error_cause': self.cause.message if hasattr(self.cause, 'message') else str(self.cause)
        }


class PolicyDecision(object):
    """
    A policy decision is a set of rule decisions and a final decision computed from those.
    Each policy rule decision can have whitelist decorators and if so will be ignored in the
    final decision computation.

    """
    __decider__ = WhitelistAwarePolicyDecider

    def __init__(self, policy_obj=None, rule_decisions=None):
        self.evaluated_policy = policy_obj
        self.decisions = rule_decisions if rule_decisions else []

    @property
    def final_decision(self):
        return self.__decider__.decide(self.decisions)

    def json(self):
        return {
            'policy': self.evaluated_policy.json() if self.evaluated_policy else None,
            'decisions': [r.json() for r in self.decisions] if self.decisions else None,
            'final_action': self.final_decision
        }

class BundleDecision(object):
    """
    Extentions of a PolicyDecision to include Image Blacklist and Whitelist abilities
    """

    def __init__(self, policy_decision, whitelist_match=None, blacklist_match=None):
        self.policy_decision = policy_decision
        self.whitelisted_image = whitelist_match if whitelist_match else None
        self.blacklisted_image = blacklist_match if blacklist_match else None

        if self.blacklisted_image:
            self.final_decision = GateAction.stop
            self.reason = 'blacklisted'
        elif self.whitelisted_image:
            self.final_decision = GateAction.go
            self.reason = 'whitelisted'
        else:
            self.final_decision = self.policy_decision.final_decision
            self.reason = 'policy_evaluation'

    def json(self):
        return {
            'policy_decision': self.policy_decision.json() if self.policy_decision else None,
            'policy_final_action': self.policy_decision.final_decision.name,
            'matched_whitelisted_image_rule': self.whitelisted_image.json() if self.whitelisted_image else None,
            'matched_blacklisted_image_rule': self.blacklisted_image.json() if self.blacklisted_image else None,
            'final_action': self.final_decision.name,
            'reason': self.reason
        }


class FallThruPolicyDecision(PolicyDecision):
    __decider__ = AlwaysGoDecider


class FailurePolicyDecision(PolicyDecision):
    __decider__ = AlwaysStopDecider


class BundleExecution(object):
    """
    Bundle Execution is the resulting state from a bundle execution and includes output and warnings/errors
    occuring during execution or validation.

    """
    CLI_COMPATIBLE_HEADER_SET = [
        'Image_Id',
        'Repo_Tag',
        'Trigger_Id',
        'Gate',
        'Trigger',
        'Check_Output',
        'Gate_Action',
        'Whitelisted'
    ]

    def __init__(self, bundle, image_id, tag, matched_mapping=None, decision=None):
        self.executed_bundle = bundle
        self.executed_mapping = matched_mapping
        self.image_id = image_id
        self.tag = tag
        self.bundle_decision = decision
        self.warnings = []
        self.errors = []

    def json(self):
        return {
            'bundle': self.executed_bundle.json() if self.executed_bundle else None,
            'mapping': self.executed_mapping.json() if self.executed_mapping else None,
            'image_id': self.image_id,
            'tag': self.tag,
            'bundle_decision': self.bundle_decision.json() if self.bundle_decision else None,
            'warnings': [str(x) for x in self.warnings] if self.warnings else None,
            'errors': [str(x) for x in self.errors] if self.errors else None
        }

    def _row_json(self, policy_rule_decision):
        """
        Return a table-row entry for the triggered item
        :param policy_rule_decision:
        :return: json-safe list of values
        """

        return [
            self.image_id,
            self.tag,
            policy_rule_decision.match.id,
            policy_rule_decision.match.trigger.gate_cls.__gate_name__,
            policy_rule_decision.match.trigger.__trigger_name__,
            policy_rule_decision.match.msg,
            policy_rule_decision.action.name,
            policy_rule_decision.match.whitelisted_json() if hasattr(policy_rule_decision.match, 'whitelisted_json') else False
        ]

    def as_table_json(self):
        """
        Render as table-style json, compatible with anchore cli output
        :return:
        """

        wh_data = []
        exec_policy = None
        if self.executed_mapping:
            for x in self.executed_mapping.whitelist_ids:
                # A bit of error handling here for partial results due to validation errors that can make this not consistent
                wl = self.executed_bundle.whitelists.get(x)
                if wl:
                    wh_data += whitelist_json_to_txt(wl.json())
                else:
                    log.warn('Executed bundle: {} against tag {}, image: {} contains whitelist reference {} in executed rule that is not found'.format(self.executed_bundle.id if self.executed_bundle else 'none', self.tag, self.image_id, x))

        if self.executed_bundle and self.executed_bundle.policies and self.executed_mapping.policy_id:
            exec_policy = self.executed_bundle.policies.get(self.executed_mapping.policy_id)
            if exec_policy:
                exec_policy = exec_policy.json()


        table = {
            self.image_id: {
                'result': {
                    'header': self.CLI_COMPATIBLE_HEADER_SET,
                    'row_count': len(self.bundle_decision.policy_decision.decisions),
                    'rows': [self._row_json(t) for t in self.bundle_decision.policy_decision.decisions],
                    'final_action': self.bundle_decision.final_decision.name.upper(),
                },
            },
            'policy_name': self.executed_mapping.policy_id if self.executed_mapping else '',
            'whitelist_names': self.executed_mapping.whitelist_ids if self.executed_mapping else [],
            'policy_data': policy_json_to_txt(exec_policy),
            'whitelist_data': wh_data
        }

        return table


class PolicyRule(object):
    def __init__(self, policy_json=None):
        self.gate_name = policy_json.get('gate')
        self.trigger_name = policy_json.get('trigger')
        self.rule_id = policy_json.get('id')

        # Convert to lower-case for case-insensitive matches
        self.trigger_params = {p.get('name').lower(): p.get('value') for p in policy_json.get('params')}

        action = policy_json.get('action', '').lower()
        try:
            self.action = GateAction.__members__[action]
        except KeyError:
            raise InvalidGateAction(gate=self.gate_name, trigger=self.trigger_name, rule_id=self.rule_id, action=action,
                                    valid_actions=filter(lambda x: not x.startswith('_'), GateAction.__dict__.keys()))

        self.error_exc = None
        self.errors = []

    def execute(self, image_obj, exec_context):
        pass


def policy_rule_factory(policy_json, strict_validation=True):
    try:
        rule = ExecutablePolicyRule(policy_json)
    except GateNotFoundError as ex:
        if not strict_validation and EndOfLifedPolicyRule.is_eoled(policy_json):
            rule = EndOfLifedPolicyRule(policy_json)
        else:
            raise ex

    return rule


class EndOfLifedPolicyRule(PolicyRule):
    end_of_lifed_gates = [
        'pkgdiff',
        'suiddiff',
        'base_check'
    ]

    class EOLedGate(Gate):
        def prepare_context(self, image_obj, context):
            return context

    def __init__(self, policy_json=None):
        super(EndOfLifedPolicyRule, self).__init__(policy_json)
        self.errors.append(DeprecatedGateWarning(self.gate_name))
        self.gate_cls = EndOfLifedPolicyRule.EOLedGate

    def execute(self, image_obj, exec_context):
        return self.errors, []

    @classmethod
    def is_eoled(cls, policy_json):
        return policy_json.get('gate').lower() in cls.end_of_lifed_gates


class ExecutablePolicyRule(PolicyRule):
    """
    A single rule to be compiled and executable.

    A rule is a single gate, trigger tuple with associated parameters for the trigger. The execution output
    is the set of fired trigger instances resulting from execution against a specific image.
    """

    def __init__(self, policy_json=None):
        super(ExecutablePolicyRule, self).__init__(policy_json)

        # Configure the trigger instance
        try:
            self.gate_cls = Gate.get_gate_by_name(self.gate_name)
        except KeyError:
            # Gate not found
            self.error_exc = GateNotFoundError(gate=self.gate_name, valid_gates=Gate.registered_gate_names(), rule_id=self.rule_id)
            self.configured_trigger = None
            raise self.error_exc

        try:
            selected_trigger_cls = self.gate_cls.get_trigger_named(self.trigger_name.lower())
        except KeyError:
            self.error_exc = TriggerNotFoundError(valid_triggers=self.gate_cls.trigger_names(), trigger=self.trigger_name, gate=self.gate_name, rule_id=self.rule_id)
            self.configured_trigger = None
            raise self.error_exc

        try:

            try:
                self.configured_trigger = selected_trigger_cls(parent_gate_cls=self.gate_cls, rule_id=self.rule_id, **self.trigger_params)
            except [TriggerNotFoundError, InvalidParameterError, ParameterValueInvalidError] as e:
                # Error finding or initializing the trigger
                log.exception('Policy rule execution exception: {}'.format(e))
                self.error_exc = e
                self.configured_trigger = None

                if hasattr(e, 'gate') and e.gate is None:
                    e.gate = self.gate_name
                if hasattr(e, 'trigger') and e.trigger is None:
                    e.trigger = self.trigger_name
                if hasattr(e, 'rule_id') and e.rule_id is None:
                    e.rule_id = self.rule_id
                raise e
        except PolicyError:
            raise # To filter out already-handled errors
        except Exception as e:
            raise ValidationError.caused_by(e)

    def execute(self, image_obj, exec_context):
        """
        Execute the trigger specified in the rule with the image and gate (for prepared context) and exec_context)

        :param image_obj: The image to execute against
        :param exec_context: The prepared execution context from the gate init
        :return: a tuple of a list of errors and a list of PolicyRuleDecisions, one for each fired trigger match produced by the trigger execution
        """

        matches = None

        try:
            if not self.configured_trigger:
                log.error('No configured trigger to execute for gate {} and trigger: {}. Returning'.format(self.gate_name, self.trigger_name))
                raise TriggerNotFoundError(trigger_name=self.trigger_name, gate_name=self.gate_name)

            try:
                self.configured_trigger.execute(image_obj, exec_context)
            except TriggerEvaluationError as e:
                log.exception('Error executing trigger {} on image {}'.format(self.trigger_name, image_obj.id))
                raise
            except Exception as e:
                log.exception('Unmapped exception caught during trigger evaluation')
                raise TriggerEvaluationError('Could not evaluate trigger due to error in evaluation execution')

            matches = self.configured_trigger.fired
            decisions = []

            # Try all rules and record all decisions and errors so multiple errors can be reported if present, not just the first encountered
            for match in matches:
                try:
                    decisions.append(PolicyRuleDecision(trigger_match=match, policy_rule=self))
                except TriggerEvaluationError as e:
                    log.exception('Policy rule decision mapping exception: {}'.format(e))
                    self.errors.append(str(e))

            return self.errors, decisions
        except Exception as e:
            log.exception('Error executing trigger!')
            raise

    def _safe_execute(self, image_obj, exec_context):
        """
        An alternate execution path that treats failures like specific triggers so they can be handled with
        whitelists etc. NOT CURRENTLY USED!

        :param image_obj:
        :param exec_context:
        :return:
        """
        pass
        # matches = None
        # try:
        #     if not self.configured_trigger:
        #         if self.gate_cls:
        #             err_trigger = ErrorMatch.EmptyTrigger(parent_gate_cls=self.gate_cls,
        #                                                   msg='Trigger not found: {}'.format(self.trigger_name))
        #             err_trigger._fire(instance_id='invalid_trigger',
        #                               msg='Trigger {} not found in gate'.format(self.trigger_name))
        #             self.configured_trigger = err_trigger
        #         else:
        #             match = None
        #             return [PolicyRuleFailure(trigger_match=match, policy_rule=self,
        #                                   failure_msg='No implementation found for gate/trigger: {}/{}'.format(
        #                                       self.gate_name, self.trigger_name), failure_cause=self.error_exc)]
        #     else:
        #         # Normal execution
        #         try:
        #             self.configured_trigger.execute(image_obj, exec_context)
        #         except Exception as e:
        #             log.exception('Error executing trigger on image {}'.format(image_obj.id))
        #             if self.configured_trigger.fired:
        #
        #
        #
        #     matches = self.configured_trigger.fired
        #     raise Exception('Always fail!!')
        #     decisions = [PolicyRuleDecision(trigger_match=match, policy_rule=self) for match in matches]
        #     return decisions
        # except Exception as e:
        #     if matches:
        #         return [PolicyRuleFailure(trigger_match=matches, policy_rule=self, failure_msg='Error evaluating rule', failure_cause=e)]
        #     else:
        #         return [PolicyRuleFailure(trigger_match=ErrorMatch(trigger=self.configured_trigger), policy_rule=self, failure_msg='Error evaluating rule', failure_cause=e)]


    def json(self):
        return {
            'gate': self.gate_name,
            'action': self.action.name,
            'trigger': self.trigger_name,
            'params': self.trigger_params
        }


class ExecutablePolicy(VersionedEntityMixin):
    """
    A sequence of gate triggers to be executed with specific parameters.

    The build process establishes the set of gates and triggers and the order based on the policy and configures
    each with the parameters defined in the policy document.

    Execution is the process of invoking each trigger with the proper image context and collecting the results.
    Policy executions only depend on the image analysis context, not the tag mapping.

    Gate objects are used only to construct the triggers and to prepare the execution context for each trigger.

    """

    def __init__(self, raw_json=None, strict_validation=True):
        self.raw = raw_json
        if not raw_json:
            raise ValueError('Empty whitelist json')
        self.verify_version(raw_json)
        self.version = raw_json.get('version')

        self.id = raw_json.get('id')
        self.name = raw_json.get('name')
        self.comment = raw_json.get('comment')
        self.rules = []
        errors = []

        for x in raw_json.get('rules'):
            try:
                self.rules.append(policy_rule_factory(x, strict_validation=strict_validation))
            except PolicyRuleValidationErrorCollection as e:
                for err in e.validation_errors:
                    errors.append(err)
            except PolicyError as e:
                errors.append(e)
            except Exception as e:
                errors.append(ValidationError.caused_by(e))

        if errors:
            raise InitializationError(message='Policy initialization failed due to validation errors', init_errors=errors)

        self.gates = OrderedDict()

        # Map the rule set into a minimal set of gates to execute linked to the list of rules for each gate
        for r in self.rules:
            if r.gate_cls not in self.gates:
                self.gates[r.gate_cls] = [r]
            else:
                self.gates[r.gate_cls].append(r)

    def execute(self, image_obj, context):
        """
        Execute the policy and return the result as a list of PolicyRuleDecisions

        :param image_obj: the image object to evaluate
        :param context: an ExecutionContext object
        :return: a PolicyDecision object
        """

        results = []
        errors = []
        for gate, policy_rules in self.gates.items():
            # Initialize the gate object
            gate_obj = gate()
            exec_context = gate_obj.prepare_context(image_obj, context)
            for rule in policy_rules:
                errs, matches = rule.execute(image_obj=image_obj, exec_context=exec_context)
                if errs:
                    errors += errs
                if matches:
                    results += matches

        return errors, PolicyDecision(self, results)

    def json(self):
        if self.raw:
            return self.raw
        else:
            return {
                'id': self.id,
                'name': self.name,
                'version': self.version,
                'comment': self.comment,
                'rules': [r.json() for r in self.rules]
            }


class MappingRule(object):
    """
    A mapping rule that selects targets
    """
    def __init__(self, rule_json=None):
        self.registry = rule_json.get('registry')
        self.repository = rule_json.get('repository')
        self.image_match_type = rule_json.get('image').get('type')

        if self.image_match_type == 'tag':
            self.image_tag = rule_json.get('image').get('value')
        else:
            self.image_tag = None

        if self.image_match_type == 'id':
            self.image_id = rule_json.get('image').get('value')
        else:
            self.image_id = None

        if self.image_match_type == 'digest':
            self.image_digest = rule_json.get('image').get('value')
        else:
            self.image_digest = None

        self.policy_id = rule_json.get('policy_id')
        self.whitelist_ids = rule_json.get('whitelist_ids')
        self.raw = rule_json

    def json(self):
        if self.raw:
            return self.raw
        else:
            return {
                'registry': self.registry,
                'repository': self.repository,
                'image': {
                    'type': self.image_match_type,
                    'value': self.image_tag if self.image_tag else self.image_digest if self.image_digest else self.image_id if self.image_id else None
                }
            }

    def is_all_registry(self):
        return self.registry == '*'

    def is_all_repository(self):
        return self.repository == '*'

    def is_all_tags(self):
        return self.image_tag == '*'

    def is_tag(self):
        return self.image_match_type == 'tag'

    def is_digest(self):
        return self.image_match_type == 'digest'

    def is_id(self):
        return self.image_match_type == 'id'

    def _registry_match(self, registry_str):
        return is_match(regexify, self.registry, registry_str)

    def _repository_match(self, repository_str):
        return is_match(regexify, self.repository, repository_str)

    def _tag_match(self, tag_str):
        return is_match(regexify, self.image_tag, tag_str)

    def _id_match(self, image_id):
        return self.image_id == image_id and image_id is not None

    def _digest_match(self, image_digest):
        return self.image_digest == image_digest and image_digest is not None

    def matches(self, image_obj, tag):
        """
        Returns true if this rule matches the given tag and image tuple according to the matching rules.

        :param image_obj: loaded image object
        :param tag: tag string
        :return: Boolean
        """

        if not tag:
            raise ValueError('Tag cannot be empty or null for matching evaluation')
        else:
            match_target = parse_dockerimage_string(tag)

        # Must match registry and repo first
        if not (self._registry_match(match_target.get('registry')) and self._repository_match(match_target.get('repo'))):
            return False

        if self.is_digest():
            return self._digest_match(image_obj.digest)
        elif self.is_id():
            return self._id_match(image_obj.id)
        elif self.is_tag():

            if image_obj:
                return self._tag_match(match_target.get('tag')) or self._id_match(image_obj.id) or self._digest_match(image_obj.digest)
            else:
                return self._tag_match(match_target.get('tag'))


class PolicyMappingRule(MappingRule):
    """
    A single mapping rule that can be evaluated against a tag and image
    """

    def __init__(self, rule_json=None):
        super(PolicyMappingRule, self).__init__(rule_json)

        self.policy_id = rule_json.get('policy_id')
        self.whitelist_ids = rule_json.get('whitelist_ids')

    def json(self):
        if self.raw:
            return self.raw
        else:
            r = super(PolicyMappingRule, self).json()
            r['policy_id'] = self.policy_id,
            r['whitelist_ids'] = self.whitelist_ids
            return r


class ExecutableMapping(object):
    """
    A set of mapping rules to be evaluated against a tag name and image (image identifiers can be in mapping rules)

    Evaluates the bundle mappings in order. Order is very important and must be preserved.
    """

    def __init__(self, mapping_json=None, rule_cls=MappingRule):
        self.raw = mapping_json
        self.mapping_rules = [rule_cls(rule) for rule in mapping_json]

    def execute(self, image_obj, tag):
        """
        Execute the mapping by performing a match and returning the policy and whitelists referenced.

        :param image_obj: loaded image object from db
        :param tag: tag string
        :return: ExecutableMappingRule that is the first match in the ruleset
        """

        if not tag:
            raise ValueError('tag cannot be None')

        # Special handling of 'dockerhub' -> 'docker.io' conversion.
        if tag and tag.startswith('dockerhub/'):
            target_tag = tag.replace('dockerhub/', 'docker.io/')
        else:
            target_tag = tag

        result = filter(lambda y: y.matches(image_obj, target_tag), self.mapping_rules)

        # Could have more than one match, in which case return the first
        if result and len(result) >= 1:
            return result[0]
        else:
            return None

    def json(self):
        if self.raw:
            return self.raw
        else:
            return [m.json() for m in self.mapping_rules]


class WhitelistedTriggerMatch(TriggerMatch):
    """
    A recursive type extension for trigger match to indicate a whitelist match. May match against a base trigger match or
    another type of trigger match including other WhitelistedTriggerMatches.
    """

    def __init__(self, trigger_match, matched_whitelist_item):
        super(WhitelistedTriggerMatch, self).__init__(trigger_match.trigger, trigger_match.id, trigger_match.msg)
        self.whitelist_match = matched_whitelist_item

    def is_whitelisted(self):
        return self.whitelist_match is not None

    def whitelisted_json(self):
        return {
            'whitelist_name': self.whitelist_match.parent_whitelist.name,
            'whitelist_id': self.whitelist_match.parent_whitelist.id,
            'matched_rule_id': self.whitelist_match.id
        }

    def json(self):
        j = super(WhitelistedTriggerMatch, self).json()

        # Note: encode this as an object in the 'whitelisted' col for tabular output.
        # Note when rendering to json for result, a regular FiredTrigger's 'whitelisted' column should = bool false
        j['whitelisted'] = {
            'whitelist_name': self.whitelist_match.parent_whitelist.name,
            'whitelist_id': self.whitelist_match.parent_whitelist.id,
            'matched_rule_id': self.whitelist_match.id
        }
        return j


class ExecutableWhitelistItem(object):
    """
    A single whitelist item to evaluate against a single gate trigger instance
    """
    def __init__(self, item_json, parent):
        self.id = item_json.get('id')
        self.gate = item_json.get('gate').lower()
        self.trigger_id = item_json.get('trigger_id')
        self.parent_whitelist = parent

    def execute(self, trigger_match):
        """
        Return a processed instance
        :param trigger_inst: the trigger instance to check
        :return: a WhitelistedTriggerInstance or a TriggerInstance depending on if the items match
        """
        if hasattr(trigger_match, 'is_whitelisted') and trigger_match.is_whitelisted():
            return trigger_match

        if hasattr(trigger_match, 'id'):
            if self.matches(trigger_match):
                return WhitelistedTriggerMatch(trigger_match, self)
            else:
                return trigger_match

    def matches(self, fired_trigger_obj):
        # TODO: add alias checks here for backwards compat

        return self.gate == fired_trigger_obj.trigger.gate_cls.__gate_name__.lower() and \
               (self.trigger_id == fired_trigger_obj.id or is_match(regexify, self.trigger_id, fired_trigger_obj.id))

    def json(self):
        return {
            'id': self.id,
            'gate': self.gate,
            'trigger_id': self.trigger_id
        }


class IWhitelistItemIndex(object):
    """
    A data structure to lookup potential whitelist items for a given gate output
    """

    def add(self, item):
        """
        Add the whitelist item to the index for lookup

        :param item:
        :return:
        """
        pass

    def candidates_for(self, decision_match):
        """
        Return whitelist items that may match the decision. Depending on the implementation may be an exact or fuzzy match.

        :param decision_match:
        :return: list of ExecutableWhitelistItem objects
        """
        raise NotImplementedError()


class HybridTriggerIdKeyedItemIndex(IWhitelistItemIndex):
    """
    An index that has a primary keyed lookup and a secondary list for unkeyed entries.

    Each gate has its own index composed of a keyed index and an array for any whitelist items that are not triggerid specific
    """

    GateItemIndex = namedtuple('GateItemIndex', ['keyed','unkeyed'])

    def __init__(self, item_key_fn=None, match_key_fn=None):
        self.gate_keys = OrderedDict()
        self.key_fn = item_key_fn
        self.match_key_fn = match_key_fn

    def add(self, item):
        key = None
        if self.key_fn:
            key = self.key_fn(item)

        gate_name = item.gate.lower()

        if gate_name not in self.gate_keys:
            self.gate_keys[gate_name] = HybridTriggerIdKeyedItemIndex.GateItemIndex(keyed=OrderedDict(), unkeyed=[])

        if not key:
            self.gate_keys[gate_name].unkeyed.append(item)
        else:
            if key not in self.gate_keys[gate_name].keyed:
                self.gate_keys[gate_name].keyed[key] = []

            self.gate_keys[gate_name].keyed[key].append(item)

    def candidates_for(self, decision):
        gate_entry = self.gate_keys.get(decision.match.trigger.gate_cls.__gate_name__.lower())
        if not gate_entry:
            return []

        if self.match_key_fn:
            key = self.match_key_fn(decision)
        else:
            key = None

        if key:
            keyed = gate_entry.keyed.get(key, [])
        else:
            keyed = []

        unkeyed = gate_entry.unkeyed
        return keyed + unkeyed


class StandardCVETriggerIdKey(object):
    cve_trigger_id_regex = re.compile('([A-Za-z0-9\-])+\+\*')
    supported_gates = [AnchoreSecGate.__gate_name__.lower()]

    @classmethod
    def whitelist_item_key(cls, item):
        """
        Return a key value for the item if the item is an ANCHORESEC gate with trigger_id of the
        form <CVE>+<pkg> where <pkg> may be '*'. Else return None

        :param item: a whitelist item json
        :return: a key for a dictionary or None if not hashable/indexable
        """

        if item.gate.lower() in cls.supported_gates and cls.cve_trigger_id_regex.match(item.trigger_id):
            return cls.anchoresec_trigger_id_to_parts(item.trigger_id)
        return None

    @classmethod
    def anchoresec_trigger_id_to_parts(cls, trigger_id):
        pieces = trigger_id.split('+', 1)
        if len(pieces) > 1:
            cve, pkg = pieces
            # pkg is either a specific pkg or a wildcard
            return cve
        return trigger_id

    @classmethod
    def decision_item_key(cls, decision):
        gate = decision.match.trigger.gate_cls.__gate_name__.lower()
        if gate in cls.supported_gates:
            return cls.anchoresec_trigger_id_to_parts(decision.match.id)
        else:
            return decision.match.id

    @classmethod
    def noop_key(cls, item):
        """
        Always return None, so no keyed lookups are done.

        :param item:
        :return:
        """
        return None


class ExecutableWhitelist(VersionedEntityMixin):
    """
    A list of items to whitelist. Executable in the sense that the whitelist can be executed against a policy output
    to result in a WhitelistedPolicyEvaluation.
    """
    _use_indexes = True

    def __init__(self, whitelist_json):
        self.raw = whitelist_json
        if not whitelist_json:
            raise ValueError('Empty whitelist json')

        self.verify_version(whitelist_json)
        self.version = whitelist_json.get('version')

        self.id = whitelist_json.get('id')
        self.name = whitelist_json.get('name')
        self.comment = whitelist_json.get('comment')

        self.items = []
        self.whitelist_item_index = HybridTriggerIdKeyedItemIndex(item_key_fn=StandardCVETriggerIdKey.whitelist_item_key, match_key_fn=StandardCVETriggerIdKey.decision_item_key)
        self.items_by_gate = OrderedDict()

        for item in self.raw.get('items'):
            i = ExecutableWhitelistItem(item, self)
            self.items.append(i)
            self.whitelist_item_index.add(i)

            if not item.get('gate').lower() in self.items_by_gate:
                self.items_by_gate[item.get('gate').lower()] = []
            self.items_by_gate[item.get('gate').lower()].append(ExecutableWhitelistItem(item, self))

    def execute(self, policyrule_decisions):
        """
        Transform the given list of fired triggers into a set of WhitelistedFiredTriggers as defined by this policy.
        Resulting list may contain a mix of FiredTrigger and WhitelistedFiredTrigger objects.

        Any trigger already whitelisted should be modified and simply passed thru.

        :param evaluation_result: a list of TriggerMatch objects or WhitelistedTrigger objects to process
        :return: a new modified list of TriggerMatch objects updated with the policy specified by this whitelist
        """

        processed_decisions = copy.deepcopy(policyrule_decisions)

        for decision in processed_decisions:
            if ExecutableWhitelist._use_indexes:
                rules = self.whitelist_item_index.candidates_for(decision)
            else:
                rules = self.items_by_gate.get(decision.match.trigger.gate_cls.__gate_name__.lower(), [])

            # If whitelist match, wrap it with the match data, else pass thru
            for rule in rules:
                decision.match = rule.execute(decision.match)

        return processed_decisions

    def json(self):
        return {
            'id': self.id,
            'version': self.version,
            'name': self.name,
            'comment': self.comment,
            'items': [i.json() for i in self.items]
        }


class ExecutableBundle(VersionedEntityMixin):
    """
    An executable representation of a policy bundle. Usage is to configure the bundle and then
    execute it with a specific image and tag tuple. Tag is necessary for the mapping evaluation.

    The bundle is compiled without the image directly so it can be executed repeatedly with different tags and images
    each time for efficiency.
    """

    def __init__(self, bundle_json, tag=None, strict_validation=True):
        """
        Build and initialize the bundle. If errors are encountered they are buffered until the end and all returned
        at once in an aggregated InitializationError to ensure that all errors can be presented back to the user, not
        just the first one. The exception to that rule is the version check on the bundle itself, which is returned directly
        if the UnsupportedVersionError is raised since parsing cannot proceed reliably.

        :param bundle_json: the json the build
        :param tag: a string tag value to use to execute mapping and optimize bundle for if present (optional)
        :param strict_validation: bool to toggle support for deprecated gates
        """
        if not bundle_json:
            raise ValidationError('No bundle json received')

        self.verify_version(bundle_json)

        self.raw = bundle_json
        self.id = self.raw.get('id')
        self.name = self.raw.get('name')
        self.version = self.raw.get('version')
        self.comment = self.raw.get('comment')
        self.policies = {}
        self.whitelists = {}
        self.mapping = None
        self.trusted_image_mappings = []
        self.blacklisted_image_mappings = []

        self.init_errors = []
        if tag:
            self.target_tag = tag
        else:
            self.target_tag = None


        try:
            # Build the mapping first, then build reachable policies and whitelists
            self.mapping = ExecutableMapping(self.raw.get('mappings', []), rule_cls=PolicyMappingRule)
            self.whitelisted_image_mapping = ExecutableMapping(self.raw.get('whitelisted_images', []))
            self.blacklisted_image_mapping = ExecutableMapping(self.raw.get('blacklisted_images', []))

            # If building for a specific tag target, only build the mapped rules, else build all rules
            if self.target_tag:
                rule = self.mapping.execute(image_obj=None, tag=self.target_tag)
                if rule is not None:
                    rules = [rule]
                    self.mapping.mapping_rules = filter(lambda x: x == rule, self.mapping.mapping_rules)
                else:
                    rules = []

            else:
                rules = self.mapping.mapping_rules

            for rule in rules:
                try:
                    # Build the specified policy for the rule
                    policy = filter(lambda x: x['id'] == rule.policy_id, self.raw.get('policies', []))
                    if not policy:
                        raise ReferencedObjectNotFoundError(reference_id=rule.policy_id, reference_type='policy')
                    elif len(policy) > 1:
                        raise DuplicateIdentifierFoundError(identifier=rule.policy_id, identifier_type='policy')

                    self.policies[rule.policy_id] = ExecutablePolicy(policy[0], strict_validation=strict_validation)
                except Exception as e:
                    if isinstance(e, InitializationError):
                        self.init_errors += e.causes
                    else:
                        self.init_errors.append(e)

                # Build the whitelists for the rule
                for wl in rule.whitelist_ids:
                    try:
                        whitelist = filter(lambda x: x['id'] == wl, self.raw.get('whitelists', []))
                        if not whitelist:
                            raise ReferencedObjectNotFoundError(reference_id=wl, reference_type='whitelist')
                        elif len(whitelist) > 1:
                            raise DuplicateIdentifierFoundError(identifier=wl, identifier_type='whitelist')

                        self.whitelists[wl] = ExecutableWhitelist(whitelist[0])
                    except Exception as e:
                        if isinstance(e, InitializationError):
                            self.init_errors += e.causes
                        else:
                            self.init_errors.append(e)

        except Exception as e:
            if isinstance(e, InitializationError):
                self.init_errors += e.causes
            else:
                self.init_errors.append(e)

    def _validate_mappings(self):
        # Validate mapping references
        for m in self.mapping.mapping_rules:
            if m.policy_id not in self.policies:
                raise ReferencedObjectNotFoundError(reference_id=m.policy_id, reference_type='policy')
            for w in m.whitelist_ids:
                if w not in self.whitelists:
                    raise ReferencedObjectNotFoundError(reference_id=w, reference_type='whitelist')

    def validate(self):
        """
        Executes a validation pass on the policy bundle as constructed. Does not alter any state.
        :return: list of errors, if empty, the validation has passed
        """

        return self.init_errors

    def execute(self, image_object, tag, context):
        """
        Execute the bundle evaluation in isolated context (includes db session if necessary)
        
        :param image_id: 
        :param tag_list: 
        :return: 
        """

        if self.target_tag and tag != self.target_tag:
            raise BundleTargetTagMismatchError(self.target_tag, tag)

        bundle_exec = BundleExecution(self, image_id=image_object.id, tag=tag)

        if self.init_errors:
            raise InitializationError(message='Initialization of the bundle failed with errors',
                                      init_errors=self.init_errors)

        # Execute the mapping to find the policy and whitelists to execute next
        try:
            if self.mapping:
                bundle_exec.executed_mapping = self.mapping.execute(image_object, tag)
            else:
                bundle_exec.executed_mapping = None
                bundle_exec.bundle_decision = BundleDecision(policy_decision=FailurePolicyDecision())
                return bundle_exec

        except PolicyError as e:
            log.exception('Error executing bundle mapping')
            bundle_exec.errors.append(e)
            bundle_exec.bundle_decision = BundleDecision(policy_decision=FailurePolicyDecision())
            return bundle_exec
        except Exception as e:
            log.exception('Error executing bundle mapping')
            bundle_exec.errors.append(PolicyError.caused_by(e))
            bundle_exec.bundle_decision = BundleDecision(policy_decision=FailurePolicyDecision())
            return bundle_exec

        # Evaluate the selected policy or set none if none found
        try:
            if bundle_exec.executed_mapping:
                evaluated_policy = self.policies[bundle_exec.executed_mapping.policy_id]
            else:
                evaluated_policy = None
        except KeyError:
            # Referenced policy is not found, mark error
            bundle_exec.errors.append(ReferencedObjectNotFoundError(reference_id=bundle_exec.executed_mapping.policy_id, reference_type='policy'))

            bundle_exec.bundle_decision = BundleDecision(policy_decision=FailurePolicyDecision())
            return bundle_exec

        try:
            if evaluated_policy:
                errors, policy_decision = evaluated_policy.execute(image_obj=image_object, context=context)
                if errors:
                    log.warn('Evaluation encountered errors/warnings: {}'.format(errors))
                    bundle_exec.errors += errors

                # Send thru the whitelist handlers
                for wl in bundle_exec.executed_mapping.whitelist_ids:
                    policy_decision.decisions = self.whitelists[wl].execute(policy_decision.decisions)
            else:
                errors = None
                policy_decision = FallThruPolicyDecision()

            # Send thru the whitelist mapping
            whitelisted_image_match = None
            if self.whitelisted_image_mapping:
                whitelisted_image_match = self.whitelisted_image_mapping.execute(image_obj=image_object, tag=tag)

            # Send thru the blacklist mapping
            blacklist_image_match = None
            if self.blacklisted_image_mapping:
                blacklist_image_match = self.blacklisted_image_mapping.execute(image_obj=image_object, tag=tag)

            bundle_exec.bundle_decision = BundleDecision(policy_decision=policy_decision, whitelist_match=whitelisted_image_match, blacklist_match=blacklist_image_match)

        except PolicyEvaluationError as e:
            bundle_exec.errors.append(e.errors)

        return bundle_exec

    def json(self):
        if self.raw:
            return self.raw
        else:
            return {
                'id': self.id,
                'name': self.name,
                'version': self.version,
                'comment': self.comment,
                'policies': [p.json() for p in self.policies],
                'whitelists': [w.json() for w in self.whitelists],
                'mappings': self.mapping.json()
            }


def build_empty_error_execution(image_obj, tag, bundle, errors=None, warnings=None):
    """
    Creates an empty BundleExecution suitable for use in error cases where the bundle was not actually run but this object
    is needed to populate errors and warnings for return.

    :param image_obj:
    :param tag:
    :param bundle:
    :return: BundleExecution object with bundle, image, and tag set and a STOP final action.
    """

    b = BundleExecution(bundle=bundle, image_id=image_obj.id, tag=tag)
    b.bundle_decision = BundleDecision(policy_decision=FailurePolicyDecision())
    b.errors = errors
    b.warnings = warnings
    return b


def build_bundle(bundle_json, for_tag=None, allow_deprecated=False):
    """
    Parse and build an executable bundle from the input. Handles versions to construct the
    proper bundle object or raises an exception if version is not supported.

    If for_tag is provided, will return a bundle build to only execute the given tag. If the mapping section
    of the bundle_json does not provide a mapping for the tag, None is returned since there is no bundle to execute for that tag.
    
    :param bundle_json:
    :param for_tag: the tag to build the bundle for exclusively
    :return: ExecutableBundle object
    """
    if bundle_json:

        if for_tag:
            try:
                bundle = ExecutableBundle(bundle_json, tag=for_tag, strict_validation=(not allow_deprecated))
            except KeyError:
                bundle = None
        else:
            bundle = ExecutableBundle(bundle_json)
    else:
        raise ValueError('No bundle json found')
    return bundle
