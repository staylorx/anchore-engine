from test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db import get_thread_scoped_session, Image

from anchore_engine.services.policy_engine.engine.policy.gates.licenses import LicensesGate, FullMatchTrigger, SubstringMatchTrigger


class LicenseBlacklistGateTest(GateUnitTest):
    gate_clazz = LicensesGate


    def get_initialized_trigger(self, name, config=None, **kwargs):
        clazz = self.gate_clazz.get_trigger_named(name)
        trigger = clazz(self.gate_clazz, **kwargs)
        context = ExecutionContext(db_session=get_thread_scoped_session(), configuration=config)
        gate = trigger.gate_cls()

        return trigger, gate, context

    def test_fullmatch(self):
        t, gate, test_context = self.get_initialized_trigger(FullMatchTrigger.__trigger_name__,
                                                             licblacklist_fullmatch='Apache-2.0')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 1)

    def test_namematch(self):
        t, gate, test_context = self.get_initialized_trigger(SubstringMatchTrigger.__trigger_name__,
                                                             licblacklist_submatch='GPL')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 1)
