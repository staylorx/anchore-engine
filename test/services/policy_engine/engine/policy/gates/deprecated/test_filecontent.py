from test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db import get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.policy.gates.files import FileCheckGate, FilenameMatchTrigger, ContentMatchTrigger, SuidCheckTrigger
from anchore_engine.db import Image

class FileCheckGateTest(GateUnitTest):
    gate_clazz = FileCheckGate

    def get_initialized_trigger(self, name, config=None, **kwargs):
        clazz = self.gate_clazz.get_trigger_named(name)
        trigger = clazz(self.gate_clazz, **kwargs)
        context = ExecutionContext(db_session=get_thread_scoped_session(), configuration=config)
        gate = trigger.gate_cls()

        return trigger, gate, context

    def test_filenamematch(self):
        t, gate, test_context = self.get_initialized_trigger(FilenameMatchTrigger.__trigger_name__, filecheck_nameregexp='/etc/.*')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertGreater(len(t.fired), 0)

    def test_contentmatch(self):
        t, gate, test_context = self.get_initialized_trigger(ContentMatchTrigger.__trigger_name__, filecheck_contentregexp='.*password.*')
        db = get_thread_scoped_session()
        content_test_image = db.query(Image).get((self.test_env.get_images_named('alpine_3.5')[0][0], '0'))
        test_context = gate.prepare_context(content_test_image, test_context)
        t.evaluate(content_test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 1)

        t.reset()
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 0)

    def test_suidchecktrigger(self):
        t, gate, test_context = self.get_initialized_trigger(SuidCheckTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertGreater(len(t.fired), 0)



