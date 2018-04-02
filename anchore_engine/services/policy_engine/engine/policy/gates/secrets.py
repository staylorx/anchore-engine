import re
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.policy.params import TypeValidator, TriggerParameter
from anchore_engine.db import AnalysisArtifact
log = get_logger()


default_included_regex_names = ["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "PRIV_KEY", "DOCKER_AUTH", "API_KEY"]


class SecretContentMatchTrigger(BaseTrigger):
    __trigger_name__ = 'content_regex_match'
    __description__ = 'Triggers if the content search analyzer has found any matches with the configured and named regexes. Matches are filtered by the content_regex_name and filename_regex if they are set'

    secret_contentregexp = TriggerParameter(name='content_regex_name', validator=TypeValidator('string'), example_str='"{}"'.format(default_included_regex_names[0]), description='Name of content regexps configured in the analyzer that should trigger if found in the image, instead of triggering for any match. Names available by default are: {}'.format(default_included_regex_names))
    name_regexps = TriggerParameter(name='filename_regex', validator=TypeValidator('string'), example_str='"/etc/.*"', description='Regexp to filter the content matched files by')

    def evaluate(self, image_obj, context):
        match_filter = self.secret_contentregexp.value(default_if_none=[])
        name_re = re.compile(self.name_regexps.value()) if self.name_regexps.value() else None

        if match_filter:
            matches = [x.encode('base64') for x in match_filter]
            matches_decoded = match_filter
        else:
            matches = []
            matches_decoded = []

        for thefile, regexps in context.data.get('secret_content_regexp', {}).items():
            thefile = thefile.encode('ascii', errors='replace')
            if not regexps:
                continue

            if regexps and (not name_re or name_re.match(thefile)):
                for regexp in regexps.keys():
                    try:
                        regexp_name, theregexp = regexp.decode('base64').split("=", 1)
                    except:
                        regexp_name = None
                        theregexp = regexp.decode('base64')

                    if not matches:
                        self._fire(msg='Secret search analyzer found regexp match in container: file={} regexp={}'.format(thefile, regexp.decode('base64')))
                    elif regexp in matches or theregexp in matches_decoded:
                        self._fire(msg='Secret search analyzer found regexp match in container: file={} regexp={}'.format(thefile, regexp.decode('base64')))
                    elif regexp_name and regexp_name in matches_decoded:
                        self._fire(msg='Secret search analyzer found regexp match in container: file={} regexp={}'.format(thefile, regexp.decode('base64')))


class SecretCheckGate(Gate):
    __gate_name__ = 'secret_scans'
    __description__ = 'Checks for Secrets Found in the Image'
    __triggers__ = [
        SecretContentMatchTrigger
    ]

    def prepare_context(self, image_obj, context):
        """
        prepare the context by extracting the file name list once and placing it in the eval context to avoid repeated
        loads from the db. this is an optimization and could removed.

        :param image_obj:
        :param context:
        :return:
        """

        if image_obj.fs:
            extracted_files_json = image_obj.fs.files

            if extracted_files_json:
                context.data['filenames'] = extracted_files_json.keys()

        content_matches = image_obj.analysis_artifacts.filter(AnalysisArtifact.analyzer_id == 'secret_search', AnalysisArtifact.analyzer_artifact == 'regexp_matches.all', AnalysisArtifact.analyzer_type == 'base').all()
        matches = {}
        for m in content_matches:
            matches[m.artifact_key] = m.json_value
        context.data['secret_content_regexp'] = matches

        return context
