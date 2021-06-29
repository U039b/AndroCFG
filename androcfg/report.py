import json
import os

from androguard.core.bytecodes.apk import APK
from pybars import Compiler


class MdReport:
    def __init__(self, rules_report, apk: APK):
        self.rules_report = rules_report
        self.apk = apk

    def generate(self, output_dir):
        app = {
            'package': self.apk.get_package(),
            'name': self.apk.get_app_name(),
            'version_name': self.apk.get_androidversion_name(),
            'version_code': self.apk.get_androidversion_code(),
            'permissions': [{
                'name': k,
                'level': v[0],
                'short': v[1].replace('your ', ''),
            } for k, v in self.apk.get_details_permissions().items()]
        }

        ctx = {
            'app': app,
            'rules': self.rules_report
        }
        with open(f'{output_dir}/report.json', mode='w') as json_report:
            json.dump(ctx, json_report)
        compiler = Compiler()
        report_path = f'{output_dir}/report.md'
        root = os.path.dirname(os.path.realpath(__file__))
        template_path = os.path.join(root, 'report.tpl')
        with open(template_path) as template_file:
            template = compiler.compile(template_file.read())
        with open(report_path, mode='w') as report_file:
            report_file.write(template(ctx))

        return report_path
