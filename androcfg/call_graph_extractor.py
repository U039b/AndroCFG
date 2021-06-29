import json
import os
from hashlib import md5
from pathlib import Path

import networkx as nx
from PIL import Image, ImageFont, ImageDraw
from androguard.core.mutf8 import MUTF8String
from androguard.misc import AnalyzeAPK
from graphviz import Digraph as dg
from networkx import neighbors, reverse_view
from pygments import highlight
from pygments.formatters.img import ImageFormatter
from pygments.lexers.jvm import JavaLexer

from androcfg.code_style import U39bStyle
from androcfg.genom import Genom
from androcfg.report import MdReport


def flatten(elements, flat_elements):
    if isinstance(elements, dict):
        for k, v in elements.items():
            flat_elements.append(k)
            flat_elements.extend(flatten(v, []))
    elif isinstance(elements, list):
        for elt in elements:
            flat_elements.extend(flatten(elt, []))
    elif isinstance(elements, MUTF8String) or isinstance(elements, str):
        flat_elements.append(str(elements))
    return flat_elements


class CFG:
    def __init__(self, apk_file, output_dir, rules_file=None, save_graphs=True) -> object:
        self.apk, self.dalvik_format_list, self.analysis = AnalyzeAPK(apk_file)
        self.apk_file = apk_file
        self.rules_file = rules_file
        self.output_dir = output_dir
        if self.rules_file is None:
            root = os.path.dirname(os.path.realpath(__file__))
            self.rules_file = os.path.join(root, 'rules.json')
        self.cfg_output_dir = f'{output_dir}/cfg/'
        self.code_output_dir = f'{output_dir}/code/'
        self.report_output_dir = f'{output_dir}/'
        self.cluster_names = {}
        self.call_graph = None
        self.save_graphs = save_graphs
        self._init_cluster_names()
        self._init_rules()
        self._init_output_dirs()
        self.report = []
        self.genom = Genom(self.rules_file, list(self.cluster_names.keys()))

    def _init_output_dirs(self):
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.cfg_output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.code_output_dir).mkdir(parents=True, exist_ok=True)

    def _init_rules(self):
        with open(self.rules_file) as rf:
            self.rules = json.load(rf)

    def _init_cluster_names(self):
        self.cluster_names = {
            'thread': self._get_sub_classes(['java/lang/ThreadLocal', 'java/lang/Thread']) +
                      self._get_impl_of('Ljava/lang/Runnable;'),
            'callable': self._get_impl_of('Ljava/util/concurrent/Callable;'),
            'fragment': self._get_sub_classes(['androidx/fragment/app/Fragment']),
            'webview_client': self._get_sub_classes(['android/webkit/WebViewClient']),
            'task': self._get_sub_classes(['android/os/AsyncTask']),
            'application': self._get_sub_classes(['android/app/Application']),
            'handler': self._get_sub_classes(['android/os/Handler']),
            'activity': self._get_sub_classes(['android/app/Activity',
                                               'androidx/appcompat/app/AppCompatActivity']),
            'provider': self._get_sub_classes(
                ['android/view/accessibility/AccessibilityNodeProvider',
                 'android/content/ContentProvider',
                 'android/view/ViewOutlineProvider']),
            'receiver': self._get_sub_classes(['android/content/BroadcastReceiver']),
            'service': self._get_sub_classes(['android/app/Service']),
            'intent_service': self._get_sub_classes(['android/app/IntentService']),
        }

    def _get_impl_of(self, interface):
        implementations = []
        for clazz in self.analysis.get_classes():
            if interface in clazz.implements:
                implementations.append(clazz.name[1:-1])
        return implementations

    def _get_sub_classes(self, super_class_name):
        scn = super_class_name
        sub_classes = []
        if isinstance(super_class_name, str):
            scn = [super_class_name]
        for dalvik in self.dalvik_format_list:
            hierarchy = dalvik.list_classes_hierarchy()['Root']
            for elt in hierarchy:
                if list(elt)[0] in scn:
                    sub_classes.extend(flatten(elt, []))
        return sub_classes

    def get_cluster_name(self, class_name):
        for cluster, classes in self.cluster_names.items():
            if class_name in classes:
                return cluster
        return 'unknown'

    def generate_json_report(self) -> dict:
        ctx = {
            'genom': self.genom.dumps(),
            'rules': self.report
        }

        return ctx

    @staticmethod
    def append_legend(image_file, text, font_size=10):
        def add_margin(pil_img, top, right, bottom, left, color):
            width, height = pil_img.size
            new_width = width + right + left
            new_height = height + top + bottom
            result = Image.new(pil_img.mode, (new_width, new_height), color)
            result.paste(pil_img, (left, top))
            return result

        original = Image.open(image_file)
        bottom_margin = 30
        new = add_margin(original, 0, 0, bottom_margin, 0, (89, 49, 150))
        image_height = new.height
        root = os.path.dirname(os.path.realpath(__file__))
        font_file = os.path.join(root, 'fonts/OpenSans-Regular.ttf')
        font = ImageFont.truetype(font_file, font_size)
        text_width, text_height = font.getsize(text)
        text_left = 10
        text_top = image_height - bottom_margin / 2 - text_height / 2
        draw = ImageDraw.Draw(new)
        draw.text((text_left, text_top), text, font=font)
        new.save(image_file)

    def trace_back_method(self, class_name, method_name, root_node):
        trace_back = nx.DiGraph()
        for m in self.analysis.find_methods(methodname=method_name, classname=class_name):
            ancestors = nx.ancestors(self.call_graph, m)
            ancestors.add(m)
            graph = self.call_graph.subgraph(ancestors)
            trace_back.add_edges_from(graph.edges())
            trace_back.add_edge(m, root_node)
        return trace_back

    def compute_apk_call_graph(self):
        self.call_graph = self.analysis.get_call_graph()

    def generate_md_report(self):
        report = MdReport(self.report, self.apk)
        report.generate(self.report_output_dir)
        return self.report

    def compute_rules(self):
        if not self.call_graph:
            self.compute_apk_call_graph()

        def clean_name(node):
            name = str(node.get_method())
            return name[0:name.rfind('(')] + '()'

        def get_package_name(name):
            package = name[0:name.rfind('/')]
            return '/'.join(package.split('/')[0:min(package.count('/'), 2)])

        for rule in self.rules:
            rule_report = {
                'rule': rule,
                'findings': [],
                'cfg_file': None
            }
            rule_report['rule']['title'] = rule_report['rule']['title'][:-1]

            fg = dg(engine='dot',
                    format='png',
                    graph_attr={'overlap': 'orthoxy',
                                'diredgeconstraints': 'true',
                                'splines': 'ortho'},
                    edge_attr={'color': '#593196', },
                    node_attr={'shape': 'box',
                               'style': 'filled',
                               'color': '#ece5f6',
                               'fontcolor': '#593196',
                               'fontsize': '10',
                               'fontname': 'sans-serif'})

            entire_call_graph = nx.DiGraph()
            contracted_call_graph = nx.DiGraph()

            # Init the clusters
            clusters = {'unknown': []}
            for c, _ in self.cluster_names.items():
                clusters[c] = []

            # Find matching API methods
            methods = []
            for search in rule['or_predicates']:
                class_name = '/'.join(search.split('/')[:-1])
                method_name = search.split('/')[-1]
                for m in self.analysis.find_methods(methodname=method_name, classname=class_name):
                    methods.append(m)
                    # Build CFG
                    fg.node(clean_name(m), color='#593196', fontcolor='white')
                    ancestors = nx.ancestors(self.call_graph, m)
                    ancestors.add(m)
                    graph = self.call_graph.subgraph(ancestors)
                    entire_call_graph.add_edges_from(graph.edges())
                    for n, d in graph.in_degree():
                        if d == 0:
                            class_name = n.get_class_name()
                            cluster_name = self.get_cluster_name(class_name[1:-1])
                            self.genom.add_gene(cluster_name, search)

            rule_name = rule['name']

            # Extract method source code
            if self.save_graphs:
                for n, d in entire_call_graph.out_degree():
                    if d == 0:
                        for parent in neighbors(reverse_view(entire_call_graph), n):
                            try:
                                java_code = parent.get_method().get_source()
                                class_name = parent.get_method().get_class_name()
                                hash = md5()
                                hash.update(parent.get_method().full_name)
                                h = hash.hexdigest()
                                filename = f'code_{rule_name}_{class_name}_{h}.bmp'.replace('/', '-').replace(' ', '_')
                                file_path = f'{self.code_output_dir}/{filename}'
                                rule_report['findings'].append({
                                    'id': h,
                                    'call_by': str(class_name)[1:-1],
                                    'evidence_file': os.path.relpath(file_path, start=self.report_output_dir)
                                })
                                with open(file_path, mode='wb') as out:
                                    result = highlight(java_code,
                                                       JavaLexer(),
                                                       ImageFormatter(style=U39bStyle,
                                                                      image_format='BMP',
                                                                      font_name='DejaVu Sans Mono',
                                                                      line_pad=4,
                                                                      font_size=12,
                                                                      line_number_bg='#A991D4',
                                                                      line_number_fg='#ffffff'))
                                    out.write(result)
                                try:
                                    CFG.append_legend(f'{self.code_output_dir}/{filename}', str(class_name), 12)
                                except Exception:
                                    pass
                            except Exception:
                                pass

            # List nodes to be traced back - compute the clusters
            for n, d in entire_call_graph.in_degree():
                if d == 0:
                    class_name = n.get_class_name()
                    cluster_name = self.get_cluster_name(class_name[1:-1])
                    clusters[cluster_name].append(n)

            roots = []
            leaves = []

            # Contract CFG
            for n, d in entire_call_graph.in_degree():
                if d == 0:
                    u = clean_name(n)
                    roots.append(u)
                elif n in methods:
                    u = clean_name(n)
                    leaves.append(u)

            for u, v in entire_call_graph.edges():
                _u = get_package_name(clean_name(u))
                if clean_name(u) in roots:
                    _u = clean_name(u)
                _v = get_package_name(clean_name(v))
                if clean_name(v) in leaves:
                    _v = clean_name(v)
                contracted_call_graph.add_edge(_u, _v)

            # Create graph clusters
            with fg.subgraph(name=f'cluster_entrypoints') as entry:
                entry.attr(label=f'Entrypoints')
                entry.attr(shape='box')
                entry.attr(color='#593196')
                entry.attr(fontcolor='#593196')
                entry.attr(fontsize='14')
                entry.attr(margin='6')
                entry.attr(fontname='sans-serif')
                entry.attr(labeljust='l')
                for k, v in clusters.items():
                    if v:
                        with entry.subgraph(name=f'cluster_{k}') as c:
                            name = k.replace('_', ' ').title()
                            c.attr(label=f'{name}')
                            c.attr(color='#ece5f6')
                            c.attr(style='filled')
                            c.attr(margin='5')
                            c.attr(fontcolor='#593196')
                            c.attr(fontsize='12')
                            c.attr(fontname='sans-serif')
                            c.attr(labeljust='l')
                            for n in v:
                                c.node(clean_name(n), color='#a991d4', fontcolor='white')

            # Create graphviz graph
            for u, v in contracted_call_graph.edges():
                if u != v:
                    fg.edge(u, v, constraint='true')

            with fg.subgraph(name=f'cluster_other_entrypoints') as others:
                for n in clusters['unknown']:
                    others.node(clean_name(n), color='#a991d4', fontcolor='white')

            if len(contracted_call_graph.nodes()) > 1 and self.save_graphs:
                graph_name = rule['name']
                path = f'{self.cfg_output_dir}/{graph_name}'
                fg.render(path)
                rule_report['cfg_file'] = os.path.relpath(path, self.report_output_dir)
                self.report.append(rule_report)

