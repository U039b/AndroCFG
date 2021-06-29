import json
from pprint import pprint


class Genom:
    def __init__(self, rule_file: str, cluster_names: list):
        self.rule_file = rule_file
        self.cluster_names = cluster_names
        self.indices = {}
        self.sequence = []
        self.__build_indices()

    def __build_indices(self):
        with open(self.rule_file, mode='r') as r:
            rules = json.load(r)

        or_predicates = []
        for rule in rules:
            or_predicates.extend(rule.get('or_predicates'))

        or_predicates.sort()
        self.cluster_names.append('unknown')
        self.cluster_names.sort()

        counter = 0
        for predicate in or_predicates:
            for cluster in self.cluster_names:
                self.indices[(cluster, predicate)] = counter
                counter += 1

        self.sequence = [0]*counter

    def __get_gene_index(self, cluster_name: str, api_call: str)->int:
        return self.indices[(cluster_name, api_call)]

    def add_gene(self, cluster_name: str, api_call: str):
        index = self.__get_gene_index(cluster_name, api_call)
        self.sequence[index] += 1

    def dump(self, file_path):
        with open(file_path, mode='w') as dump_file:
            dump_file.write(','.join([str(e) for e in self.sequence]))

    def dumps(self) -> str:
        return ','.join([str(e) for e in self.sequence])

    def load(self, file_path):
        with open(file_path, mode='r') as dump_file:
            content = dump_file.read()
        self.sequence = [
            int(elt) for elt in content.split(',')
        ]

    def pprint(self):
        for i in range(0, len(self.sequence)):
            v = self.sequence[i]
            if v:
                for gene, index in self.indices.items():
                    if index == i:
                        print(f'{gene}: {v}')
                        break
