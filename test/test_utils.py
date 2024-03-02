from unittest import TestCase
from elephant_socks5.utils import chunk_list, parse_uri, Metric


class Test(TestCase):

    def test_metric(self):
        metric = Metric.of("test")
        self.assertEqual(metric.name, "test")
        metric.record(1)
        metric.record(3)
        self.assertEqual(metric.count, 2)
        self.assertEqual(metric.sum, 4)
        self.assertEqual(metric.min, 1)
        self.assertEqual(metric.max, 3)
        self.assertEqual(metric.avg, 2)
        print(metric)

    def test_chunk_list(self):
        self.assertEqual(chunk_list([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 3), [[1, 2, 3], [4, 5, 6], [7, 8, 9], [10]])

    def test_parse_uri(self):
        example_uri = "wss://localhost:4443/elephant/ws?alias=test"
        uri_params = parse_uri(example_uri)
        self.assertEqual(uri_params, {'alias': ['test']})

        example_uri = "wss://localhost:4443/elephant/ws?alias=test&alias=test2"
        uri_params = parse_uri(example_uri)
        self.assertEqual(uri_params, {'alias': ['test', 'test2']})

        example_uri = "wss://localhost:4443/elephant/ws"
        uri_params = parse_uri(example_uri)
        self.assertEqual(uri_params, {})
