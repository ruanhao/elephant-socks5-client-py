from unittest import TestCase
from elephant_sock5.utils import chunk_list, parse_uri


class Test(TestCase):
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
