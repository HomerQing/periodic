#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author: Canon
# Date: 2018-05-24
# Version: 0.1
# ELK

from pandas.io.json import json_normalize
from tqdm import tqdm, tqdm_notebook

class GetDomain:
    def filter_dns(self, _df):
        if 'proto' in _df:
            filter_port_obj = _df['dst_port'] == 53
            filter_proto_obj = _df['proto'] == 'UDP'
            df = _df[(~filter_proto_obj) & (~filter_port_obj)]
        else:
            filter_port_obj = _df['dst_port'] == 53
            df = _df[~filter_port_obj]

        return df


    def dns_query_body(self, _dst_ip, _rdata, _gte, _lte):
        body = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "term": {
                                "event_digest": "nta_dns"
                            }
                        },
                        {
                            "term": {
                                "event_name": "DNS响应"
                            }
                        },
                        {
                            "term": {
                                "dst_address": _dst_ip  # src_ip
                            }
                        },
                        {
                            "term": {
                                "dns_answer": _rdata    # dst_ip
                            }
                        },
                        {
                            'range': {
                                'occur_time': {
                                    'gte': _gte,
                                    'lte': _lte,
                                    'format': 'epoch_millis'
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "rrname": {
                    "terms": {
                        "field": "domain_name"
                    }
                }
            },
            "size": 0
        }

        return body


    def dns_search(self, _row, _gte, _lte, _es_search, _index):

        dst_ip =  _row['src_ip']
        rdata =  _row['dst_ip']

        # dns_query_body(_dst_ip, _rdata, _gte, _lte)
        body = self.dns_query_body(dst_ip, rdata, _gte, _lte)

        # es_search(index, body)
        dns_json = _es_search(index=_index, body=body)

        # format dns_json
        dns_data = dns_json['aggregations']['rrname']['buckets']

        if dns_data:
            dns_data = json_normalize(dns_data).key.tolist()

        _row['domain'] = dns_data

        return _row


    def main(self, df, gte, lte, es_search, index):

        # filter_dns(_df, _dst_port, _proto)
        df = self.filter_dns(df)

        # dns_search(_row, _gte, _lte, _es_search, _index)
        tqdm.pandas(desc="Local WhoisLookup")
        res = df.progress_apply(lambda row: self.dns_search(row, gte, lte, es_search, index), axis=1)

        return res