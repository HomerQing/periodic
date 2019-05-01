#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author: Homer
# Date: 2018-05-15
# Version: 0.3
# ELK


import os, json, time, datetime, argparse
from multiprocessing import Process, JoinableQueue, Lock, Manager

import pandas as pd
from pandas.io.json import json_normalize
from elasticsearch import Elasticsearch, helpers
from tqdm import tqdm, tqdm_notebook

from iputils import private_check, multicast_check, reserved_check
from tld import TLD
from whois import WhoisLookup
from threat import TI
# from es_domain import GetDomain


def readJson(files):
    with open(files, encoding='utf-8') as f:
        data = json.load(f)
    return data


class HawkEye():
    def __init__(self):
        '''
            初始化配置文件设置
        '''

        # 脚本参数初始化
        self.parser = argparse.ArgumentParser(description='基于Flow的周期检测工具. by Homer.')
        self.parser.add_argument('-c', dest='config', type=str, help='Config Files. Default: config.json')
        self.parser.add_argument('-f', dest='file', type=str, help='Load local raw_data')
        self.parser.add_argument('-o', dest='output', type=str, help='Output Files')
        self.parser.add_argument('--ti', help='Threat Intelligence', action='store_true')
        self.parser.add_argument('--tld', help='Host to TLD', action='store_true')
        self.parser.add_argument('--dns', help='IP TO Domain', action='store_true')
        self.parser.add_argument('--whois', help='WhoisLookup', action='store_true')
        self.parser.add_argument('--json', help='Save CSV Files', action='store_true')
        self.parser.add_argument('--csv', help='Save Json Files', action='store_true')
        self.parser.add_argument('--debug', help='Enable debug mode', action='store_true')
        self.args = self.parser.parse_args()
        
        if not self.args.config:
            print('Specify configuration file.')
            os._exit(0)

        if not self.args.output:
            print('Specify Save Path.')
            os._exit(0)

        self.config = readJson(self.args.config)

        # 产品类型初始化
        self.product = self.config['product'].lower()
        
        # 实例化ES
        host = self.config['host']
        timeout = self.config['timeout']
        self.es = Elasticsearch(host, timeout=timeout)
        
        # ES字段初始化
        self.index = self.config['index']
        self.timestamp = self.config['field']['timestamp']
        self.src_ip = self.config['field']['src_ip']
        self.proto = self.config['field']['proto']
        self.dst_ip = self.config['field']['dst_ip']
        self.dst_port = self.config['field']['dst_port']
        self.flow_id = self.config['field']['flow_id']
        self.flow_age = self.config['field']['flow_age']
        self.flow_bytes_toserver = self.config['field']['flow_bytes_toserver']

        # 扩展字段 2018_05_22
        self.columns = self.config['columns']['basis_columns']
        self.ext_columns = self.config['columns']['ext_columns']
        
        if self.proto:
            self.columns.insert(1, self.ext_columns[0])
        if self.flow_bytes_toserver:
            self.columns.append(self.ext_columns[1])
        if self.product == 'nta' or self.product == 'nta':
            self.columns.extend(self.ext_columns[2:])

        # ES语句初始化
        event_type = self.config['event_type']
        period = self.config['period']
        self.gte, self.lte = self.getTimestamp(period)
        self.body = self.hour_query_body(event_type)

        # 周期性检测配置
        self.min_occur = self.config['min_occur']
        self.min_interval = self.config['min_interval']
        self.min_percent = self.config['min_percent']
        self.window = self.config['window']
        self.threads = self.config['threads']
        
        # 多进程配置
        self.q_job = JoinableQueue()
        self.lock_df = Lock()
        self.lock_list = Lock()

        
    def getTimestamp(self, _hour):
        '''
            获取时间戳方法
        '''
        now = int(time.time() * 1000)
        seconds = 1000
        minutes = 60 * seconds
        hours = 60 * minutes
        lte = now
        gte = int(now - _hour * hours)
        
        return gte, lte
    
    
    def hour_query_body(self, _event_type):
        '''
            查询语句
        '''
        exclude_field = self.config.get('must_not', [])

        # 新增测试代码 2018_05_22

        timestamp_field = self.timestamp
        event_field = 'event_type'
        raw_field = list(self.config['field'].values())

        if self.product == 'ep' or self.product == 'nta':
            event_field = 'event_name'
            timestamp_field = 'occur_time'
        
        if self.product == 'nta':
            raw_field = ['original_log']

        include_field = self.config.get('must', [])
        
            
        body = {
            '_source': raw_field,
            'query': {
                'bool': {
                    'filter': [
                        {
                            'term': {
                                event_field: _event_type
                            }
                        },
                        {
                            'range': {
                                timestamp_field: {
                                    'gte': self.gte,
                                    'lte': self.lte,
                                    'format': 'epoch_millis'
                                }
                            }
                        }
                    ],
                    'must_not': exclude_field,
                    'must': include_field   # 新增代码 2018_05_22
                }
            }
        }
        
        return body

    
    def search(self):
        '''
            滚动查询方法
        '''
        es_results = helpers.scan(
            client = self.es,
            index = self.index,
            query = self.body,
            size = 10000,
            scroll = '90m',
            timeout = '10m'
        )
        json_results = [ item['_source'] for item in tqdm(es_results)]
        df_results = json_normalize(json_results)

        return df_results

    
    def tetrad(self, _df):

        if self.proto:
            # tetrad: src_ip、proto、dst_ip、dst_port
            _df['tetrad_id'] = (_df[self.src_ip] + _df[self.proto] + _df[self.dst_ip] + _df[self.dst_port].astype(str)).apply(hash)
        else:
            # tetrad: src_ip、dst_ip、dst_port
            _df['tetrad_id'] = (_df[self.src_ip] + _df[self.dst_ip] + _df[self.dst_port].astype(str)).apply(hash)

        _df['tetrad_freq'] = _df.groupby('tetrad_id')['tetrad_id'].transform('count').fillna(0).astype(int)
        
        return _df

    
    def percent_grouping(self, _dict, _total):
        '''
            百分比计算
        '''
        mx = 0
        interval = 0
        # Finding the key with the largest value (interval with most events)
        mx_key = int(max(iter(list(_dict.keys())), key=(lambda key: _dict[key])))

        mx_percent = 0.0

        for i in range(mx_key - self.window, mx_key + 1):
            current = 0
            # Finding center of current window
            curr_interval = i + int(self.window / 2)
            for j in range(i, i + self.window):
                if j in _dict:
                    current += _dict[j]
            percent = float(current) / _total * 100

            if percent > mx_percent:
                mx_percent = percent
                interval = curr_interval

        return interval, mx_percent
    
    
    def find_beacon(self, _raw_data, _beacon_list):
        '''
            查询周期方法
        '''

        if self.product == 'nta' or self.product == 'ep':
            milliseconds = 1000
        else:
            milliseconds = 1000000000

        while not self.q_job.empty():
            tetrad_id = self.q_job.get()
            self.lock_df.acquire()
            work = _raw_data[_raw_data.tetrad_id == tetrad_id].reset_index(drop=True)
            self.lock_df.release()
            
            work[self.timestamp] = pd.to_datetime(work[self.timestamp])
            work[self.timestamp] = (work[self.timestamp].astype(int) / milliseconds).astype(int)
            work = work.sort_values([self.timestamp])
            work['delta'] = (work[self.timestamp] - work[self.timestamp].shift()).fillna(0)
            work = work[1:]

            d = dict(work.delta.value_counts())
            for key in list(d.keys()):
                if key < self.min_interval:
                    del d[key]
            
            # Finding the total number of events
            total = sum(d.values())
            
            if d and total > self.min_occur:
                _window, _percent = self.percent_grouping(d, total)
                if _percent > self.min_percent and total > self.min_occur:
                    percent = int(_percent)
                    window = _window
                    src_ip = work[self.src_ip].unique()[0]                    
                    dst_ip = work[self.dst_ip].unique()[0]
                    dst_port = work[self.dst_port].unique()[0]
                    src_degree = len(work[self.dst_ip].unique())
                    occur = total

                    col = [src_ip, dst_ip, dst_port, src_degree, occur, percent, window]

                    if self.proto:
                        proto = work[self.proto].unique()[0]
                        col.insert(1, proto)

                    if self.flow_bytes_toserver:
                        flow_bytes_sum = work[self.flow_bytes_toserver].sum()
                        col.append(flow_bytes_sum)

                    if self.product == 'nta' or self.product == 'suricata':
                        groups = {
                            self.flow_bytes_toserver: ['min', 'max', 'mean', 'std'],
                            self.flow_age: ['min', 'max', 'mean', 'std']
                        }

                        columns = {
                            'flow_bytes': {
                                'min': 'flow_bytes_min',
                                'max': 'flow_bytes_max',
                                'mean': 'flow_bytes_mean',
                                'std': 'flow_bytes_std'
                            },
                            'flow_age': {
                                'min': 'flow_age_min',
                                'max': 'flow_age_max',
                                'mean': 'flow_age_mean',
                                'std': 'flow_age_std'
                            }
                        }

                        work_group = work.groupby('tetrad_id').aggregate(groups)
                        work_flow_bytes = work_group[self.flow_bytes_toserver].rename(columns=columns['flow_bytes'])
                        work_flow_age = work_group[self.flow_age].rename(columns=columns['flow_age'])
                        
                        flow_bytes_val = work_flow_bytes.values.tolist()[0]
                        flow_age_val = work_flow_age.values.tolist()[0]

                        col.extend(flow_bytes_val)
                        col.extend(flow_age_val)

                    self.lock_list.acquire()
                    _beacon_list.append(col)
                    self.lock_list.release()
            
            self.q_job.task_done()

            
    def find_beacons(self, _raw_data):
        '''
            多线程分析
        '''

        high_freq = list(_raw_data[_raw_data.tetrad_freq > self.min_occur].groupby('tetrad_id').groups.keys())

        for _tetrad_id in high_freq:
            self.q_job.put(_tetrad_id)

        mgr = Manager()
        beacon_list = mgr.list()
        processes = [ Process(target=self.find_beacon, args=(_raw_data, beacon_list,)) for thread in range(self.threads) ]

        # Run processes
        for p in processes:
            p.start()

        # Exit the completed processes
        for p in processes:
            p.join()

        beacon_list = list(beacon_list)
        beacon_df = pd.DataFrame(beacon_list, columns=self.columns).dropna()
        beacon_df.interval = beacon_df.interval.astype(int)

        beacon_df['dst_degree'] = beacon_df.groupby('dst_ip')['dst_ip'].transform('count').fillna(0).astype(int)

        private_check_src_obj = beacon_df['src_ip'].apply(private_check)
        private_check_dst_obj = beacon_df['dst_ip'].apply(private_check)
        multicast_check_dst_obj = beacon_df['dst_ip'].apply(multicast_check)
        reserved_check_dst_obj = beacon_df['dst_ip'].apply(reserved_check)
        beacon_df = beacon_df[(private_check_src_obj) & (~multicast_check_dst_obj) & (~reserved_check_dst_obj) & (~private_check_dst_obj)]

        return beacon_df


    def ntaFlow_normalization(self, _original_log):
        '''
            NTA数据标准化
        '''
        original_log_raw = _original_log['original_log'].str.strip()
        original_log_raw = original_log_raw.apply(lambda original_log: json.loads(original_log))
        
        original_log = pd.DataFrame(original_log_raw.tolist())

        if self.flow_bytes_toserver:
            original_log['bytes_toserver'] = original_log['flow'].apply(lambda x: x.get('bytes_toserver'))
        
        if self.flow_age:
            original_log['age'] = original_log['flow'].apply(lambda x: x.get('age'))
        
        col = ['@end_timestamp', 'app_proto', 'app_proto_tc', 'app_proto_ts', 'flow', 'ndpi_app_proto', 'protocol', 'tcp', 'src_port', \
        'app_proto_expected', 'app_proto_orig', 'icmp_code', 'icmp_type']

        for i in col:
            if i in original_log.columns:
                original_log.drop(i, axis=1, inplace=True)
        
        return original_log


    def dns_query_body(self, _dst_ip, _rdata):
        '''
            DNS响应事件 请求体
        '''
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
                                "dst_address": _dst_ip  # 对应 analyze_data: src_ip
                            }
                        },
                        {
                            "term": {
                                "dns_answer": _rdata    # 对应 analyze_data: dst_ip
                            }
                        },
                        {
                            'range': {
                                'occur_time': {
                                    'gte': self.gte,
                                    'lte': self.lte,
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


    def dns_search(self, _df):
        '''
            1. DNS响应数据查询
            2. 格式化输出
        '''
        dst_ip = _df['src_ip']
        dns_rdata = _df['dst_ip']
        body = self.dns_query_body(dst_ip, dns_rdata)
        dns_json = self.es.search(index=self.index, body=body)
        dns_data = dns_json['aggregations']['rrname']['buckets']
        if dns_data:
            dns_data = json_normalize(dns_data).key.tolist()

        _df['domain'] = dns_data

        return _df

        
    def filter_dns(self, _df):
        '''
            DNS响应查询
        '''
        if self.proto:
            filter_port_obj = _df[self.dst_port] == 53
            filter_proto_obj = _df[self.proto] == 'UDP'
            df = _df[(~filter_proto_obj) & (~filter_port_obj)]
        else:
            filter_port_obj = _df[self.dst_port] == 53
            df = _df[~filter_port_obj]

        return df


    def save_file(self, _df, _file):
        if self.args.json:
            suffix = '.json'
            _df.to_json(self.args.output + _file + suffix, orient='index')
        elif self.args.csv:
            suffix = '.csv'
            _df.to_csv(self.args.output + _file + suffix, index=False)
        print('Data saved Successfully.')


    def load_file(self, _file):
        reader = pd.read_csv(_file, chunksize=100000000)
        chunks = []
        for chunk in reader:
            chunks.append(chunk)
        df = pd.concat(chunks)
        print('Data loading Successful.')

        return df


    def main(self):

        if not self.args.file:
            print('Searching Netflow.')
            res = self.search()
            # if self.args.debug:
            #     res.to_csv(self.args.output + 'raw_data_search.csv', index=False)

            # 标准化 NTA 数据
            if self.product == 'nta':
                res = self.ntaFlow_normalization(res)

            print('Create Tetrad.')
            res = self.tetrad(res)
            if self.args.debug:
                res.to_csv(self.args.output + 'raw_data.csv', index=False)
        else:
            print('Data loading.')
            res = self.load_file(self.args.file)
            
        # 分析数据
        print('Data analysis.')
        res = self.find_beacons(res)
        if self.args.debug:
            self.save_file(res, 'analyze_data_fin')
        print('Data analysis completed.')

        if self.args.dns:
            if not res.empty:
                # Local WhoisLookup
                res = self.filter_dns(res)
                tqdm.pandas(desc="Local WhoisLookup")
                res = res.progress_apply(lambda x: self.dns_search(x), axis=1)
                if self.args.debug:
                    self.save_file(res, 'local_whois_fin')
                print('Local WhoisLookup completed.')

                if self.args.tld:
                    # Domain to TLD
                    tools_tld = TLD()
                    res = tools_tld.main(res)
                    if self.args.debug:
                        self.save_file(res, 'local_tld_fin')
                    print('Domain to TLD completed.')
            else:
                print('The result is empty, Local WhoisLookup not Working.')

        if self.args.whois:
            if not res.empty:
                # Online WhoisLookup
                tools_whois = WhoisLookup()
                res = tools_whois.main(res)
                if self.args.debug:
                    self.save_file(res, 'online_whois_fin')
                print('Online WhoisLookup completed.')
            else:
                print('The result is empty, Online WhoisLookup not Working.')

        if self.args.ti:
            # Threat Intelligence
            tools_ti = TI()
            if not res.empty:
                res = tools_ti.main(res)
                if self.args.debug:
                    self.save_file(res, 'ti_fin')
                print('Check Threat Intelligence completed.')
            else:
                print('The result is empty, Threat Intelligence not working.')
            
        
        res.sort_values('percent', ascending=False, inplace=True)
        res.reset_index(drop=True, inplace=True)

        self.save_file(res, 'analysis_result')
        
        print('Analysis completed, program exit.')

        os._exit(0)


if __name__ == '__main__':
    hawkEye = HawkEye()
    hawkEye.main()