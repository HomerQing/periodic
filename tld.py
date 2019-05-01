#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author: Homer
# Date: 2018-05-20
# Version: 0.2
# ELK

import requests, tldextract, json
import pandas as pd
from tqdm import tqdm
from tools import Tools

class TLD:
    def __init__(self):

        self.tool = Tools()

        '''
            初始化白名单路径
        '''
        cisco = '/opt/top_1m/Cisco_top-1m.csv'
        alexa = '/opt/top_1m/Alexa_top-1m.csv'
        majestic = '/opt/top_1m/Majestic_top-1m.csv'
        statvoo = '/opt/top_1m/Statvoo_top-1m.csv'

        alexa_1m = pd.read_csv(alexa, header=None, usecols=[1], names=['Domain'])
        cisco_1m = pd.read_csv(cisco, header=None, usecols=[1], names=['Domain'])
        statvoo_1m = pd.read_csv(statvoo, header=None, usecols=[1], names=['Domain'])
        majestic_1m = pd.read_csv(majestic, usecols=['Domain'])

        self.top_1m = pd.concat([alexa_1m.Domain, cisco_1m.Domain, majestic_1m.Domain, statvoo_1m.Domain]).unique()


    def host2tld(self, _domains):
        '''
            Host转换TLD
        '''
        _dict = {}
        for host in _domains:
            ext = tldextract.extract(host)
            tld = '.'.join(ext[-2:])
            _dict.setdefault(tld, [])
            _dict[tld].append(host)
        return _dict


    def check_top_1m(self, _tld):
        '''
            白名单检查方法
        '''
        _list = []
        for _domain in _tld.keys():
            if _domain not in self.top_1m:
                _list.append(_domain)
        return _list


    def tld2host(self, _df):
        '''
            TLD转换Host
        '''
        tlds = _df.tld
        host = _df.host
        hosts = []
        for tld in tlds:
            hosts.append(host.get(tld))
        return hosts


    def main(self, _df):

        # str2list
        _df.domain = _df.domain.apply(lambda x: self.tool.str2list(x))

        # ip、domain
        raw_data_ip = _df[~_df.domain.apply(lambda x: self.tool.isna_list(x))]
        raw_data_domain = _df[_df.domain.apply(lambda x: self.tool.isna_list(x))]

        # host2tld
        dict_tld_host = raw_data_domain.domain.apply(lambda x: self.host2tld(x))

        # top_1m
        tqdm.pandas(desc="Check Top-1M")
        tld = dict_tld_host.progress_apply(lambda x: self.check_top_1m(x))
        tld = tld[tld.apply(lambda x: self.tool.isna_list(x))]

        if not tld.empty:
            # res
            res = pd.DataFrame({'tld': tld, 'host': dict_tld_host[tld.index]})
            res = res.apply(lambda x: self.tld2host(x), axis=1)
            raw_data_domain = raw_data_domain.loc[res.index.tolist()]
            raw_data_domain['domain'].update(res)

            # df append
            raw_data = raw_data_domain.append(raw_data_ip).reset_index(drop=True)
        else:
            raw_data = raw_data_ip.reset_index(drop=True)
        
        return raw_data