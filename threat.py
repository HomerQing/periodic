#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author: Homer
# Date: 2018-05-21
# Version: 0.2
# ELK

import requests, json
import pandas as pd
from tqdm import tqdm
from tools import Tools

class TI:
    def __init__(self):
        
        self.tool = Tools()

        '''
            HanSight_TI_API
        '''
        self.ti_url = 'http://172.16.100.32:80/ti/simplebulkapi'


    def check_ti(self, _data, **kwargs):
        '''
            威胁情报查询 - type = Domain、IP
        '''

        if kwargs['type'] == 'domain':
            results = []
            for _domians in _data:  # _data == [['ahmed1337.in', 'ns1.wowservers.ru', 'proxy.letengwireless.cn']]
                for _domain in _domians:    # _domain == ['ahmed1337.in', 'ns1.wowservers.ru', 'proxy.letengwireless.cn']
                    params = {'iocs': _domain}
                    response = requests.post(self.ti_url, data=params)
                    res = json.loads(response.content.decode())

                    for _dict in res:
                        data = {
                            'ioc': _dict['ioc'],
                            'tag': _dict['hansight']['tags'],
                            'time': _dict['hansight']['timestamp'],
                            'producer': _dict['hansight']['producer']
                        }
                        results.append(data)

            return results

        elif kwargs['type'] == 'ip':
            params = {'iocs': _data}
            response = requests.post(self.ti_url, data=params)
            res = json.loads(response.content.decode())

            for _dict in res:
                data = {
                    'ioc': _dict['ioc'],
                    'tag': _dict['hansight']['tags'],
                    'time': _dict['hansight']['timestamp'],
                    'producer': _dict['hansight']['producer']
                }

                return data
    

    def main(self, _df):
        # str2list
        _df.domain = _df.domain.apply(lambda x: self.tool.str2list(x))

        # ip、domain
        raw_data_ip = _df[~_df.domain.apply(lambda x: self.tool.isna_list(x))]
        raw_data_domain = _df[_df.domain.apply(lambda x: self.tool.isna_list(x))]

        # Check - Domain
        tqdm.pandas(desc="Check TI Domain")
        raw_data_domain['TI'] = raw_data_domain.domain.progress_apply(lambda x: self.check_ti(x, type='domain'))
        ## Check - IP
        tqdm.pandas(desc="Check TI IP")
        raw_data_ip['TI'] = raw_data_ip.dst_ip.progress_apply(lambda x: self.check_ti(x, type='ip'))
        
        # df_append
        raw_data = raw_data_domain.append(raw_data_ip).reset_index(drop=True)

        return raw_data