#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author: Homer
# Date: 2018-05-20
# Version: 0.1
# ELK

import pandas as pd
from pandas.io.json import json_normalize
from tqdm import tqdm
from robtex import Robtex, RobtexError


'''
    IP反查域名
'''

class WhoisLookup():

    def __init__(self):
        self.whois = Robtex()


    def lookup(self, _data, **kwargs):
        
        pas_dict = {}
        pash_dict = {}
        act_dict = {}
        acth_dict = {}
        
        if kwargs['type'] == 'ip':
            res = self.whois.get_ip_info(_data)
                            
            if 'pas' in res:
                if len(res['pas']):
                    for d in res['pas']:
                        pas_dict[d['o']] = d['date']

            if 'pash' in res:
                if len(res['pash']):
                    for d in res['pash']:
                        pash_dict[d['o']] = d['date']

            if 'act' in res:
                if len(res['act']):
                    for d in res['act']:
                        act_dict[d['o']] = d['date']

            if 'acth' in res:
                if len(res['acth']):
                    for d in res['acth']:
                        acth_dict[d['o']] = d['date']
                            
            data = {
                'AS': 'AS ' + str(res.get('as', 'None')) + ': ' + res.get('asname', 'None'),
                'Location': res.get('city', 'None') + ', ' + res.get('country', 'None'),
                'BGP Route': res.get('bgproute', 'None') + ', ' + res.get('routedesc', 'None'),
                'Whois': res.get('whoisdesc', 'None'),
                'Passive DNS': pas_dict,
                'Passive DNS History': pash_dict,
                'Active DNS': act_dict,
                'Active DNS History': acth_dict
            }
            
            return data

    def main(self, _df):
        tqdm.pandas(desc="WhoisLookup")
        _df['whois'] = _df.dst_ip.progress_apply(lambda x: self.lookup(x, type='ip'))
        data = pd.DataFrame(_df['whois'].tolist())
        data = pd.merge(_df, data, left_index=True, right_index=True)
        data.drop('whois', axis=1, inplace=True)

        return data