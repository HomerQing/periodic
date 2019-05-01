# 周期性流量特征提取

## 导入库

```python
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
```

## 读取json文件

定义读取json文件的方法，全局调用

```python
def readJson(files):
    with open(files, encoding='utf-8') as f:
        data = json.load(f)
    return data
```

## 周期性检测类

### 初始化配置文件

```python
def __init__(self):
```

#### 脚本参数初始化

```python
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
```

#### 如果用户没有定义配置文件输出提示信息

```python
        if not self.args.config:
            print('Specify configuration file.')
            os._exit(0)
```

#### 如果用户没有定义结果保存处理输出提示信息

```python
        if not self.args.output:
            print('Specify Save Path.')
            os._exit(0)
```

#### 调用readJson方法格式化配置文件，赋值给self.config

```python
        self.config = readJson(self.args.config)
```

#### 初始化配置文件中的各参数

##### 产品类型初始化

```PYTHN
        self.product = self.config['product'].lower()
```

##### ES初始化

```python
        host = self.config['host']
        timeout = self.config['timeout']
        self.es = Elasticsearch(host, timeout=timeout)
```

##### ES字段初始化

初始化字段包括索引、时间戳、源IP、协议、目的IP、目的端口、flow id、flow时间、发送到服务器的字节数

```PYTHON
        self.index = self.config['index']
        self.timestamp = self.config['field']['timestamp']
        self.src_ip = self.config['field']['src_ip']
        self.proto = self.config['field']['proto']
        self.dst_ip = self.config['field']['dst_ip']
        self.dst_port = self.config['field']['dst_port']
        self.flow_id = self.config['field']['flow_id']
        self.flow_age = self.config['field']['flow_age']
        self.flow_bytes_toserver = self.config['field']['flow_bytes_toserver']
```

##### 初始化扩展字段，判断若存在协议、字节、产品名称，追加到列表中

```python
self.columns = self.config['columns']['basis_columns']
self.ext_columns = self.config['columns']['ext_columns']
        
        if self.proto:
            self.columns.insert(1, self.ext_columns[0])
        if self.flow_bytes_toserver:
            self.columns.append(self.ext_columns[1])
        if self.product == 'nta' or self.product == 'nta':
            self.columns.extend(self.ext_columns[2:])
```

##### ES语句初始化

```python
        event_type = self.config['event_type']
        period = self.config['period']
        self.gte, self.lte = self.getTimestamp(period)
        self.body = self.hour_query_body(event_type)
```

##### 周期性检测配置



