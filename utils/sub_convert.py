#!/usr/bin/env python3

import base64
import json
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import geoip2.database
import requests


class sub_convert():
    def get_node_from_sub(url_raw):
        
        # 分割订阅链接
        urls = url_raw.split('|')
        sub_content = []
        for url in urls:
            node_list = sub_convert.get_sub_content_from_webtrans(url)
            # print(f'\n格式化{url} 返回数据开始...')
            node_list_formated = sub_convert.format(node_list)
            # print(f'\n格式化{url} 返回数据结束...')
            sub_content.append(node_list_formated)
        sub_content_all = ''.join(sub_content)
        return sub_content_all

    def get_sub_content_from_webtrans(url):
        # 使用远程订阅转换服务
        server_host_list = ['https://sub.xeton.dev', 'https://api.dler.io', 'https://sub.nerocats.cn', 'https://api.wcc.best', 'https://api.sublink.dev', 'https://api.tsutsu.one', 'https://api.nexconvert.com', 'https://api.subcsub.com']
        # server_host_list = ['https://subconverter-479081675.b4a.run']
        url_quote = urllib.parse.quote(url, safe='')
        for server_host in server_host_list:
            converted_url = server_host+'/sub?target=mixed&url='+url_quote+'&list=true'
            try:
                # print(f"\n获取转换链接:{converted_url} 开始\n")
                resp = requests.get(converted_url)
                # print(f"\n获取转换链接:{converted_url} 结束\n")
                if 'No nodes were found!' in resp.text or url in resp.text or 'Error code' in resp.text or 'An error' in resp.text:
                    print(f"\n警告!!! 未发现有效配置, 订阅链接: {url} 转换链接:{converted_url}\n")
                else:
                    return resp.text
            except Exception:
                print(f"\n错误!!! 订阅链接转换失败, 订阅链接: {url} 转换链接:{converted_url}\n")
            if server_host is server_host_list[-1]:
                print(f'\n无法转换订阅链接: {url}, 获取url内容开始\n')
                try:
                    resp = requests.get(url)
                    print(f'\n无法转换订阅链接: {url}, 获取url结束\n')
                    return resp.text
                except Exception:
                    print(f'\n无法获取: {url}\n')
                    return ''

    def format(node_list):
        # 重命名
        node_list_formated_array = []
        # 替换://://字符串，以修复后期toclash转换错误
        if '://' not in node_list:
            try:
                node_list = sub_convert.base64_decode(node_list)
            except Exception:
                print(f'\n无法格式化: {node_list}\n')
        node_list = node_list.replace('://://', '://')
        node_list_array = node_list.split('\n')
        for node in node_list_array:
            # ss有多种格式，需要分别处理
            if 'ss://' in node and 'vless://' not in node and 'vmess://' not in node:
                try:
                    node_del_head = re.sub('ss://|\/', '', node)
                    if '@' in node_del_head:
                        node_part = re.split('@|#', node_del_head, maxsplit=2)
                        server_head = sub_convert.find_country(
                            node_part[1].split(':')[0])
                        server_body = node_part[1].split('?')[0]
                        password = sub_convert.base64_decode(
                            node_part[0]).split(':')[-1]
                        name_renamed = server_head + server_body + '(' + password + ')'
                        node_name = urllib.parse.quote(name_renamed, safe='')
                        node_raw = node_part[0] + '@' + node_part[1] + '#' + node_name
                        node = 'ss://' + node_raw
                    else:
                        # print("\n特殊ss节点：" + node + "\n")
                        node_part = re.split('\?|#', node_del_head)
                        node_part_head_decoded = sub_convert.base64_decode(
                            node_part[0])
                        node_part_head = re.split('@|:', node_part_head_decoded, maxsplit=0)
                        server_port = node_part_head[-1].split('?')[0]
                        server = node_part_head[-2]
                        server_head = sub_convert.find_country(
                            server)
                        password = node_part_head[-3]
                        name_renamed = server_head + server +  ':' + server_port + '(' + password + ')'
                        node_name = urllib.parse.quote(
                            name_renamed, safe='')
                        node_raw = node_part[0] + '#' + node_name
                        node = 'ss://' + node_raw
                    node_list_formated_array.append(node)
                except Exception as err:
                    print(f'\n改名 ss 节点: {node} 发生错误: {err}\n')
                    continue
            elif 'ssr://' in node:
                try:
                    node_del_head = node.replace('ssr://', '')
                    node_part = sub_convert.base64_decode(
                        node_del_head).split('/?')
                    # example : 194.50.171.214:9566:origin:rc4:plain:bG5jbi5vcmcgOGw/?obfsparam=&remarks=5L-E572X5pavTQ&group=TG5jbi5vcmc
                    node_part_head = re.split(':|\?',node_part[0])
                    server_head = sub_convert.find_country(node_part_head[0])
                    try:
                        password = sub_convert.base64_decode(node_part_head[5])
                    except Exception:
                        password = node_part_head[5]
                    name_renamed = server_head + node_part_head[0] + ':' + node_part_head[1] + '(' + password + ')'
                    node_part_foot = node_part[-1].split('&')
                    for i in range(len(node_part_foot)):
                        if 'remarks' in node_part_foot[i]:
                            node_part_foot[i] = 'remarks=' + sub_convert.base64_encode(name_renamed)
                            break
                    node_part_foot_str = '&'.join(node_part_foot)
                    node_raw = sub_convert.base64_encode(
                        node_part[0] + '/?' + node_part_foot_str)
                    node = 'ssr://' + node_raw
                    node_list_formated_array.append(node)
                except Exception as err:
                    print(f'\n改名 ssr 节点: {node} 发生错误: {err}\n')
                    continue
            elif 'vmess://' in node:
                try:
                    node_part_list = re.split('[^a-zA-Z0-9_+-/:=`]+',node)
                    for node_part in node_part_list:
                        if 'vmess://' in node_part:
                            node_del_head = node_part.replace('vmess://', '')
                            break
                    node_json_raw = sub_convert.base64_decode(node_del_head)
                    if '"' in node_json_raw:
                        node_json = json.loads(node_json_raw)
                    else:
                        node_json = eval(node_json_raw)
                    name_renamed = sub_convert.find_country(node_json['add']) + node_json['add'] + ':' + str(node_json['port']) + '(' + node_json['id'] + ')'
                    node_json['ps'] = name_renamed
                    node_json_dumps = json.dumps(node_json)
                    node_raw = sub_convert.base64_encode(node_json_dumps)
                    node = 'vmess://' + node_raw
                    node_list_formated_array.append(node)
                except Exception as err:
                    print(f'\n改名 vmess 节点: {node} 发生错误: {err}\n')
                    continue
            elif 'trojan://' in node:
                try:
                    node_del_head = node.replace('trojan://', '')
                    node_list = re.split('\?|#', node_del_head)
                    node_server_part = node_list[0]
                    node_password = node_server_part.rsplit('@',1)[0]
                    node_server_part_expasswd = node_server_part.rsplit('@',1)[1]
                    node_part = [node_password] + [node_server_part_expasswd] + node_list[1:]
                    node_server_and_port = urllib.parse.unquote(node_part[1])
                    node_server_and_port_part = node_server_and_port.split(':')
                    if node_server_and_port_part[1].isdigit() and node_server_and_port_part[0]:
                        server_head = sub_convert.find_country(node_server_and_port_part[0])
                        password = re.sub('trojan://|!str|!<str>| |\[|\]|{|}','',urllib.parse.unquote(node_password))
                        name_renamed = server_head + node_server_and_port + '(' + password + ')'
                        node_raw = node_del_head.split('#')[0] + '#' + urllib.parse.quote(name_renamed, safe='')
                        node = 'trojan://' + node_raw
                        node_list_formated_array.append(node)
                    else:
                        continue
                except Exception as err:
                    print(f'\n改名 trojan 节点: {node} 发生错误: {err}\n')
                    continue
        node_list_formated = '\n'.join(node_list_formated_array)
        if node_list_formated == '':
            return node_list_formated
        else:
            return node_list_formated + '\n'

    def duplicate_removal(node_list):
        node_list_dr_array = []
        node_name_dr_array = []
        for node in node_list:
            if ("ss://" in node or "ssr://" in node or "trojan://" in node and "vless://" not in node):
                node_name = sub_convert.get_node_name(node)
                if node_name not in node_name_dr_array:
                    node_name_dr_array.append(node_name)
                    node_list_dr_array.append(node)

        return node_list_dr_array

    def get_node_name(node):
        name = ""
        if 'ss://' in node and 'vless://' not in node and 'vmess://' not in node:
            try:
                node_del_head = node.replace('ss://', '')
                node_part = node_del_head.split('#')
                name = urllib.parse.unquote(node_part[1])
            except Exception as err:
                print(f'\n获取节点名错误: {err}\n')
        elif 'ssr://' in node:
            try:
                node_del_head = node.replace('ssr://', '')
                node_part = sub_convert.base64_decode(
                    node_del_head).split('/?')
                node_part_foot = node_part[-1].split('&')
                for i in range(len(node_part_foot)):
                    if 'remarks' in node_part_foot[i]:
                        name = sub_convert.base64_decode(
                            node_part_foot[i].replace('remarks=', ''))
                        break
            except Exception as err:
                print(f'\n获取节点名错误: {err}\n')
        elif 'vmess://' in node:
            try:
                node_del_head = node.replace('vmess://', '')
                node_json = json.loads(
                    sub_convert.base64_decode(node_del_head))
                name = node_json['ps']
            except Exception as err:
                print(f'\n获取节点名错误: {err}\n')
        elif 'trojan://' in node:
            try:
                node_del_head = node.replace('trojan://', '')
                node_part = node_del_head.split('#')
                name = urllib.parse.unquote(node_part[-1])
            except Exception as err:
                print(f'\n获取节点名错误: {err}\n')
        return name

    def find_country(server):
        if server.replace('.', '').isdigit():
            ip = server
        else:
            try:
                # https://cloud.tencent.com/developer/article/1569841
                ip = socket.gethostbyname(server)
            except Exception:
                ip = server
        with geoip2.database.Reader('./Country.mmdb') as ip_reader:
            try:
                response = ip_reader.country(ip)
                country_code = response.country.iso_code
            except Exception:
                country_code = 'NOWHERE'
        return '[' + country_code + ']'

    def write_to_node(node_list_array, path):
        node_list = '\n'.join(node_list_array)
        node_list_file = open(path, 'w', encoding='utf-8')
        node_list_file.write(node_list)
        node_list_file.close()

    def write_to_base64(node_list_array, path):
        node_list = '\n'.join(node_list_array)
        node_list_base64 = sub_convert.base64_encode(node_list)
        node_list_base64_file = open(path, 'w', encoding='utf-8')
        node_list_base64_file.write(node_list_base64)
        node_list_base64_file.close()

    def write_to_clash(node_list_array, path):
        # for i in range(0, len(node_list_array), 3000):
        #     node_list_array_part = node_list_array[i:i + 3000]
        #     node_list_part = sub_convert.yaml_encode(node_list_array_part)
        #     node_list_part_file = open(f'{path}{(i+1)//3000}.yaml', 'w', encoding='utf-8')
        #     node_list_part_file.write(node_list_part)
        #     node_list_part_file.close()
        node_converted_list = ThreadPoolExecutor(max_workers=5000).map(sub_convert.yaml_encode, node_list_array)
        nodes =list(filter(None, list(node_converted_list))) 
        sub_head = 'proxies:\n'
        for i in range(0, len(nodes), 2000):
            sub_content = sub_head + '\n'.join(nodes[i:i + 2000])
            node_list_file = open(f'{path}{(i+1)//2000}.yaml', 'w', encoding='utf-8')
            node_list_file.write(sub_content)
            node_list_file.close()

    def base64_encode(url_content):  # 将 URL 内容转换为 Base64
        base64_content = base64.b64encode(
            url_content.encode('utf-8')).decode('ascii')
        return base64_content

    def base64_decode(url_content):  # Base64 转换为 URL 链接内容
        url_content = url_content.replace('-', '+').replace('_', '/')
        missing_padding = len(url_content) % 4
        if missing_padding != 0:
            # 不是4的倍数后加= https://www.cnblogs.com/wswang/p/7717997.html
            url_content += '='*(4 - missing_padding)
        try:
            base64_content = base64.b64decode(url_content.encode('utf-8')).decode('utf-8', 'ignore')  # https://www.codenong.com/42339876/
            base64_content_format = base64_content
            return base64_content_format
        except UnicodeDecodeError:
            base64_content = base64.b64decode(url_content)
            base64_content_format = base64_content
            return base64_content

    def check_node_validity(host, port):
        # socket.setdefaulttimeout(5)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if sock.connect_ex((host,int(port))):
                return False
            else:
                return True
        except Exception:
            return False
    def yaml_encode(line):  # 将 URL 内容转换为 YAML (输出默认 YAML 格式)
        ss_cipher = ["aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "rc4-md5", "chacha20-ietf", "xchacha20", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"]
        ssr_cipher = ["aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "rc4-md5", "chacha20-ietf", "xchacha20"]
        ssr_protocol = ["origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"]
        ssr_obfs = ["plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"]
        vmess_cipher = ["auto", "aes-128-gcm", "chacha20-poly1305", "none"]

        yaml_url = {}
        if 'vmess://' in line:
            try:
                vmess_json_config = json.loads(
                    sub_convert.base64_decode(line.replace('vmess://', '')))
                vmess_default_config = {
                    'v': 'Vmess Node', 'ps': 'Vmess Node', 'add': '0.0.0.0', 'port': 0, 'id': '',
                    'aid': 0, 'scy': 'auto', 'net': '', 'type': '', 'host': vmess_json_config['add'], 'path': '/', 'tls': ''
                }
                vmess_default_config.update(vmess_json_config)
                vmess_config = vmess_default_config
                #yaml_config_str = ['name', 'server', 'port', 'type', 'uuid', 'alterId', 'cipher', 'tls', 'skip-cert-verify', 'network', 'ws-path', 'ws-headers']
                #vmess_config_str = ['ps', 'add', 'port', 'id', 'aid', 'scy', 'tls', 'net', 'host', 'path']
                # 生成 yaml 节点字典
                if vmess_config['id'] == '':
                    print(f'\n节点格式错误: {line}\n')
                    return ''
                else:
                    yaml_url.setdefault('name', '"' + urllib.parse.unquote(vmess_config['ps']) + '"')
                    vmess_config['add'] = re.sub('\[|\]|{|}', '', vmess_config['add'])
                    if re.match('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$', vmess_config['add']):
                        yaml_url.setdefault('server', vmess_config['add'])
                    else:
                        return ''
                    yaml_url.setdefault('port', int(vmess_config['port']))
                    yaml_url.setdefault('type', 'vmess')
                    if vmess_config['id'] == '0' or re.findall("[g-z]", vmess_config['id']) or len(vmess_config['id']) != 36:
                        return ''
                    else:
                        yaml_url.setdefault('uuid', vmess_config['id'])
                    yaml_url.setdefault('alterId', int(vmess_config['aid']))
                    if vmess_config['scy'] in vmess_cipher:
                        yaml_url.setdefault('cipher', vmess_config['scy'])
                    else:
                        return ''                            
                    if vmess_config['net'] != '':
                        yaml_url.setdefault('network', vmess_config['net'])
                    if vmess_config['path'] is not None:
                        vmess_config['path'] = re.sub(' |\[|\]|{|}|\?|@|"','',urllib.parse.unquote(vmess_config['path'])).split(':')[-1]
                    if vmess_config['host'] is not None:
                        vmess_config['host'] = re.sub(' |\[|\]|{|}|\?|@|"','',urllib.parse.unquote(vmess_config['host'])).split(':')[-1]
                        vmess_config['host'] = re.sub(' |\[|\]|{|}|\?|@|"','',urllib.parse.unquote(vmess_config['host'])).split(':')[-1]
                    if vmess_config['net'] == 'ws':
                        if vmess_config['tls'] == 'tls':
                            yaml_url.setdefault('tls', 'true')
                        else:
                            yaml_url.setdefault('tls', 'false')
                        # yaml_url.setdefault('skip-cert-verify', 'true')
                        if vmess_config['path'] == '' or vmess_config['path'] is None:
                            yaml_url.setdefault('ws-opts', {'path': '/'})
                        else:
                            yaml_url.setdefault('ws-opts', {}).setdefault('path', vmess_config['path'])
                        if vmess_config['host'] != '':
                            yaml_url.setdefault('ws-opts', {}).setdefault('headers', {'host': vmess_config['host']})
                    elif vmess_config['net'] == 'h2':
                        yaml_url.setdefault('tls', 'true')
                        yaml_url.setdefault('h2-opts', {}).setdefault('host', '[' + vmess_config['host'] + ']')
                        if vmess_config['path'] == '' or vmess_config['path'] is None:
                            yaml_url.setdefault('h2-opts', {}).setdefault('path', '/')
                        else:
                            yaml_url.setdefault('h2-opts', {}).setdefault('path', vmess_config['path'])
                    elif vmess_config['net'] == 'grpc':
                        yaml_url.setdefault('tls', 'true')
                        # yaml_url.setdefault('skip-cert-verify', 'true')
                        if vmess_config['host'] == '':
                            yaml_url.setdefault('servername', '""')
                        else:
                            yaml_url.setdefault('servername', vmess_config['host'])
                        if vmess_config['path'] == '' or vmess_config['path'] is None:
                            yaml_url.setdefault('grpc-opts', {'grpc-service-name': '/'})
                        else:
                            yaml_url.setdefault('grpc-opts', {'grpc-service-name': vmess_config['path']})
                    elif vmess_config['net'] == 'http':
                        yaml_url.setdefault('http-opts', {}).setdefault('method', "GET")
                        if vmess_config['path'] == '' or vmess_config['path'] is None:
                            yaml_url.setdefault('http-opts', {}).setdefault('path', '[/]')
                        else:
                            yaml_url.setdefault('http-opts', {}).setdefault('path', '[' + vmess_config['path'] + ']')
            except Exception as err:
                print(f'\nyaml_encode 解析 vmess 节点: {line}\n发生错误: {err}\n')
                return ''

        elif 'ss://' in line and 'vless://' not in line and 'vmess://' not in line:
            try:
                ss_content = re.sub('ss://|\/', '', line)
                if '@' in ss_content:
                    ss_content_array = re.split('@|\?|#', ss_content)
                    yaml_url.setdefault('name', '"' + urllib.parse.unquote(ss_content_array[-1]) + '"')
                    # include cipher password
                    config_first_decode_list = sub_convert.base64_decode(ss_content_array[0]).split(':')
                    # include server port
                    config_second_list = ss_content_array[1].split(':')
                    server_address = re.sub('\[|\]','',':'.join(config_second_list[:-1]))
                    if "::" in server_address:
                        return ''
                    else:
                        yaml_url.setdefault('server', server_address)
                    if config_second_list[-1].isdigit():
                        yaml_url.setdefault('port', config_second_list[-1])
                    else:
                        return ''
                    yaml_url.setdefault('type', 'ss')
                    if config_first_decode_list[0] in ss_cipher:
                        yaml_url.setdefault('cipher', config_first_decode_list[0])
                    else:
                        return ''
                    server_password = re.sub('!str|!<str>|!<str| |\[|\]|{|}','',config_first_decode_list[1])
                    if (server_password == ''):
                        return ''
                    elif re.compile(r'^[-+]?[-0-9]\d*\.\d*|[-+]?\.?[0-9]\d*$').match(server_password):
                        yaml_url.setdefault('password', '!<str> ' + server_password)
                    else:
                        yaml_url.setdefault('password', '"' + server_password + '"')
                    if len(ss_content_array) >= 4:
                        # include more server config
                        parameters_raw = urllib.parse.unquote(ss_content_array[2])
                        parameters = parameters_raw.split(';')
                        # or 'plugin=' in parameter for parameter in parameters:
                        if 'plugin=' in str(parameters):
                            if 'obfs' in str(parameters):
                                yaml_url.setdefault('plugin', 'obfs')
                            elif 'v2ray-plugin' in str(parameters):
                                yaml_url.setdefault('plugin', 'v2ray-plugin')
                        for parameter in parameters:
                            if 'plugin' in yaml_url.keys():
                                if 'obfs' in yaml_url['plugin']:
                                    if 'obfs=' in parameter:
                                        obfs_mode_list = ['tls','http']
                                        if parameter in obfs_mode_list:
                                            yaml_url.setdefault('plugin-opts', {}).setdefault('mode', parameter.split('=')[-1])
                                    elif 'obfs-host=' in parameter:
                                        yaml_url.setdefault('plugin-opts', {}).setdefault('host', re.sub('\[|\]|{|}','',parameter.split('=')[-1]))
                                elif 'v2ray-plugin' in yaml_url['plugin']:
                                    if 'mode=' in parameter:
                                        # v2ray_plugin_mode_list = ['websocket']
                                        # if parameter in v2ray_plugin_mode_list:
                                        yaml_url.setdefault('plugin-opts', {}).setdefault('mode', 'websocket')
                                    elif 'tls' in parameter:
                                        yaml_url.setdefault('plugin-opts', {}).setdefault('tls', 'true')
                                    elif 'mux' in parameter:
                                        yaml_url.setdefault('plugin-opts', {}).setdefault('mux', 'true')
                                    elif 'host=' in parameter:
                                        yaml_url.setdefault('plugin-opts', {}).setdefault('host', parameter.split('=')[-1])
                                    elif 'path=' in parameter:
                                        if parameter.split('=')[-1] == '':
                                            yaml_url.setdefault('plugin-opts', {}).setdefault('path', '/')
                                        else:
                                            yaml_url.setdefault('plugin-opts', {}).setdefault('path', parameter.split('=')[-1])
                        if 'plugin' in yaml_url.keys():
                            if 'plugin-opts' not in yaml_url.keys():
                                yaml_url.setdefault('plugin-opts', {})
                            if 'obfs' in yaml_url['plugin']:
                                if 'mode' not in yaml_url['plugin-opts'].keys() or not yaml_url['plugin-opts']['mode']:
                                    yaml_url.setdefault('plugin-opts', {}).setdefault('mode', 'tls')
                            if 'v2ray-plugin' in yaml_url['plugin']:
                                if 'mode' not in yaml_url['plugin-opts'].keys() or not yaml_url['plugin-opts']['mode']:
                                    yaml_url.setdefault('plugin-opts', {}).setdefault('mode', 'websocket')
                else:
                    ss_content_array = ss_content.split("#")
                    ss_content_head = sub_convert.base64_decode(ss_content_array[0])
                    ss_content_head_array = re.split(':|@',ss_content_head)
                    yaml_url.setdefault('name', '"' + urllib.parse.unquote(ss_content_array[-1]) + '"')
                    server_address = re.sub('\[|\]','',ss_content_head_array[-2])
                    if "::" in server_address:
                        return ''
                    else:
                        yaml_url.setdefault('server', server_address)
                    if ss_content_head_array[-1].isdigit():
                        yaml_url.setdefault('port', ss_content_head_array[-1])
                    yaml_url.setdefault('type', 'ss')
                    if ss_content_head_array[0] in ss_cipher:
                        yaml_url.setdefault('cipher', ss_content_head_array[0])
                    else:
                        return ''
                    server_password = re.sub('!str|!<str>|!<str| |\[|\]|{|}','',ss_content_head_array[1])
                    if (server_password == ''):
                        return ''
                    elif re.compile(r'^[-+]?[-0-9]\d*\.\d*|[-+]?\.?[0-9]\d*$').match(server_password):
                        yaml_url.setdefault('password', '!<str> ' + server_password)
                    else:
                        yaml_url.setdefault('password', '"' + server_password + '"')
            except Exception as err:
                print(f'\nyaml_encode 解析 ss: {line} 节点发生错误: {err}\n')
                return ''

        elif 'ssr://' in line:
            try:
                ssr_content = sub_convert.base64_decode(line.replace('ssr://', ''))
                part_list = ssr_content.split('/?')
                if '&' in part_list[1]:
                    # 将 SSR content /？后部分参数分割
                    ssr_part = re.split('\?|&',part_list[1])
                    for item in ssr_part:
                        if 'remarks=' in item:
                            remarks_part = item.replace('remarks=', '')
                    try:
                        remarks = sub_convert.base64_decode(remarks_part)
                    except Exception:
                        remarks = 'ssr'
                else:
                    remarks_part = part_list[1].replace('remarks=', '')
                    try:
                        remarks = sub_convert.base64_decode(remarks_part)
                    except Exception:
                        remarks = 'ssr'
                        print(f'\nSSR 格式化错误, 内容:{remarks_part}\n')
                yaml_url.setdefault('name', '"' + urllib.parse.unquote(remarks) + '"')
                server_part_list = re.split(':|\?|&', part_list[0])
                if "NULL" in server_part_list[0]:
                    return ''
                else:
                    yaml_url.setdefault('server', server_part_list[0])
                yaml_url.setdefault('port', server_part_list[1])
                yaml_url.setdefault('type', 'ssr')
                if server_part_list[3] in ssr_cipher:
                    yaml_url.setdefault('cipher', server_part_list[3])
                else:
                    return ''
                try:
                    server_password = sub_convert.base64_decode(server_part_list[5])
                except Exception:
                    server_password = server_part_list[5]
                server_password = re.sub('!str|!<str>|!<str| |\[|\]|{|}','', server_password)
                if re.compile(r'^[-+]?[-0-9]\d*\.\d*|[-+]?\.?[0-9]\d*$').match(server_password):
                    yaml_url.setdefault('password', '!<str> ' + server_password)
                else:
                    yaml_url.setdefault('password', '"' + server_password + '"')
                if server_part_list[2] in ssr_protocol:
                    yaml_url.setdefault('protocol', server_part_list[2])
                else:
                    return ''
                if server_part_list[4] in ssr_obfs:
                    yaml_url.setdefault('obfs', server_part_list[4])
                else:
                    return ''
                if 'ssr_part' in vars():
                    for item in ssr_part:
                        if 'obfsparam=' in item:
                            obfs_param = sub_convert.base64_decode(urllib.parse.unquote(item.replace('obfsparam=', '')))
                            obfs_param = re.sub('\[|\]|{|}', '', obfs_param)
                            if obfs_param != '':
                                yaml_url.setdefault('obfs-param', '"' + obfs_param + '"')
                            else:
                                yaml_url.setdefault('obfs-param', '""')
                        elif 'protoparam=' in item:
                            protocol_param = sub_convert.base64_decode(urllib.parse.unquote(item.replace('protoparam=', '')))
                            protocol_param = re.sub('\[|\]|{|}', '', protocol_param)
                            if protocol_param != '':
                                yaml_url.setdefault('protocol-param', protocol_param)
                            else:
                                yaml_url.setdefault('protocol-param', '""')
                if 'obfs-param' not in yaml_url.keys():
                    yaml_url.setdefault('obfs-param', '""')
                if 'protocol-param' not in yaml_url.keys():
                    yaml_url.setdefault('protocol-param', '""')
            except Exception as err:
                print(f'\nyaml_encode 解析 ssr 节点: {line} 发生错误: {err}\n')
                return ''

        elif 'trojan://' in line:
            try:
                url_content = line.replace('trojan://', '')
                url_part_list = re.split('\?|#',url_content)
                node_password = url_part_list[0].rsplit('@',1)[0]
                node_server_and_port = url_part_list[0].rsplit('@',1)[1]
                part_list = [node_password] + [node_server_and_port] + url_part_list[1:]
                yaml_url.setdefault('name', '"' + urllib.parse.unquote(part_list[-1]) + '"')
                yaml_url.setdefault('server', re.sub(' |\[|\]|{|}|\?','',urllib.parse.unquote(part_list[1]).split(':')[0]))
                yaml_url.setdefault('port', urllib.parse.unquote(part_list[1]).split(':')[1])
                yaml_url.setdefault('type', 'trojan')
                server_password = re.sub('trojan://|!str|!<str>| |\[|\]|{|}','',urllib.parse.unquote(part_list[0]))
                if not server_password:
                    return ''
                elif re.compile(r'^[-+]?[-0-9]\d*\.\d*|[-+]?\.?[0-9]\d*$').match(server_password):
                    yaml_url.setdefault('password', '!<str> ' + server_password)
                else:
                    yaml_url.setdefault('password', '"' + server_password + '"')
                if len(part_list) == 4:
                    for config in part_list[2].split('&'):
                        if 'sni=' in config:
                            config = config[4:]
                            if '@' in config:
                                yaml_url.setdefault('sni', '"' + urllib.parse.unquote(config) + '"')
                            else:    
                                yaml_url.setdefault('sni', urllib.parse.unquote(config))
                        elif 'type=' in config:
                            yaml_url.setdefault('network', config[5:])
                            yaml_url.setdefault('udp', 'true')
                        if 'type=ws' in part_list[2]:
                            if 'path=' in config:
                                yaml_url.setdefault('ws-opts', {}).setdefault('path', re.sub(' |\[|\]|{|}|\?|@|"','',urllib.parse.unquote(config[5:])))
                            elif 'host=' in config:
                                yaml_url.setdefault('ws-opts', {}).setdefault('headers', {}).setdefault('host', config[5:])
                        elif 'type=grpc' in part_list[2]:
                            if 'servicename=' in config:
                                yaml_url.setdefault('grpc-opts', {}).setdefault('grpc-service-name', config[12:])
                        else:
                            if 'alpn=' in config:
                                yaml_url.setdefault('alpn','[' + '"' + re.sub("\[|\]|'",'',urllib.parse.unquote(config[5:])) + '"' + ']')
                    if 'network' in yaml_url.keys():
                        if yaml_url['network'] == 'ws':
                            if 'ws_opts' not in yaml_url.keys():
                                yaml_url.setdefault('ws-opts', {})
                            if yaml_url['ws-opts']['path'] == '':
                                yaml_url.setdefault('ws-opts', {}).setdefault('path', '/')
                        if yaml_url['network'] == 'grpc':
                            if 'grpc-opts' not in yaml_url.keys():
                                yaml_url.setdefault('grpc-opts', {})
                            if 'grpc-service-name' not in yaml_url['grpc-opts'].keys():
                                yaml_url.setdefault('grpc-opts', {}).setdefault('grpc-service-name', '""')
            except Exception as err:
                print(f'\nyaml_encode 解析 trojan 节点: {line} 发生错误: {err}\n')
                return ''
        if yaml_url['server'] == '' or yaml_url['port'] == 0:
            return ''
        if not sub_convert.check_node_validity(yaml_url['server'], yaml_url['port']):
            return ''
        yaml_node_raw = str(yaml_url)
        yaml_node_body = yaml_node_raw.replace('\'', '')
        yaml_node_head = '  - '
        yaml_node = yaml_node_head + yaml_node_body
        return yaml_node
    
if __name__ == '__main__':
    # print(sub_convert.check_node_validity('121.40.115.140','25535'))
    # file = open("./subscription/others/node.txt", 'r', encoding='utf-8')
    # nodes = file.read().split('\n')
    # file.close()
    # sub_convert.write_to_clash(nodes,'./test/')
    # sub_convert.get_node_from_sub("https://raw.githubusercontent.com/mheidari98/.proxy/main/all")
    sub_convert.format("vmess://eyJ2IjoiMiIsInBzIjoi8J+HuvCfh7Ig576O5Zu944CQ5LuY6LS55o6o6I2Q77yaaHR0cHM6Ly90dC52Zy92aXDjgJEyMjMiLCJhZGQiOiJjZi1sdC5zaGFyZWNlbnRyZS5vbmxpbmUiLCJwb3J0IjoiODAiLCJ0eXBlIjoibm9uZSIsImlkIjoiMmQ1ZDhiOWMtOGVjNC00YTM3LWI2MTAtNzhlNzFlMTNlYWVmIiwiYWlkIjoiMCIsIm5ldCI6IndzIiwicGF0aCI6Ii9zaGlya2VyIiwiaG9zdCI6Imx2My5zaGFyZWNlbnRyZXByby5vcmciLCJ0bHMiOiIifQ==")
    # sub_convert.yaml_encode("ssr://MTUuMTg4LjE3Ny4wOjQyODMzOm9yaWdpbjphZXMtMjU2LWNmYjpodHRwX3NpbXBsZTpXWEJZTW05d1FtSnlabkZLZW5wTmN3PT0vP3JlbWFya3M9Vy9DZmg2dnduNGUzWFRFMUxqRTRPQzR4TnpjdU1EbzBNamd6TXloWmNGZ3liM0JDWW5KbWNVcDZlazF6S1E9PQ==")
