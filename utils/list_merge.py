#!/usr/bin/env python3

# Python 之间互相调用文件https://blog.csdn.net/winycg/article/details/78512300
import json
from concurrent.futures import ThreadPoolExecutor
from urllib import request

from list_update import update_url
from sub_convert import sub_convert

# 分析当前项目依赖 https://blog.csdn.net/lovedingd/article/details/102522094


# 文件路径定义
# readme = './README.md'
sub_list_json = './subscription/others/sub_list.json'
sub_list_path = './subscription/others/list/'


class sub_merge():
    # 将转换后的所有 Url 链接内容合并转换 YAML or Base64,并输出文件，输入订阅列表。
    def get_sub_content(url_list):
        url = url_list['url']
        ids = url_list['id']
        remarks = url_list['remarks']
        if not url_list['enabled']:
            return ''
        content = sub_convert.get_node_from_sub(url)
        if content == '':
            print(f'\n写入 {remarks} 的错误信息到 {ids:0>2d}.txt 完成. \n')
            file = open(f'{sub_list_path}{ids:0>2d}.txt',
                        'w', encoding='utf-8')
            file.write(f'节点解析出错，请检查订阅链接：{ids} 是否正确')
            file.close()
            return ''
        else:
            file = open(f'{sub_list_path}{ids:0>2d}.txt',
                        'w', encoding='utf-8')
            file.write(content)
            file.close()
            print(f'写入内容: {remarks} 到文件: {ids:0>2d}.txt 完成. \n')
            return content

    def sub_merge(content_list_array):
        print('\n合并数据...\n')
        # https://python3-cookbook.readthedocs.io/zh_CN/latest/c02/p14_combine_and_concatenate_strings.html
        content_list = ''.join(content_list_array)
        # 去重
        content_array = content_list.split('\n')
        content_array_deduplication = sub_convert.duplicate_removal(
            content_array)
        # 写入文件
        sub_convert.write_to_node(
            content_array_deduplication, './subscription/others/node.txt')
        sub_convert.write_to_base64(
            content_array_deduplication, './subscription/others/base64')
        sub_convert.write_to_clash(content_array_deduplication, './subscription/')
        print('\n合并数据完成.\n')

    def read_list(json_file):  # 将 sub_list.json Url 内容读取为列表
        with open(json_file, 'r', encoding='utf-8') as f:
            raw_list = json.load(f)
        return raw_list

    def geoip_update(url):
        print('\n下载geoip2.database 中的 Country.mmdb...\n')
        try:
            request.urlretrieve(url, './Country.mmdb')
            print('\n下载完成. \n')
        except Exception:
            print('\n下载失败. \n')
            pass


if __name__ == '__main__':
    update_url.update_main()
    sub_merge.geoip_update('https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb')
    sub_list = sub_merge.read_list(sub_list_json)
    print("\n#################### Getting server list start ###############################\n")
    contents = ThreadPoolExecutor(max_workers=100).map(sub_merge.get_sub_content, sub_list)
    content_list = list(filter(None, list(contents)))
    print("\n#################### Getting server list stop  ###############################\n")
    print("\n#################### Formating server list start  ###############################\n")
    sub_merge.sub_merge(content_list)
    print("\n#################### Formating server list stop   ###############################\n")
