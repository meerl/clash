#!/usr/bin/env python3

import json
from datetime import datetime, timedelta

import requests
from requests.adapters import HTTPAdapter

# 文件路径定义
sub_list_json = './subscription/others/sub_list.json'


with open(sub_list_json, 'r', encoding='utf-8') as f:  # 载入订阅链接
    raw_list = json.load(f)
    f.close()


def check_url(url):  # 判断远程远程链接是否已经更新
    s = requests.Session()
    s.mount('http://', HTTPAdapter(max_retries=2))
    s.mount('https://', HTTPAdapter(max_retries=2))
    try:
        resp = s.get(url, timeout=2)
        status = resp.status_code
    except Exception:
        status = 404
    if status == 200:
        isAccessable = True
    else:
        isAccessable = False
    return isAccessable


class update_url():

    def update_main():

        if len(raw_list) > 0:
            for index in range(len(raw_list)):
                status = update_url.update(raw_list[index]['id'])
                if status is not None:
                    update_url.update_write(status[0], status[1])
                else:
                    continue
            updated_list = json.dumps(
                raw_list, sort_keys=False, indent=2, ensure_ascii=False)
            file = open(sub_list_json, 'w', encoding='utf-8')
            file.write(updated_list)
            file.close()
        else:
            print('\nDon\'t need to be updated.\n')

    def update_write(id, updated_url):
        if updated_url == 404:
            print(f'Id {id} URL 无可用更新\n')
        else:
            if updated_url != raw_list[id]['url']:
                raw_list[id]['url'] = updated_url
                print(f'\nId {id} URL 更新至 : {updated_url}\n')
            else:
                print(f'\nId {id} URL 无可用更新\n')

    def update(id):
        # if id == 0:
        #     # remarks: pojiezhiyuanjun/freev2, 将原链接更新至 https://raw.fastgit.org/pojiezhiyuanjun/freev2/master/%MM%(DD - 1).txt
        #     # today = datetime.today().strftime('%m%d')
        #     # 得到当前日期前一天 https://blog.csdn.net/wanghuafengc/article/details/42458721
        #     yesterday = (datetime.today() + timedelta(-1)).strftime('%m%d')
        #     front_url = 'https://raw.githubusercontent.com/pojiezhiyuanjun/freev2/master/'
        #     end_url = 'clash.yml'
        #     # 修改字符串中的某一位字符 https://www.zhihu.com/question/31800070/answer/53345749
        #     url_update = front_url + yesterday + end_url
        #     return [id, url_update]

        # if id == 11:
        #     today = datetime.today()
        #     front_url = 'https://raw.githubusercontent.com/halfaaa/Free/main/'
        #     end_url = '.txt'
        #     url_update = front_url + \
        #         str(today.month) + "." + str(today.day) + \
        #         "." + str(today.year) + end_url
        #     if check_url(url_update):
        #         return [id, url_update]
        #     else:
        #         return [id, 404]

        
        if id == 25:
            today = datetime.today().strftime('%Y%m%d')
            month = datetime.today().strftime('%m') + '/'
            year = datetime.today().strftime('%Y') + '/'
            front_url = 'https://v2rayshare.com/wp-content/uploads/'
            end_url = '.txt'
            url_update = front_url + year + month + today + end_url
            if check_url(url_update):
                return [id, url_update]
            else:
                return [id, 404]

        elif id == 34:
            url_raw = [
                "https://raw.githubusercontent.com/WilliamStar007/ClashX-V2Ray-TopFreeProxy/main/combine/clashsub.txt",
            ]
            url_update_array = []
            try:
                for url in url_raw:
                    resp = requests.get(url, timeout=3)
                    resp_content = resp.content.decode('utf-8')
                    resp_content = resp_content.split('\n')
                    for line in resp_content:
                        if 'http' in line:
                            url_update_array.append(line.replace('\r',''))
                        else:
                            continue
                url_update = '|'.join(url_update_array)
                return [id, url_update]
            except Exception as err:
                print(f'\nSubscription: {id}, Occurred error: {err}\n')
                return [id, 404]

        # elif id == 35:
        #     url_raw = 'https://raw.githubusercontent.com/arielherself/autosub/main/subs.txt'
        #     url_update_array = []

        #     try:
        #         resp = requests.get(url_raw, timeout=2)
        #         resp_content = resp.content.decode('utf-8')
        #         resp_content = resp_content.split('\n')
        #         for line in resp_content:
        #             if 'http' in line:
        #                 url_update_array.append(line)
        #             else:
        #                 continue
        #         url_update = '|'.join(url_update_array)
        #         return [id, url_update]
        #     except Exception as err:
        #         print(f'\nSubscription: {id}, Occurred error: {err}\n')
        #         return [id, 404]
            
        elif id == 43:
            # remarks: v2raydy/v2ray, 将原链接更新至 https://https://raw.githubusercontent.com/v2raydy/v2ray/main/%MM-%(DD - 1)%str%1.txt
            # 得到当前日期前一天 https://blog.csdn.net/wanghuafengc/article/details/42458721
            today = datetime.today().strftime('%Y%m%d')
            year = datetime.today().strftime('%Y')
            month = datetime.today().strftime('%m')
            front_url = 'https://nodefree.org/dy/'
            end_url = '.txt'
            url_update = front_url + year + '/' + month + '/' + today + end_url
            if check_url(url_update):
                return [id, url_update]
            else:
                return [id, 404]

        elif id == 54:
            url_raw = [
                "https://raw.githubusercontent.com/RenaLio/Mux2sub/main/urllist",
                "https://raw.githubusercontent.com/RenaLio/Mux2sub/main/sub_list"
            ]
            url_update_array = []
            try:
                for url in url_raw:
                    resp = requests.get(url, timeout=3)
                    resp_content = resp.content.decode('utf-8')
                    resp_content = resp_content.split('\n')
                    for line in resp_content:
                        if 'http' in line:
                            url_update_array.append(line)
                        else:
                            continue
                url_update = '|'.join(url_update_array)
                return [id, url_update]
            except Exception as err:
                print(f'\nSubscription: {id}, Occurred error: {err}\n')
                return [id, 404]

        elif id == 57:
            today = datetime.today().strftime('%Y%m%d')
            month = datetime.today().strftime('%m')
            year = datetime.today().strftime('%Y')
            front_url = 'https://clashnode.com/wp-content/uploads/'
            end_url = '.txt'
            url_update = front_url + year + '/' + month  + '/' + today + end_url
            if check_url(url_update):
                return [id, url_update]
            else:
                return [id, 404]

        elif id == 58:
            today = datetime.today().strftime('%d')
            year = datetime.today().strftime('%Y')
            month = datetime.today().strftime('%m')
            front_url = 'https://freenode.me/wp-content/uploads/'
            end_url = '8.txt'
            url_update = front_url + year + '/' + month + '/' + today + end_url
            if check_url(url_update):
                return [id, url_update]
            else:
                return [id, 404]
            
        elif id == 66:
            today = datetime.today().strftime('%Y%m%d')
            year = datetime.today().strftime('%Y')
            month = datetime.today().strftime('%m')
            front_url = 'https://oneclash.cc/wp-content/uploads/'
            end_url = '.txt'
            url_update = front_url + year + '/' + month + '/' + today + end_url
            if check_url(url_update):
                return [id, url_update]
            else:
                return [id, 404]
            
        elif id == 68:
            today = datetime.today().strftime('%Y%m%d')
            year = datetime.today().strftime('%Y')
            month = datetime.today().strftime('%m')
            front_url = 'https://wefound.cc/freenode/'
            end_url = '.txt'
            url_update = front_url + year + '/' + month + '/' + today + end_url
            if check_url(url_update):
                return [id, url_update]
            else:
                return [id, 404]

        elif id == 76:
            url_raw = ['https://raw.githubusercontent.com/cdddbc/getAirport/main/config/sublist_free','https://raw.githubusercontent.com/cdddbc/getAirport/main/config/sublist_mining']
            url_update_array = []
            try:
                for url in url_raw:
                    resp = requests.get(url, timeout=3)
                    resp_content = resp.content.decode('utf-8')
                    resp_content = resp_content.split('\n')
                    for line in resp_content:
                        if 'http' in line:
                            url_update_array.append(line)
                        else:
                            continue
                url_update = '|'.join(url_update_array)
                return [id, url_update]
            except Exception as err:
                print(f'\nSubscription: {id}, Occurred error: {err}\n')
                return [id, 404]


if __name__ == '__main__':
    update_url.update_main()
