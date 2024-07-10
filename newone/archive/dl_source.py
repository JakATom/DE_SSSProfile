"""下载规则源文件"""

import os
import time
import yaml
from urllib.parse import urljoin, urlparse
import httpx
import re
import ipaddress
import timeit
from log import Logger
from git import Repo
import shutil

# 当前文件所在的路径
current_path = os.path.dirname(os.path.abspath(__file__))

# 时间戳 来用于生成文件夹
time_now = time.strftime("%Y-%m-%d", time.localtime())

# 生成随机时间，在0~60s之间，用于随机间隔抓取文件
#

# log对象
log = Logger(os.path.join(current_path, 'record.log'), level='info')


def create_folders(data, current_path):
    """ 在当前文件所在目录下创建文件存放目录 
        data: 从配置文件中读取的配置，用于生成目录路径
        current_path: 当前文件所在的路径，作为根目录
        ##time_now: 根据日期生成目录，按天来保存
    """
    folder = current_path
    os.path.exists(folder) or os.makedirs(folder)

    # 创建rule-set的目录
    # 2023-09-09
    #   +- dalao1
    #       +- direct
    #           +- rule1.list
    #           +- rule2.list
    #       +- proxy
    #           +- rule3.list
    #           +- rule4.list
    #   +- dalao2
    #       +- direct
    #           +- rule1.list
    #               ...

    # 用于存储规则文件夹path
    dict_folder = {}

    dalaos = data['dalao']

    # 增加domain-set目录, 这里添加会直接改变data的整体数据，不能使用
    # dalaos.append("domain_set")

    for policy in ('direct', 'proxy', 'reject', 'delete'):
        # 用于存储规则文件夹path
        lst_folder = []

        for dalao in dalaos:
            if policy in data[dalao].keys():
                sub_folder = os.path.join(folder, dalao, policy)
                os.path.exists(sub_folder) or os.makedirs(sub_folder)
                lst_folder.append(sub_folder)

        if policy in data['domain_set'].keys():
            sub2_folder = os.path.join(folder, 'domain_set', policy)
            os.path.exists(sub2_folder) or os.makedirs(sub2_folder)
            lst_folder.append(sub2_folder)

        dict_folder[policy] = lst_folder

    log.logger.info('folders created ok.')
    log.logger.debug('folders: dict_folder')
    return dict_folder
    pass


def read_conf(file):
    """ 读取yaml配置 """

    data = None
    # yaml配置文件获取规则链接
    with open(file) as f:
        data = yaml.load(f.read(), Loader=yaml.SafeLoader)

    if data == None:
        log.logger.error(f"read config: {file} error!")
        raise Exception(f"read config: {file} error!")
    else:
        log.logger.info("yaml config read ok.")
        return data


def get_links(data, policy):
    """ 从yaml解析的数据中获取到rule-set类型的规则下载链接 """

    # 获取rule-set下的所有链接

    dalaos = data['dalao']

    links_policy = []
    for dalao in dalaos:

        if not policy in data[dalao].keys():
            continue

        short_links = data[dalao].get(policy, [])

        if len(short_links) == 0:
            continue

        for short in short_links:
            link = urljoin(data[dalao]['base_url'], short)
            d = {
                'dalao': dalao,
                'policy': policy,
                'url': link
            }
            links_policy.append(d)

    return links_policy

# def get_reject_links(data):
#     """ 获取reject的links，rule-set """

#     dalaos = data['dalao']
#     policy = 'reject'

#     links_policy = []
#     for dalao in dalaos:
#         # 有reject 字段
#         if not policy in data[dalao].keys(): continue

#         short_links = data[dalao].get(policy, [])
#         # 排除空
#         if len(short_links) == 0: continue

#         for short in short_links:
#             link = urljoin(data[dalao]['base_url'], short)
#             d = {
#                 'dalao': dalao,
#                 'policy': policy,
#                 'url': link
#             }
#             links_policy.append(d)

#     return links_policy


def scrape_link(url):
    """github页面爬取"""

    log.logger.debug(f'now, going to scrape {url}')
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        'Content-Type': 'text/html; charset=utf-8',
    }

    try:
        client = httpx.Client(http2=True)
        resp = client.get(url, headers=headers, timeout=10)
        log.logger.debug(resp.status_code)
        if resp.status_code == 200:
            return resp.text

    except Exception as e:
        log.logger.error(
            f"exception {type(e).__name__} occured while scrape {url}. args:\n{e.args}")

    # 捕获异常后，程序继续执行
    finally:
        pass


def get_domainset_links(data, policy):
    """ 从yaml解析的数据中获取到domain-set类型的规则下载链接 """

    # 获取domain_set下的所有链接

    domain_set = data['domain_set']

    links_policy = []

    if not policy in domain_set.keys():
        return []

    links_domain_set = domain_set.get(policy, [])

    if len(links_domain_set) == 0:
        return []

    for link in links_domain_set:
        d = {
            'dalao': 'domain_set',
            'policy': policy,
            'url': link
        }
        links_policy.append(d)

    return links_policy


def save_data(file, data):
    """ 保存文件到本地 """
    with open(file, 'w') as f:
        f.write(data)


def dl_rule_files(data, current_path):
    """ 下载rules文件到本地 """

    links = []
    for policy in ('direct', 'proxy', 'reject', 'delete'):
        links.extend(get_links(data, policy))
        links.extend(get_domainset_links(data, policy))

    log.logger.info('get all rules links.')
    # download & save

    for link in links:
        file_name = os.path.basename(urlparse(link['url']).path)

        if not (file_name.endswith('.list') or file_name.endswith('.txt')):
            log.logger.info(link['url'])
            continue

        file_path2 = os.path.join(current_path, link['dalao'], link['policy'])
        abs_file = os.path.join(file_path2, file_name)

        if not os.path.exists(abs_file):
            html_text = scrape_link(link['url'])

            if not html_text is None:
                save_data(abs_file, html_text)

        # 休息0-60s，模拟点击网页的行为. :太慢了！
        # time.sleep(randint(0, 1))

    log.logger.info('download all rules ok.')
    pass


def gen_domainset_set(folder):
    """ 生成domainset格式的set集合 """
    # 在 gen_policy_file() 函数之后使用

    # 将DOMAIN-SET格式转为RULE-SET格式
    lst_domain_set = set()

    for root, dirs, files in os.walk(folder):
        log.logger.debug(f'start {folder}')
        for file in files:
            if not (file.endswith('.list') or file.endswith('.txt')):
                log.logger.info(os.path.join(root, file))
                continue
            _file = os.path.join(root, file)

            log.logger.debug(f'start to open file: {_file}')
            with open(_file) as f:
                for line in f:
                    line = line.strip()
                    line = line.upper()
                    if '#' in line:
                        continue
                    elif ';' in line:
                        continue
                    elif '//' in line:
                        continue
                    elif len(line) == 0:
                        continue
                    elif line.startswith('.'):
                        new_line = 'DOMAIN-SUFFIX,' + \
                            line.lstrip('.').strip() + '\n'
                        lst_domain_set.add(new_line)
                    else:
                        new_line = 'DOMAIN,' + line.strip() + '\n'
                        lst_domain_set.add(new_line)

    log.logger.debug(f'gen_domainset_set {folder} ok.')
    return lst_domain_set


def gen_ruleset_set(folder):
    """ 生成ruleset格式的set集合 """

    line_set = set()

    for root, dirs, files in os.walk(folder):
        log.logger.debug(f'start {folder}')
        for file in files:
            if not (file.endswith('.list') or file.endswith('.txt')):
                log.logger.info(os.path.join(root, file))
                continue
            _file = os.path.join(root, file)
            log.logger.debug(f'start to open file: {_file}')
            with open(_file) as f:
                # 逐行处理
                for line in f:
                    # 去除最后的换行符，然后手动增加换行符
                    line = line.strip()
                    line = line.upper()
                    line += '\n'

                    if '#' in line:
                        continue
                    elif ';' in line:
                        continue
                    elif '//' in line:
                        continue
                    elif 'DOMAIN' in line:
                        line_set.add(line)
                    elif 'IP-CIDR' in line:
                        l = line.replace(',no-resolve', '')
                        line_set.add(l)
                    elif 'USER-AGENT' in line:
                        line_set.add(line)
                    else:
                        continue

    log.logger.debug(f'gen_ruleset_set {folder} ok.')
    return line_set


def gen_policy_set(dict_folder, policy):
    """ 汇总ruleset和domainset格式的set集合，合并到同一个policy中 """

    log.logger.debug(f'gen_policy_set {policy}')
    lst_folders = dict_folder[policy]
    policy_set = set()

    for folder in lst_folders:
        if 'domain_set' in folder:
            tmp_domset = gen_domainset_set(folder)
            policy_set |= tmp_domset
        else:
            tmp_set = gen_ruleset_set(folder)
            policy_set |= tmp_set

    return policy_set


def save_set(file, data_set):
    """ 循环data_set写到文件file """
    with open(file, 'w') as f:
        for line in data_set:
            f.write(line)


def handle_dedup_domain(policy_set):
    """ 生成域名文件 """
    # """ handle direct_set about DOMAIN-KEYWORD/DOMAIN-SUFFIX/DOMAIN """
    # -- 这些代理app的处理规则不是那么完美，所以没必要进行DOMAIN-KEYWORD/DOMAIN-SUFFIX/DOMAIN的去重合
    # -- 直接保留他们原始的DOMAIN-KEYWORD/DOMAIN-SUFFIX/DOMAIN规则。
    # 去重合原则：同一个policy下分别去重合DOMAIN-KEYWORD/DOMAIN-SUFFIX/DOMAIN，然后都汇总到一个policy_set下，
    #           再进行 direct_set 与 proxy_set 的整体去重合（proxy_set -= direct_set）

    set_keyword, set_suffix, set_domain = set(), set(), set()
    for line in policy_set:
        linesplit = line.split(',')
        try:
            l = linesplit[1]
        except Exception as e:
            log.logger.error(
                f"exception {type(e).__name__} : {line}. args:\n{e.args}")
        l = l.strip()
        l = l.strip('.')

        if 'DOMAIN-KEYWORD' in line:
            set_keyword.add(l)
        elif 'DOMAIN-SUFFIX' in line:
            set_suffix.add(l)
        elif 'DOMAIN' in line:
            set_domain.add(l)
        else:
            continue

    # # 去重合部分，不用了删除
    set_suffix -= set_keyword
    set_domain -= set_keyword
    set_domain -= set_suffix

    # 关键字与后缀去重
    set_keyword_suffix = {
        j for i in set_keyword for j in set_suffix if i in j.split('.')}
    set_suffix -= set_keyword_suffix

    # 关键字与域名去重
    set_keyword_domian = {
        j for i in set_keyword for j in set_domain if i in j.split('.')}
    set_domain -= set_keyword_domian

    # 后缀与域名去重
    set_suffix_domain = set()
    for suff in set_suffix:
        re_pattern = re.compile(rf'\w.*\.{suff}$', re.I)
        for do in set_domain:
            if re.search(re_pattern, do):
                set_suffix_domain.add(do)
    set_domain -= set_suffix_domain

    return set_keyword, set_suffix, set_domain

    pass


def handle_dedup_ip(policy_set):
    """ ip类规则去重，生成规则文件 """

    set_ipv4, set_ipv6 = set(), set()

    for line in policy_set:
        lst_line = line.split(',')

        if 'IP-CIDR6' in lst_line:
            ip = lst_line[1].strip()
            ipn = ipaddress.ip_network(ip, strict=False)
            if ":" in ip:
                set_ipv6.add(ipn)
            elif "." in ip:
                set_ipv4.add(ipn)

        elif 'IP-CIDR' in lst_line:
            ip = lst_line[1].strip()
            ipn = ipaddress.ip_network(ip, strict=False)
            if ":" in ip:
                set_ipv6.add(ipn)
            elif "." in ip:
                set_ipv4.add(ipn)

        else:
            continue

    # ip范围去重合
    def get_dedup_ip(set_ip):
        # 判断ip范围重合
        # 将set转为list，将list从头到尾，依次扫描，判断2个元素是否互为子网
        subnet_set = set()

        n = len(set_ip)
        lst_set = list(set_ip)

        for i in range(n):
            for j in range(i+1, n):
                if lst_set[i].subnet_of(lst_set[j]):
                    subnet_set.add(lst_set[i])
                elif lst_set[j].subnet_of(lst_set[i]):
                    subnet_set.add(lst_set[j])
        return subnet_set

        pass

    same_ipv4_set = get_dedup_ip(set_ipv4)
    set_ipv4 -= same_ipv4_set

    same_ipv6_set = get_dedup_ip(set_ipv6)
    set_ipv6 -= same_ipv6_set

    return set_ipv4, set_ipv6


def handle_dedup_useragent(policy_set):
    """ user-agent类规则去重，生成规则文件 """

    set_ua = set()
    for line in policy_set:
        if 'USER-AGENT' in line.split(','):
            set_ua.add(line)
        else:
            continue

    return set_ua


def gen_policy_file(dict_folder, root_folder):
    """ 生成direct.list proxy.list """

    direct_set = set()
    proxy_set = set()

    direct_set = gen_policy_set(dict_folder, 'direct')
    proxy_set = gen_policy_set(dict_folder, 'proxy')
    reject_set = gen_policy_set(dict_folder, 'reject')

    # generate direct.list / proxy.list
    output_folder = os.path.join(root_folder, 'output_rules')
    os.path.exists(output_folder) or os.makedirs(output_folder)

    # >>> 2023.11.09 add: direct_set - desss_proxy
    lst_proxy_dicts = dict_folder['proxy']
    folders = [i for i in lst_proxy_dicts if 'desss' in i]
    #print(folders)
    desss_proxy_set = gen_ruleset_set(folders[0])
    direct_set -= desss_proxy_set

    # >>> 2023.11.09 add: proxy_set - desss_direct
    lst_direct_dicts = dict_folder['direct']
    folderss = [i for i in lst_direct_dicts if 'desss' in i]
    desss_direct_set = gen_ruleset_set(folderss[0])
    proxy_set -= desss_direct_set

    ## ---- 2023.12.10 add: rules of delete: proxy_set - desss_delete, direct_set - desss_delete
    lst_delete_dicts = dict_folder['delete']
    foldersss = [i for i in lst_delete_dicts if 'desss' in i]
    desss_delete_set = gen_ruleset_set(foldersss[0])
    proxy_set -= desss_delete_set
    direct_set -= desss_delete_set

    ## ---- 2023.11.02 mod: proxy first, direct second.

    ## 去重1：优先direct，将proxy中重复的部分删除
    ## reject 目前只使用sogouinput.list，所以这里只用于去重
    proxy_set -= direct_set
    #direct_set -= proxy_set
    proxy_set -= reject_set
    direct_set -= reject_set


    # save
    direct_file = os.path.join(output_folder, 'direct.list')
    save_set(direct_file, direct_set)
    proxy_file = os.path.join(output_folder, 'proxy.list')
    save_set(proxy_file, proxy_set)
    proxy_file = os.path.join(output_folder, 'reject.list')
    save_set(proxy_file, reject_set)

    log.logger.info('direct.list & proxy.list generated successfully.')

    # -- handle direct_set about DOMAIN-KEYWORD/DOMAIN-SUFFIX/DOMAIN
    # 生成域名类的.list 文件
    set_keyword_direct, set_suffix_direct, set_domain_direct = \
        handle_dedup_domain(direct_set)
    set_keyword_proxy, set_suffix_proxy, set_domain_proxy = \
        handle_dedup_domain(proxy_set)

    set_keyword_proxy -= set_keyword_direct
    set_suffix_proxy -= set_suffix_direct
    set_domain_proxy -= set_domain_direct
    
    ## ---- 2023.11.02 mod: sep file domain_direct.list to 3 files 
    ## ---- 1: domain_direct_domain.list
    ## ---- 2: domain_direct_suffix.list
    ## ---- 3: domain_direct_keyword.list
    ## ---- and same for .yaml

    # save
    #domain_file = os.path.join(output_folder, "domain_direct.list")
    #if not os.path.exists(domain_file):
    #    with open(domain_file, 'w') as f:
    #        for i in set_keyword_direct:
    #            ii = f"DOMAIN-KEYWORD,{i}\n"
    #            f.write(ii)
    #
    #        for i in set_suffix_direct:
    #            ii = f"DOMAIN-SUFFIX,{i}\n"
    #            f.write(ii)
    #
    #        for i in set_domain_direct:
    #            ii = f"DOMAIN,{i}\n"
    #            f.write(ii)
    file_domain_direct_domain = os.path.join(output_folder, "domain_direct_domain.list")
    if not os.path.exists(file_domain_direct_domain):
        with open(file_domain_direct_domain, 'w') as f:
            for i in set_domain_direct:
                ii = f"DOMAIN,{i}\n"
                f.write(ii)
    domain_direct_suffix = os.path.join(output_folder, "domain_direct_suffix.list")
    if not os.path.exists(domain_direct_suffix):
        with open(domain_direct_suffix, 'w') as f:
            for i in set_suffix_direct:
                ii = f"DOMAIN-SUFFIX,{i}\n"
                f.write(ii)
                 
    domain_direct_keyword = os.path.join(output_folder, "domain_direct_keyword.list")
    if not os.path.exists(domain_direct_keyword):
        with open(domain_direct_keyword, 'w') as f:
            for i in set_keyword_direct:
                ii = f"DOMAIN-KEYWORD,{i}\n"
                f.write(ii)



#    domain_file = os.path.join(output_folder, "domain_proxy.list")
#    if not os.path.exists(domain_file):
#        with open(domain_file, 'w') as f:
#            for i in set_keyword_proxy:
#                ii = f"DOMAIN-KEYWORD,{i}\n"
#                f.write(ii)
#
#            for i in set_suffix_proxy:
#                ii = f"DOMAIN-SUFFIX,{i}\n"
#                f.write(ii)
#
#            for i in set_domain_proxy:
#                ii = f"DOMAIN,{i}\n"
#                f.write(ii)
#
    file_domain_proxy_domain = os.path.join(output_folder, "domain_proxy_domain.list")
    if not os.path.exists(file_domain_proxy_domain):
        with open(file_domain_proxy_domain, 'w') as f:
            for i in set_domain_proxy:
                ii = f"DOMAIN,{i}\n"
                f.write(ii)
    
    domain_proxy_suffix = os.path.join(output_folder, "domain_proxy_suffix.list")
    if not os.path.exists(domain_proxy_suffix):
        with open(domain_proxy_suffix, 'w') as f:
            for i in set_suffix_proxy:
                ii = f"DOMAIN-SUFFIX,{i}\n"
                f.write(ii)
    
    domain_proxy_keyword = os.path.join(output_folder, "domain_proxy_keyword.list")
    if not os.path.exists(domain_proxy_keyword):
        with open(domain_proxy_keyword, 'w') as f:
            for i in set_keyword_proxy:
                ii = f"DOMAIN-KEYWORD,{i}\n"
                f.write(ii)
    
    # for Clash
#    domain_file = os.path.join(output_folder, "domain_direct.yaml")
#    if not os.path.exists(domain_file):
#        with open(domain_file, 'w') as f:
#            f.write("payload:\n")
#
#            for i in set_keyword_direct:
#                ii = f"  - DOMAIN-KEYWORD,{i}\n"
#                f.write(ii)
#
#            for i in set_suffix_direct:
#                ii = f"  - DOMAIN-SUFFIX,{i}\n"
#                f.write(ii)
#
#            for i in set_domain_direct:
#                ii = f"  - DOMAIN,{i}\n"
#                f.write(ii)
#
#    domain_file = os.path.join(output_folder, "domain_proxy.yaml")
#    if not os.path.exists(domain_file):
#        with open(domain_file, 'w') as f:
#            f.write("payload:\n")
#
#            for i in set_keyword_proxy:
#                ii = f"  - DOMAIN-KEYWORD,{i}\n"
#                f.write(ii)
#
#            for i in set_suffix_proxy:
#                ii = f"  - DOMAIN-SUFFIX,{i}\n"
#                f.write(ii)
#
#            for i in set_domain_proxy:
#                ii = f"  - DOMAIN,{i}\n"
#                f.write(ii)
    
    file_domain_direct_domain = os.path.join(output_folder, "domain_direct_domain.yaml")
    if not os.path.exists(file_domain_direct_domain):
        with open(file_domain_direct_domain, 'w') as f:
            f.write("payload:\n")
            for i in set_domain_direct:
                ii = f"  - DOMAIN,{i}\n"
                f.write(ii)
    
    domain_direct_suffix = os.path.join(output_folder, "domain_direct_suffix.yaml")
    if not os.path.exists(domain_direct_suffix):
        with open(domain_direct_suffix, 'w') as f:
            f.write("payload:\n")
            for i in set_suffix_direct:
                ii = f"  - DOMAIN-SUFFIX,{i}\n"
                f.write(ii)
    
    domain_direct_keyword = os.path.join(output_folder, "domain_direct_keyword.yaml")
    if not os.path.exists(domain_direct_keyword):
        with open(domain_direct_keyword, 'w') as f:
            f.write("payload:\n")
            for i in set_keyword_direct:
                ii = f"  - DOMAIN-KEYWORD,{i}\n"
                f.write(ii)
    
    
    file_domain_proxy_domain = os.path.join(output_folder, "domain_proxy_domain.yaml")
    if not os.path.exists(file_domain_proxy_domain):
        with open(file_domain_proxy_domain, 'w') as f:
            f.write("payload:\n")
            for i in set_domain_proxy:
                ii = f"  - DOMAIN,{i}\n"
                f.write(ii)
    
    domain_proxy_suffix = os.path.join(output_folder, "domain_proxy_suffix.yaml")
    if not os.path.exists(domain_proxy_suffix):
        with open(domain_proxy_suffix, 'w') as f:
            f.write("payload:\n")
            for i in set_suffix_proxy:
                ii = f"  - DOMAIN-SUFFIX,{i}\n"
                f.write(ii)
    
    domain_proxy_keyword = os.path.join(output_folder, "domain_proxy_keyword.yaml")
    if not os.path.exists(domain_proxy_keyword):
        with open(domain_proxy_keyword, 'w') as f:
            f.write("payload:\n")
            for i in set_keyword_proxy:
                ii = f"  - DOMAIN-KEYWORD,{i}\n"
                f.write(ii)
    
    log.logger.info(
        f"gen domain_direct.list & domain_proxy.list successfully.")

    # ip 去重合
    start_time = timeit.default_timer()
    set_ipv4_direct, set_ipv6_direct = handle_dedup_ip(direct_set)
    end_time = timeit.default_timer()
    log.logger.info(f"handle_dedup_ip direct cost {end_time-start_time}s.")

    start_time = timeit.default_timer()
    set_ipv4_proxy, set_ipv6_proxy = handle_dedup_ip(proxy_set)
    end_time = timeit.default_timer()
    log.logger.info(f"handle_dedup_ip proxy cost {end_time-start_time}s.")

    set_ipv4_proxy -= set_ipv4_direct
    set_ipv6_proxy -= set_ipv6_direct

    # save
    ip_file = os.path.join(output_folder, "ip_direct.list")
    if not os.path.exists(ip_file):
        with open(ip_file, 'w') as f:
            for i in set_ipv4_direct:
                ii = f"IP-CIDR,{i},no-resolve\n"
                f.write(ii)

            for i in set_ipv6_direct:
                ii = f"IP-CIDR6,{i},no-resolve\n"
                f.write(ii)

    ip_file = os.path.join(output_folder, "ip_proxy.list")
    if not os.path.exists(ip_file):
        with open(ip_file, 'w') as f:
            for i in set_ipv4_proxy:
                ii = f"IP-CIDR,{i},no-resolve\n"
                f.write(ii)

            for i in set_ipv6_proxy:
                ii = f"IP-CIDR6,{i},no-resolve\n"
                f.write(ii)

    # for Clash
    ip_file = os.path.join(output_folder, "ip_direct.yaml")
    if not os.path.exists(ip_file):
        with open(ip_file, 'w') as f:
            f.write("payload:\n")

            for i in set_ipv4_direct:
                ii = f"  - IP-CIDR,{i},no-resolve\n"
                f.write(ii)

            for i in set_ipv6_direct:
                ii = f"  - IP-CIDR6,{i},no-resolve\n"
                f.write(ii)

    ip_file = os.path.join(output_folder, "ip_proxy.yaml")
    if not os.path.exists(ip_file):
        with open(ip_file, 'w') as f:
            f.write("payload:\n")

            for i in set_ipv4_proxy:
                ii = f"  - IP-CIDR,{i},no-resolve\n"
                f.write(ii)

            for i in set_ipv6_proxy:
                ii = f"  - IP-CIDR6,{i},no-resolve\n"
                f.write(ii)

    log.logger.info(f"gen ip_direct.list & ip_proxy.list successfully.")

    # user-agent 类的文件处理
    ua_set_direct = handle_dedup_useragent(direct_set)
    ua_set_proxy = handle_dedup_useragent(proxy_set)

    ua_set_proxy -= ua_set_direct

    # save
    ua_direct_file = os.path.join(output_folder, "useragent_direct.list")
    if not os.path.exists(ua_direct_file):
        with open(ua_direct_file, 'w') as f:
            for i in ua_set_direct:
                f.write(i)

    ua_proxy_file = os.path.join(output_folder, "useragent_proxy.list")
    if not os.path.exists(ua_proxy_file):
        with open(ua_proxy_file, 'w') as f:
            for i in ua_set_proxy:
                f.write(i)

    # for Clash
    ua_direct_file = os.path.join(output_folder, "useragent_direct.yaml")
    if not os.path.exists(ua_direct_file):
        with open(ua_direct_file, 'w') as f:
            f.write("payload:\n")
            for i in ua_set_direct:
                f.write(f"  - {i}")

    ua_proxy_file = os.path.join(output_folder, "useragent_proxy.yaml")
    if not os.path.exists(ua_proxy_file):
        with open(ua_proxy_file, 'w') as f:
            f.write("payload:\n")
            for i in ua_set_proxy:
                f.write(f"  - {i}")

    log.logger.info(
        f"gen useragent_direct.list & useragent_proxy.list successfully.")


def push_github(rules_folder, repo_folder):
    """ pushu to github """
    # rules_folder: rules folder( .../output_rules)
    # repo_folder: github repo folder

    # for simple use: subprocess library , not gitpython

    # 前提：在机器上，已经安装git，并且成功拉取远端git repo到本地。切换到newone分支
    # repo_folder = 'git@github.com:JakATom/DE_SSSProfile.git'
    try:
        repo = Repo(repo_folder)

        # 通过cmd: git branch  -r 查看

        remote_branch = repo.git.branch('-r')
        if '/' in remote_branch:
            repo_remote = remote_branch.split('/')[0].strip()
        else:
            log.logger.error('repo_remote get failed.')
            log.logger.error('failed to push files to github.')            
            return

        remote = repo.remote(repo_remote)
        # remote = repo.remotes['newone']
        # remote.pull('refs/heads/newone:refs/heads/newone')

        # # 获取所有分支
        # branches = remote.refs
        # for b in branches:
        #     print(b.remote_head)

        cur_branch = repo.git.branch()
        if not '* newone' in cur_branch.split('\n'):
            log.logger.info('cur branch is not newone, switch to newone')
            repo.git.checkout('newone')

        remote.pull()
        
        # 获取版本库的暂存区
        index = repo.index

        fils_git = []
        # do something about files: cp rule files to git repo path
        for root, dirs, files in os.walk(rules_folder):
            for file in files:
                if not (file.endswith('.list') or file.endswith('.yaml')):
                    log.logger.info(os.path.join(root, file))
                    continue
                
                source = os.path.join(root, file)
                target = os.path.join(repo_folder, 'newone', file)
                fils_git.append(target)

                log.logger.debug(f'start to cp files to git repo path')
                shutil.copy(source, target)
                log.logger.info(f'{file} copied.')
        
        ## ---- 2023.12.10 add push source .py script to github
        target_dl_source_py = os.path.join(repo_folder, 'newone', 'archive', 'dl_source.py')
        dl_source_py = os.path.join(current_path, 'dl_source.py')

        target_rules_yaml = os.path.join(repo_folder, 'newone', 'archive', 'rules.yaml')
        rules_yaml = os.path.join(current_path, 'rules.yaml')
        
        log.logger.debug('start to cp dl_source.py to git repo path')
        shutil.copy(dl_source_py, target_dl_source_py)
        log.logger.info('dl_source.py copied.')
        
        log.logger.debug('start to cp rules.yaml to git repo path')
        shutil.copy(rules_yaml, target_rules_yaml)
        log.logger.info('rules.yaml copied.')

        fils_git.append(target_dl_source_py)
        fils_git.append(target_rules_yaml)
        ## ---- 2023.12.10 add end.

        index.add(fils_git)
        index.commit(f'{time_now} rule files update.')
        #
        remote.push()
        log.logger.info('git push ok.')

    except Exception as e:
        log.logger.error(f"git_push: {type(e).__name__} ,args:\n{e.args}")

    pass

def check_folders():
    """ 存储的数据大小，超过5天就删除否则删除旧的 """
    log.logger.info('enter check_folders()')

    log.logger.info(f'before paths: {current_path}')
    paths = os.listdir(current_path)
    log.logger.info(f'paths: {paths}')

    ab_paths = [os.path.join(current_path, p) for p in paths]
    log.logger.info(f'ab_paths: {ab_paths}')

    dirs = [p for p in ab_paths if os.path.isdir(p)]
    log.logger.info(f'dirs: {dirs}')

    len_dirs = len(dirs)
    MAX_DIRS = 5

    if len_dirs > MAX_DIRS:
        dirs.sort(reverse=True)
        log.logger.info(f'sorted dirs: {dirs}')
        
        for i in range(MAX_DIRS-len_dirs, 0):
            # remove
            try:
                log.logger.info('before shutil.rmtree.')
                shutil.rmtree(os.path.join(current_path, dirs[i]))
                log.logger.info(f'{os.path.join(current_path, dirs[i])} removed.')
            except Exception as e:
                log.logger.error(f"check_folders: {type(e).__name__}: {os.path.join(current_path, dirs[i])} ,args:\n{e.args}")

            
    pass

def create_asn_folder(folder):
    """创建asn本地路径"""
    # //
    # - 2023-10-19
    #     - acl4ssr
    #     - ...
    #     - asn
    #         - asn.xxx.list
    os.path.exists(folder) or os.makedirs(folder)
    pass


def download_asn_file(links_cn_asn, folder_asn):
    """下载asn文件到本地"""

    for url in links_cn_asn:
        abs_file = os.path.join(folder_asn, url['name'])
        log.logger.debug(abs_file)

        if not os.path.exists(abs_file):
            html_text = scrape_link(url['url'])
            log.logger.debug(f"get {url['url']}")

            if html_text is not None:
                save_data(abs_file, html_text)
                log.logger.debug(f"download {url['url']}")
    pass


def handle_asn(root_folder):
    """处理asn文件，生成规则文件
    root_folder：日期 目录
    """
    line_set = set()

    re_pattern = re.compile(r'^IP-ASN,\s*(\d+)', re.I)

    folder_asn = os.path.join(root_folder, 'asn')
    for root, _, files in os.walk(folder_asn):
        for file in files:
            if not (file.endswith('.list') or file.endswith('.txt')):
                log.logger.error(os.path.join(root, file))
                continue

            _file = os.path.join(root, file)
            log.logger.debug(f'start to open file: {_file}')
            with open(_file) as f:
                # 逐行处理
                for line in f:
                    # 去除最后的换行符，然后手动增加换行符
                    line = line.strip()
                    line = line.upper()

                    if line.startswith('IP-ASN'):
                        l = re.search(re_pattern, line)
                        line_set.add(l.group(1))
                    else:
                        continue
    log.logger.info('asn handle ok.')
    # save
    output_folder = os.path.join(root_folder, 'output_rules')
    os.path.exists(output_folder) or os.makedirs(output_folder)

    output_file = os.path.join(output_folder, 'asn.cn.list')
    with open(output_file, 'w') as f:
        for line in line_set:
            f.write(f"IP-ASN,{line},no-resolve\n")
    log.logger.info('asn.cn.list generated.')

if __name__ == '__main__':

    # # download rules to local
    config_file = os.path.join(current_path, 'rules.yaml')
    data = read_conf(config_file)

    root_folder = os.path.join(current_path, time_now)
    dict_folder = create_folders(data, root_folder)

    dl_rule_files(data, root_folder)

    # handle rules:
    log.logger.info('begin to generate policy file')
    gen_policy_file(dict_folder, root_folder)

    # ----2023.11.03 add: cn asn rules
    folder_asn = os.path.join(root_folder, 'asn')
    create_asn_folder(folder_asn)
    
    links_cn_asn = [
        { 'name': 'ASN.China.list', 'url':'https://raw.githubusercontent.com/VirgilClyne/GetSomeFries/main/ruleset/ASN.China.list'},
        { 'name': 'auto.ASN.China.list', 'url':'https://raw.githubusercontent.com/VirgilClyne/GetSomeFries/auto-update/ruleset/ASN.China.list'}
    ]
    download_asn_file(links_cn_asn, folder_asn)

    handle_asn(root_folder)

    # push to github
    rules_folder = os.path.join(root_folder, 'output_rules')
    # repo_folder = '/root/dess'
    repo_folder = '/Users/bulejames/Documents/ccDESSrules'
    push_github(rules_folder, repo_folder)

    # 存储的数据大小，超过5天就删除否则删除旧的
    time.sleep(10)
    check_folders()


    # ---- 待添加的功能 --- to do
    # 日志logging记录  - done
    # 存储的数据大小，超过5天就删除否则删除旧的

    # 集成git，直接提交到Github   - done

    # 结果通知：1. email 2.telegram
    # 1 is simple. so now choose it.

    # ---- no，直接重新生成把，直接使用新的
    # 时间记录，记录上一次运行时生成的时间（上次用于生成规则目录），
    # 用于下一次 的文件比较，比较是否有刷新的规则

    # 自己的规则库，用于定制化的规则  --- done

    pass
