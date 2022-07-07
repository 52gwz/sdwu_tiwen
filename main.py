from pickle import TRUE
import re
import time
import random
import requests
import base64
from pyDes import des, ECB, PAD_PKCS5
import json

# 密码加密
def des_encrypt(s, key):
    """
    DES 加密
    :param key: 秘钥
    :param s: 原始字符串
    :return: 加密后字符串，16进制
    """
    secret_key = base64.b64decode(key)
    k = des(secret_key, mode=ECB, pad=None, padmode=PAD_PKCS5)
    en = k.encrypt(s, padmode=PAD_PKCS5)
    return base64.b64encode(en).decode('utf-8')


def getCsrfToken(session):
    # 获取跨域请求
    url = "https://i.sdwu.edu.cn/infoplus/form/XSMRJKZKTBB/start"
    res = session.get(url)
    pattern = r'<meta itemscope="csrfToken" content="(.*?)">'

    csrf_token = str(re.findall(pattern, res.text)[0])
    return csrf_token


def loginin(username, password, session):
    res = session.get("https://sso.sdwu.edu.cn/login")

    pattern = r'<p id="login-croypto">(.*?)</p>'
    croypto = str(re.findall(pattern, res.text)[0])

    pattern = '<p id="login-page-flowkey">(.*?)</p>'
    execution = str(re.findall(pattern, res.text)[0])
    post_data = {
        'username': username,
        'type': 'UsernamePassword',
        '_eventId': 'submit',
        'geolocation': '',
        'execution': execution,
        'captcha_code:': '',
        'captcha_code': '',
        'croypto': croypto,
        'password': des_encrypt(password, croypto)
    }

    res = session.post("https://sso.sdwu.edu.cn/login", data=post_data)
    return res.status_code != 401


# 使用前需要用户登录
def getFormUrl(session, csrftoken):
    url = "https://i.sdwu.edu.cn/infoplus/interface/start"
    post_data = {
        "idc": "XSMRJKZKTBB",
        "release": "",
        "csrfToken": csrftoken,
        "formData": '{\"_VAR_URL\":\"https://i.sdwu.edu.cn/infoplus/form/XSMRJKZKTBB/start\",\"_VAR_URL_Attr\":\"{}\"}'
    }

    res = session.post(url, data=post_data)
    return res.json()['entities'][0]

def sign(stdnum,password):
    headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36"}
    session = requests.session()
    session.headers = headers
    if (loginin(stdnum, password, session)):
        print(stdnum+"登录成功")
        
    else:
        print("登录失败，请查看验证码")
        return False
    csrfToken = getCsrfToken(session)
    form_url =getFormUrl(session,csrfToken)
    form_id = re.findall(r"[0-9]+",form_url)[0]

    # 获取表单信息
    form_data = session.post("https://i.sdwu.edu.cn/infoplus/interface/render", data={
        "stepId": form_id,
        "instanceId": "",
        "admin": "true",
        "rand": random.random()*999,
        "width": "1283",
        "lang": "zh",
        "csrfToken": csrfToken
    },headers={
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
        "Referer":form_url

    })
    form_data = form_data.json()
    if(form_data['errno']!=0):
        print(form_data['error'])
        return False
    form_data = form_data["entities"][0]["data"]

    form_data["fieldK2"] = str(random.randint(362,368)/10)
    form_data["fieldK2_Name"] = form_data["fieldK2"] + "℃"
    form_data["fieldK3"] = str(random.randint(362,368)/10)
    form_data["fieldK3_Name"] = form_data["fieldK3"] + "℃"

    form_data["_VAR_ENTRY_NUMBER"] = str(form_data["_VAR_ENTRY_NUMBER"])
    form_data["_VAR_ENTRY_NAME"] = "学生每日健康状况填报表___"
    form_data["_VAR_ENTRY_TAGS"] = "学生工作部,学工管理"
    form_data["_VAR_NOW"] = str(form_data["_VAR_NOW"])
    form_data["_VAR_NOW_DAY"] = str(form_data["_VAR_NOW_DAY"])
    form_data["_VAR_NOW_MONTH"] = str(form_data["_VAR_NOW_MONTH"])
    form_data["_VAR_NOW_YEAR"] = str(form_data["_VAR_NOW_YEAR"])
    form_data["_VAR_STEP_NUMBER"] = str(form_data["_VAR_STEP_NUMBER"])
    form_data["_VAR_RELEASE"] = str.lower(str(form_data["_VAR_RELEASE"]))
    form_data["_VAR_URL"] = form_url

    if form_data['fieldSHI'] != "":
        form_data["fieldSHI_Attr"] = json.dumps({
        "_parent": form_data["fieldSHENG"]
        })
        form_data["fieldXIAN_Attr"] = json.dumps({
            "_parent": form_data["fieldSHI"]
        })

    # print("dumpted:\n" + json.dumps(form_data))
    post_data = {
        'actionId': 1,
        'formData': json.dumps(form_data),

        'rand': random.random() * 999,
        'stepId': form_id,
        'timestamp': int(time.time()),  # ?
        'boundFields': "fieldXH,fieldFXQK,fieldXM,fieldYC1,fieldYC2,fieldK10,fieldXXDD,fieldK11,fieldK12,fieldK13,fieldWFXYY,fieldZY,fieldK14,fieldK16,fieldK17,fieldTBSJ,fieldK18,fieldK19,fieldLH,fieldHSJG,fieldK9,fieldBJ,fieldK3,fieldK4,fieldFJH,fieldK1,fieldK2,fieldSHENG,fieldK7,fieldTJSJYC,fieldK8,fieldK5,fieldK20,fieldK6,fieldK21,fieldK22,fieldXIAN,fieldDQJZWZ,fieldSHI,fieldXYMC,fieldSJHM,fieldHSSJ",
        #可以优化
        'csrfToken': csrfToken,  # needed
        'lang': 'zh'

    }

    action_url="https://i.sdwu.edu.cn/infoplus/interface/listNextStepsUsers"
    resb = session.post(action_url,post_data)

    do_action_url = "https://i.sdwu.edu.cn/infoplus/interface/doAction"
    # post_data["rand"] =  random.random() * 999
    post_data["timestamp"] = int(time.time())
    post_data["nextUsers"] = "{}"
    resb = session.post(do_action_url, post_data)
    if(resb.json()["errno"] != 0):
        # print(resb['error'])
        if(resb['error'] == "今日已填报，请勿重复填报"):
            return True
        return False
    else:
        print("填报成功！")
    return True
if __name__ == '__main__':
    
    print(sign("账号","密码"))
    # {"errno": 0, "ecode": "SUCCEED", "entities": [
    #    {"stepId": 2, "name": "完成", "code": "autoStep1", "status": 0, "type": "Auto", "flowStepId": 0,
    #     "executorSelection": 0, "timestamp": 0, "posts": [], "users": [], "parallel": false,
    #     "hasInstantNotification": false, "hasCarbonCopy": false, "entryId": 4374621, "entryStatus": 0,
    #     "entryRelease": false}]}
