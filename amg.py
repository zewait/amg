#!/usr/bin/env python
# -*- coding:utf-8 -*-
import json
from jsonschema import validate
import socket
from subprocess import Popen
import smtplib
import time
import argparse
from const import VERSION
import sys

reload(sys)
sys.setdefaultencoding('utf-8')

APP_SCHEMA = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string'},
        'ip': {'type': 'string'},
        'port': {'type': 'number'},
        'command': {'type': 'string'},
        'subject': {'type': 'string'},
        'msg': {'type': 'string'}
    },
    'required': ['ip', 'port', 'name', 'subject', 'msg']
}


def validate_config(opts):
    json_config = json.load(opts.test)
    map(lambda x: validate(x, APP_SCHEMA), json_config['apps'])


def get_cmd_optparse():
    parse = argparse.ArgumentParser(
        prog='amg',
        description='server app manager',
        epilog='Create by zewait')
    parse.add_argument('-v', '--verbose', action='store_true',
                       help='Product verbose output.')
    parse.add_argument('-f', '--config', type=argparse.FileType('r'),
                       help='config file')
    parse.add_argument('-t', '--test', type=argparse.FileType('r'),
                       help='test config file', metavar='CONFIG')
    parse.add_argument('-V', '--version', action='version',
                       version='%(prog)s '+VERSION)
    return parse


def send_email(user, pwd, recipient, subject, body):
    FROM = user
    # TO = recipient if recipient is list else [recipient]
    TO = recipient
    TEXT = body

    # Prepare actual message
    message = """From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (FROM, ", ".join(TO), subject, TEXT)


    try:
        server = smtplib.SMTP_SSL('smtp.163.com', 587)
        #server = smtplib.SMTP_SSL('smtp.qq.com', 465)
        #server.ehlo()
        #server.starttls()
        server.login(user, pwd)
        server.sendmail(FROM, TO, message)
        server.close()
        print(message)
        print('successfully sent the mail')
    except BaseException as e:
        print('failed send email, the error is: ', e, '\n')
        #send_email(user, pwd, recipient, subject, body)


def getip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('baidu.com', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except BaseException:
        return 'Unknow'


def sholud_restart_app(opts):
    email_user = '${user}'
    email_pwd = '${password}'
    datenow_str = time.strftime('%Y/%m/%d %H:%M:%s')
    ip = getip()

    json_config = json.load(opts.config, encoding='utf-8')
    opts.config.close()
    map(lambda x: validate(x, APP_SCHEMA), json_config['apps'])

    for app in json_config['apps']:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((app['ip'], app['port']))
        if result != 0:
            #send_body = """[%s](%s:%d): closed at %s
            #""" % (app['name'], ip, app['port'], datenow_str)
            send_body = app['msg'] % (app['name'], ip, app['port'], datenow_str)

            send_email(
                email_user, email_pwd,
                app['emails'], app['subject'], send_body)
            if 'command' in app:
                Popen([app['command']], shell=True)


def main():
    parse = get_cmd_optparse()
    opts = parse.parse_args()
    if opts.config is not None:
        sholud_restart_app(opts)
    elif opts.test is not None:
        validate_config(opts)
    else:
        parse.print_help()

def test_send():
    #email_user = '737250911@qq.com'
    #email_pwd = 'hqsaqlabokuzbdif'
    email_user = 'ze_wait@163.com'
    email_pwd = 'Ze888888'
    send_email(email_user, email_pwd, '773108248@qq.com', '服务器出问题', 'How To Cover Your Tracks On The Internet2008-06-25')


if __name__ == '__main__':
    main()
    #test_send()
