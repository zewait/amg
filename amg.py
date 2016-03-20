#!/usr/bin/env python
# -*- coding:utf-8 -*-
import json
from jsonschema import validate
import socket
from subprocess import Popen
import smtplib
import time
import argparse

APP_SCHEMA = {
    'type': 'object',
    'properties': {
        'ip': {'type': 'string'},
        'port': {'type': 'number'},
        'command': {'type': 'string'}
    },
    'required': ['ip', 'port', 'command']
}


def validate_config(opts):
    json_config = json.load(opts.test)
    [validate(app, APP_SCHEMA) for app in json_config['apps']]


def get_cmd_opt():
    parse = argparse.ArgumentParser(
        prog='amg',
        description='server app manager',
        epilog='Create by hsf')
    parse.add_argument('-v', '--verbose', action='store_true',
                       help='Product verbose output.')
    parse.add_argument('-f', '--config', type=argparse.FileType('r'),
                       help='config file')
    parse.add_argument('-t', '--test', type=argparse.FileType('r'),
                       help='test config file', metavar='CONFIG')
    return parse.parse_args()


def send_email(user, pwd, recipient, subject, body):
    FROM = user
    # TO = recipient if recipient is list else [recipient]
    TO = recipient
    TEXT = body

    # Prepare actual message
    message = """\From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (FROM, ", ".join(TO), subject, TEXT)

    try:
        server = smtplib.SMTP_SSL('smtp.163.com', 587)
        server.ehlo()
        server.starttls()
        server.login(user, pwd)
        server.sendmail(FROM, TO, message)
        server.close()
        print 'successfully sent the mail'
    except BaseException, e:
        print 'failed send email, the error is: ', e, '\n'


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
    email_user = 'ze_wait@163.com'
    email_pwd = 'Ze123456'
    datenow_str = time.strftime('%Y/%m/%d %H:%M:%s')
    SUBJECT = '[EDS Server Error]'
    ip = getip()

    json_config = json.load(opts.config)
    opts.config.close()
    [validate(app, APP_SCHEMA) for app in json_config['apps']]

    for app in json_config['apps']:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((app['ip'], app['port']))
        if result == 0:
            print 'Port is open'
        else:
            send_body = """the %s:%d is closed at %s
                    """ % (ip, app['port'], datenow_str)
            send_email(
                email_user, email_pwd,
                app['email'], SUBJECT, send_body)
            print ip, app['port'], 'is close.'
            Popen([app['command']], shell=True)


def main():
    opts = get_cmd_opt()
    if opts.config is not None:
        sholud_restart_app(opts)
    elif opts.test is not None:
        validate_config(opts)


if __name__ == '__main__':
    main()
