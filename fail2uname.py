#!/usr/bin/env python3
""" Match up IPs banned by fail2ban with failed logins

    NB: Requires sudo
    Usage:
      sudo ./fail2uname.py
"""


import sys, subprocess, datetime, pprint


def fail2ban():
  data = {} # key: ip, value:(datetime, 'Ban' | 'Unban')
  with open('/var/log/fail2ban.log') as log:
    for line in log:
     
      #2021-10-01 09:23:17,983 fail2ban.actions        [1132]: NOTICE  [sshd] Ban 205.185.114.141
      #0                 18                                     
      timestr = line[0:19]
      timestamp = datetime.datetime.strptime(timestr, "%Y-%m-%d %H:%M:%S")
      logtype = line[56:64].strip()
      message = line[71:].strip()
      if logtype == 'NOTICE':
        if message.startswith('Ban') or message.startswith('Unban'):
          action, address = message.split()
          if address not in data:
            data[address] = []
          data[address].append((timestamp, action))
    return data

def failed_logins():
  lastb = subprocess.run(['lastb', '-F'], stdout=subprocess.PIPE, universal_newlines=True) # TODO: add support for older files
  data = {}
  for line in lastb.stdout.splitlines():
    if line and not line.startswith('btmp'):

      #postgres ssh:notty    209.141.34.247   Fri Oct  1 07:15:43 2021 - Fri Oct  1 07:15:43 2021  (00:00)
      user, _, address, wkday1, month1, day1, time1, year1, _, wkday2, month2, day2, time2, year2, tz = line.split()
      startstr = '%02i-%s-%s %s' % (int(day1), month1, year1, time1)
      endstr = '%02i-%s-%s %s' % (int(day2), month2, year2, time2)
      startdt = datetime.datetime.strptime(startstr, "%d-%b-%Y %H:%M:%S")
      enddt = datetime.datetime.strptime(endstr, "%d-%b-%Y %H:%M:%S")
      if address not in data:
        data[address] = []
      data[address].append((startdt, user))
  return data

def match():
  bans = fail2ban()
  fails = failed_logins()
  common = set(bans).intersection(fails)
  for address in common:
    print(address)
    addr_fails = sorted(fails[address], key=lambda fail: fail[0]) # sort by start time of attempted login
    addr_bans = sorted(bans[address], key=lambda ban: ban[0])
    info = sorted(addr_fails + addr_bans)
    for i in info:
      print('  ', str(i[0]), i[1])


if __name__ == '__main__':
  match()

