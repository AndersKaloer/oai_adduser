import MySQLdb
import random
import argparse
import textwrap

# MySQL config
MYSQL_USER = 'root'
MYSQL_PASSWD = 'linux'
MYSQL_HOST = '127.0.0.1'
MYSQL_OAI_DB = 'oai_db'

# APN config
APN_NAME = 'oai.ipv4'

# MME config
MME_HOST = 'labuser.111.111'
MME_REALM = '111.111'

# PGW config
PGW_IPV4_VAL = '10.0.0.2'
PGW_IPV6_VAL = '0'

help_str = """Example usage:
./oai_adduser.py --imsi=208930000000008 \
--msisdn=88211005938 --ki=2DC204753BEA70DC8F010A4DFEDCEE33 \
--opc=bfa1d8864980a90313f0560144f97a74
"""

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=textwrap.dedent(help_str))
parser.add_argument('--imsi', metavar='SIM_IMSI', help='The IMSI of the sim card', required=True)
parser.add_argument('--msisdn', metavar='SIM_MSISDN', help='The MSISDN of the sim card', required=True)
parser.add_argument('--ki', metavar='SIM_KI', help='The KI used to program the sim card', required=True)
parser.add_argument('--opc', metavar='SIM_OPC', help='The OPC of the sim card', required=True)

args = parser.parse_args()

user_imsi = args.imsi
user_msisdn = args.msisdn
user_ki = args.ki
user_opc = args.opc

# Connect to db
con = MySQLdb.connect(user=MYSQL_USER, passwd=MYSQL_PASSWD,
                      host=MYSQL_HOST, db=MYSQL_OAI_DB);
c = con.cursor()

print("Updating MySQL tables")

# Insert apn - ignore if already exists
print("Inserting to apn table")
c.execute("""INSERT IGNORE INTO `apn` (`apn-name`, `pdn-type`)
             VALUES (%s, 'IPv4');""", (APN_NAME))
con.commit()

# Get idmmeidentity
c.execute("""SELECT `idmmeidentity` FROM `mmeidentity`
             WHERE `mmehost`=%s AND `mmerealm`=%s""",
             (MME_HOST, MME_REALM))
con.commit()
mmeid = -1
if c.rowcount > 0:
    mmeid = c.fetchone()[0]
    print("Found existing mmeidentity with id: %d" % mmeid)
else:
    # Insert to mmeidentity with host information
    print("Inserting to mmeidentity table")
    c.execute("""INSERT INTO `mmeidentity`
             (`mmehost`, `mmerealm`, `UE-Reachability`)
             VALUES (%s, %s, 0);""", (MME_HOST, MME_REALM))
    con.commit()
    mmeid = c.lastrowid
    print("New mmeidentity id: %d" % mmeid)


# Ensure pgw entry exists
c.execute("""SELECT `id` FROM `pgw`
             WHERE `ipv4`=%s AND `ipv6`=%s""",
             (PGW_IPV4_VAL, PGW_IPV6_VAL))
con.commit()
pgwid = -1
if c.rowcount > 0:
    pgwid = c.fetchone()[0]
    print("Found existing pgw with id: %d" % pgwid)
else:
    # Insert to mmeidentity with host information
    print("Inserting to pgw table")
    c.execute("""INSERT INTO `pgw`
                 (`ipv4`, `ipv6`)
                 VALUES (%s, %s);""", (PGW_IPV4_VAL, PGW_IPV6_VAL))
    con.commit()
    pgwid = c.lastrowid
    print("New pgw id: %d" % pgwid)

# Add pdn entry if not exists
c.execute("""SELECT `id` FROM `pdn`
             WHERE `apn`=%s AND `pgw_id`=%s AND `users_imsi`=%s""",
             (APN_NAME, pgwid, user_imsi))
con.commit()
if c.rowcount > 0:
    pdnid = c.fetchone()[0]
    print("Found existing pdn with id %d. Replacing..." % pdnid)
    # Replace
    c.execute("""UPDATE `pdn` SET
              `apn`=%s, `pdn_type`='IPv4', `pdn_ipv4`='0.0.0.0',
              `pdn_ipv6`='0:0:0:0:0:0:0:0',
              `aggregate_ambr_ul`=50000000,
              `aggregate_ambr_dl`=100000000,
              `pgw_id`=%s, `users_imsi`=%s, `qci`=9, `priority_level`=15,
              `pre_emp_cap`='DISABLED', `pre_emp_vul`='ENABLED',
              `LIPA-Permissions`='LIPA-only'
              WHERE `id`=%s;""",
              (APN_NAME, pgwid, user_imsi, pdnid))
    con.commit()
else:
    print("Inserting to pdn table")
    c.execute("""INSERT INTO `pdn`
                 (`apn`, `pdn_type`, `pdn_ipv4`, `pdn_ipv6`,
                  `aggregate_ambr_ul`, `aggregate_ambr_dl`,
                  `pgw_id`, `users_imsi`, `qci`, `priority_level`,
                  `pre_emp_cap`, `pre_emp_vul`, `LIPA-Permissions`)
                 VALUES
                 (%s, 'IPv4', '0.0.0.0', '0:0:0:0:0:0:0:0',
                  50000000, 100000000,
                  %s, %s, 9, 15,
                  'DISABLED', 'ENABLED', 'LIPA-only');""",
                 (APN_NAME, pgwid, user_imsi))
    con.commit()
    pdnid = c.lastrowid
    print("New pdn id: %d" % pdnid)

# Add user
print("Inserting to users table")
c.execute("""REPLACE INTO `users`
             (`imsi`, `msisdn`, `imei`,
              `imei_sv`, `ms_ps_status`,
              `rau_tau_timer`, `ue_ambr_ul`,
              `ue_ambr_dl`, `access_restriction`,
              `mme_cap`, `mmeidentity_idmmeidentity`,
              `key`, `RFSP-Index`, `urrp_mme`,
              `sqn`, `rand`, `OPc`)
             VALUES
             (%s, %s, NULL,
              NULL, 'PURGED',
              120, 50000000,
              100000000, 47,
              0000000000, %s,
              UNHEX(%s), 1, 0,
              0, UNHEX(%s), UNHEX(%s));""",
          (user_imsi, user_msisdn, mmeid, user_ki,
           "%x" % random.randint(0, 2**(8*16)), user_opc))
con.commit()
print("Added new user")


c.close()
con.close()
