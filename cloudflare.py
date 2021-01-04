import CloudFlare
import json
import requests
from dateutil.parser import parse
import time
import datetime
import pytz

cf = CloudFlare.CloudFlare(token='ADD your ToKeN hErE')
global zoneid

#main function
def main():
    # gets all zone details
    zonelist = cf.zones.get()
    for zone in zonelist:
        print(zone['name'])
    choose = str(input("enter zone to open: "))
    #loops over all zones
    for z in zonelist:
        if z['name']==choose:
            zonedetails(z)
        else:
            continue
    exit(0)

def zonedetails(zone):
    #getting zone dns details
    print('id', zone['id'])
    print('site', zone['name'])
    print('status', zone['status'])
    print('cloudflare state', zone['paused'])
    print('cf_type', zone['type'])
    print('development_mode', zone['development_mode'])
    print('nameserver 1',zone['name_servers'][0])
    print('nameserver 2',zone['name_servers'][1])
    for i in zone['original_name_servers']:
        print('original nameservers', i)
    print('original registrar', zone['original_registrar'])
    print('original dns host', zone['original_dnshost'])
    print('created on', parse(zone['created_on']))
    print('activated on', parse(zone['activated_on']))
    print('modified on', parse(zone['modified_on']))
    print('phishing detedted', zone['meta']['phishing_detected'])
    print("owner email", zone['owner']['email'])
    print('owner name', zone['account']['name'])
    print('website plan', zone['plan']['name'])
    for p in zone['permissions']:
        print('permissions', p)

    zoneid = zone['id']
    choice = int(input("press\n1.Site Details\n2.DNS\n3.DNSSEC\n4.SSL certs\5.Analytics\n6.Page Rules\n7.purge cache\n8.settings\n9. account logs\n enter your choice: "))
    if choice==1:
        print("scroll up to view site details")
    elif choice==2:
        dns(zoneid)
    elif choice==3:
        dnssec(zoneid)
    elif choice==4:
        sslcerts(zoneid)
    elif choice==5:
        analytics(zoneid)
    elif choice==6:
        pagerules(zoneid)
    elif choice==7:
        purgecache(zoneid)
    elif choice==8:
        settings(zoneid)
    elif choice==9:
        logs()
    else:
        print("TRY AGAIN press\n2.DNS\n3.DNSSEC\n4.SSL certs\5.Analytics\n6.Page Rules\n7.purge cache\n8.settings\n9. account logs")

#create, delete, view dns records
def dns(zone_id):
    print("type 0 to delete dns\ntype 1 to create dns\ntype 2 to show dns")
    do = int(input())
    # request the DNS records from that zone
    if do==0:
        deletedns(zone_id)
    elif do==1:
        createdns(zone_id)
    elif do==2:
        showdns(zone_id)
    else:
        print("type 0 to delete dns\ntype 1 to create dns\ntype 2 to show dns\n")

#show dns records
def showdns(zoneid):
    zone_id = zoneid
    try:
        dns_records = cf.zones.dns_records.get(zone_id)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit('/zones/dns_records.get %d %s - api call failed' % (e, e))

    # then all the DNS records for that zone
    for dnsrecord in dns_records:
        r_name = dnsrecord['name']
        r_type = dnsrecord['type']
        r_value = dnsrecord['content']
        r_id = dnsrecord['id']
        print('\t', r_name, r_type, r_value, '\n')

#creates dns records
def createdns(zoneid):
    zone_id = zoneid
    r_name = input("give an name to record: ")
    r_type = input("type of record A/AAAA/CNAME/TXT/SRV/MX/CAA: ")
    r_content = input("record content: ")
    record = {'name':r_name, 'type': r_type, 'content': r_content}
    cf.zones.dns_records.post(zoneid, data=record)
    print("added record", record)

#deletes dns records
def deletedns(zoneid):
    print("TRYING TO DELETE DNS RECORD")
    zone_id = zoneid
    dns_records = cf.zones.dns_records.get(zone_id)
    for dns_record in dns_records:
        dns_record_id = dns_record['id']
        dns_record_value = dns_record['content']
        print(dns_record_id, dns_record_value)
    d_record = str(input("record id :"))
    cf.zones.dns_records.delete(zoneid, d_record)
    print(d_record, "is deleted")

#zone settings
def settings(zoneid):
    settings = cf.zones.settings.get(zoneid)
    for setting in sorted(settings, key=lambda v: v['id']):
            r_name = setting['id']
            r_value = setting['value']
            r_editable = setting['editable']
            try:
                k = sorted(r_value.keys())
                print('\t%-30s %10s = %s' % (r_name, '(editable)' if r_editable else '', '{'))
                for k in sorted(r_value.keys()):
                    print('\t%-30s %10s    %s = %s' % ('', '', r_name+'/'+k, r_value[k]))
                print('\t%-30s %10s = %s' % ('', '', '}'))
            except:
                print('\t%-30s %10s = %s' % (r_name, '(editable)' if r_editable else '', r_value))

    print('')

#zone ssl settings
def sslcerts(zone_id):
    try:
            certificates = cf.zones.ssl.certificate_packs.get(zone_id)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
            exit('/zones.ssl.certificate_packs %d %s - api call failed' % (e, e))

    for certificate in certificates:
            certificate_type = certificate['type']
            primary_certificate = certificate['primary_certificate']
            certificate_hosts = certificate['hosts']
            certificate_sig = certificate['certificates'][0]['signature']
            certificate_sig_count = len(certificate['certificates'])
            if certificate_sig_count > 1:
                c = certificate['certificates'][0]
                print('%-10s %-32s    %-15s [ %s ]' % (
                    certificate_type,
                    primary_certificate,
                    c['signature'],
                    ','.join(certificate_hosts)
                ))
                nn = 0
                for c in certificate['certificates']:
                    nn += 1
                    if nn == 1:
                        next
                    print('%-40s %-10s %-32s %2d:%-15s [ %s ]' % (
                        '',
                        '',
                        '',
                        nn,
                        c['signature'],
                        ''
                    ))
            else:
                for c in certificate['certificates']:
                    print('%-10s %-32s    %-15s [ %s ]' % (
                        certificate_type,
                        primary_certificate,
                        c['signature'],
                        ','.join(certificate_hosts)
                    ))

    sslcerts_verify = cf.zones.ssl.verification.get(zone_id)
    print(sslcerts_verify)

#view dnssec for the zone
def dnssec(zone_id):
    try:
            settings = cf.zones.dnssec.get(zone_id)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
            exit('/zones.dnssec.get %d %s - api call failed' % (e, e))

        #print(zone_id, zone_name)
        # display every setting value
    for setting in sorted(settings):
            print('\t%-30s %10s = %s' % (
                setting,
                '(editable)' if setting == 'status' else '',
                settings[setting]
            ))

    print('')

#purgecache for the zone
def purgecache(zone_id):
    clear = {"purge_everything":True}
    cf.zones.purge_cache.delete(zone_id, data=clear)
    print("cache cleared")

def logs():
    lograw = requests.get('https://api.cloudflare.com/client/v4/accounts/ACCOUNT-ID/audit_logs', headers={'X-Auth-Email': 'account email', 'X-Auth-Key': 'account global api key','Content-Type': 'application/json'})
    if lograw.status_code != 200:
        print('FETCH failed: '+ str(lograw.status_code))
    logs = json.loads(lograw.content)
    #print(logs['result'])
    for log in logs['result']:
        log_action = log['action']['type']
        try:
            log_actor = log['actor']['email']
        except:
            log_actor = None
        log_res = log['resource']['type']
        log_date = parse(log['when'])
        print(log_date, log_action, log_actor, log_res)

#view pagerules
def pagerules(zone_id):
    rules = cf.zones.pagerules.get(zone_id)
    if len(rules)==0:
        print("No Page rules associated")
    for rule in rules:
        for target in rule['targets']:
            print("rule", target['constraint']['operator'], target['constraint']['value'])
        for action in rule['actions']:
            print("actions", action['id'], action['value'])
        #print(rule['targets'],rule['actions'], '\n')


def now_iso8601_time(h_delta):
    """Cloudflare API code - example"""

    t = time.time() - (h_delta * 3600)
    r = datetime.datetime.fromtimestamp(int(t), tz=pytz.timezone("UTC")).strftime('%Y-%m-%dT%H:%M:%SZ')
    return r

#graphql analytics for zone
def analytics(zone_id):
    date_before = now_iso8601_time(0) # now
    date_after = now_iso8601_time(7 * 24) # 7 days worth

    query="""
      query {
        viewer {
            zones(filter: {zoneTag: "%s"} ) {
            httpRequests1dGroups(limit:40, filter:{date_lt: "%s", date_gt: "%s"}) {
              sum { countryMap { bytes, requests, clientCountryName } }
              dimensions { date }
            }
          }
        }
      }
    """ % (zone_id, date_before[0:10], date_after[0:10]) # only use yyyy-mm-dd part for httpRequests1dGroups

    # query - always a post
    try:
        r = cf.graphql.post(data={'query':query})
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit('/graphql.post %d %s - api call failed' % (e, e))

    ## only one zone, so use zero'th element!
    zone_info = r['data']['viewer']['zones'][0]

    httpRequests1dGroups = zone_info['httpRequests1dGroups']

    for h in sorted(httpRequests1dGroups, key=lambda v: v['dimensions']['date']):
        result_date = h['dimensions']['date']
        result_info = h['sum']['countryMap']
        print(result_date)
        for element in sorted(result_info, key=lambda v: -v['bytes']):
            print("    %7d %7d %2s" % (element['bytes'], element['requests'], element['clientCountryName']))


if __name__ == '__main__':
    main()