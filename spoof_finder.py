from requests import get as http_get
from colored_logs.logger import Logger, LogType
from contextlib import suppress
from netaddr import IPNetwork
from datetime import datetime
from ScrapeSearchEngine.ScrapeSearchEngine import Google, Bing, Yahoo, Duckduckgo
from re import compile

cphone = compile("[+]\d+(?:[-\s]|)[\d\-\s]+")
cmail = compile("\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*")

ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'

def find_links(query):
    query = query
    links = []
    try:
        links = Google(query, )
    except:
        try: links = Bing(query, ua)
        except:
            try: links = Yahoo(query, ua)
            except:
                try: links = Duckduckgo(query, ua)
                except:
                    try: links = Givewater(query, ua)
                    except:
                        try: links = Ecosia(query, ua)
                        except: pass

    return links
    

def important_input(*message):
    while 1:
        msg = input(*message).strip() or None
        if msg: return msg

def find_contact(asn):
    site, mail, phone = None, None, None
    try:
        with http_get("https://rdap.db.ripe.net/autnum/" + asn) as res:
            text = res.text
            mail = cmail.search(text)
            try:
                site = mail.group(0).split("@")[1]
            except:
                pass
            phone = cphone.search(text)
    except Exception as e:
        raise e
    return site, mail, phone

logger = Logger(
    ID='SpoofFinder'
)

def is_valid_asn(asn):
    if not isinstance(asn, int) and not asn.isdigit(): return False
    if len(asn) > 9: return False
    if len(asn) < 3: return False
    return True

def split_ASN(asn):
    if isinstance(asn, int) or asn.isdigit(): return asn
    return asn[2:]

while 1:
    inp = important_input("Target [ASN, RANGE, IP, CIDR]: ")

    logger.start_process('Getting %s infomention' % inp)
    target = inp
    
    if target.lower().startswith("as") or target.isdigit():
        if is_valid_asn(split_ASN(target)):
            target = ("AS" + target) if target.isdigit() else target
    
    elif "/" in target:
        try:
            target = str(IPNetwork(target)[0])
        except Exception as e:
            logger.stop_process(
                log_type=LogType.Error,
                values=str(e) or repr(e)
            )
            continue

            
    elif "-" in target:
        target = target.split("-")[0]
    
    target = target.strip()

    if not is_valid_asn(split_ASN(target)):
        with http_get("https://ipwhois.app/json/%s/" % target) as resp:
            json = resp.json()
            if not json["success"]:
                logger.stop_process(
                    log_type=LogType.Error,
                    values=json["message"]
                )
                continue
            target = json["asn"]

        logger.stop_process(
            log_type=LogType.Info,
            values="ASN: \033[95m%s\033[0m" % target
        )
    else:
        logger.info("ASN: \033[95m%s\033[0m" % target)

    break


logger.start_process('Getting %s spoof infomention from database' % target)

try:
    with http_get("https://api.spoofer.caida.org/sessions?asn=%s" % split_ASN(target)) as resp:
        data1 = resp.json()
        data = None
        if not data1: raise Exception("No Data found in database")

        with http_get("https://api.asrank.caida.org/v2/restful/asns/%s" % split_ASN(target)) as resp2:
            data2 = resp2.json()["data"]
            if not data2: raise Exception("No Data found in database")

            for bruh in data1["hydra:member"][::-1]:
                if bruh["routedspoof"] == "unknown":
                    continue
                data = bruh
                break
            if not data: raise Exception("No Data found in database")

            date_time_obj = datetime.strptime(data["timestamp"], '%Y-%m-%dT%H:%M:%S+00:00')

            site, mail, phone = find_contact(split_ASN(target))

            links = [
                *find_links(data2["asn"]["asnName"] + " server"),
                *(find_links(site) if site else [])
            ]

            spoof = data["routedspoof"]  == "received"
            logger.info('Name: %s' % data2["asn"]['asnName'])
            logger.info('Is IPHM (Spoofable): %s' % ("\033[92mYes" if spoof else "\033[91mNo"))
            logger.info('Countrey: \033[94m%s' % (data["country"].upper() + f" ({data2['asn']['country']['iso']})"))
            logger.info('Last Check: \033[96m%s' % date_time_obj.strftime("%b %d %Y %I:%M%p"))
            logger.info('Full Ips: \033[30m%s' % f'{data2["asn"]["cone"]["numberAddresses"]:,}')
            if spoof: logger.info('Spoof Ips: \033[32m%s' % len(IPNetwork(data["client4"] or data["client6"])))

            
            if site: logger.info('Owner Email Tag (Site): \033[033%s' % site )
            if mail: logger.info('Owner Email Address: \033[96m%s' % mail.group(0) )
            if phone: logger.info('Owner Phone Number: \033[94m%s' % phone.group(0) )
            
            if links:
                logger.info('Linkes:')
                for link in links:
                    logger.info('- ' + link)
            logger.stop_process()

except Exception as e:
    logger.error(str(e) or repr(e))
    logger.stop_process()
