import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.win32.tasks as tasks
import volatility.plugins.malware.malfind as malfind
import struct, string, yara, os

class DnsVadScanner(malfind.BaseYaraScanner):

    def __init__(self, task = None, **kwargs):
        self.task = task
        malfind.BaseYaraScanner.__init__(self, address_space = task.get_process_address_space(), **kwargs)

    def scan(self, offset = 0, maxlen = None):
        heaps = [heap.v() for heap in self.task.Peb.ProcessHeaps.dereference()]
        for vad, self.address_space in self.task.get_vads(vad_filter = lambda x : x.Start in heaps):
            for match in malfind.BaseYaraScanner.scan(self, vad.Start, vad.Length):
                yield match

class DnsScan(common.AbstractWindowsCommand):
    """Scan for hostnames in the DNS resolver"""

    @staticmethod
    def build_signatures(tld_file_path):
        """Build Yara signatures from the TLD file."""

        tlds = [l.strip().lower() for l in open(tld_file_path).readlines()]
        full_texts = []
        texts = []
        count = 0

        for line in tlds:
            count += len(line)
            texts.append(line)
            if count > 500:
                full_texts.append("$_ = /\.(" + "|".join(texts) + ")/ nocase wide")
                texts = []
                count = 0

        rule = "rule dns {\nstrings: \n"
        for text in full_texts:
            rule += "\t"
            rule += text
            rule += "\n"
        rule += "condition: any of them\n}"

        signatures = {'namespace1' : rule}
        return tlds, signatures

    @staticmethod
    def dns_scan(proc, tlds, sources):

        valid_chars = string.ascii_letters + string.digits + "-" + "."
        rules = yara.compile(sources = sources)
        scanner = DnsVadScanner(task = proc, rules = rules)
        seen = set()

        for hit, address in scanner.scan():

            size = 512
            data = scanner.address_space.zread(address - size, size + 32)
            
            count = size
            while count > 2:
                byte = data[count-2:count]
                if byte == "\x00\x00" or byte[0] not in valid_chars:
                    break
                count -= 2

            start = count

            while count < len(data):
                byte = data[count:count+2]
                if byte == "\x00\x00" or byte[0] not in valid_chars:
                    break
                count += 2

            hostname = data[start:count].replace('\x00', '')
            
            if hostname.startswith(".") or os.path.splitext(hostname)[-1][1:].lower() not in tlds:
                continue
            
            if hostname in seen:
                continue
            seen.add(hostname)

            hostname = "".join([c for c in hostname if c in valid_chars])
            yield address - size + start, hostname

    def calculate(self):
    
        tlds, sources = DnsScan.build_signatures("/Users/mhl/Desktop/Files/tlds-alpha-by-domain.txt")
        addr_space = utils.load_as(self._config)

        for proc in tasks.pslist(addr_space):
            if str(proc.ImageFileName) == "svchost.exe":
                found = False
                for mod in proc.get_load_modules():
                    if str(mod.BaseDllName or '') == "dnsrslvr.dll":
                        found = True
                        break
                if found:
                    for result in DnsScan.dns_scan(proc, tlds, sources):
                        yield result 
                    break

    def render_text(self, outfd, data):
        for a, s2 in data:
            print hex(a), s2