import volatility.plugins.common as common 
import volatility.utils as utils
import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.poolscan as poolscan 
import volatility.plugins.registry.shimcache as shimcache 
import volatility.plugins.registry.registryapi as registryapi

class ShimScanner(poolscan.SinglePoolScanner):
    """Pool scanner for allocs on 2003 and later"""

    checks = [ 
            ('PoolTagCheck', dict(tag = "Sdba")),
            ('CheckPoolSize', dict(condition = lambda x : x > 60)),
            ('CheckPoolType', dict(paged = True, non_paged = True)),
            ]

class ShimScan(common.AbstractWindowsCommand):
    """Finds appcompat cache entries from memory and registry"""

    @staticmethod
    def shimcache_xp(address_space):
        """Enumerate entries from the shared memory section 
        on XP systems."""

        seen = []
        shim = lambda x : (x.Tag == "Vad " and 
                                  x.VadFlags.Protection == 4)

        for process in tasks.pslist(address_space):
            for vad, space in process.get_vads(vad_filter = shim):
    
                if space.read(vad.Start, 4) != "\xEF\xBE\xAD\xDE":
                    continue
                  
                records = obj.Object("ShimRecords", 
                                     offset = vad.Start, 
                                     vm = space)

                for entry in records.Entries:

                    if not entry.is_valid():
                        continue

                    entry_offset = space.vtop(entry.obj_offset)
                    if entry_offset in seen:
                        continue
                    seen.append(entry_offset)

                    yield entry.Path, entry.LastModified, entry.LastUpdate

    @staticmethod
    def shimcache_new(address_space):
        """Enumerate entries on 2003 and later systems by finding
        the kernel's sdb pool allocations."""

        #physical_space = address_space.base
        header_size = address_space.profile.get_obj_size("_POOL_HEADER")

        for offset in ShimScanner().scan(address_space):

            value = obj.Object("String", 
                               offset = offset + header_size, 
                               vm = address_space, 
                               length = 512, 
                               encoding = "utf16")
            yield value, None, None

    def calculate(self):
        address_space = utils.load_as(self._config)
        regapi = registryapi.RegistryApi(self._config)

        profile = address_space.profile
        meta = profile.metadata 
        vers = (meta.get("major"), meta.get("minor"))

        if vers == (5, 1):
            for entry in ShimScan.shimcache_xp(address_space):
                yield "Memory", entry 
        else:
            for entry in ShimScan.shimcache_new(address_space):
                yield "Memory", entry

        for entry in shimcache.ShimCache.get_entries(address_space, regapi):
            yield "Registry", entry

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Source", "10"),
                                  ("Last Modified", "30"),
                                  ("Last Update", "30"),
                                  ("Path", ""),
                                 ])

        for method, (path, mod, upd) in data:
            if path.startswith("\\??\\"):
                self.table_row(outfd, method, mod, upd, path)
